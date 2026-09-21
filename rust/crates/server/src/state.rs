use crate::review_gate::ReviewGate;
use ignite_db_store::IssueRow;
use ignite_fix_pr::FixCandidate;
use ignite_tool_runner::ToolRunner;
use std::collections::HashMap;
use std::path::PathBuf;
use parking_lot::Mutex;
use std::time::Instant;

/// In-flight/finished state of one `POST /api/pipeline/:job_id/fix-pr/preview`
/// background run, keyed by job id in `AppState::fix_pr_previews` — lets
/// `GET .../fix-pr/preview/status` report real per-issue progress instead
/// of the frontend's old fake asymptotic timer, and lets the whole preview
/// generation (which can run one LLM call per open issue, serially) happen
/// off the request/response cycle.
#[derive(Default)]
pub struct FixPrPreviewJob {
    pub total: usize,
    pub completed: usize,
    pub done: bool,
    pub candidates: Vec<FixCandidate>,
    pub considered_count: usize,
    /// Set instead of running at all, e.g. "AI service unavailable."
    pub reason: Option<String>,
    /// True once a caller has cancelled this job via
    /// `DELETE .../fix-pr/preview`. Set alongside `done = true` at the
    /// same time the background task is aborted, since an aborted task
    /// never gets to run its own completion code.
    pub cancelled: bool,
    /// Handle to abort the `tokio::spawn`'d generation task outright —
    /// including whatever LLM request is in flight — rather than only
    /// stopping it between issues. `None` once the job has already
    /// finished/been cancelled and the handle was consumed.
    pub abort_handle: Option<tokio::task::AbortHandle>,
}

/// In-flight SSE pipeline job state (`runningRuns` in server.js) — one
/// entry per job currently streaming through `POST /api/pipeline`
/// (routes/pipeline_interactive.rs). `all_issues` mirrors the DB-persisted
/// snapshot (kept in sync via `replace_project_issues` +
/// `get_project_issues` on every phase) so `job_issues::lookup_job_issues`
/// (used by sarif.rs/github_annotations.rs) sees the same shape whether
/// the job is still running or already finished. `review_active` is true
/// only while the run is actually paused at the review gate — Ignite
/// Studio's file/rescan routes (not yet ported) check this before
/// exposing the live staging tree.
pub struct LiveRun {
    pub org: String,
    pub repo: String,
    pub project_id: Option<i64>,
    pub all_issues: Vec<IssueRow>,
    pub project_root: Option<PathBuf>,
    pub source_backup_dir: Option<PathBuf>,
    pub review_active: bool,
}

/// A run that ended without shipping for real (dry run, stopped at
/// review, unresolved findings, CI failure) but made it far enough to
/// have a publishable immutable snapshot. Short-TTL seam for
/// `POST /api/projects/:projectId/effectivate` (routes/review_gate.rs,
/// not yet ported) to provision + push it later without re-running
/// phases 1-5.
pub struct PendingEffectivation {
    pub org: String,
    pub repo: String,
    pub source_backup_dir: PathBuf,
    pub created_at: Instant,
}

pub struct AppState {
    pub runner: ToolRunner,
    pub db: ignite_db_store::DbStore,
    pub running_runs: Mutex<HashMap<String, LiveRun>>,
    pub pending_effectivations: Mutex<HashMap<i64, PendingEffectivation>>,
    pub review_gate: ReviewGate,
    pub llm_config: ignite_llm_client::LlmClientConfig,
    /// `config.json` + env overrides, loaded once at startup
    /// (`ignite_config::load_config`). Feeds `crate::phase4_config` and
    /// `state::runner_from_config` so tool enabled/binary flags actually
    /// reflect what's on disk instead of every check crate's hardcoded
    /// `::default()`.
    pub config: ignite_config::Config,
    /// One instance for the server's whole lifetime, passed by reference
    /// into every `run_phase4_checks` call. `PackageHallucinationChecker`
    /// carries a "process-lifetime" existence cache by design (see its own
    /// doc comment) — constructing a fresh one per request, as the
    /// orchestrator used to, silently discarded that cache on every single
    /// call and forced a full set of registry HTTP round-trips on every
    /// scan, never actually caching anything across repeat scans of the
    /// same repo the way Node's equivalent in-process cache does.
    pub package_hallucination_checker: ignite_package_hallucination::PackageHallucinationChecker<ignite_package_hallucination::HttpRegistryChecker>,
    /// Background fix-PR preview jobs, keyed by pipeline job id. See
    /// [`FixPrPreviewJob`].
    pub fix_pr_previews: Mutex<HashMap<String, FixPrPreviewJob>>,
    /// Shared client for `ignite-audit-log` sink deliveries — reused
    /// (rather than built per-event) for connection pooling, same
    /// rationale as every other shared `reqwest::Client` in this codebase.
    pub audit_http: reqwest::Client,
}

impl AppState {
    /// Persists the event to the local, tamper-evident audit trail
    /// (`db_store::audit_events`) unconditionally — GxP/Part-11-style
    /// auditability can't depend on an operator having configured an
    /// external SIEM sink, so this write always happens regardless of
    /// `audit_log.enabled`. It's then fire-and-forget-dispatched to any
    /// configured sinks as before: that half spawns the actual delivery so
    /// a slow/unreachable SIEM endpoint can never add latency to — or
    /// fail — the request that triggered the event, and stays a no-op
    /// (nothing spawned) when no sinks are configured.
    pub fn emit_audit_event(&self, event: ignite_audit_log::AuditEvent) {
        let metadata_json = if event.metadata.is_null() { None } else { Some(event.metadata.to_string()) };
        if let Err(e) = self.db.record_audit_event(&event.event_type, &event.severity, &event.summary, event.actor.as_deref(), event.org.as_deref(), event.repo.as_deref(), metadata_json.as_deref()) {
            tracing::error!("record_audit_event failed for {}: {e}", event.event_type);
        }

        if !self.config.audit_log.enabled || self.config.audit_log.sinks.is_empty() {
            return;
        }
        let sinks: Vec<ignite_audit_log::AuditSink> = self
            .config
            .audit_log
            .sinks
            .iter()
            .map(|s| ignite_audit_log::AuditSink {
                url: s.url.clone(),
                kind: match s.kind.as_str() {
                    "splunk_hec" => ignite_audit_log::AuditSinkKind::SplunkHec,
                    "datadog" => ignite_audit_log::AuditSinkKind::Datadog,
                    "cef" => ignite_audit_log::AuditSinkKind::Cef,
                    _ => ignite_audit_log::AuditSinkKind::Generic,
                },
                token: s.token.clone(),
            })
            .collect();
        let http = self.audit_http.clone();
        tokio::spawn(async move { ignite_audit_log::dispatch(&http, &sinks, &event).await });
    }
}

pub fn default_package_hallucination_checker() -> ignite_package_hallucination::PackageHallucinationChecker<ignite_package_hallucination::HttpRegistryChecker> {
    ignite_package_hallucination::PackageHallucinationChecker::new(ignite_package_hallucination::HttpRegistryChecker::default())
}

/// Resolves the configured LLM provider (`cfg.llm.provider`: `"local"`
/// (default), `"openai"`, `"anthropic"`, or `"azure-foundry"`) into the
/// client config both Phase 4's deep-scan and Ignite Studio's "Explain
/// issue"/"Suggest AI fix" buttons share.
pub fn llm_config_from_config(cfg: &ignite_config::Config) -> ignite_llm_client::LlmClientConfig {
    let provider = match cfg.llm.provider.as_str() {
        "openai" => ignite_llm_client::Provider::OpenAi,
        "anthropic" => ignite_llm_client::Provider::Anthropic,
        "azure-foundry" | "azure_foundry" | "azurefoundry" => ignite_llm_client::Provider::AzureFoundry,
        _ => ignite_llm_client::Provider::Local,
    };
    ignite_llm_client::LlmClientConfig {
        provider,
        openai_api_key: cfg.llm.openai.api_key.clone(),
        openai_base_url: cfg.llm.openai.base_url.clone(),
        openai_model: cfg.llm.openai.model.clone(),
        anthropic_api_key: cfg.llm.anthropic.api_key.clone(),
        anthropic_base_url: cfg.llm.anthropic.base_url.clone(),
        anthropic_model: cfg.llm.anthropic.model.clone(),
        azure_foundry_api_key: cfg.llm.azure_foundry.api_key.clone(),
        azure_foundry_endpoint: cfg.llm.azure_foundry.endpoint.clone(),
        azure_foundry_deployment: cfg.llm.azure_foundry.deployment.clone(),
        azure_foundry_api_version: cfg.llm.azure_foundry.api_version.clone(),
        scan_url: cfg.llm.url.clone(),
        scan_model: cfg.llm.model.clone(),
    }
}

/// Test/back-compat convenience: the local-LLM defaults with no
/// config.json/env involved.
#[cfg(test)]
pub fn default_llm_config() -> ignite_llm_client::LlmClientConfig {
    llm_config_from_config(&ignite_config::Config::default())
}

/// Serializes tests that mutate the process-global `GH_TOKEN`/
/// `GITHUB_TOKEN` env vars (`resolve_server_github_token()` reads them
/// directly) against each other — `cargo test` runs this binary's tests
/// concurrently on multiple threads by default, so without this a test
/// asserting "no token" behavior can observe a token another test just
/// set, and vice versa. Lives here (not `#[cfg(test)]`-gated) so both
/// `main.rs`'s and `routes/effectivate.rs`'s test modules can share the
/// same lock.
#[cfg(test)]
pub static GH_TOKEN_ENV_GUARD: Mutex<()> = Mutex::new(());

/// Serializes tests that mutate the process-global `IGNITE_DATA_DIR` env
/// var (`routes::pipeline_interactive::ignite_data_dir()` reads it
/// directly, and `routes::studio::codeql_db_dir_for` keys a real CodeQL
/// database's on-disk path off of it plus a numeric project id). Each test
/// in this binary gets its own fresh sqlite db via `spawn_test_server*`,
/// so its first-created project always gets id 1 — meaning two tests that
/// both build/query a real CodeQL database for "their" project 1 would
/// otherwise race on the exact same real directory unless this env var is
/// pointed at a fresh per-test tempdir for the guard's duration. Same
/// rationale/pattern as `GH_TOKEN_ENV_GUARD`.
#[cfg(test)]
pub static IGNITE_DATA_DIR_ENV_GUARD: Mutex<()> = Mutex::new(());

/// Test/back-compat convenience: tool binaries resolved from
/// `ignite_config::Config::default()` (every binary name equal to the
/// tool name, matching config.json's own defaults). Real server startup
/// uses `crate::phase4_config::runner_from_config(&state.config)` instead,
/// so a config.json/env binary override actually takes effect.
#[cfg(test)]
pub fn default_runner() -> ToolRunner {
    crate::phase4_config::runner_from_config(&ignite_config::Config::default())
}

#[cfg(test)]
mod characterization_tests {
    //! Pins what `AppState::emit_audit_event` guarantees today: the local trail
    //! is always written, synchronously, whether or not any SIEM sink exists.
    use super::*;

    fn state_with(config: ignite_config::Config) -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&dir.path().join("test.db")).unwrap();
        let state = AppState {
            runner: default_runner(),
            db,
            running_runs: Mutex::new(HashMap::new()),
            pending_effectivations: Mutex::new(HashMap::new()),
            review_gate: crate::review_gate::ReviewGate::default(),
            llm_config: default_llm_config(),
            config,
            package_hallucination_checker: default_package_hallucination_checker(),
            fix_pr_previews: Mutex::new(HashMap::new()),
            audit_http: reqwest::Client::new(),
        };
        (state, dir)
    }

    #[test]
    fn an_audit_event_is_recorded_locally_at_once_even_with_no_sink_configured() {
        let (state, _dir) = state_with(ignite_config::Config::default());
        assert!(!state.config.audit_log.enabled, "sinks are off by default");
        state.emit_audit_event(
            ignite_audit_log::AuditEvent::new("override.approved", "info", "override approved for secret: x".to_string())
                .actor("owner@example.com".to_string())
                .repo("acme", "widgets")
                .metadata(serde_json::json!({ "issueId": "secret::a.js::1", "origin": "api_key" })),
        );
        let rows = state.db.list_audit_events(Some("acme"), Some("widgets"), Some("override.approved"), None, None, None, None, 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].actor.as_deref(), Some("owner@example.com"));
        assert_eq!(rows[0].severity, "info");
        let meta: serde_json::Value = serde_json::from_str(rows[0].metadata_json.as_deref().unwrap()).unwrap();
        assert_eq!(meta["origin"], "api_key");
        assert!(state.db.verify_audit_chain().is_ok());
    }

    #[test]
    fn an_event_without_metadata_stores_no_metadata() {
        let (state, _dir) = state_with(ignite_config::Config::default());
        state.emit_audit_event(ignite_audit_log::AuditEvent::new("gate.push_rejected", "critical", "rejected".to_string()));
        let rows = state.db.list_audit_events(None, None, Some("gate.push_rejected"), None, None, None, None, 10);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].metadata_json.is_none());
    }
}
