//! Ignite configuration — config.json < environment variables. Faithful
//! Rust port of `config.js`'s `loadConfig()`.
//!
//! Strategy: build the typed `Config::default()` (mirrors the JS `defaults`
//! object literal-for-literal), convert it to a `serde_json::Value`, deep-
//! merge the on-disk config.json onto it (object keys merge, anything else
//! — including arrays — replaces wholesale, which is *stricter* than the
//! JS version and sidesteps the array-vs-empty-default-object gotcha the JS
//! `merge()` needed three explicit special-cases to work around), then
//! deserialize back into `Config`. Env var overrides apply afterward,
//! mutating the typed struct directly — one block per JS `if
//! (process.env.X) ...` line, in the same order, for an easy side-by-side
//! diff against config.js.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};

/// Placeholder shown by a redacted-`Debug` config struct in place of a
/// secret field's real value — never the value itself, so an accidental
/// `{:?}`/`tracing::debug!("{:?}", config)` on a struct holding an API
/// key, webhook secret, or SMTP password can't leak it into logs.
const REDACTED: &str = "[REDACTED]";

fn redact_str(s: &str) -> &str {
    if s.is_empty() {
        ""
    } else {
        REDACTED
    }
}

fn redact_opt(o: &Option<String>) -> Option<&str> {
    o.as_deref().map(|s| if s.is_empty() { "" } else { REDACTED })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub port: u16,
    pub llm: LlmConfig,
    pub github: GithubConfig,
    pub governance: GovernanceConfig,
    pub notifications: NotificationsConfig,
    pub auth: AuthConfig,
    pub security: SecurityConfig,
    pub compliance: ComplianceConfig,
    pub sbom: SbomConfig,
    pub metrics: MetricsConfig,
    pub api: ApiConfig,
    pub code_intelligence: CodeIntelligenceConfig,
    pub architecture: ArchitectureConfig,
    pub ignore_file: IgnoreFileConfig,
    /// Opaque per-phase title/description/enabled overrides — not yet
    /// consumed by anything on the Rust side (the phase-orchestration
    /// server isn't ported yet), kept as raw JSON so round-tripping
    /// config.json never loses data.
    #[serde(default)]
    pub phases: Vec<serde_json::Value>,
    pub mcp: McpConfig,
    pub ai_auto_justify: AiAutoJustifyConfig,
    pub sla: SlaConfig,
    pub audit_log: AuditLogConfig,
    pub policy: PolicyConfig,
    pub org_repos: OrgReposConfig,
    pub daily_report: DailyReportConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            port: 51337,
            llm: LlmConfig::default(),
            github: GithubConfig::default(),
            governance: GovernanceConfig::default(),
            notifications: NotificationsConfig::default(),
            auth: AuthConfig::default(),
            security: SecurityConfig::default(),
            compliance: ComplianceConfig::default(),
            sbom: SbomConfig::default(),
            metrics: MetricsConfig::default(),
            api: ApiConfig::default(),
            code_intelligence: CodeIntelligenceConfig::default(),
            architecture: ArchitectureConfig::default(),
            ignore_file: IgnoreFileConfig { enabled: true },
            phases: Vec::new(),
            mcp: McpConfig::default(),
            ai_auto_justify: AiAutoJustifyConfig::default(),
            sla: SlaConfig::default(),
            audit_log: AuditLogConfig::default(),
            policy: PolicyConfig::default(),
            org_repos: OrgReposConfig::default(),
            daily_report: DailyReportConfig::default(),
        }
    }
}

/// GitHub Org view scan scheduling. `maxConcurrentScans` (default 2) caps
/// how many `rescan_one` runs (clone -> validate-all -> github-check, 5-16+
/// minutes each per `rust/MIGRATION_STATUS.md`'s own benchmark) execute at
/// once across "Scan now", "Scan all" and the auto-rescan sweep alike;
/// every scan beyond the cap waits in a FIFO queue (shown as "Queued" in
/// the UI) and starts the moment a running one finishes. Read once at
/// server startup — changing it needs a restart. `0` is treated as `1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OrgReposConfig {
    pub max_concurrent_scans: u32,
    /// How stale a repo's last scan has to be before the auto-rescan sweep
    /// (`POST /api/org-repos/auto-rescan/run`, meant to be hit hourly by
    /// an external cron/launchd timer — deliberately not a live in-process
    /// scheduler, matching `scheduled-rescan`'s own "run by hand/cron/
    /// systemd" posture) re-triggers it. A repo never scanned at all is
    /// always considered stale regardless of this value. Whether the
    /// sweep does anything at all on a given hour is a separate, runtime-
    /// toggleable flag (`DbStore::get_bool_setting("auto_rescan_enabled")`)
    /// — not this static config value — since that's meant to be flipped
    /// live from the UI without a server restart.
    pub auto_rescan_stale_after_hours: u32,
}
impl Default for OrgReposConfig {
    fn default() -> Self { OrgReposConfig { max_concurrent_scans: 2, auto_rescan_stale_after_hours: 24 } }
}

/// Org-level daily findings digest: once a day, one email per org listing
/// every repo's still-unjustified (`status = 'open'`, no approved override)
/// findings from its most recent scan. Runs on a small in-process timer
/// (unlike the heavyweight `auto-rescan` sweep, which stays external —
/// this only reads `ignite.db` and sends one email per org, so there's no
/// scan load to keep off the server). Off by default. `time` is `HH:MM` in
/// the server's local timezone; `to` overrides `notifications.to` for this
/// report only (comma-separated, same as every other notification) and
/// falls back to it when empty. Sending itself still requires
/// `notifications.enabled`. `pdfBrowserBinary` is the Chrome/Chromium/Edge
/// executable used to render the report as a PDF download (headless
/// `--print-to-pdf` of the same HTML the email carries); empty auto-detects
/// (macOS app bundles, then common names on `PATH`), and with none found
/// the PDF export answers 501 instead of failing obscurely.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DailyReportConfig {
    pub enabled: bool,
    pub time: String,
    pub to: String,
    pub pdf_browser_binary: String,
    /// HTTPS endpoint (e.g. a Microsoft Sentinel Logic App / generic webhook)
    /// that receives the report as a JSON POST carrying a pre-built Sentinel
    /// incident object. Empty = webhook channel unconfigured.
    pub webhook_url: String,
    /// Optional secret sent as `Authorization: Bearer <token>` with the webhook POST.
    pub webhook_token: String,
    /// Azure Blob container SAS URL (`https://<acct>.blob.core.windows.net/<container>?<sas>`)
    /// the `.json`/`.pdf` report is PUT into. Empty = Azure Blob channel unconfigured.
    pub azure_blob_container_url: String,
}
impl Default for DailyReportConfig {
    fn default() -> Self {
        DailyReportConfig {
            enabled: false,
            time: "23:59".to_string(),
            to: String::new(),
            pdf_browser_binary: String::new(),
            webhook_url: String::new(),
            webhook_token: String::new(),
            azure_blob_container_url: String::new(),
        }
    }
}

/// GHAS-parity SIEM/audit-log streaming (`ignite-audit-log`): where to
/// deliver governance events (override approved, gate passed with
/// overrides, push rejected, API key created). Off by default and empty —
/// same "operator's explicit call" posture as `SecretVerificationConfig`,
/// since this sends internal governance data to a third-party endpoint.
/// `sinks[].kind`/`token` mirror `ignite_audit_log::AuditSink` field for
/// field; kept here as a separate type (not a re-export) so this crate
/// never depends on `ignite-audit-log`, matching every other config
/// struct in this file staying a plain data description.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogConfig {
    pub enabled: bool,
    #[serde(default)]
    pub sinks: Vec<AuditSinkConfig>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditSinkConfig {
    pub url: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub token: Option<String>,
}
impl std::fmt::Debug for AuditSinkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditSinkConfig").field("url", &self.url).field("kind", &self.kind).field("token", &redact_opt(&self.token)).finish()
    }
}

/// GHAS-parity SLA tracking: how many days an open issue may sit
/// unresolved before it counts as an "SLA breach" (surfaced as a badge on
/// the Onboarded Repos view and as a blocking failure from
/// `scheduled-rescan`). Bucketed by `override-engine`'s existing 0-10
/// issue score rather than the coarser two-value error/warning severity,
/// since the score already carries the finer-grained triage signal.
/// Defaults follow common vuln-management SLA norms (critical/high/medium
/// tiers); `mediumDays` also covers everything below the high threshold.
/// US-02: which named [`ignite_policy::PolicyVersion`] `validate-all`
/// pins for a run. `strict: false` (default) is
/// [`ignite_policy::PolicyVersion::legacy_compatible`] — every existing
/// installation's gate behavior is unchanged, coverage is still reported
/// but never turns a clean-findings run `incomplete`. `strict: true` opts
/// into [`ignite_policy::PolicyVersion::strict_publication`] — a
/// deliberate, explicit per-deployment choice, matching this backlog's
/// "require deliberate configuration to change an existing installation's
/// gating policy" instruction.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PolicyConfig {
    pub strict: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlaConfig {
    pub enabled: bool,
    pub critical_days: u32,
    pub high_days: u32,
    pub medium_days: u32,
}
impl Default for SlaConfig {
    fn default() -> Self { SlaConfig { enabled: true, critical_days: 7, high_days: 30, medium_days: 90 } }
}

/// Auto-justification of low-risk blocking findings via the configured LLM
/// (`llm.*`) at the final review gate, right after any exact-match
/// carry-forward from a previous scan of the same org/repo has already
/// been applied. Off by default and deliberately narrow: only categories
/// on `categories` are ever offered to the model, and its response is
/// still filtered back down to that same allowlist server-side — the
/// model is never trusted to decide which categories are safe to
/// auto-acknowledge, only to draft a justification within ones a human
/// already scoped as low-risk (parseable-license mismatches, not secrets
/// or SAST findings with real exploitation potential). Applied overrides
/// are recorded distinctly (actor `ai-assist@ignite.internal`) so Ignite
/// Studio can show them as identified-but-justified without conflating
/// them with a human's own review decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiAutoJustifyConfig {
    pub enabled: bool,
    pub categories: Vec<String>,
    /// Upper bound on how many eligible findings go into a single
    /// justification request — keeps the prompt (and a single bad
    /// response) bounded regardless of how many low-risk findings a scan
    /// turns up.
    pub max_findings_per_request: usize,
}
impl Default for AiAutoJustifyConfig {
    fn default() -> Self {
        AiAutoJustifyConfig { enabled: false, categories: vec!["license-compliance".to_string()], max_findings_per_request: 50 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmConfig {
    /// Which backend `llm.url`/`llm.model` below, `llm.openai`,
    /// `llm.anthropic`, or `llm.azureFoundry` resolves against: `"local"`,
    /// `"openai"`, `"anthropic"`, or `"azure-foundry"`. Drives both Phase
    /// 4's deep-scan (Check 3) and Ignite Studio's on-demand "Explain
    /// issue"/"Suggest AI fix" buttons — both share this one connection.
    pub provider: String,
    pub url: String,
    pub model: String,
    pub mode: String,
    pub max_files: u32,
    pub chunk_chars: u32,
    pub deep_scan_enabled: bool,
    /// `"warning"`: quality/encapsulation findings show as warnings;
    /// `"info"`: informational only. See `LLM_ADVISORY_LEVEL`.
    pub advisory_level: String,
    pub openai: OpenAiLlmConfig,
    pub anthropic: AnthropicLlmConfig,
    pub azure_foundry: AzureFoundryLlmConfig,
}
impl Default for LlmConfig {
    fn default() -> Self {
        LlmConfig {
            provider: "local".into(),
            url: "http://localhost:8050".into(),
            model: "default".into(),
            mode: "warn".into(),
            max_files: 40,
            chunk_chars: 10_000,
            deep_scan_enabled: true,
            advisory_level: "info".into(),
            openai: OpenAiLlmConfig::default(),
            anthropic: AnthropicLlmConfig::default(),
            azure_foundry: AzureFoundryLlmConfig::default(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenAiLlmConfig {
    pub api_key: String,
    pub base_url: String,
    pub model: String,
}
impl std::fmt::Debug for OpenAiLlmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAiLlmConfig").field("api_key", &redact_str(&self.api_key)).field("base_url", &self.base_url).field("model", &self.model).finish()
    }
}
impl Default for OpenAiLlmConfig {
    fn default() -> Self {
        OpenAiLlmConfig { api_key: String::new(), base_url: "https://api.openai.com/v1".into(), model: "gpt-4o-mini".into() }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnthropicLlmConfig {
    pub api_key: String,
    pub base_url: String,
    pub model: String,
}
impl std::fmt::Debug for AnthropicLlmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnthropicLlmConfig").field("api_key", &redact_str(&self.api_key)).field("base_url", &self.base_url).field("model", &self.model).finish()
    }
}
impl Default for AnthropicLlmConfig {
    fn default() -> Self {
        AnthropicLlmConfig { api_key: String::new(), base_url: "https://api.anthropic.com/v1".into(), model: "claude-opus-5".into() }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureFoundryLlmConfig {
    pub api_key: String,
    /// Resource endpoint only, e.g. `https://my-resource.openai.azure.com`
    /// — no `/openai/deployments/...` suffix, that's built from
    /// `deployment`/`api_version` at request time.
    pub endpoint: String,
    /// Azure Foundry addresses models by deployment name, not model name —
    /// this is what appears in the request URL and is sent as `model` in
    /// the request body (Azure ignores the body value; the deployment in
    /// the URL is authoritative).
    pub deployment: String,
    pub api_version: String,
}
impl std::fmt::Debug for AzureFoundryLlmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureFoundryLlmConfig").field("api_key", &redact_str(&self.api_key)).field("endpoint", &self.endpoint).field("deployment", &self.deployment).field("api_version", &self.api_version).finish()
    }
}
impl Default for AzureFoundryLlmConfig {
    fn default() -> Self {
        AzureFoundryLlmConfig { api_key: String::new(), endpoint: String::new(), deployment: String::new(), api_version: "2024-10-21".into() }
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OauthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scope: String,
}
impl std::fmt::Debug for OauthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OauthConfig").field("client_id", &self.client_id).field("client_secret", &redact_str(&self.client_secret)).field("redirect_uri", &self.redirect_uri).field("scope", &self.scope).finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubConfig {
    pub orgs: String,
    pub bootstrap_branch: String,
    /// 'https' | 'ssh'
    pub remote_protocol: String,
    pub oauth: OauthConfig,
}
impl Default for GithubConfig {
    fn default() -> Self {
        GithubConfig {
            orgs: String::new(),
            bootstrap_branch: "ignite".into(),
            remote_protocol: "https".into(),
            oauth: OauthConfig {
                scope: "repo".into(),
                ..Default::default()
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceConfig {
    pub repo: String,
    pub workflow: String,
    pub event: String,
    pub timeout_minutes: u32,
}
impl Default for GovernanceConfig {
    fn default() -> Self {
        GovernanceConfig {
            repo: "ai-governance-poc-2026/devops-governance".into(),
            workflow: "ai-guardrails-orchestrator.yml".into(),
            event: "pull_request".into(),
            timeout_minutes: 30,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub secure: bool,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
}
impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig").field("host", &self.host).field("port", &self.port).field("secure", &self.secure).field("user", &self.user).field("pass", &redact_opt(&self.pass)).finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationsConfig {
    pub enabled: bool,
    pub to: String,
    pub from: String,
    pub smtp: SmtpConfig,
}
impl Default for NotificationsConfig {
    fn default() -> Self {
        NotificationsConfig {
            enabled: false,
            to: String::new(),
            from: "Ignite Gatekeeper <ignite@localhost>".into(),
            smtp: SmtpConfig {
                port: 587,
                ..Default::default()
            },
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scope: String,
}
impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig").field("issuer", &self.issuer).field("client_id", &self.client_id).field("client_secret", &redact_str(&self.client_secret)).field("redirect_uri", &self.redirect_uri).field("scope", &self.scope).finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthConfig {
    /// 'standalone' | 'oidc' | 'github'
    pub mode: String,
    pub allow_self_registration: bool,
    pub oidc: OidcConfig,
}
impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            mode: "standalone".into(),
            allow_self_registration: true,
            oidc: OidcConfig {
                scope: "openid email profile".into(),
                ..Default::default()
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecretsConfig {
    #[serde(default)]
    pub known_public_key_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitleaksConfig {
    pub enabled: bool,
    pub binary: String,
    pub config_path: String,
    /// Also runs `gitleaks detect` against full git commit history (not
    /// just the current working tree), catching a secret that was
    /// committed then removed in a later commit — the one class of secret
    /// GHAS's own secret-scanning alerts catch that a working-tree-only
    /// scan structurally cannot. Off by default here — it requires a real
    /// `.git` directory (a no-op on an uploaded ZIP with no git history)
    /// and costs meaningfully more time than a working-tree scan on a repo
    /// with a long history — but `phase4-orchestrator::run_phase4_checks`
    /// forces it on whenever it runs in full (non-`fast`) mode regardless
    /// of this default, so it only actually stays off for `fast` runs.
    #[serde(default)]
    pub scan_history: bool,
}
impl Default for GitleaksConfig {
    fn default() -> Self {
        GitleaksConfig { enabled: false, binary: "gitleaks".into(), config_path: String::new(), scan_history: false }
    }
}

macro_rules! tool_toggle {
    ($name:ident, $default_enabled:expr, $default_binary:expr) => {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            pub enabled: bool,
            pub binary: String,
        }
        impl Default for $name {
            fn default() -> Self {
                $name { enabled: $default_enabled, binary: $default_binary.into() }
            }
        }
    };
}
tool_toggle!(TrivyConfig, true, "trivy");
tool_toggle!(CheckovConfig, true, "checkov");
tool_toggle!(HadolintConfig, true, "hadolint");
tool_toggle!(BearerConfig, true, "bearer");
tool_toggle!(GuardDogConfig, true, "guarddog");
tool_toggle!(SyftConfig, true, "syft");
tool_toggle!(GoclocConfig, true, "gocloc");
tool_toggle!(OasdiffConfig, true, "oasdiff");
tool_toggle!(ZizmorConfig, true, "zizmor");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosignConfig {
    pub enabled: bool,
    pub binary: String,
    pub identity_regexp: String,
    pub issuer_regexp: String,
    pub cache_ttl_seconds: u64,
}
impl Default for CosignConfig {
    fn default() -> Self {
        CosignConfig {
            enabled: true,
            binary: "cosign".into(),
            identity_regexp: ".*".into(),
            issuer_regexp: ".*".into(),
            cache_ttl_seconds: 3600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemgrepConfig {
    pub enabled: bool,
    pub binary: String,
    pub config: String,
}
impl Default for SemgrepConfig {
    fn default() -> Self {
        SemgrepConfig {
            enabled: true,
            binary: "semgrep".into(),
            config: "p/security-audit,p/owasp-top-ten".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeqlConfig {
    pub enabled: bool,
    pub binary: String,
    pub languages: Vec<String>,
    /// Per-language query pack, pinned to an explicit `@version` (e.g.
    /// `codeql/javascript-queries@2.4.4:...`) rather than an unpinned
    /// `security-extended` reference, so the ruleset used for every scan
    /// is reproducible and only moves when a human bumps it here. Re-pin
    /// by checking the versions bundled with the installed CodeQL CLI
    /// (`codeql pack download codeql/<lang>-queries`, or
    /// `~/.codeql/packages/codeql/<lang>-queries`) and bump
    /// `last_reviewed_at` in the same change.
    pub query_suites: std::collections::BTreeMap<String, String>,
    pub threads: i64,
    #[serde(rename = "ramMB")]
    pub ram_mb: i64,
    pub timeout_ms: u64,
    /// How often the pinned query-suite versions in `query_suites` above
    /// should be manually reviewed and re-pinned — dropping GHAS means
    /// losing GitHub's continuously-updated CodeQL packs, so this ruleset
    /// is now static until a human bumps it. See `is_codeql_review_overdue`.
    pub review_cadence_days: i64,
    /// ISO 8601 date (or `None`) of the last time a human confirmed the
    /// pinned query-suite versions in `query_suites` are still current.
    pub last_reviewed_at: Option<String>,
}
impl Default for CodeqlConfig {
    fn default() -> Self {
        let mut query_suites = std::collections::BTreeMap::new();
        query_suites.insert("javascript".into(), "codeql/javascript-queries@2.4.4:codeql-suites/javascript-security-extended.qls".into());
        query_suites.insert("python".into(), "codeql/python-queries@1.8.9:codeql-suites/python-security-extended.qls".into());
        query_suites.insert("java".into(), "codeql/java-queries@1.11.9:codeql-suites/java-security-extended.qls".into());
        query_suites.insert("go".into(), "codeql/go-queries@1.6.9:codeql-suites/go-security-extended.qls".into());
        CodeqlConfig {
            enabled: true,
            binary: "codeql".into(),
            languages: vec!["javascript".into(), "python".into(), "java".into(), "go".into()],
            query_suites,
            threads: 0,
            ram_mb: 0,
            timeout_ms: 20 * 60_000,
            review_cadence_days: 90,
            last_reviewed_at: None,
        }
    }
}

/// Pure decision logic for the server-startup CodeQL query-suite review
/// warning: overdue when there's no recorded review date at all, or when
/// the recorded date is further in the past than `cadence_days`. `now` and
/// `last_reviewed_at` are both plain `YYYY-MM-DD` dates (or a full RFC3339
/// timestamp — only the date portion is parsed) so a config author never
/// needs to think about time zones for this.
pub fn is_codeql_review_overdue(last_reviewed_at: Option<&str>, cadence_days: i64, now: chrono::NaiveDate) -> bool {
    let Some(raw) = last_reviewed_at else { return true };
    let date_part = raw.split('T').next().unwrap_or(raw);
    let Ok(last) = chrono::NaiveDate::parse_from_str(date_part, "%Y-%m-%d") else { return true };
    (now - last).num_days() > cadence_days
}

/// `enabled: false` here is the default for a direct/interactive scan (a
/// real image build is expensive); `phase4-orchestrator::run_phase4_checks`
/// forces this on regardless whenever it runs in full (non-`fast`) mode, so
/// this default only actually applies to `fast` runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrivyImageConfig {
    pub enabled: bool,
    pub severity_threshold: String,
    pub build_timeout_ms: u64,
}
impl Default for TrivyImageConfig {
    fn default() -> Self {
        TrivyImageConfig {
            enabled: false,
            severity_threshold: "HIGH,CRITICAL".into(),
            build_timeout_ms: 30 * 60_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PicklescanConfig {
    pub enabled: bool,
    pub binary: String,
    pub extensions: Vec<String>,
}
impl Default for PicklescanConfig {
    fn default() -> Self {
        PicklescanConfig {
            enabled: true,
            binary: "picklescan".into(),
            extensions: vec![".pkl".into(), ".pickle".into(), ".pt".into(), ".pth".into(), ".ckpt".into(), ".bin".into()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageHallucinationConfig {
    pub enabled: bool,
}
impl Default for PackageHallucinationConfig {
    fn default() -> Self { PackageHallucinationConfig { enabled: true } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyGraphConfig {
    pub enabled: bool,
}
impl Default for DependencyGraphConfig {
    fn default() -> Self { DependencyGraphConfig { enabled: true } }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeScanningConfig {
    pub enabled: bool,
    /// GHAS-parity bidirectional alert state sync: when Ignite's own
    /// override-engine already has a human-justified override for a
    /// finding, dismiss the matching GitHub code-scanning alert too
    /// (`GithubApi::gh_dismiss_code_scanning_alert`), instead of leaving
    /// it sitting open in GitHub's UI after `gh_upload_sarif` creates it.
    /// Only ever dismisses alerts backing an override Ignite itself
    /// already recorded — never based on unattended scan output. Has no
    /// effect when `enabled` is `false` (nothing gets uploaded to
    /// dismiss in the first place).
    #[serde(default = "default_true")]
    pub sync_dismissals: bool,
    /// GHAS-parity inbound sync (the other direction from
    /// `sync_dismissals`): the shared secret GitHub signs its
    /// `code_scanning_alert` webhook deliveries with
    /// (`X-Hub-Signature-256`), so `POST /api/webhooks/github/code-scanning`
    /// can verify a delivery actually came from GitHub before trusting it
    /// to flip an issue's status. `None` (the default — secrets don't
    /// belong in a committed `config.json`) makes the endpoint reject
    /// every request; set via `CODE_SCANNING_INBOUND_WEBHOOK_SECRET` to
    /// enable, matching the webhook's own "Secret" field when it's
    /// registered on the repo/org in GitHub's settings.
    #[serde(default)]
    pub inbound_webhook_secret: Option<String>,
}
impl Default for CodeScanningConfig {
    fn default() -> Self { CodeScanningConfig { enabled: true, sync_dismissals: true, inbound_webhook_secret: None } }
}
impl std::fmt::Debug for CodeScanningConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeScanningConfig").field("enabled", &self.enabled).field("sync_dismissals", &self.sync_dismissals).field("inbound_webhook_secret", &redact_opt(&self.inbound_webhook_secret)).finish()
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyReviewConfig {
    pub enabled: bool,
}
impl Default for DependencyReviewConfig {
    fn default() -> Self { DependencyReviewConfig { enabled: true } }
}

/// GHAS "Copilot Autofix"-parity inline PR review suggestions — one
/// ```suggestion-fenced review comment per still-open, single-line-fixable
/// finding, posted alongside the SARIF/dependency-graph/dependency-review
/// pushes in `routes/github_pr_status.rs`'s `github_check` handler.
/// Deliberately narrow (see `ignite_fix_pr::SINGLE_LINE_FIX_CATEGORIES`/
/// `build_pr_suggestions`) and best-effort/non-fatal like every other push
/// there — `enabled: true` by default is safe precisely because the scope
/// is that narrow, the same posture as `dependency_review`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrSuggestionsConfig {
    pub enabled: bool,
}
impl Default for PrSuggestionsConfig {
    fn default() -> Self { PrSuggestionsConfig { enabled: true } }
}

/// GHAS-parity active token verification (`ignite-secret-verifier`) —
/// off by default, unlike every other `enabled: true`-by-default check in
/// this file: it sends a credential found in scanned code to a
/// third-party provider API, which is an operator's explicit call to
/// make, not a default a static-analysis scan should silently opt into.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretVerificationConfig {
    pub enabled: bool,
    pub timeout_ms: u64,
}
impl Default for SecretVerificationConfig {
    fn default() -> Self { SecretVerificationConfig { enabled: false, timeout_ms: 5_000 } }
}

/// GHAS-parity inbound sync for GitHub's own secret **push-protection**
/// bypass — when a developer pushes a commit GitHub's pre-receive check
/// flagged as containing a secret, GitHub lets them push anyway with a
/// justification ("used in tests", "false positive", ...) and can notify
/// the org via a `secret_scanning_alert` webhook carrying
/// `push_protection_bypassed: true`. A bypass is a live, knowingly-pushed
/// secret — the class of finding this endpoint exists to make sure a
/// human actually sees, not silently vanish into a webhook nobody's
/// watching. `inbound_webhook_secret` (`None` by default, same posture as
/// `CodeScanningConfig`'s) gates the endpoint the same way — unset means
/// `POST /api/webhooks/github/push-protection` always 404s.
/// `auto_file_issue` (off by default, same posture as
/// `SecretVerificationConfig`) additionally opens a real GitHub issue via
/// `gh_create_issue` summarizing the bypass — an operator's explicit
/// call to make, not a default this should silently do on an
/// unattended webhook delivery.
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PushProtectionConfig {
    #[serde(default)]
    pub inbound_webhook_secret: Option<String>,
    #[serde(default)]
    pub auto_file_issue: bool,
}
impl std::fmt::Debug for PushProtectionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushProtectionConfig").field("inbound_webhook_secret", &redact_opt(&self.inbound_webhook_secret)).field("auto_file_issue", &self.auto_file_issue).finish()
    }
}

/// Inbound `secret_scanning_alert` webhook parity — `code_scanning.enabled`'s
/// dismissal sync only ever covers `code_scanning_alert` deliveries;
/// `push_protection`'s webhook only covers the `push_protection_bypassed:
/// true` case of a `secret_scanning_alert` delivery. Nothing previously
/// handled a plain `created`/`resolved`/`reopened`/`validated`/
/// `publicly_leaked` `secret_scanning_alert` — see
/// `routes/secret_scanning_webhook.rs`. Same posture as the other two
/// inbound webhooks: unset secret means the endpoint 404s, so an
/// unconfigured deployment exposes nothing new.
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecretScanningConfig {
    #[serde(default)]
    pub inbound_webhook_secret: Option<String>,
}
impl std::fmt::Debug for SecretScanningConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretScanningConfig").field("inbound_webhook_secret", &redact_opt(&self.inbound_webhook_secret)).finish()
    }
}

/// Zero-touch repo onboarding — GitHub's org-level "Security Configurations"
/// auto-apply to any new repo; Ignite previously only enrolled a repo (its
/// `projects` table row) when someone manually uploaded/scanned it or ran
/// `enforce-gate-branch-protection`/`scheduled-rescan` against it by name,
/// leaving a gap between "repo created in the org" and "Ignite knows about
/// it or has protected it." See `routes/repository_events_webhook.rs`.
/// Same posture as the other inbound webhooks: unset secret means the
/// endpoint 404s. `apply_org_ruleset`/`trigger_baseline_scan` are separate,
/// both off by default — applying branch protection and kicking off a real
/// clone-and-scan against a repo the operator didn't explicitly name are
/// each their own explicit opt-in, same posture as `pushProtection.autoFileIssue`.
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryEventsConfig {
    #[serde(default)]
    pub inbound_webhook_secret: Option<String>,
    #[serde(default)]
    pub apply_org_ruleset: bool,
    #[serde(default)]
    pub trigger_baseline_scan: bool,
}
impl std::fmt::Debug for RepositoryEventsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepositoryEventsConfig").field("inbound_webhook_secret", &redact_opt(&self.inbound_webhook_secret)).field("apply_org_ruleset", &self.apply_org_ruleset).field("trigger_baseline_scan", &self.trigger_baseline_scan).finish()
    }
}

/// Dual-custody / role-based approval for critical-severity overrides —
/// previously any authenticated (or even just self-declared-in-the-request-body)
/// user could submit an override justification and it took effect
/// immediately, with no second reviewer required regardless of severity.
/// Off by default (`enabled: false`) — an existing deployment's override
/// flow behaves identically until an operator opts in, since requiring a
/// second reviewer is a real workflow change, not a pure bugfix. When
/// enabled, an override on an issue scoring `>= criticalScoreThreshold`
/// (`ignite_override_engine::CRITICAL_SCORE_THRESHOLD`, same `9` SLA
/// bucketing already uses) is created `pending` instead of taking effect
/// immediately, and stays pending — the issue keeps blocking the gate —
/// until a *different* user whose email is in `approverEmails` calls the
/// approve endpoint. There's no database-backed role/permission system in
/// Ignite today (see CLAUDE.md's own gap analysis); this config-driven
/// allowlist is the "role" this feature needs without a broader
/// users/roles schema change.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OverrideApprovalConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub approver_emails: Vec<String>,
}

/// Lets an org treat warning-only results as a failing `ignite/gate`
/// commit status instead of green — without this, a run with zero
/// blocking errors always reports `success` regardless of how many
/// non-blocking warnings it carries, which some orgs consider policy
/// debt they want surfaced as a red check rather than silently green.
/// `None` (the default) preserves the original "any warning count still
/// passes" behavior exactly.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PrStatusConfig {
    #[serde(default)]
    pub max_warnings: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecurityConfig {
    pub gitleaks: GitleaksConfig,
    pub secrets: SecretsConfig,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    pub trivy: TrivyConfig,
    pub checkov: CheckovConfig,
    pub hadolint: HadolintConfig,
    pub cosign: CosignConfig,
    pub semgrep: SemgrepConfig,
    pub bearer: BearerConfig,
    pub guarddog: GuardDogConfig,
    pub codeql: CodeqlConfig,
    pub trivy_image: TrivyImageConfig,
    pub picklescan: PicklescanConfig,
    pub package_hallucination: PackageHallucinationConfig,
    pub zizmor: ZizmorConfig,
    pub dependency_graph: DependencyGraphConfig,
    pub code_scanning: CodeScanningConfig,
    pub dependency_review: DependencyReviewConfig,
    pub pr_suggestions: PrSuggestionsConfig,
    pub secret_verification: SecretVerificationConfig,
    pub push_protection: PushProtectionConfig,
    pub secret_scanning: SecretScanningConfig,
    pub repository_events: RepositoryEventsConfig,
    pub override_approval: OverrideApprovalConfig,
    #[serde(default)]
    pub pr_status: PrStatusConfig,
    /// `POST /api/pipeline/validate-all` requires an authenticated caller
    /// (session or API key) by default — the endpoint runs a full pipeline
    /// scan and, when the request body carries `overrides`, records
    /// override/audit-log entries attributed to whatever email is in that
    /// body, so an anonymous caller could otherwise spend resources and
    /// forge attributed overrides. Set this to `true` only for a headless
    /// deployment that can't complete the one-time login needed to mint an
    /// API key (e.g. an offline/air-gapped CI runner with no path to the
    /// GitHub OAuth flow `auth.mode: "github"` requires) — actor
    /// attribution still falls back to the request body's own `actor`
    /// field in that case (see `resolve_actor`), it just isn't backed by a
    /// verified login. Every other route this session added `RequireAuth`
    /// to is unaffected; this flag is scoped to this one endpoint only.
    #[serde(default)]
    pub allow_unauthenticated_validate_all: bool,

    /// Same bypass as `allow_unauthenticated_validate_all`, extended to
    /// the interactive browser upload endpoint (`POST /api/pipeline`) —
    /// but scoped to `dryRun: true` requests only, never a real
    /// provisioning+push. A simulation run has no GitHub side effects to
    /// protect regardless of who's calling; a real push still requires an
    /// actual session (`run_interactive_pipeline`'s own Phase 1 check
    /// enforces this independently: `dryRun: false` with no session-backed
    /// GitHub token fails with "connect GitHub" before Phase 1 completes,
    /// this flag notwithstanding). Default `false` — an existing
    /// deployment's behavior never changes silently. When enabled and no
    /// session is present, the run is attributed to a clearly-labeled
    /// synthetic actor (`unauthenticated-simulation@ignite.internal`),
    /// never a client-supplied identity, so this can't be used to spoof
    /// the audit trail the way trusting a request body would.
    #[serde(default)]
    pub allow_unauthenticated_interactive_dry_run: bool,

    /// Same bypass shape as `allow_unauthenticated_validate_all`, scoped
    /// to `POST /api/issues/explain` and `POST /api/issues/suggest-fix`
    /// (`routes/issues.rs`) — the two Studio "Explain this issue"/"AI
    /// Suggested Fix" actions, which `RequireAuth`-gate by default because
    /// each call spends real money against the configured LLM provider's
    /// API key with no per-caller limit otherwise. Default `false`: an
    /// existing deployment's behavior never changes silently. Set `true`
    /// only for a single-operator local/offline deployment where the
    /// GitHub-OAuth login flow is friction with no real attribution
    /// benefit (no one else can reach the server) — a real multi-user
    /// deployment should leave this off so LLM spend stays attributable.
    #[serde(default)]
    pub allow_unauthenticated_ai_assist: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostureConfig {
    pub enabled: bool,
    pub ruleset: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EuAiActDocumentsConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EuAiActConfig {
    pub report_as_findings: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceConfig {
    pub posture: PostureConfig,
    pub eu_ai_act_documents: EuAiActDocumentsConfig,
    pub eu_ai_act: EuAiActConfig,
}
impl Default for ComplianceConfig {
    fn default() -> Self {
        ComplianceConfig {
            // config.js resolves this to an absolute path.join(__dirname, ...)
            // at load time — the Rust port resolves it the same way in
            // `load_config`, relative to the config directory passed in, so
            // the struct default here is just the bare filename.
            posture: PostureConfig { enabled: true, ruleset: "ignite-posture-rules.yaml".into() },
            eu_ai_act_documents: EuAiActDocumentsConfig { enabled: true },
            eu_ai_act: EuAiActConfig { report_as_findings: false },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SbomConfig {
    pub syft: SyftConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JscpdConfig {
    pub enabled: bool,
    pub binary: String,
    pub min_lines: u32,
    pub min_tokens: u32,
    pub ignore_patterns: Vec<String>,
}
impl Default for JscpdConfig {
    fn default() -> Self {
        JscpdConfig {
            enabled: false,
            binary: "jscpd".into(),
            min_lines: 5,
            min_tokens: 50,
            ignore_patterns: [
                "docs/**", "**/*.test.*", "**/*.spec.*", "**/__tests__/**",
                "**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml",
                "**/Gemfile.lock", "**/poetry.lock", "**/Cargo.lock", "**/go.sum",
                "**/composer.lock",
            ].into_iter().map(String::from).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileSizeConfig {
    pub enabled: bool,
    pub max_lines: u32,
}
impl Default for FileSizeConfig {
    fn default() -> Self { FileSizeConfig { enabled: true, max_lines: 1000 } }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MetricsConfig {
    pub jscpd: JscpdConfig,
    pub gocloc: GoclocConfig,
    pub file_size: FileSizeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpectralConfig {
    pub enabled: bool,
    pub binary: String,
    pub ruleset: String,
}
impl Default for SpectralConfig {
    fn default() -> Self {
        SpectralConfig { enabled: true, binary: "spectral".into(), ruleset: "spectral-default-ruleset.yaml".into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApiConfig {
    pub spectral: SpectralConfig,
    pub oasdiff: OasdiffConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeadCodeConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthConfig {
    pub enabled: bool,
    pub cyclomatic_warn_threshold: u32,
    pub complexity_density_warn_threshold: f64,
    pub maintainability_warn_threshold: u32,
    pub top_hotspots: u32,
}
impl Default for HealthConfig {
    fn default() -> Self {
        HealthConfig {
            enabled: true,
            cyclomatic_warn_threshold: 20,
            complexity_density_warn_threshold: 0.3,
            maintainability_warn_threshold: 40,
            top_hotspots: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CssDeadCodeConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeIntelligenceConfig {
    pub dead_code: DeadCodeConfig,
    pub health: HealthConfig,
    pub css_dead_code: CssDeadCodeConfig,
}
impl Default for CodeIntelligenceConfig {
    fn default() -> Self {
        CodeIntelligenceConfig {
            dead_code: DeadCodeConfig { enabled: true },
            health: HealthConfig::default(),
            css_dead_code: CssDeadCodeConfig { enabled: true },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BoundariesConfig {
    pub enabled: bool,
    pub preset: String,
    #[serde(default)]
    pub zones: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ArchitectureConfig {
    pub boundaries: BoundariesConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IgnoreFileConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpConfig {
    pub auto_start: bool,
    pub http_port: u16,
}
impl Default for McpConfig {
    fn default() -> Self { McpConfig { auto_start: true, http_port: 51338 } }
}

// --- merge + load -----------------------------------------------------

/// Deep-merges `over` onto `base` in place: recurses only when *both* sides
/// are JSON objects; anything else (including an array, or a type
/// mismatch) is a wholesale replace. This is the JS `merge()`'s "walk the
/// base's own keys" behavior, done through a value model where an array
/// can never be mistaken for a mergeable object — the three explicit
/// array-vs-empty-default-object special cases config.js needs
/// (`phases`, `security.secrets.knownPublicKeyPatterns`,
/// `security.excludePaths`) fall out for free here instead.
fn merge_json(base: &mut serde_json::Value, over: &serde_json::Value) {
    match (base, over) {
        (serde_json::Value::Object(base_map), serde_json::Value::Object(over_map)) => {
            for (k, v) in over_map {
                match base_map.get_mut(k) {
                    Some(existing) => merge_json(existing, v),
                    None => {
                        base_map.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (base_slot, over_val) => {
            *base_slot = over_val.clone();
        }
    }
}

#[derive(Debug)]
pub enum LoadConfigError {
    Io(std::io::Error),
    Json(serde_json::Error),
}
impl std::fmt::Display for LoadConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadConfigError::Io(e) => write!(f, "{e}"),
            LoadConfigError::Json(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for LoadConfigError {}

/// `config_dir` stands in for the Node original's `__dirname` (the
/// directory config.js itself lives in, next to config.json/
/// ignite-posture-rules.yaml/spectral-default-ruleset.yaml) — the caller
/// passes the repo root.
pub fn load_config(config_dir: &Path) -> Result<Config, LoadConfigError> {
    // `IGNITE_CONFIG_DIR` reaches every caller (server, CLI, create-api-key,
    // ...) as a raw, uncanonicalized path — a relative path (interpreted
    // differently depending on the process's cwd at the moment it
    // launched) or one containing `..`/symlink segments could resolve to a
    // different directory than the operator intended, silently loading the
    // wrong org's config.json. Canonicalizing here, the one choke point
    // every caller already funnels through, closes that regardless of how
    // each binary itself parsed the env var.
    let config_dir_owned;
    let config_dir = match std::fs::canonicalize(config_dir) {
        Ok(canonical) if canonical.is_dir() => {
            config_dir_owned = canonical;
            config_dir_owned.as_path()
        }
        Ok(_) => return Err(LoadConfigError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("IGNITE_CONFIG_DIR ({}) is not a directory", config_dir.display())))),
        Err(e) => return Err(LoadConfigError::Io(e)),
    };
    // Faithful port of server.js's `require('dotenv').config()` — the Rust
    // server otherwise never reads `.env` at all (only real exported shell
    // env vars reach `apply_env_overrides` below), which silently strands
    // every secret/setting documented in `.env.example` (API keys included)
    // unless the operator manually exports them. `.env` lives next to
    // `config.json` under `config_dir` (both governed by `IGNITE_CONFIG_DIR`),
    // not necessarily the process's cwd. Like dotenv, this never overrides
    // a var already set in the real environment, and a missing file is not
    // an error (`config.example.json`'s and `.env.example`'s defaults still
    // apply either way).
    let _ = dotenvy::from_path(config_dir.join(".env"));

    let defaults = Config::default();
    let mut merged_value = serde_json::to_value(&defaults).expect("Config always serializes");

    // Same override convention as IGNITE_DB_PATH — lets a test point at an
    // empty fixture file instead of a developer's real, locally-customized
    // config.json.
    let config_path = env::var("IGNITE_CONFIG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| config_dir.join("config.json"));

    let file_value: serde_json::Value = match std::fs::read_to_string(&config_path) {
        Ok(content) => serde_json::from_str(&content).map_err(LoadConfigError::Json)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::Value::Null,
        Err(e) => return Err(LoadConfigError::Io(e)),
    };
    if !file_value.is_null() {
        merge_json(&mut merged_value, &file_value);
    }

    let mut merged: Config = serde_json::from_value(merged_value).map_err(LoadConfigError::Json)?;

    // config.js resolves these two ruleset paths to path.join(__dirname, ...)
    // at load time (not deferred to the check itself), unless config.json
    // supplied its own value (an absolute/relative override, left as-is).
    if merged.compliance.posture.ruleset == "ignite-posture-rules.yaml" {
        merged.compliance.posture.ruleset = config_dir.join("ignite-posture-rules.yaml").to_string_lossy().into_owned();
    }
    if merged.api.spectral.ruleset == "spectral-default-ruleset.yaml" {
        merged.api.spectral.ruleset = config_dir.join("spectral-default-ruleset.yaml").to_string_lossy().into_owned();
    }

    apply_env_overrides(&mut merged);
    Ok(merged)
}

fn env_bool(name: &str) -> Option<bool> {
    env::var(name).ok().map(|v| v == "true")
}
fn env_str(name: &str) -> Option<String> {
    env::var(name).ok()
}
fn env_num<T: std::str::FromStr>(name: &str) -> Option<T> {
    env::var(name).ok().and_then(|v| v.parse().ok())
}
fn env_csv(name: &str) -> Option<Vec<String>> {
    env::var(name).ok().map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
}

/// Every `if (process.env.X) ...` line in config.js's `loadConfig()`,
/// ported 1:1 and in the same order, so this function and that one stay
/// easy to diff against each other as either changes.
fn apply_env_overrides(merged: &mut Config) {
    if let Some(v) = env_str("NOTIFICATIONS_SMTP_PASS").or_else(|| env_str("SMTP_PASS")).or_else(|| env_str("SMTP_PASSWORD")) {
        if !v.is_empty() {
            merged.notifications.smtp.pass = Some(v);
        }
    }
    if let Some(v) = env_str("GOVERNANCE_REPO") { merged.governance.repo = v; }
    if let Some(v) = env_str("GOVERNANCE_WORKFLOW") { merged.governance.workflow = v; }
    if let Some(v) = env_str("ACT_EVENT") { merged.governance.event = v; }
    if let Some(v) = env_num::<u32>("ACT_TIMEOUT_MIN") { merged.governance.timeout_minutes = v; }
    if let Some(v) = env_str("AUTH_MODE") { merged.auth.mode = v; }
    if let Some(v) = env_str("OIDC_CLIENT_ID") { merged.auth.oidc.client_id = v; }
    if let Some(v) = env_str("OIDC_CLIENT_SECRET") { merged.auth.oidc.client_secret = v; }
    if let Some(v) = env_str("OIDC_REDIRECT_URI") { merged.auth.oidc.redirect_uri = v; }
    if let Some(v) = env_str("OIDC_ISSUER") { merged.auth.oidc.issuer = v; }
    // GitHub OAuth's redirectUri in particular has no other override path:
    // config.json is gitignored per-environment, so a value baked in for
    // local dev (e.g. http://localhost:<port>/...) silently stays in force
    // on every other deployment unless one of these env vars is set —
    // matching the escape hatch every other config.json value already has.
    if let Some(v) = env_str("GITHUB_OAUTH_CLIENT_ID") { merged.github.oauth.client_id = v; }
    if let Some(v) = env_str("GITHUB_OAUTH_CLIENT_SECRET") { merged.github.oauth.client_secret = v; }
    if let Some(v) = env_str("GITHUB_OAUTH_REDIRECT_URI") { merged.github.oauth.redirect_uri = v; }
    if let Some(v) = env_str("GITHUB_OAUTH_SCOPE") { merged.github.oauth.scope = v; }
    if let Some(v) = env_bool("GITLEAKS_ENABLED") { merged.security.gitleaks.enabled = v; }
    if let Some(v) = env_bool("GITLEAKS_SCAN_HISTORY") { merged.security.gitleaks.scan_history = v; }
    if let Some(v) = env_str("GITLEAKS_BINARY") { merged.security.gitleaks.binary = v; }
    if let Some(v) = env_str("GITLEAKS_CONFIG_PATH") { merged.security.gitleaks.config_path = v; }
    if let Some(v) = env_csv("SECRETS_KNOWN_PUBLIC_KEY_PATTERNS") { merged.security.secrets.known_public_key_patterns = v; }
    if let Some(v) = env_csv("SECURITY_EXCLUDE_PATHS") { merged.security.exclude_paths = v; }
    if let Some(v) = env_bool("TRIVY_ENABLED") { merged.security.trivy.enabled = v; }
    if let Some(v) = env_str("TRIVY_BINARY") { merged.security.trivy.binary = v; }
    if let Some(v) = env_bool("CHECKOV_ENABLED") { merged.security.checkov.enabled = v; }
    if let Some(v) = env_str("CHECKOV_BINARY") { merged.security.checkov.binary = v; }
    if let Some(v) = env_bool("HADOLINT_ENABLED") { merged.security.hadolint.enabled = v; }
    if let Some(v) = env_str("HADOLINT_BINARY") { merged.security.hadolint.binary = v; }
    if let Some(v) = env_bool("COSIGN_ENABLED") { merged.security.cosign.enabled = v; }
    if let Some(v) = env_str("COSIGN_BINARY") { merged.security.cosign.binary = v; }
    if let Some(v) = env_str("COSIGN_IDENTITY_REGEXP") { merged.security.cosign.identity_regexp = v; }
    if let Some(v) = env_str("COSIGN_ISSUER_REGEXP") { merged.security.cosign.issuer_regexp = v; }
    if let Some(v) = env_num::<u64>("COSIGN_CACHE_TTL_SECONDS") { merged.security.cosign.cache_ttl_seconds = v; }
    if let Some(v) = env_bool("PICKLESCAN_ENABLED") { merged.security.picklescan.enabled = v; }
    if let Some(v) = env_str("PICKLESCAN_BINARY") { merged.security.picklescan.binary = v; }
    if let Some(v) = env_bool("PACKAGE_HALLUCINATION_ENABLED") { merged.security.package_hallucination.enabled = v; }
    if let Some(v) = env_bool("ZIZMOR_ENABLED") { merged.security.zizmor.enabled = v; }
    if let Some(v) = env_bool("DEPENDENCY_GRAPH_ENABLED") { merged.security.dependency_graph.enabled = v; }
    if let Some(v) = env_bool("CODE_SCANNING_ENABLED") { merged.security.code_scanning.enabled = v; }
    if let Some(v) = env_bool("CODE_SCANNING_SYNC_DISMISSALS") { merged.security.code_scanning.sync_dismissals = v; }
    if let Some(v) = env_str("CODE_SCANNING_INBOUND_WEBHOOK_SECRET") { merged.security.code_scanning.inbound_webhook_secret = Some(v); }
    if let Some(v) = env_bool("DEPENDENCY_REVIEW_ENABLED") { merged.security.dependency_review.enabled = v; }
    if let Some(v) = env_bool("PR_SUGGESTIONS_ENABLED") { merged.security.pr_suggestions.enabled = v; }
    if let Some(v) = env_bool("SECRET_VERIFICATION_ENABLED") { merged.security.secret_verification.enabled = v; }
    if let Some(v) = env_str("PUSH_PROTECTION_INBOUND_WEBHOOK_SECRET") { merged.security.push_protection.inbound_webhook_secret = Some(v); }
    if let Some(v) = env_bool("PUSH_PROTECTION_AUTO_FILE_ISSUE") { merged.security.push_protection.auto_file_issue = v; }
    if let Some(v) = env_str("SECRET_SCANNING_INBOUND_WEBHOOK_SECRET") { merged.security.secret_scanning.inbound_webhook_secret = Some(v); }
    if let Some(v) = env_str("PR_STATUS_MAX_WARNINGS").and_then(|s| s.parse::<u64>().ok()) { merged.security.pr_status.max_warnings = Some(v); }
    if let Some(v) = env_str("REPOSITORY_EVENTS_INBOUND_WEBHOOK_SECRET") { merged.security.repository_events.inbound_webhook_secret = Some(v); }
    if let Some(v) = env_bool("REPOSITORY_EVENTS_APPLY_ORG_RULESET") { merged.security.repository_events.apply_org_ruleset = v; }
    if let Some(v) = env_bool("REPOSITORY_EVENTS_TRIGGER_BASELINE_SCAN") { merged.security.repository_events.trigger_baseline_scan = v; }
    if let Some(v) = env_bool("OVERRIDE_APPROVAL_ENABLED") { merged.security.override_approval.enabled = v; }
    if let Some(v) = env_bool("ALLOW_UNAUTHENTICATED_VALIDATE_ALL") { merged.security.allow_unauthenticated_validate_all = v; }
    if let Some(v) = env_bool("ALLOW_UNAUTHENTICATED_INTERACTIVE_DRY_RUN") { merged.security.allow_unauthenticated_interactive_dry_run = v; }
    if let Some(v) = env_bool("ALLOW_UNAUTHENTICATED_AI_ASSIST") { merged.security.allow_unauthenticated_ai_assist = v; }
    if let Some(v) = env_csv("OVERRIDE_APPROVAL_APPROVER_EMAILS") { merged.security.override_approval.approver_emails = v; }
    if let Some(v) = env_bool("POLICY_STRICT") { merged.policy.strict = v; }
    if let Some(v) = env_bool("SLA_ENABLED") { merged.sla.enabled = v; }
    if let Some(v) = env_num::<u32>("SLA_CRITICAL_DAYS") { merged.sla.critical_days = v; }
    if let Some(v) = env_num::<u32>("SLA_HIGH_DAYS") { merged.sla.high_days = v; }
    if let Some(v) = env_num::<u32>("SLA_MEDIUM_DAYS") { merged.sla.medium_days = v; }
    if let Some(v) = env_bool("AUDIT_LOG_ENABLED") { merged.audit_log.enabled = v; }
    if let Some(v) = env_num::<u32>("ORG_REPOS_MAX_CONCURRENT_SCANS") { merged.org_repos.max_concurrent_scans = v; }
    if let Some(v) = env_num::<u32>("ORG_REPOS_AUTO_RESCAN_STALE_AFTER_HOURS") { merged.org_repos.auto_rescan_stale_after_hours = v; }
    if let Some(v) = env_bool("DAILY_REPORT_ENABLED") { merged.daily_report.enabled = v; }
    if let Some(v) = env_str("DAILY_REPORT_TIME") { merged.daily_report.time = v; }
    if let Some(v) = env_str("DAILY_REPORT_TO") { merged.daily_report.to = v; }
    if let Some(v) = env_str("DAILY_REPORT_WEBHOOK_URL") { merged.daily_report.webhook_url = v; }
    if let Some(v) = env_str("DAILY_REPORT_WEBHOOK_TOKEN") { merged.daily_report.webhook_token = v; }
    if let Some(v) = env_str("DAILY_REPORT_AZURE_BLOB_CONTAINER_URL") { merged.daily_report.azure_blob_container_url = v; }
    if let Some(v) = env_str("AUDIT_LOG_SINKS") {
        if let Ok(sinks) = serde_json::from_str::<Vec<AuditSinkConfig>>(&v) {
            merged.audit_log.sinks = sinks;
        } // malformed JSON — keep the config.json sinks rather than crash boot
    }
    if let Some(v) = env_str("ZIZMOR_BINARY") { merged.security.zizmor.binary = v; }
    if let Some(v) = env_bool("SEMGREP_ENABLED") { merged.security.semgrep.enabled = v; }
    if let Some(v) = env_str("SEMGREP_BINARY") { merged.security.semgrep.binary = v; }
    if let Some(v) = env_str("SEMGREP_CONFIG") { merged.security.semgrep.config = v; }
    if let Some(v) = env_bool("BEARER_ENABLED") { merged.security.bearer.enabled = v; }
    if let Some(v) = env_str("BEARER_BINARY") { merged.security.bearer.binary = v; }
    if let Some(v) = env_bool("GUARDDOG_ENABLED") { merged.security.guarddog.enabled = v; }
    if let Some(v) = env_str("GUARDDOG_BINARY") { merged.security.guarddog.binary = v; }
    if let Some(v) = env_bool("CODEQL_ENABLED") { merged.security.codeql.enabled = v; }
    if let Some(v) = env_str("CODEQL_BINARY") { merged.security.codeql.binary = v; }
    if let Some(v) = env_csv("CODEQL_LANGUAGES") { merged.security.codeql.languages = v; }
    if let Some(v) = env_str("CODEQL_QUERY_SUITES") {
        if let Ok(overrides) = serde_json::from_str::<std::collections::BTreeMap<String, String>>(&v) {
            merged.security.codeql.query_suites.extend(overrides);
        } // malformed JSON — keep the default/config.json suites rather than crash boot
    }
    if let Some(v) = env_num::<i64>("CODEQL_THREADS") { merged.security.codeql.threads = v; }
    if let Some(v) = env_num::<i64>("CODEQL_RAM_MB") { merged.security.codeql.ram_mb = v; }
    if let Some(v) = env_num::<u64>("CODEQL_TIMEOUT_MS") { merged.security.codeql.timeout_ms = v; }
    if let Some(v) = env_num::<i64>("CODEQL_REVIEW_CADENCE_DAYS") { merged.security.codeql.review_cadence_days = v; }
    if let Some(v) = env_str("CODEQL_LAST_REVIEWED_AT") { merged.security.codeql.last_reviewed_at = Some(v); }
    if let Some(v) = env_bool("DEAD_CODE_ENABLED") { merged.code_intelligence.dead_code.enabled = v; }
    if let Some(v) = env_bool("HEALTH_ENABLED") { merged.code_intelligence.health.enabled = v; }
    if let Some(v) = env_bool("CSS_DEAD_CODE_ENABLED") { merged.code_intelligence.css_dead_code.enabled = v; }
    if let Some(v) = env_bool("ARCHITECTURE_BOUNDARIES_ENABLED") { merged.architecture.boundaries.enabled = v; }
    if let Some(v) = env_str("ARCHITECTURE_BOUNDARIES_PRESET") { merged.architecture.boundaries.preset = v; }
    if let Some(v) = env_bool("IGNOREFILE_ENABLED") { merged.ignore_file.enabled = v; }
    if let Some(v) = env_bool("TRIVY_IMAGE_ENABLED") { merged.security.trivy_image.enabled = v; }
    if let Some(v) = env_str("TRIVY_IMAGE_SEVERITY") { merged.security.trivy_image.severity_threshold = v; }
    if let Some(v) = env_num::<u64>("TRIVY_IMAGE_BUILD_TIMEOUT_MS") { merged.security.trivy_image.build_timeout_ms = v; }
    if let Some(v) = env_bool("AI_AUTO_JUSTIFY_ENABLED") { merged.ai_auto_justify.enabled = v; }
    if let Some(v) = env_csv("AI_AUTO_JUSTIFY_CATEGORIES") { merged.ai_auto_justify.categories = v; }
    if let Some(v) = env_bool("POSTURE_ENABLED") { merged.compliance.posture.enabled = v; }
    if let Some(v) = env_str("POSTURE_RULESET") { merged.compliance.posture.ruleset = v; }
    if let Some(v) = env_bool("EU_AI_ACT_DOCS_ENABLED") { merged.compliance.eu_ai_act_documents.enabled = v; }
    if let Some(v) = env_bool("EU_AI_ACT_REPORT_AS_FINDINGS") { merged.compliance.eu_ai_act.report_as_findings = v; }
    if let Some(v) = env_bool("JSCPD_ENABLED") { merged.metrics.jscpd.enabled = v; }
    if let Some(v) = env_str("JSCPD_BINARY") { merged.metrics.jscpd.binary = v; }
    if let Some(v) = env_num::<u32>("JSCPD_MIN_LINES") { merged.metrics.jscpd.min_lines = v; }
    if let Some(v) = env_num::<u32>("JSCPD_MIN_TOKENS") { merged.metrics.jscpd.min_tokens = v; }
    if let Some(v) = env_csv("JSCPD_IGNORE") { merged.metrics.jscpd.ignore_patterns = v; }
    if let Some(v) = env_bool("GOCLOC_ENABLED") { merged.metrics.gocloc.enabled = v; }
    if let Some(v) = env_str("GOCLOC_BINARY") { merged.metrics.gocloc.binary = v; }
    if let Some(v) = env_bool("FILE_SIZE_ENABLED") { merged.metrics.file_size.enabled = v; }
    if let Some(v) = env_num::<u32>("FILE_SIZE_MAX_LINES") { merged.metrics.file_size.max_lines = v; }
    if let Some(v) = env_bool("SPECTRAL_ENABLED") { merged.api.spectral.enabled = v; }
    if let Some(v) = env_str("SPECTRAL_BINARY") { merged.api.spectral.binary = v; }
    if let Some(v) = env_str("SPECTRAL_RULESET") { merged.api.spectral.ruleset = v; }
    if let Some(v) = env_bool("OASDIFF_ENABLED") { merged.api.oasdiff.enabled = v; }
    if let Some(v) = env_str("OASDIFF_BINARY") { merged.api.oasdiff.binary = v; }
    if let Some(v) = env_bool("SYFT_ENABLED") { merged.sbom.syft.enabled = v; }
    if let Some(v) = env_str("SYFT_BINARY") { merged.sbom.syft.binary = v; }
    if let Some(v) = env_bool("MCP_AUTOSTART") { merged.mcp.auto_start = v; }
    if let Some(v) = env_num::<u16>("MCP_HTTP_PORT") { merged.mcp.http_port = v; }
    if let Some(v) = env_str("LLM_PROVIDER") { merged.llm.provider = v; }
    if let Some(v) = env_str("LLM_SCAN_URL") { merged.llm.url = v; }
    if let Some(v) = env_str("LLM_SCAN_MODEL") { merged.llm.model = v; }
    if let Some(v) = env_str("LLM_SCAN_MODE") { merged.llm.mode = v; }
    if let Some(v) = env_num::<u32>("LLM_MAX_FILES") { merged.llm.max_files = v; }
    if let Some(v) = env_num::<u32>("LLM_CHUNK_CHARS") { merged.llm.chunk_chars = v; }
    if let Some(v) = env_bool("LLM_DEEP_SCAN_ENABLED") { merged.llm.deep_scan_enabled = v; }
    if let Some(v) = env_str("LLM_ADVISORY_LEVEL") { merged.llm.advisory_level = v; }
    if let Some(v) = env_str("OPENAI_API_KEY") { merged.llm.openai.api_key = v; }
    if let Some(v) = env_str("OPENAI_BASE_URL") { merged.llm.openai.base_url = v; }
    if let Some(v) = env_str("OPENAI_MODEL") { merged.llm.openai.model = v; }
    if let Some(v) = env_str("ANTHROPIC_API_KEY") { merged.llm.anthropic.api_key = v; }
    if let Some(v) = env_str("ANTHROPIC_BASE_URL") { merged.llm.anthropic.base_url = v; }
    if let Some(v) = env_str("ANTHROPIC_MODEL") { merged.llm.anthropic.model = v; }
    if let Some(v) = env_str("AZURE_FOUNDRY_API_KEY") { merged.llm.azure_foundry.api_key = v; }
    if let Some(v) = env_str("AZURE_FOUNDRY_ENDPOINT") { merged.llm.azure_foundry.endpoint = v; }
    if let Some(v) = env_str("AZURE_FOUNDRY_DEPLOYMENT") { merged.llm.azure_foundry.deployment = v; }
    if let Some(v) = env_str("AZURE_FOUNDRY_API_VERSION") { merged.llm.azure_foundry.api_version = v; }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::tempdir;

    #[test]
    fn debug_redacts_secret_fields_but_keeps_non_secret_fields_visible() {
        let mut cfg = Config::default();
        cfg.llm.openai.api_key = "sk-live-supersecret".to_string();
        cfg.github.oauth.client_secret = "oauth-secret-value".to_string();
        cfg.security.code_scanning.inbound_webhook_secret = Some("whsec-supersecret".to_string());
        cfg.notifications.smtp.pass = Some("smtp-password".to_string());
        let out = format!("{cfg:?}");
        assert!(!out.contains("sk-live-supersecret"));
        assert!(!out.contains("oauth-secret-value"));
        assert!(!out.contains("whsec-supersecret"));
        assert!(!out.contains("smtp-password"));
        assert!(out.contains("[REDACTED]"));
        // Non-secret fields must still be visible for the redaction to be
        // useful for debugging rather than swallowing the whole struct.
        assert!(out.contains("gpt-4o-mini"));
    }

    #[test]
    fn debug_redacts_empty_secret_as_empty_not_as_redacted() {
        // An unset secret should read as empty, not as "[REDACTED]" —
        // that distinction (configured-but-hidden vs. not-configured-at-all)
        // matters when debugging a deployment.
        let cfg = Config::default();
        let out = format!("{:?}", cfg.llm.openai);
        assert!(!out.contains("[REDACTED]"));
    }

    // Env vars are process-global state — serialize tests that touch them
    // so they don't race each other (same reasoning as the Node suite's
    // withServerEnv helper, which re-requires modules per test instead).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_test_env() {
        for (k, _) in env::vars() {
            if k == "IGNITE_CONFIG_PATH" || k.ends_with("_ENABLED") || k.ends_with("_BINARY")
                || k.starts_with("SEMGREP_") || k.starts_with("CODEQL_") || k.starts_with("AUTH_MODE")
                || k.starts_with("GOVERNANCE_") || k.starts_with("ACT_")
            {
                env::remove_var(k);
            }
        }
    }

    #[test]
    fn defaults_match_config_js_literal_values() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let dir = tempdir().unwrap();
        env::set_var("IGNITE_CONFIG_PATH", dir.path().join("nonexistent.json"));
        let cfg = load_config(dir.path()).unwrap();
        assert_eq!(cfg.port, 51337);
        assert_eq!(cfg.security.semgrep.config, "p/security-audit,p/owasp-top-ten");
        assert_eq!(cfg.security.codeql.languages, vec!["javascript", "python", "java", "go"]);
        assert!(cfg.security.trivy.enabled);
        assert!(!cfg.security.trivy_image.enabled);
        assert_eq!(cfg.auth.mode, "standalone");
        env::remove_var("IGNITE_CONFIG_PATH");
    }

    #[test]
    fn config_json_overrides_defaults_and_deep_merges_nested_objects() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.json"),
            r#"{ "port": 9999, "security": { "semgrep": { "enabled": false } } }"#,
        ).unwrap();
        let cfg = load_config(dir.path()).unwrap();
        assert_eq!(cfg.port, 9999);
        assert!(!cfg.security.semgrep.enabled);
        // Deep merge: only `enabled` was overridden, the rest of semgrep's
        // config (binary, config string) must survive from defaults.
        assert_eq!(cfg.security.semgrep.binary, "semgrep");
        assert_eq!(cfg.security.semgrep.config, "p/security-audit,p/owasp-top-ten");
    }

    #[test]
    fn array_default_is_replaced_wholesale_not_merged_as_object() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.json"),
            r#"{ "security": { "excludePaths": [".devcontainer/"] }, "phases": [{ "id": 4, "enabled": false }] }"#,
        ).unwrap();
        let cfg = load_config(dir.path()).unwrap();
        assert_eq!(cfg.security.exclude_paths, vec![".devcontainer/"]);
        assert_eq!(cfg.phases.len(), 1);
    }

    #[test]
    fn env_var_overrides_take_precedence_over_config_json() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), r#"{ "security": { "semgrep": { "enabled": true } } }"#).unwrap();
        env::set_var("SEMGREP_ENABLED", "false");
        env::set_var("CODEQL_LANGUAGES", "javascript, python");
        let cfg = load_config(dir.path()).unwrap();
        assert!(!cfg.security.semgrep.enabled);
        assert_eq!(cfg.security.codeql.languages, vec!["javascript", "python"]);
        env::remove_var("SEMGREP_ENABLED");
        env::remove_var("CODEQL_LANGUAGES");
    }

    #[test]
    fn daily_report_delivery_fields_load_from_json_and_env_overrides_win() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.json"),
            r#"{ "dailyReport": { "webhookUrl": "https://json.example/hook", "webhookToken": "json-token", "azureBlobContainerUrl": "https://a.blob.core.windows.net/c?sig=json" } }"#,
        )
        .unwrap();
        let cfg = load_config(dir.path()).unwrap();
        assert_eq!(cfg.daily_report.webhook_url, "https://json.example/hook");
        assert_eq!(cfg.daily_report.webhook_token, "json-token");
        assert_eq!(cfg.daily_report.time, "23:59", "unset keys keep their defaults");

        env::set_var("DAILY_REPORT_WEBHOOK_URL", "https://env.example/hook");
        env::set_var("DAILY_REPORT_WEBHOOK_TOKEN", "env-token");
        env::set_var("DAILY_REPORT_AZURE_BLOB_CONTAINER_URL", "https://a.blob.core.windows.net/c?sig=env");
        let cfg = load_config(dir.path()).unwrap();
        assert_eq!(cfg.daily_report.webhook_url, "https://env.example/hook");
        assert_eq!(cfg.daily_report.webhook_token, "env-token");
        assert_eq!(cfg.daily_report.azure_blob_container_url, "https://a.blob.core.windows.net/c?sig=env");
        env::remove_var("DAILY_REPORT_WEBHOOK_URL");
        env::remove_var("DAILY_REPORT_WEBHOOK_TOKEN");
        env::remove_var("DAILY_REPORT_AZURE_BLOB_CONTAINER_URL");
    }

    #[test]
    fn governance_config_json_and_env_overrides_both_take_effect() {
        // Regression test: three server routes (pipeline_validate.rs,
        // pipeline_onboard.rs, pipeline_interactive.rs) used to hardcode a
        // literal "nunomcpereira/ai-guardrails-orchestrator" repo/workflow
        // instead of reading these fields at all, silently ignoring
        // config.json's real governance.repo/workflow/event/timeoutMinutes
        // for every deployment. This proves the config values those routes
        // now read are themselves wired correctly end to end.
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), r#"{ "governance": { "repo": "acme/gov", "workflow": "ci.yml", "event": "push", "timeoutMinutes": 15 } }"#).unwrap();
        let cfg = load_config(dir.path()).unwrap();
        assert_eq!(cfg.governance.repo, "acme/gov");
        assert_eq!(cfg.governance.workflow, "ci.yml");
        assert_eq!(cfg.governance.event, "push");
        assert_eq!(cfg.governance.timeout_minutes, 15);

        env::set_var("GOVERNANCE_REPO", "other-org/other-repo");
        env::set_var("GOVERNANCE_WORKFLOW", "other.yml");
        env::set_var("ACT_EVENT", "workflow_dispatch");
        env::set_var("ACT_TIMEOUT_MIN", "45");
        let cfg = load_config(dir.path()).unwrap();
        assert_eq!(cfg.governance.repo, "other-org/other-repo");
        assert_eq!(cfg.governance.workflow, "other.yml");
        assert_eq!(cfg.governance.event, "workflow_dispatch");
        assert_eq!(cfg.governance.timeout_minutes, 45);
        clear_test_env();
    }

    #[test]
    fn missing_config_json_falls_back_to_defaults_without_erroring() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let dir = tempdir().unwrap();
        env::set_var("IGNITE_CONFIG_PATH", dir.path().join("nonexistent.json"));
        let cfg = load_config(dir.path());
        assert!(cfg.is_ok());
        env::remove_var("IGNITE_CONFIG_PATH");
    }

    #[test]
    fn posture_and_spectral_rulesets_resolve_relative_to_config_dir() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let dir = tempdir().unwrap();
        env::set_var("IGNITE_CONFIG_PATH", dir.path().join("nonexistent.json"));
        let cfg = load_config(dir.path()).unwrap();
        assert!(cfg.compliance.posture.ruleset.ends_with("ignite-posture-rules.yaml"));
        // `load_config` now canonicalizes `config_dir` up front (BUG-191) —
        // on macOS a `tempdir()` path is typically itself a symlink
        // (`/var/...` -> `/private/var/...`), so the resolved ruleset path
        // must be compared against the canonical form, not the original
        // (possibly symlinked) `dir.path()`.
        let canonical_dir = std::fs::canonicalize(dir.path()).unwrap();
        assert!(cfg.compliance.posture.ruleset.starts_with(canonical_dir.to_str().unwrap()));
        env::remove_var("IGNITE_CONFIG_PATH");
    }

    #[test]
    fn codeql_review_overdue_when_never_reviewed() {
        let now = chrono::NaiveDate::from_ymd_opt(2026, 9, 2).unwrap();
        assert!(is_codeql_review_overdue(None, 90, now));
    }

    #[test]
    fn codeql_review_overdue_when_past_cadence() {
        let now = chrono::NaiveDate::from_ymd_opt(2026, 9, 2).unwrap();
        assert!(is_codeql_review_overdue(Some("2026-05-01"), 90, now));
    }

    #[test]
    fn codeql_review_not_overdue_within_cadence() {
        let now = chrono::NaiveDate::from_ymd_opt(2026, 9, 2).unwrap();
        assert!(!is_codeql_review_overdue(Some("2026-08-15"), 90, now));
    }

    #[test]
    fn codeql_review_accepts_rfc3339_timestamp_date_portion() {
        let now = chrono::NaiveDate::from_ymd_opt(2026, 9, 2).unwrap();
        assert!(!is_codeql_review_overdue(Some("2026-08-15T10:00:00Z"), 90, now));
    }

    #[test]
    fn codeql_review_overdue_when_unparseable() {
        let now = chrono::NaiveDate::from_ymd_opt(2026, 9, 2).unwrap();
        assert!(is_codeql_review_overdue(Some("not-a-date"), 90, now));
    }

    #[test]
    fn codeql_env_overrides_review_fields() {
        let dir = tempfile::tempdir().unwrap();
        env::set_var("CODEQL_REVIEW_CADENCE_DAYS", "30");
        env::set_var("CODEQL_LAST_REVIEWED_AT", "2026-01-01");
        let cfg = load_config(dir.path()).unwrap();
        assert_eq!(cfg.security.codeql.review_cadence_days, 30);
        assert_eq!(cfg.security.codeql.last_reviewed_at.as_deref(), Some("2026-01-01"));
        env::remove_var("CODEQL_REVIEW_CADENCE_DAYS");
        env::remove_var("CODEQL_LAST_REVIEWED_AT");
    }

    // ---- characterization (generated from `apply_env_overrides`): pins that each
    // ---- direct env override still lands in the config field it names, so that
    // ---- reshaping how config reaches the checks can't silently drop one.
    // ---- When you add an override, add its row here.

    fn load_with_env(name: &str, value: &str) -> Config {
        clear_test_env();
        let dir = tempdir().unwrap();
        env::set_var("IGNITE_CONFIG_PATH", dir.path().join("nonexistent.json"));
        env::set_var(name, value);
        let cfg = load_config(dir.path()).unwrap();
        env::remove_var(name);
        env::remove_var("IGNITE_CONFIG_PATH");
        cfg
    }

    #[test]
    fn every_direct_env_override_lands_in_the_config_field_it_names() {
        let _guard = ENV_LOCK.lock().unwrap();
        assert_eq!(load_with_env("GOVERNANCE_REPO", "pin-GOVERNANCE_REPO").governance.repo, "pin-GOVERNANCE_REPO", "GOVERNANCE_REPO");
        assert_eq!(load_with_env("GOVERNANCE_WORKFLOW", "pin-GOVERNANCE_WORKFLOW").governance.workflow, "pin-GOVERNANCE_WORKFLOW", "GOVERNANCE_WORKFLOW");
        assert_eq!(load_with_env("ACT_EVENT", "pin-ACT_EVENT").governance.event, "pin-ACT_EVENT", "ACT_EVENT");
        assert_eq!(load_with_env("ACT_TIMEOUT_MIN", "7").governance.timeout_minutes.to_string(), "7", "ACT_TIMEOUT_MIN");
        assert_eq!(load_with_env("AUTH_MODE", "pin-AUTH_MODE").auth.mode, "pin-AUTH_MODE", "AUTH_MODE");
        assert_eq!(load_with_env("OIDC_CLIENT_ID", "pin-OIDC_CLIENT_ID").auth.oidc.client_id, "pin-OIDC_CLIENT_ID", "OIDC_CLIENT_ID");
        assert_eq!(load_with_env("OIDC_CLIENT_SECRET", "pin-OIDC_CLIENT_SECRET").auth.oidc.client_secret, "pin-OIDC_CLIENT_SECRET", "OIDC_CLIENT_SECRET");
        assert_eq!(load_with_env("OIDC_REDIRECT_URI", "pin-OIDC_REDIRECT_URI").auth.oidc.redirect_uri, "pin-OIDC_REDIRECT_URI", "OIDC_REDIRECT_URI");
        assert_eq!(load_with_env("OIDC_ISSUER", "pin-OIDC_ISSUER").auth.oidc.issuer, "pin-OIDC_ISSUER", "OIDC_ISSUER");
        assert_eq!(load_with_env("GITHUB_OAUTH_CLIENT_ID", "pin-GITHUB_OAUTH_CLIENT_ID").github.oauth.client_id, "pin-GITHUB_OAUTH_CLIENT_ID", "GITHUB_OAUTH_CLIENT_ID");
        assert_eq!(load_with_env("GITHUB_OAUTH_CLIENT_SECRET", "pin-GITHUB_OAUTH_CLIENT_SECRET").github.oauth.client_secret, "pin-GITHUB_OAUTH_CLIENT_SECRET", "GITHUB_OAUTH_CLIENT_SECRET");
        assert_eq!(load_with_env("GITHUB_OAUTH_REDIRECT_URI", "pin-GITHUB_OAUTH_REDIRECT_URI").github.oauth.redirect_uri, "pin-GITHUB_OAUTH_REDIRECT_URI", "GITHUB_OAUTH_REDIRECT_URI");
        assert_eq!(load_with_env("GITHUB_OAUTH_SCOPE", "pin-GITHUB_OAUTH_SCOPE").github.oauth.scope, "pin-GITHUB_OAUTH_SCOPE", "GITHUB_OAUTH_SCOPE");
        assert!(load_with_env("GITLEAKS_ENABLED", "true").security.gitleaks.enabled, "GITLEAKS_ENABLED=true");
        assert!(!load_with_env("GITLEAKS_ENABLED", "false").security.gitleaks.enabled, "GITLEAKS_ENABLED=false");
        assert!(load_with_env("GITLEAKS_SCAN_HISTORY", "true").security.gitleaks.scan_history, "GITLEAKS_SCAN_HISTORY=true");
        assert!(!load_with_env("GITLEAKS_SCAN_HISTORY", "false").security.gitleaks.scan_history, "GITLEAKS_SCAN_HISTORY=false");
        assert_eq!(load_with_env("GITLEAKS_BINARY", "pin-GITLEAKS_BINARY").security.gitleaks.binary, "pin-GITLEAKS_BINARY", "GITLEAKS_BINARY");
        assert_eq!(load_with_env("GITLEAKS_CONFIG_PATH", "pin-GITLEAKS_CONFIG_PATH").security.gitleaks.config_path, "pin-GITLEAKS_CONFIG_PATH", "GITLEAKS_CONFIG_PATH");
        assert!(load_with_env("TRIVY_ENABLED", "true").security.trivy.enabled, "TRIVY_ENABLED=true");
        assert!(!load_with_env("TRIVY_ENABLED", "false").security.trivy.enabled, "TRIVY_ENABLED=false");
        assert_eq!(load_with_env("TRIVY_BINARY", "pin-TRIVY_BINARY").security.trivy.binary, "pin-TRIVY_BINARY", "TRIVY_BINARY");
        assert!(load_with_env("CHECKOV_ENABLED", "true").security.checkov.enabled, "CHECKOV_ENABLED=true");
        assert!(!load_with_env("CHECKOV_ENABLED", "false").security.checkov.enabled, "CHECKOV_ENABLED=false");
        assert_eq!(load_with_env("CHECKOV_BINARY", "pin-CHECKOV_BINARY").security.checkov.binary, "pin-CHECKOV_BINARY", "CHECKOV_BINARY");
        assert!(load_with_env("HADOLINT_ENABLED", "true").security.hadolint.enabled, "HADOLINT_ENABLED=true");
        assert!(!load_with_env("HADOLINT_ENABLED", "false").security.hadolint.enabled, "HADOLINT_ENABLED=false");
        assert_eq!(load_with_env("HADOLINT_BINARY", "pin-HADOLINT_BINARY").security.hadolint.binary, "pin-HADOLINT_BINARY", "HADOLINT_BINARY");
        assert!(load_with_env("COSIGN_ENABLED", "true").security.cosign.enabled, "COSIGN_ENABLED=true");
        assert!(!load_with_env("COSIGN_ENABLED", "false").security.cosign.enabled, "COSIGN_ENABLED=false");
        assert_eq!(load_with_env("COSIGN_BINARY", "pin-COSIGN_BINARY").security.cosign.binary, "pin-COSIGN_BINARY", "COSIGN_BINARY");
        assert_eq!(load_with_env("COSIGN_IDENTITY_REGEXP", "pin-COSIGN_IDENTITY_REGEXP").security.cosign.identity_regexp, "pin-COSIGN_IDENTITY_REGEXP", "COSIGN_IDENTITY_REGEXP");
        assert_eq!(load_with_env("COSIGN_ISSUER_REGEXP", "pin-COSIGN_ISSUER_REGEXP").security.cosign.issuer_regexp, "pin-COSIGN_ISSUER_REGEXP", "COSIGN_ISSUER_REGEXP");
        assert_eq!(load_with_env("COSIGN_CACHE_TTL_SECONDS", "7").security.cosign.cache_ttl_seconds.to_string(), "7", "COSIGN_CACHE_TTL_SECONDS");
        assert!(load_with_env("PICKLESCAN_ENABLED", "true").security.picklescan.enabled, "PICKLESCAN_ENABLED=true");
        assert!(!load_with_env("PICKLESCAN_ENABLED", "false").security.picklescan.enabled, "PICKLESCAN_ENABLED=false");
        assert_eq!(load_with_env("PICKLESCAN_BINARY", "pin-PICKLESCAN_BINARY").security.picklescan.binary, "pin-PICKLESCAN_BINARY", "PICKLESCAN_BINARY");
        assert!(load_with_env("PACKAGE_HALLUCINATION_ENABLED", "true").security.package_hallucination.enabled, "PACKAGE_HALLUCINATION_ENABLED=true");
        assert!(!load_with_env("PACKAGE_HALLUCINATION_ENABLED", "false").security.package_hallucination.enabled, "PACKAGE_HALLUCINATION_ENABLED=false");
        assert!(load_with_env("ZIZMOR_ENABLED", "true").security.zizmor.enabled, "ZIZMOR_ENABLED=true");
        assert!(!load_with_env("ZIZMOR_ENABLED", "false").security.zizmor.enabled, "ZIZMOR_ENABLED=false");
        assert!(load_with_env("DEPENDENCY_GRAPH_ENABLED", "true").security.dependency_graph.enabled, "DEPENDENCY_GRAPH_ENABLED=true");
        assert!(!load_with_env("DEPENDENCY_GRAPH_ENABLED", "false").security.dependency_graph.enabled, "DEPENDENCY_GRAPH_ENABLED=false");
        assert!(load_with_env("CODE_SCANNING_ENABLED", "true").security.code_scanning.enabled, "CODE_SCANNING_ENABLED=true");
        assert!(!load_with_env("CODE_SCANNING_ENABLED", "false").security.code_scanning.enabled, "CODE_SCANNING_ENABLED=false");
        assert!(load_with_env("CODE_SCANNING_SYNC_DISMISSALS", "true").security.code_scanning.sync_dismissals, "CODE_SCANNING_SYNC_DISMISSALS=true");
        assert!(!load_with_env("CODE_SCANNING_SYNC_DISMISSALS", "false").security.code_scanning.sync_dismissals, "CODE_SCANNING_SYNC_DISMISSALS=false");
        assert!(load_with_env("DEPENDENCY_REVIEW_ENABLED", "true").security.dependency_review.enabled, "DEPENDENCY_REVIEW_ENABLED=true");
        assert!(!load_with_env("DEPENDENCY_REVIEW_ENABLED", "false").security.dependency_review.enabled, "DEPENDENCY_REVIEW_ENABLED=false");
        assert!(load_with_env("PR_SUGGESTIONS_ENABLED", "true").security.pr_suggestions.enabled, "PR_SUGGESTIONS_ENABLED=true");
        assert!(!load_with_env("PR_SUGGESTIONS_ENABLED", "false").security.pr_suggestions.enabled, "PR_SUGGESTIONS_ENABLED=false");
        assert!(load_with_env("SECRET_VERIFICATION_ENABLED", "true").security.secret_verification.enabled, "SECRET_VERIFICATION_ENABLED=true");
        assert!(!load_with_env("SECRET_VERIFICATION_ENABLED", "false").security.secret_verification.enabled, "SECRET_VERIFICATION_ENABLED=false");
        assert!(load_with_env("PUSH_PROTECTION_AUTO_FILE_ISSUE", "true").security.push_protection.auto_file_issue, "PUSH_PROTECTION_AUTO_FILE_ISSUE=true");
        assert!(!load_with_env("PUSH_PROTECTION_AUTO_FILE_ISSUE", "false").security.push_protection.auto_file_issue, "PUSH_PROTECTION_AUTO_FILE_ISSUE=false");
        assert!(load_with_env("REPOSITORY_EVENTS_APPLY_ORG_RULESET", "true").security.repository_events.apply_org_ruleset, "REPOSITORY_EVENTS_APPLY_ORG_RULESET=true");
        assert!(!load_with_env("REPOSITORY_EVENTS_APPLY_ORG_RULESET", "false").security.repository_events.apply_org_ruleset, "REPOSITORY_EVENTS_APPLY_ORG_RULESET=false");
        assert!(load_with_env("REPOSITORY_EVENTS_TRIGGER_BASELINE_SCAN", "true").security.repository_events.trigger_baseline_scan, "REPOSITORY_EVENTS_TRIGGER_BASELINE_SCAN=true");
        assert!(!load_with_env("REPOSITORY_EVENTS_TRIGGER_BASELINE_SCAN", "false").security.repository_events.trigger_baseline_scan, "REPOSITORY_EVENTS_TRIGGER_BASELINE_SCAN=false");
        assert!(load_with_env("OVERRIDE_APPROVAL_ENABLED", "true").security.override_approval.enabled, "OVERRIDE_APPROVAL_ENABLED=true");
        assert!(!load_with_env("OVERRIDE_APPROVAL_ENABLED", "false").security.override_approval.enabled, "OVERRIDE_APPROVAL_ENABLED=false");
        assert!(load_with_env("ALLOW_UNAUTHENTICATED_VALIDATE_ALL", "true").security.allow_unauthenticated_validate_all, "ALLOW_UNAUTHENTICATED_VALIDATE_ALL=true");
        assert!(!load_with_env("ALLOW_UNAUTHENTICATED_VALIDATE_ALL", "false").security.allow_unauthenticated_validate_all, "ALLOW_UNAUTHENTICATED_VALIDATE_ALL=false");
        assert!(load_with_env("ALLOW_UNAUTHENTICATED_INTERACTIVE_DRY_RUN", "true").security.allow_unauthenticated_interactive_dry_run, "ALLOW_UNAUTHENTICATED_INTERACTIVE_DRY_RUN=true");
        assert!(!load_with_env("ALLOW_UNAUTHENTICATED_INTERACTIVE_DRY_RUN", "false").security.allow_unauthenticated_interactive_dry_run, "ALLOW_UNAUTHENTICATED_INTERACTIVE_DRY_RUN=false");
        assert!(load_with_env("ALLOW_UNAUTHENTICATED_AI_ASSIST", "true").security.allow_unauthenticated_ai_assist, "ALLOW_UNAUTHENTICATED_AI_ASSIST=true");
        assert!(!load_with_env("ALLOW_UNAUTHENTICATED_AI_ASSIST", "false").security.allow_unauthenticated_ai_assist, "ALLOW_UNAUTHENTICATED_AI_ASSIST=false");
        assert!(load_with_env("POLICY_STRICT", "true").policy.strict, "POLICY_STRICT=true");
        assert!(!load_with_env("POLICY_STRICT", "false").policy.strict, "POLICY_STRICT=false");
        assert!(load_with_env("SLA_ENABLED", "true").sla.enabled, "SLA_ENABLED=true");
        assert!(!load_with_env("SLA_ENABLED", "false").sla.enabled, "SLA_ENABLED=false");
        assert_eq!(load_with_env("SLA_CRITICAL_DAYS", "7").sla.critical_days.to_string(), "7", "SLA_CRITICAL_DAYS");
        assert_eq!(load_with_env("SLA_HIGH_DAYS", "7").sla.high_days.to_string(), "7", "SLA_HIGH_DAYS");
        assert_eq!(load_with_env("SLA_MEDIUM_DAYS", "7").sla.medium_days.to_string(), "7", "SLA_MEDIUM_DAYS");
        assert!(load_with_env("AUDIT_LOG_ENABLED", "true").audit_log.enabled, "AUDIT_LOG_ENABLED=true");
        assert!(!load_with_env("AUDIT_LOG_ENABLED", "false").audit_log.enabled, "AUDIT_LOG_ENABLED=false");
        assert_eq!(load_with_env("ORG_REPOS_MAX_CONCURRENT_SCANS", "7").org_repos.max_concurrent_scans.to_string(), "7", "ORG_REPOS_MAX_CONCURRENT_SCANS");
        assert_eq!(load_with_env("ORG_REPOS_AUTO_RESCAN_STALE_AFTER_HOURS", "7").org_repos.auto_rescan_stale_after_hours.to_string(), "7", "ORG_REPOS_AUTO_RESCAN_STALE_AFTER_HOURS");
        assert!(load_with_env("DAILY_REPORT_ENABLED", "true").daily_report.enabled, "DAILY_REPORT_ENABLED=true");
        assert!(!load_with_env("DAILY_REPORT_ENABLED", "false").daily_report.enabled, "DAILY_REPORT_ENABLED=false");
        assert_eq!(load_with_env("DAILY_REPORT_TIME", "pin-DAILY_REPORT_TIME").daily_report.time, "pin-DAILY_REPORT_TIME", "DAILY_REPORT_TIME");
        assert_eq!(load_with_env("DAILY_REPORT_TO", "pin-DAILY_REPORT_TO").daily_report.to, "pin-DAILY_REPORT_TO", "DAILY_REPORT_TO");
        assert_eq!(load_with_env("DAILY_REPORT_WEBHOOK_URL", "pin-DAILY_REPORT_WEBHOOK_URL").daily_report.webhook_url, "pin-DAILY_REPORT_WEBHOOK_URL", "DAILY_REPORT_WEBHOOK_URL");
        assert_eq!(load_with_env("DAILY_REPORT_WEBHOOK_TOKEN", "pin-DAILY_REPORT_WEBHOOK_TOKEN").daily_report.webhook_token, "pin-DAILY_REPORT_WEBHOOK_TOKEN", "DAILY_REPORT_WEBHOOK_TOKEN");
        assert_eq!(load_with_env("DAILY_REPORT_AZURE_BLOB_CONTAINER_URL", "pin-DAILY_REPORT_AZURE_BLOB_CONTAINER_URL").daily_report.azure_blob_container_url, "pin-DAILY_REPORT_AZURE_BLOB_CONTAINER_URL", "DAILY_REPORT_AZURE_BLOB_CONTAINER_URL");
        assert_eq!(load_with_env("ZIZMOR_BINARY", "pin-ZIZMOR_BINARY").security.zizmor.binary, "pin-ZIZMOR_BINARY", "ZIZMOR_BINARY");
        assert!(load_with_env("SEMGREP_ENABLED", "true").security.semgrep.enabled, "SEMGREP_ENABLED=true");
        assert!(!load_with_env("SEMGREP_ENABLED", "false").security.semgrep.enabled, "SEMGREP_ENABLED=false");
        assert_eq!(load_with_env("SEMGREP_BINARY", "pin-SEMGREP_BINARY").security.semgrep.binary, "pin-SEMGREP_BINARY", "SEMGREP_BINARY");
        assert_eq!(load_with_env("SEMGREP_CONFIG", "pin-SEMGREP_CONFIG").security.semgrep.config, "pin-SEMGREP_CONFIG", "SEMGREP_CONFIG");
        assert!(load_with_env("BEARER_ENABLED", "true").security.bearer.enabled, "BEARER_ENABLED=true");
        assert!(!load_with_env("BEARER_ENABLED", "false").security.bearer.enabled, "BEARER_ENABLED=false");
        assert_eq!(load_with_env("BEARER_BINARY", "pin-BEARER_BINARY").security.bearer.binary, "pin-BEARER_BINARY", "BEARER_BINARY");
        assert!(load_with_env("GUARDDOG_ENABLED", "true").security.guarddog.enabled, "GUARDDOG_ENABLED=true");
        assert!(!load_with_env("GUARDDOG_ENABLED", "false").security.guarddog.enabled, "GUARDDOG_ENABLED=false");
        assert_eq!(load_with_env("GUARDDOG_BINARY", "pin-GUARDDOG_BINARY").security.guarddog.binary, "pin-GUARDDOG_BINARY", "GUARDDOG_BINARY");
        assert!(load_with_env("CODEQL_ENABLED", "true").security.codeql.enabled, "CODEQL_ENABLED=true");
        assert!(!load_with_env("CODEQL_ENABLED", "false").security.codeql.enabled, "CODEQL_ENABLED=false");
        assert_eq!(load_with_env("CODEQL_BINARY", "pin-CODEQL_BINARY").security.codeql.binary, "pin-CODEQL_BINARY", "CODEQL_BINARY");
        assert_eq!(load_with_env("CODEQL_THREADS", "7").security.codeql.threads.to_string(), "7", "CODEQL_THREADS");
        assert_eq!(load_with_env("CODEQL_RAM_MB", "7").security.codeql.ram_mb.to_string(), "7", "CODEQL_RAM_MB");
        assert_eq!(load_with_env("CODEQL_TIMEOUT_MS", "7").security.codeql.timeout_ms.to_string(), "7", "CODEQL_TIMEOUT_MS");
        assert_eq!(load_with_env("CODEQL_REVIEW_CADENCE_DAYS", "7").security.codeql.review_cadence_days.to_string(), "7", "CODEQL_REVIEW_CADENCE_DAYS");
        assert!(load_with_env("DEAD_CODE_ENABLED", "true").code_intelligence.dead_code.enabled, "DEAD_CODE_ENABLED=true");
        assert!(!load_with_env("DEAD_CODE_ENABLED", "false").code_intelligence.dead_code.enabled, "DEAD_CODE_ENABLED=false");
        assert!(load_with_env("HEALTH_ENABLED", "true").code_intelligence.health.enabled, "HEALTH_ENABLED=true");
        assert!(!load_with_env("HEALTH_ENABLED", "false").code_intelligence.health.enabled, "HEALTH_ENABLED=false");
        assert!(load_with_env("CSS_DEAD_CODE_ENABLED", "true").code_intelligence.css_dead_code.enabled, "CSS_DEAD_CODE_ENABLED=true");
        assert!(!load_with_env("CSS_DEAD_CODE_ENABLED", "false").code_intelligence.css_dead_code.enabled, "CSS_DEAD_CODE_ENABLED=false");
        assert!(load_with_env("ARCHITECTURE_BOUNDARIES_ENABLED", "true").architecture.boundaries.enabled, "ARCHITECTURE_BOUNDARIES_ENABLED=true");
        assert!(!load_with_env("ARCHITECTURE_BOUNDARIES_ENABLED", "false").architecture.boundaries.enabled, "ARCHITECTURE_BOUNDARIES_ENABLED=false");
        assert_eq!(load_with_env("ARCHITECTURE_BOUNDARIES_PRESET", "pin-ARCHITECTURE_BOUNDARIES_PRESET").architecture.boundaries.preset, "pin-ARCHITECTURE_BOUNDARIES_PRESET", "ARCHITECTURE_BOUNDARIES_PRESET");
        assert!(load_with_env("IGNOREFILE_ENABLED", "true").ignore_file.enabled, "IGNOREFILE_ENABLED=true");
        assert!(!load_with_env("IGNOREFILE_ENABLED", "false").ignore_file.enabled, "IGNOREFILE_ENABLED=false");
        assert!(load_with_env("TRIVY_IMAGE_ENABLED", "true").security.trivy_image.enabled, "TRIVY_IMAGE_ENABLED=true");
        assert!(!load_with_env("TRIVY_IMAGE_ENABLED", "false").security.trivy_image.enabled, "TRIVY_IMAGE_ENABLED=false");
        assert_eq!(load_with_env("TRIVY_IMAGE_SEVERITY", "pin-TRIVY_IMAGE_SEVERITY").security.trivy_image.severity_threshold, "pin-TRIVY_IMAGE_SEVERITY", "TRIVY_IMAGE_SEVERITY");
        assert_eq!(load_with_env("TRIVY_IMAGE_BUILD_TIMEOUT_MS", "7").security.trivy_image.build_timeout_ms.to_string(), "7", "TRIVY_IMAGE_BUILD_TIMEOUT_MS");
        assert!(load_with_env("AI_AUTO_JUSTIFY_ENABLED", "true").ai_auto_justify.enabled, "AI_AUTO_JUSTIFY_ENABLED=true");
        assert!(!load_with_env("AI_AUTO_JUSTIFY_ENABLED", "false").ai_auto_justify.enabled, "AI_AUTO_JUSTIFY_ENABLED=false");
        assert!(load_with_env("POSTURE_ENABLED", "true").compliance.posture.enabled, "POSTURE_ENABLED=true");
        assert!(!load_with_env("POSTURE_ENABLED", "false").compliance.posture.enabled, "POSTURE_ENABLED=false");
        assert_eq!(load_with_env("POSTURE_RULESET", "pin-POSTURE_RULESET").compliance.posture.ruleset, "pin-POSTURE_RULESET", "POSTURE_RULESET");
        assert!(load_with_env("EU_AI_ACT_DOCS_ENABLED", "true").compliance.eu_ai_act_documents.enabled, "EU_AI_ACT_DOCS_ENABLED=true");
        assert!(!load_with_env("EU_AI_ACT_DOCS_ENABLED", "false").compliance.eu_ai_act_documents.enabled, "EU_AI_ACT_DOCS_ENABLED=false");
        assert!(load_with_env("EU_AI_ACT_REPORT_AS_FINDINGS", "true").compliance.eu_ai_act.report_as_findings, "EU_AI_ACT_REPORT_AS_FINDINGS=true");
        assert!(!load_with_env("EU_AI_ACT_REPORT_AS_FINDINGS", "false").compliance.eu_ai_act.report_as_findings, "EU_AI_ACT_REPORT_AS_FINDINGS=false");
        assert!(load_with_env("JSCPD_ENABLED", "true").metrics.jscpd.enabled, "JSCPD_ENABLED=true");
        assert!(!load_with_env("JSCPD_ENABLED", "false").metrics.jscpd.enabled, "JSCPD_ENABLED=false");
        assert_eq!(load_with_env("JSCPD_BINARY", "pin-JSCPD_BINARY").metrics.jscpd.binary, "pin-JSCPD_BINARY", "JSCPD_BINARY");
        assert_eq!(load_with_env("JSCPD_MIN_LINES", "7").metrics.jscpd.min_lines.to_string(), "7", "JSCPD_MIN_LINES");
        assert_eq!(load_with_env("JSCPD_MIN_TOKENS", "7").metrics.jscpd.min_tokens.to_string(), "7", "JSCPD_MIN_TOKENS");
        assert!(load_with_env("GOCLOC_ENABLED", "true").metrics.gocloc.enabled, "GOCLOC_ENABLED=true");
        assert!(!load_with_env("GOCLOC_ENABLED", "false").metrics.gocloc.enabled, "GOCLOC_ENABLED=false");
        assert_eq!(load_with_env("GOCLOC_BINARY", "pin-GOCLOC_BINARY").metrics.gocloc.binary, "pin-GOCLOC_BINARY", "GOCLOC_BINARY");
        assert!(load_with_env("FILE_SIZE_ENABLED", "true").metrics.file_size.enabled, "FILE_SIZE_ENABLED=true");
        assert!(!load_with_env("FILE_SIZE_ENABLED", "false").metrics.file_size.enabled, "FILE_SIZE_ENABLED=false");
        assert_eq!(load_with_env("FILE_SIZE_MAX_LINES", "7").metrics.file_size.max_lines.to_string(), "7", "FILE_SIZE_MAX_LINES");
        assert!(load_with_env("SPECTRAL_ENABLED", "true").api.spectral.enabled, "SPECTRAL_ENABLED=true");
        assert!(!load_with_env("SPECTRAL_ENABLED", "false").api.spectral.enabled, "SPECTRAL_ENABLED=false");
        assert_eq!(load_with_env("SPECTRAL_BINARY", "pin-SPECTRAL_BINARY").api.spectral.binary, "pin-SPECTRAL_BINARY", "SPECTRAL_BINARY");
        assert_eq!(load_with_env("SPECTRAL_RULESET", "pin-SPECTRAL_RULESET").api.spectral.ruleset, "pin-SPECTRAL_RULESET", "SPECTRAL_RULESET");
        assert!(load_with_env("OASDIFF_ENABLED", "true").api.oasdiff.enabled, "OASDIFF_ENABLED=true");
        assert!(!load_with_env("OASDIFF_ENABLED", "false").api.oasdiff.enabled, "OASDIFF_ENABLED=false");
        assert_eq!(load_with_env("OASDIFF_BINARY", "pin-OASDIFF_BINARY").api.oasdiff.binary, "pin-OASDIFF_BINARY", "OASDIFF_BINARY");
        assert!(load_with_env("SYFT_ENABLED", "true").sbom.syft.enabled, "SYFT_ENABLED=true");
        assert!(!load_with_env("SYFT_ENABLED", "false").sbom.syft.enabled, "SYFT_ENABLED=false");
        assert_eq!(load_with_env("SYFT_BINARY", "pin-SYFT_BINARY").sbom.syft.binary, "pin-SYFT_BINARY", "SYFT_BINARY");
        assert!(load_with_env("MCP_AUTOSTART", "true").mcp.auto_start, "MCP_AUTOSTART=true");
        assert!(!load_with_env("MCP_AUTOSTART", "false").mcp.auto_start, "MCP_AUTOSTART=false");
        assert_eq!(load_with_env("MCP_HTTP_PORT", "7").mcp.http_port.to_string(), "7", "MCP_HTTP_PORT");
        assert_eq!(load_with_env("LLM_PROVIDER", "pin-LLM_PROVIDER").llm.provider, "pin-LLM_PROVIDER", "LLM_PROVIDER");
        assert_eq!(load_with_env("LLM_SCAN_URL", "pin-LLM_SCAN_URL").llm.url, "pin-LLM_SCAN_URL", "LLM_SCAN_URL");
        assert_eq!(load_with_env("LLM_SCAN_MODEL", "pin-LLM_SCAN_MODEL").llm.model, "pin-LLM_SCAN_MODEL", "LLM_SCAN_MODEL");
        assert_eq!(load_with_env("LLM_SCAN_MODE", "pin-LLM_SCAN_MODE").llm.mode, "pin-LLM_SCAN_MODE", "LLM_SCAN_MODE");
        assert_eq!(load_with_env("LLM_MAX_FILES", "7").llm.max_files.to_string(), "7", "LLM_MAX_FILES");
        assert_eq!(load_with_env("LLM_CHUNK_CHARS", "7").llm.chunk_chars.to_string(), "7", "LLM_CHUNK_CHARS");
        assert!(load_with_env("LLM_DEEP_SCAN_ENABLED", "true").llm.deep_scan_enabled, "LLM_DEEP_SCAN_ENABLED=true");
        assert!(!load_with_env("LLM_DEEP_SCAN_ENABLED", "false").llm.deep_scan_enabled, "LLM_DEEP_SCAN_ENABLED=false");
        assert_eq!(load_with_env("LLM_ADVISORY_LEVEL", "pin-LLM_ADVISORY_LEVEL").llm.advisory_level, "pin-LLM_ADVISORY_LEVEL", "LLM_ADVISORY_LEVEL");
        assert_eq!(load_with_env("OPENAI_API_KEY", "pin-OPENAI_API_KEY").llm.openai.api_key, "pin-OPENAI_API_KEY", "OPENAI_API_KEY");
        assert_eq!(load_with_env("OPENAI_BASE_URL", "pin-OPENAI_BASE_URL").llm.openai.base_url, "pin-OPENAI_BASE_URL", "OPENAI_BASE_URL");
        assert_eq!(load_with_env("OPENAI_MODEL", "pin-OPENAI_MODEL").llm.openai.model, "pin-OPENAI_MODEL", "OPENAI_MODEL");
        assert_eq!(load_with_env("ANTHROPIC_API_KEY", "pin-ANTHROPIC_API_KEY").llm.anthropic.api_key, "pin-ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY");
        assert_eq!(load_with_env("ANTHROPIC_BASE_URL", "pin-ANTHROPIC_BASE_URL").llm.anthropic.base_url, "pin-ANTHROPIC_BASE_URL", "ANTHROPIC_BASE_URL");
        assert_eq!(load_with_env("ANTHROPIC_MODEL", "pin-ANTHROPIC_MODEL").llm.anthropic.model, "pin-ANTHROPIC_MODEL", "ANTHROPIC_MODEL");
        assert_eq!(load_with_env("AZURE_FOUNDRY_API_KEY", "pin-AZURE_FOUNDRY_API_KEY").llm.azure_foundry.api_key, "pin-AZURE_FOUNDRY_API_KEY", "AZURE_FOUNDRY_API_KEY");
        assert_eq!(load_with_env("AZURE_FOUNDRY_ENDPOINT", "pin-AZURE_FOUNDRY_ENDPOINT").llm.azure_foundry.endpoint, "pin-AZURE_FOUNDRY_ENDPOINT", "AZURE_FOUNDRY_ENDPOINT");
        assert_eq!(load_with_env("AZURE_FOUNDRY_DEPLOYMENT", "pin-AZURE_FOUNDRY_DEPLOYMENT").llm.azure_foundry.deployment, "pin-AZURE_FOUNDRY_DEPLOYMENT", "AZURE_FOUNDRY_DEPLOYMENT");
        assert_eq!(load_with_env("AZURE_FOUNDRY_API_VERSION", "pin-AZURE_FOUNDRY_API_VERSION").llm.azure_foundry.api_version, "pin-AZURE_FOUNDRY_API_VERSION", "AZURE_FOUNDRY_API_VERSION");
        assert_eq!(load_with_env("SECRETS_KNOWN_PUBLIC_KEY_PATTERNS", " one , two ,, three ").security.secrets.known_public_key_patterns, vec!["one", "two", "three"], "SECRETS_KNOWN_PUBLIC_KEY_PATTERNS: comma list, trimmed, empties dropped");
        assert_eq!(load_with_env("SECURITY_EXCLUDE_PATHS", " one , two ,, three ").security.exclude_paths, vec!["one", "two", "three"], "SECURITY_EXCLUDE_PATHS: comma list, trimmed, empties dropped");
        assert_eq!(load_with_env("OVERRIDE_APPROVAL_APPROVER_EMAILS", " one , two ,, three ").security.override_approval.approver_emails, vec!["one", "two", "three"], "OVERRIDE_APPROVAL_APPROVER_EMAILS: comma list, trimmed, empties dropped");
        assert_eq!(load_with_env("CODEQL_LANGUAGES", " one , two ,, three ").security.codeql.languages, vec!["one", "two", "three"], "CODEQL_LANGUAGES: comma list, trimmed, empties dropped");
        assert_eq!(load_with_env("AI_AUTO_JUSTIFY_CATEGORIES", " one , two ,, three ").ai_auto_justify.categories, vec!["one", "two", "three"], "AI_AUTO_JUSTIFY_CATEGORIES: comma list, trimmed, empties dropped");
        assert_eq!(load_with_env("JSCPD_IGNORE", " one , two ,, three ").metrics.jscpd.ignore_patterns, vec!["one", "two", "three"], "JSCPD_IGNORE: comma list, trimmed, empties dropped");
    }

    #[test]
    fn the_env_override_table_covers_every_direct_override_in_the_source() {
        // Guards this table itself: a new `if let Some(v) = env_*("X") { merged.a.b = v; }`
        // line must get a row above (regenerate or add it by hand).
        let src = include_str!("lib.rs");
        let start = src.find("fn apply_env_overrides").unwrap();
        let body = &src[start..];
        let direct = body.lines().filter(|l| l.trim_start().starts_with("if let Some(v) = env_") && l.contains("{ merged.") && l.trim_end().ends_with("= v; }")).count();
        assert_eq!(direct, 128, "a direct env override was added or removed: update every_direct_env_override_lands_in_the_config_field_it_names");
    }
}
