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

use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};

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
        }
    }
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
    /// Which backend `llm.url`/`llm.model` below, `llm.openai`, or
    /// `llm.anthropic` resolves against: `"local"`, `"openai"`, or
    /// `"anthropic"`. Drives both Phase 4's deep-scan (Check 3) and
    /// Ignite Studio's on-demand "Explain issue"/"Suggest AI fix"
    /// buttons — both share this one connection.
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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenAiLlmConfig {
    pub api_key: String,
    pub base_url: String,
    pub model: String,
}
impl Default for OpenAiLlmConfig {
    fn default() -> Self {
        OpenAiLlmConfig { api_key: String::new(), base_url: "https://api.openai.com/v1".into(), model: "gpt-4o-mini".into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnthropicLlmConfig {
    pub api_key: String,
    pub base_url: String,
    pub model: String,
}
impl Default for AnthropicLlmConfig {
    fn default() -> Self {
        AnthropicLlmConfig { api_key: String::new(), base_url: "https://api.anthropic.com/v1".into(), model: "claude-opus-5".into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OauthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scope: String,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub secure: bool,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scope: String,
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
}
impl Default for GitleaksConfig {
    fn default() -> Self {
        GitleaksConfig { enabled: false, binary: "gitleaks".into(), config_path: String::new() }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::tempdir;

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
        assert!(cfg.compliance.posture.ruleset.starts_with(dir.path().to_str().unwrap()));
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
}
