//! Compliance & Feature Posture Engine — detects the PRESENCE of security/
//! compliance features (SSO, RBAC, audit logging, TLS, backups, encryption
//! at rest, rate limiting, EU AI Act code-detectable signals), not
//! vulnerabilities. Faithful port of `checks/feature-posture.js`.
//!
//! `semgrep_tooling` (the JS original shares the *already-created* probe
//! from `checks/semantic-sast.js`'s factory, since this engine is "fully
//! conditioned on Semgrep" — same binary, same probe) is duplicated here
//! as a small standalone function rather than depending on a not-yet-
//! ported `ignite-semantic-sast` crate; once that crate exists, this
//! should share its probe the same way the JS does, instead of running
//! its own `semgrep --version`.

use ignite_fs_utils::{build_snippet, looks_binary, relative_to_root, walk_files, Snippet, SnippetOptions, BINARY_EXTENSIONS};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

pub const POSTURE_CATEGORIES: &[&str] = &[
    "sso-saml-oidc",
    "rbac-abac",
    "audit-logging",
    "siem-log-forwarding",
    "https-tls",
    "backups-dr",
    "encryption-at-rest",
    "rate-limiting",
    "mfa-2fa",
    "secrets-management",
    "ai-act-prohibited-practice",
    "ai-act-transparency-disclosure",
    "ai-act-ai-logging",
];

struct Tier {
    weak: Regex,
    strong: Regex,
}

static POSTURE_FALLBACK_PATTERNS: Lazy<BTreeMap<&'static str, Tier>> = Lazy::new(|| {
    let t = |weak: &str, strong: &str| Tier { weak: Regex::new(weak).unwrap(), strong: Regex::new(strong).unwrap() };
    [
        ("sso-saml-oidc", t(
            r"passport-saml|passport-openidconnect|passport-oauth2|org\.springframework\.security\.oauth2|org\.keycloak|keycloak-connect|auth0(-java|-spa-js)?|okta-sdk|okta-auth-js|com\.okta|cognito|microsoft-identity-web|omniauth-saml|omniauth-oauth2|ruby-saml|python3-saml|django-allauth",
            r"new\s+SamlStrategy\(|new\s+OIDCStrategy\(|new\s+Auth0Client\(|new\s+CognitoUserPool\(|OktaAuth\(|@EnableOAuth2Sso|KeycloakInstance\(|Keycloak\(\{|SAML2AuthenticationProvider\(|OidcClient\(",
        )),
        ("rbac-abac", t(
            r"casbin|open-policy-agent|org\.opa|opa-wasm|django-guardian|pundit|cancancan|micronaut-security-annotations",
            r"@PreAuthorize\(|@PostAuthorize\(|@RolesAllowed\(|@Secured\(|@RequireRole|casbin\.NewEnforcer\(|enforcer\.Enforce\(|opa\.Eval\(|requireRole\(|requirePermission\(|checkPermission\(|authorize!\(|can\?\(",
        )),
        ("audit-logging", t(
            r"AuditLogger|AuditEvent|audit_log|AuditingEntityListener|@Audited|django-auditlog|paper_trail|audited\s",
            r"auditLogger\.(log|record|emit)\(|AuditLog\.create\(|logger\.audit\(|audit_log\.(info|record|create)\(|PaperTrail\.request|@Audited\b",
        )),
        ("siem-log-forwarding", t(
            r"winston-syslog|fluent-logger|logstash|@opentelemetry|go\.opentelemetry\.io|SyslogAppender|serilog-sinks-syslog|nlog\.targets\.syslog",
            r"new\s+FluentLogger\(|winston\.transports\.Syslog\(|new\s+LogstashTransport\(|zap\.NewSyslogWriter\(|SyslogAppender\(|OpenTelemetry\.trace\.getTracer\(",
        )),
        ("https-tls", t(
            r"\bhelmet\b|force-ssl|django\.middleware\.security|Rack::SSL|Microsoft\.AspNetCore\.HttpsPolicy",
            r"helmet\.hsts\(|Strict-Transport-Security|forceSSL|SECURE_SSL_REDIRECT\s*=\s*True|app\.UseHsts\(|https\.createServer\(|config\.force_ssl\s*=\s*true",
        )),
        ("backups-dr", t(
            r"pg_dump|pg_basebackup|mongodump|mysqldump|velero|restic\s|borgbackup",
            r"backup_retention_period|BackupRetentionPeriod|RetentionPolicy|CreateDBSnapshot|CreateSnapshot\(",
        )),
        ("encryption-at-rest", t(
            r"aws-sdk.*kms|@aws-sdk/client-kms|com\.amazonaws\.services\.kms|hashicorp/vault|com\.google\.cloud\.kms|azure-keyvault",
            r#"kms\.encrypt\(|kmsClient\.Encrypt\(|vault\.write\(|createCipheriv\(|Aes\.Encrypt\(|EncryptField\(|Cipher\.getInstance\("AES"#,
        )),
        ("rate-limiting", t(
            r"express-rate-limit|bucket4j|django-ratelimit|rack-attack|flask-limiter|aspnetcoreratelimit",
            r"rateLimit\(\{|new\s+RateLimiterRedis\(|Bucket4j\.builder\(|RateLimiter\.create\(|@ratelimit\(|Rack::Attack\.throttle\(",
        )),
        ("mfa-2fa", t(
            r"speakeasy|otplib|pyotp|django-otp|devise-two-factor|rotp|com\.warrenstrange\.googleauth|authy",
            r"speakeasy\.totp\.verify\(|totp\.verify\(|pyotp\.TOTP\(|authenticator\.verify\(|GoogleAuthenticator\(\)\.authorize\(|TwoFactorAuthenticationProvider|verifyMfaChallenge\(",
        )),
        ("secrets-management", t(
            r"hashicorp/vault|node-vault|@aws-sdk/client-secrets-manager|azure-keyvault-secrets|com\.google\.cloud\.secretmanager|com\.bettercloud\.vault|doppler|python-dotenv-vault",
            r"vault\.read\(|vaultClient\.read\(|secretsManagerClient\.getSecretValue\(|new\s+SecretClient\(|secretmanager\.accessSecretVersion\(|SecretsManagerClient\(\)\.getSecretValue\(",
        )),
        // Unlike every category above, DETECTED here flags a *risk* (an EU
        // AI Act Art. 5 prohibited/restricted practice), not a safeguard.
        ("ai-act-prohibited-practice", t(
            r"face-api\.js|face_recognition|deepface|@vladmandic/face-api|com\.microsoft\.cognitiveservices\.vision\.face|azure-cognitiveservices-vision-face|aws-sdk.*rekognition|@aws-sdk/client-rekognition|google-cloud/vision.*faceDetection|emotion-recognition|py-feat|affectiva",
            r"recognizeEmotion\(|detectEmotion\(|FaceClient\(.*\)\.face\.detect|rekognition\.detectFaces\(|compareFaces\(|socialScore|social_score|creditworthiness_score.*biometric",
        )),
        ("ai-act-transparency-disclosure", t(
            r"ai-disclosure|aiDisclosure|chatbotDisclosure|synthetic-content-label|c2pa",
            r"(?i)you'?re (chatting|talking) with an ai|this (response|content) (is|was) (ai|automatically)[- ]generated|ai[- ]generated content|you are interacting with an ai system",
        )),
        ("ai-act-ai-logging", t(
            r"mlflow|wandb|weights_and_biases|langsmith|langfuse|helicone|arize-phoenix|whylogs",
            r"mlflow\.log_(param|metric|artifact|prediction)\(|wandb\.log\(|langsmith\.(trace|log_run)\(|logDecision\(|logPrediction\(|logModelInput(Output)?\(",
        )),
    ]
    .into_iter()
    .collect()
});

#[derive(Debug, Clone, Serialize)]
pub struct PostureMatch {
    pub file: String,
    pub line: usize,
    pub tier: &'static str, // "weak" | "strong"
    pub tool: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Snippet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PostureCategoryReport {
    pub status: &'static str, // "DETECTED" | "PARTIAL" | "MISSING"
    pub matches: Vec<PostureMatch>,
}

pub type PostureReport = BTreeMap<&'static str, PostureCategoryReport>;

fn empty_posture_report() -> PostureReport {
    POSTURE_CATEGORIES.iter().map(|&cat| (cat, PostureCategoryReport { status: "MISSING", matches: vec![] })).collect()
}

/// >=1 "strong" (confirmed usage) match => DETECTED. Only "weak" (import/
/// > dependency-only) matches => PARTIAL. Neither => MISSING.
fn classify_posture_matches(matches: &[PostureMatch]) -> &'static str {
    if matches.iter().any(|m| m.tier == "strong") {
        "DETECTED"
    } else if !matches.is_empty() {
        "PARTIAL"
    } else {
        "MISSING"
    }
}

/// Engine: Ignite Built-In Posture Scanner (Fallback) — used only when
/// Semgrep is unavailable. Same weak/strong two-tier model, a line-by-line
/// regex sweep instead of Semgrep's engine.
pub fn check_feature_posture_fallback(root: &Path, max_scan_file_bytes: u64) -> std::io::Result<PostureReport> {
    let mut posture = empty_posture_report();

    for file in walk_files(root)? {
        let ext = file.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        if BINARY_EXTENSIONS.contains(&ext.as_str()) {
            continue;
        }
        let Ok(metadata) = std::fs::metadata(&file) else { continue };
        if metadata.len() > max_scan_file_bytes {
            continue;
        }
        let Ok(buffer) = std::fs::read(&file) else { continue };
        if looks_binary(&buffer) {
            continue;
        }
        let content = String::from_utf8_lossy(&buffer).into_owned();
        let rel = file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");

        for &category in POSTURE_CATEGORIES {
            let tier_patterns = &POSTURE_FALLBACK_PATTERNS[category];
            for (i, line) in content.split('\n').enumerate() {
                let tier = if tier_patterns.strong.is_match(line) {
                    Some("strong")
                } else if tier_patterns.weak.is_match(line) {
                    Some("weak")
                } else {
                    None
                };
                let Some(tier) = tier else { continue };
                let line_no = i + 1;
                posture.get_mut(category).unwrap().matches.push(PostureMatch {
                    file: rel.clone(),
                    line: line_no,
                    tier,
                    tool: "ignite-fallback",
                    message: format!("{category} ({tier} signal, built-in fallback — Semgrep not installed)"),
                    code: build_snippet(&content, line_no, SnippetOptions::default()),
                });
            }
        }
    }

    for report in posture.values_mut() {
        report.status = classify_posture_matches(&report.matches);
    }
    Ok(posture)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SemgrepToolingProbe {
    pub ok: bool,
    pub version: Option<String>,
    pub reason: Option<String>,
}

/// Minimal `semgrep --version` probe — see the module doc for why this
/// duplicates (rather than shares) semantic-sast's eventual probe.
pub async fn semgrep_tooling(runner: &ToolRunner) -> SemgrepToolingProbe {
    match runner.run_tool("semgrep", &["--version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default()).await {
        Ok(out) => SemgrepToolingProbe { ok: true, version: Some(out.stdout.trim().to_string()), reason: None },
        Err(_) => SemgrepToolingProbe {
            ok: false,
            version: None,
            reason: Some("`semgrep` is not installed (brew install semgrep / pip install semgrep) — semantic SAST and posture findings are simply omitted.".to_string()),
        },
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FeaturePostureResult {
    pub engine: &'static str, // "fallback" | "semgrep"
    pub posture: PostureReport,
}

pub struct FeaturePostureConfig {
    pub enabled: bool,
    pub ruleset: String,
    pub max_scan_file_bytes: u64,
}

/// Fully conditioned on Semgrep: runs `ruleset` when connected, soft-falls
/// back to `check_feature_posture_fallback` when disabled or not
/// installed. The per-(category,file,line,tier) dedup guards against
/// Semgrep itself reporting the same match twice (observed in practice:
/// overlapping regex spans on one line).
pub async fn check_feature_posture(root: &Path, runner: &ToolRunner, config: &FeaturePostureConfig) -> std::io::Result<FeaturePostureResult> {
    let tooling = if config.enabled {
        semgrep_tooling(runner).await
    } else {
        SemgrepToolingProbe { ok: false, version: None, reason: Some("posture scan is disabled (compliance.posture.enabled=false).".to_string()) }
    };

    if !tooling.ok {
        let posture = check_feature_posture_fallback(root, config.max_scan_file_bytes)?;
        return Ok(FeaturePostureResult { engine: "fallback", posture });
    }

    let mut posture = empty_posture_report();
    let category_set: HashSet<&'static str> = POSTURE_CATEGORIES.iter().copied().collect();

    let run_result = runner
        .run_tool(
            "semgrep",
            &["scan".to_string(), "--config".to_string(), config.ruleset.clone(), "--json".to_string(), "--quiet".to_string(), "--metrics".to_string(), "off".to_string(), root.to_string_lossy().into_owned()],
            &root.to_string_lossy(),
            RunToolOptions { allowed_exit_codes: vec![0, 1], ..Default::default() },
        )
        .await;

    if let Ok(output) = run_result {
        if let Ok(data) = serde_json::from_str::<serde_json::Value>(if output.stdout.trim().is_empty() { "{}" } else { &output.stdout }) {
            let results = data.get("results").and_then(|r| r.as_array()).cloned().unwrap_or_default();
            let mut seen = HashSet::new();
            for r in results {
                let category = r.get("extra").and_then(|e| e.get("metadata")).and_then(|m| m.get("category")).and_then(|c| c.as_str());
                let Some(category) = category.and_then(|c| category_set.get(c)).copied() else { continue };
                let tier_str = r.get("extra").and_then(|e| e.get("metadata")).and_then(|m| m.get("tier")).and_then(|t| t.as_str()).unwrap_or("");
                let tier: &'static str = if tier_str == "strong" { "strong" } else { "weak" };
                let raw_path = r.get("path").and_then(|p| p.as_str()).unwrap_or("");
                let rel_file = relative_to_root(root, raw_path).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
                let line = r.get("start").and_then(|s| s.get("line")).and_then(|l| l.as_i64()).unwrap_or(1).max(1) as usize;
                let key = format!("{category}:{rel_file}:{line}:{tier}");
                if !seen.insert(key) {
                    continue;
                }
                let message = r.get("extra").and_then(|e| e.get("message")).and_then(|m| m.as_str()).unwrap_or(category).to_string();
                let content = std::fs::read_to_string(root.join(&rel_file)).ok();
                let code = content.as_deref().and_then(|c| build_snippet(c, line, SnippetOptions::default()));
                posture.get_mut(category).unwrap().matches.push(PostureMatch { file: rel_file, line, tier, tool: "semgrep", message, code });
            }
        }
    }

    for report in posture.values_mut() {
        report.status = classify_posture_matches(&report.matches);
    }
    Ok(FeaturePostureResult { engine: "semgrep", posture })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    fn runner() -> ToolRunner {
        ToolRunner::new(HashMap::new())
    }

    #[test]
    fn classify_posture_matches_precedence() {
        assert_eq!(classify_posture_matches(&[]), "MISSING");
        let weak_only = vec![PostureMatch { file: "a".into(), line: 1, tier: "weak", tool: "t", message: "m".into(), code: None }];
        assert_eq!(classify_posture_matches(&weak_only), "PARTIAL");
        let with_strong = vec![
            PostureMatch { file: "a".into(), line: 1, tier: "weak", tool: "t", message: "m".into(), code: None },
            PostureMatch { file: "b".into(), line: 1, tier: "strong", tool: "t", message: "m".into(), code: None },
        ];
        assert_eq!(classify_posture_matches(&with_strong), "DETECTED");
    }

    #[test]
    fn fallback_detects_strong_rbac_usage() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("auth.js"), "if (requirePermission('admin')) { doThing(); }\n").unwrap();

        let posture = check_feature_posture_fallback(root, 5 * 1024 * 1024).unwrap();
        assert_eq!(posture["rbac-abac"].status, "DETECTED");
        assert_eq!(posture["sso-saml-oidc"].status, "MISSING");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn fallback_classifies_weak_dependency_only_signal_as_partial() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"dependencies": {"casbin": "^5.0.0"}}"#).unwrap();

        let posture = check_feature_posture_fallback(root, 5 * 1024 * 1024).unwrap();
        assert_eq!(posture["rbac-abac"].status, "PARTIAL");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn fallback_ai_act_transparency_disclosure_is_case_insensitive_free_text() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("chat.tsx"), "const banner = \"You're chatting with an AI assistant\";\n").unwrap();

        let posture = check_feature_posture_fallback(root, 5 * 1024 * 1024).unwrap();
        assert_eq!(posture["ai-act-transparency-disclosure"].status, "DETECTED");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn disabled_config_falls_back_without_probing_semgrep() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("auth.js"), "if (requirePermission('admin')) {}\n").unwrap();

        let config = FeaturePostureConfig { enabled: false, ruleset: String::new(), max_scan_file_bytes: 5 * 1024 * 1024 };
        let result = check_feature_posture(root, &runner(), &config).await.unwrap();
        assert_eq!(result.engine, "fallback");
        assert_eq!(result.posture["rbac-abac"].status, "DETECTED");
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}
