//! `create-api-key <email> [label] [--github-token-env VAR] [--scopes a,b]` — faithful port of
//! `scripts/create-api-key.js`: mints a headless API key for an *existing*
//! Ignite user (never creates accounts), printed exactly once. Only its
//! SHA-256 hash (`ignite_auth::hash_api_key`) is stored, so it can never be
//! recovered or displayed again after this.
//!
//! Every mint is attributed to the operator running this binary
//! (`api_keys.created_by`, resolved from `IGNITE_OPERATOR` or
//! `$USER@$(hostname)`) — this proves the account exists, not that the
//! operator owns it, so attribution + a best-effort owner notification are
//! how a misuse becomes noticeable after the fact (same reasoning as the
//! Node original's doc comment).
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use std::env;

#[derive(Debug, PartialEq, Eq)]
pub struct CliArgs {
    pub email: String,
    pub label: Option<String>,
    /// Name of an env var holding a GitHub token to bind to the new key. The
    /// token itself is never taken from argv (it would land in shell history
    /// and `ps` output).
    pub github_token_env: Option<String>,
    /// Limits the key to a subset of `scan`, `override`, `publish`. `None`
    /// (the default) mints an unrestricted key, exactly as before.
    pub scopes: Option<Vec<String>>,
}

const USAGE: &str = "Usage: create-api-key <email> [label] [--github-token-env VAR] [--scopes scan,override,publish]";

pub fn parse_args(args: &[String]) -> Result<CliArgs, String> {
    let mut positional: Vec<&String> = Vec::new();
    let mut github_token_env = None;
    let mut scopes = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--scopes" {
            let raw = iter.next().filter(|n| !n.starts_with("--")).ok_or_else(|| format!("--scopes needs a comma-separated list.\n{USAGE}"))?;
            scopes = Some(ignite_db_store::parse_api_key_scopes(raw)?);
        } else if arg == "--github-token-env" {
            let name = iter.next().filter(|n| !n.starts_with("--")).ok_or_else(|| format!("--github-token-env needs an env var name.\n{USAGE}"))?;
            github_token_env = Some(name.clone());
        } else if arg.starts_with("--") {
            return Err(format!("Unknown option {arg}.\n{USAGE}"));
        } else {
            positional.push(arg);
        }
    }
    let email = positional.first().ok_or_else(|| USAGE.to_string())?.to_string();
    if positional.len() > 2 {
        return Err(format!("Too many arguments.\n{USAGE}"));
    }
    Ok(CliArgs { email, label: positional.get(1).map(|l| l.to_string()), github_token_env, scopes })
}

/// Reads the token out of the named env var and binds it to the key. Errors
/// (rather than silently minting an unbound key) when the var is unset/empty,
/// so a misconfigured provisioning script fails loudly.
pub fn bind_github_token_from_env(db: &ignite_db_store::DbStore, api_key_id: i64, env_var: &str) -> Result<(), String> {
    let token = env::var(env_var).map_err(|_| format!("Env var {env_var} is not set — key #{api_key_id} was created WITHOUT a bound GitHub token."))?;
    let token = token.trim();
    if token.is_empty() {
        return Err(format!("Env var {env_var} is empty — key #{api_key_id} was created WITHOUT a bound GitHub token."));
    }
    db.set_api_key_github_token(api_key_id, Some(token));
    Ok(())
}

#[derive(Debug)]
pub struct MintResult {
    pub api_key_id: i64,
    pub raw_key: String,
    pub operator: String,
    pub user_email: String,
    pub user_name: Option<String>,
}

pub fn default_operator() -> String {
    if let Ok(v) = env::var("IGNITE_OPERATOR") {
        if !v.is_empty() {
            return v;
        }
    }
    let user = env::var("USER").or_else(|_| env::var("USERNAME")).unwrap_or_else(|_| "unknown".to_string());
    let host = env::var("HOSTNAME")
        .ok()
        .or_else(|| std::process::Command::new("hostname").output().ok().and_then(|o| String::from_utf8(o.stdout).ok()).map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-host".to_string());
    format!("{user}@{host}")
}

pub fn mint_api_key(db: &ignite_db_store::DbStore, email: &str, label: Option<&str>, operator: &str) -> Result<MintResult, String> {
    let user = db
        .get_user_by_email(email)
        .ok_or_else(|| format!("No Ignite user found for \"{email}\". Log in via the web UI at least once first."))?;
    let raw_key = ignite_auth::generate_api_key();
    let hash = ignite_auth::hash_api_key(&raw_key);
    let api_key_id = db.create_api_key(user.id, &hash, label, Some(operator), "cli");
    Ok(MintResult { api_key_id, raw_key, operator: operator.to_string(), user_email: user.email, user_name: user.name })
}

/// Best-effort owner notification — a flaky SMTP endpoint must not fail
/// key creation, matching Node's own `sendApiKeyCreatedNotification`'s
/// try/catch pattern. Uses a short-lived tokio runtime (same pattern as
/// `emit_audit_event_blocking`) since this is a synchronous CLI binary.
pub fn attempt_owner_notification(result: &MintResult, label: Option<&str>) -> (bool, String) {
    let config_dir = std::env::var("IGNITE_CONFIG_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
    let config = match ignite_config::load_config(&config_dir) {
        Ok(c) => c,
        Err(e) => {
            return (false, format!("could not load config: {e}"));
        }
    };
    let details = ignite_notifications::ApiKeyCreatedDetails {
        owner_email: &result.user_email,
        owner_name: result.user_name.as_deref(),
        label,
        created_by: Some(&result.operator),
        created_via: Some("cli"),
    };
    let Ok(rt) = tokio::runtime::Runtime::new() else {
        return (false, "could not create tokio runtime".to_string());
    };
    match rt.block_on(ignite_notifications::send_api_key_created_notification(
        &config.notifications,
        &details,
    )) {
        Ok(r) if r.sent => (true, r.to.unwrap_or_default()),
        Ok(r) => (false, r.reason.unwrap_or_else(|| "unknown".to_string())),
        Err(e) => (false, format!("email send failed: {e}")),
    }
}

/// GHAS-parity audit-log emission (Milestone 3.3): this is a synchronous,
/// short-lived CLI (unlike the server, which fires audit events off a
/// long-lived tokio runtime), so this spins up a throwaway runtime and
/// blocks on the dispatch rather than the fire-and-forget `tokio::spawn`
/// the server uses — correctness (the mint output is already printed
/// before this runs) matters more than shaving a network round-trip off a
/// one-shot operator command.
///
/// The local durable-audit-trail write (`db.record_audit_event`) always
/// happens, same posture as `AppState::emit_audit_event` — a GxP
/// deployment's local trail can't depend on a SIEM sink being configured.
/// Only the external sink dispatch below stays gated on
/// `audit_log.enabled`/sinks being configured.
fn emit_audit_event_blocking(db: &ignite_db_store::DbStore, result: &MintResult, github_token_bound: bool, scopes: Option<&[String]>) {
    // Only *whether* a token was bound is recorded — never the token.
    if let Err(e) = db.record_audit_event("api_key.created", "warning", &format!("headless API key created for {}", result.user_email), Some(&result.operator), None, None, Some(&serde_json::json!({ "apiKeyId": result.api_key_id, "githubTokenBound": github_token_bound, "scopes": scopes }).to_string())) {
        eprintln!("Warning: could not write local audit-trail record for this key creation ({e}).");
    }

    let config_dir = env::var("IGNITE_CONFIG_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
    let config = match ignite_config::load_config(&config_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: could not load config from {} ({e}) — SIEM audit-log dispatch for this key creation was skipped. Set IGNITE_CONFIG_DIR or run from the config directory.", config_dir.display());
            return;
        }
    };
    if !config.audit_log.enabled || config.audit_log.sinks.is_empty() {
        return;
    }
    let sinks: Vec<ignite_audit_log::AuditSink> = config
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
    let event = ignite_audit_log::AuditEvent::new("api_key.created", "warning", format!("headless API key created for {}", result.user_email))
        .actor(result.operator.clone())
        .metadata(serde_json::json!({ "apiKeyId": result.api_key_id, "githubTokenBound": github_token_bound, "scopes": scopes }));
    let Ok(rt) = tokio::runtime::Runtime::new() else { return };
    rt.block_on(async {
        let http = reqwest::Client::new();
        ignite_audit_log::dispatch(&http, &sinks, &event).await;
    });
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let cli = match parse_args(&args) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };
    let (email, label) = (cli.email.clone(), cli.label.clone());

    let db_path = env::var("IGNITE_DB_PATH").unwrap_or_else(|_| "ignite.db".to_string());
    let db = ignite_db_store::DbStore::open(std::path::Path::new(&db_path)).expect("failed to open db");

    let operator = default_operator();
    match mint_api_key(&db, &email, label.as_deref(), &operator) {
        Ok(result) => {
            if let Some(scopes) = &cli.scopes {
                db.set_api_key_scopes(result.api_key_id, Some(scopes));
            }
            let mut github_token_bound = false;
            if let Some(var) = &cli.github_token_env {
                match bind_github_token_from_env(&db, result.api_key_id, var) {
                    Ok(()) => github_token_bound = true,
                    Err(msg) => eprintln!("Warning: {msg}"),
                }
            }
            println!("API key #{} created for {email}{}.", result.api_key_id, label.as_deref().map(|l| format!(" ({l})")).unwrap_or_default());
            println!("Recorded created_by={} in the audit log.", result.operator);
            match &cli.scopes {
                Some(scopes) => println!("Limited to scopes: {} (everything else is refused with 403 scope_denied).", scopes.join(", ")),
                None => println!("Unrestricted: this key can scan, override and publish. Use --scopes to limit it."),
            }
            if github_token_bound {
                println!("Bound a GitHub token to this key: publishes made with it push as that token's identity.");
            }
            println!();
            println!("{}", result.raw_key);
            println!();
            println!("Store this now — it will not be shown again. Use it as:");
            println!("  Authorization: Bearer {}", result.raw_key);

            emit_audit_event_blocking(&db, &result, github_token_bound, cli.scopes.as_deref());

            let (sent, reason) = attempt_owner_notification(&result, label.as_deref());
            if sent {
                println!("Notified {} that this key was created.", result.user_email);
            } else {
                println!("Owner notification not sent ({reason}).");
            }
        }
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_db() -> (ignite_db_store::DbStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&dir.path().join("test.db")).unwrap();
        (db, dir)
    }

    #[test]
    fn mint_fails_for_unknown_email() {
        let (db, _dir) = open_test_db();
        let err = mint_api_key(&db, "nobody@example.com", None, "test-operator").unwrap_err();
        assert!(err.contains("No Ignite user found"));
    }

    #[test]
    fn mint_succeeds_for_existing_user_and_key_authenticates() {
        let (db, _dir) = open_test_db();
        db.create_local_user("real@example.com", Some("Real User"), "hashed-password").unwrap();

        let result = mint_api_key(&db, "real@example.com", Some("ci-bot"), "test-operator@host").unwrap();
        assert!(result.raw_key.starts_with("ignite_"));
        assert_eq!(result.user_email, "real@example.com");
        assert_eq!(result.user_name.as_deref(), Some("Real User"));

        // The raw key must actually authenticate — same hash scheme the
        // server-side API-key auth path (crate::auth) already verifies
        // against.
        let hash = ignite_auth::hash_api_key(&result.raw_key);
        let identity = db.get_active_api_key_by_hash(&hash).expect("minted key should be active and lookup-able by its hash");
        assert_eq!(identity.user_id, db.get_user_by_email("real@example.com").unwrap().id);
    }

    #[test]
    fn default_operator_prefers_ignite_operator_env_var() {
        std::env::set_var("IGNITE_OPERATOR", "ci@pipeline");
        assert_eq!(default_operator(), "ci@pipeline");
        std::env::remove_var("IGNITE_OPERATOR");
    }

    #[test]
    fn notification_reports_not_sent_when_notifications_disabled() {
        let (db, _dir) = open_test_db();
        db.create_local_user("owner@example.com", None, "hashed-password").unwrap();
        let result = mint_api_key(&db, "owner@example.com", None, "test-operator").unwrap();
        let (sent, _reason) = attempt_owner_notification(&result, None);
        // With no config.json in the test working directory, notifications
        // default to disabled — the email should not be sent, but this is
        // now a config/runtime reason, not a hardcoded "not implemented".
        assert!(!sent);
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_args_accepts_email_label_and_token_env_in_any_order() {
        let a = parse_args(&args(&["a@b.com", "ci", "--github-token-env", "MY_PAT"])).unwrap();
        assert_eq!(a, CliArgs { email: "a@b.com".into(), label: Some("ci".into()), github_token_env: Some("MY_PAT".into()), scopes: None });
        let b = parse_args(&args(&["--github-token-env", "MY_PAT", "a@b.com"])).unwrap();
        assert_eq!(b, CliArgs { email: "a@b.com".into(), label: None, github_token_env: Some("MY_PAT".into()), scopes: None });
    }

    #[test]
    fn parse_args_rejects_missing_email_unknown_flags_and_a_dangling_token_flag() {
        assert!(parse_args(&args(&[])).is_err());
        assert!(parse_args(&args(&["a@b.com", "--nope"])).is_err());
        assert!(parse_args(&args(&["a@b.com", "--github-token-env"])).is_err());
        // A raw token on argv is never accepted.
        assert!(parse_args(&args(&["a@b.com", "--github-token", "ghp_x"])).is_err());
    }

    #[test]
    fn bind_github_token_from_env_stores_it_and_fails_loudly_when_unset() {
        let (db, _dir) = open_test_db();
        db.create_local_user("agent@example.com", Some("Agent"), "hashed-password").unwrap();
        let result = mint_api_key(&db, "agent@example.com", None, "op").unwrap();
        let hash = ignite_auth::hash_api_key(&result.raw_key);

        std::env::remove_var("IGNITE_TEST_UNSET_PAT");
        assert!(bind_github_token_from_env(&db, result.api_key_id, "IGNITE_TEST_UNSET_PAT").is_err());
        assert_eq!(db.get_active_api_key_github_token(&hash), None);

        std::env::set_var("IGNITE_TEST_BOUND_PAT", " ghp_agent \n");
        bind_github_token_from_env(&db, result.api_key_id, "IGNITE_TEST_BOUND_PAT").unwrap();
        std::env::remove_var("IGNITE_TEST_BOUND_PAT");
        assert_eq!(db.get_active_api_key_github_token(&hash).as_deref(), Some("ghp_agent"));
    }

    #[test]
    fn scopes_flag_is_validated_before_anything_is_minted() {
        let a = parse_args(&args(&["a@b.com", "--scopes", "scan, override"])).unwrap();
        assert_eq!(a.scopes, Some(vec!["scan".to_string(), "override".to_string()]));
        assert_eq!(parse_args(&args(&["a@b.com"])).unwrap().scopes, None, "no flag = unrestricted, as before");
        // A typo must fail here rather than mint a key that is less limited than intended.
        assert!(parse_args(&args(&["a@b.com", "--scopes", "scan,publsh"])).is_err());
        assert!(parse_args(&args(&["a@b.com", "--scopes"])).is_err());
    }
}
