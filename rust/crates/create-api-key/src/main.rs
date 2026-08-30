//! `create-api-key <email> [label]` — faithful port of
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
//!
//! Known gap vs. the Node original: no SMTP transport is wired anywhere in
//! the Rust port yet (see `ignite-notifications`' doc comment) — the
//! owner-notification email is built (`build_api_key_created_email`, so the
//! integration point/content is real and tested) but never actually sent;
//! this binary always reports it as not sent, with that reason, rather than
//! silently pretending to send it.

use std::env;

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

/// Always `sent: false` in this port — see the module doc comment. Kept as
/// a function (rather than inlined in `main`) so the real
/// `build_api_key_created_email` integration point is exercised and
/// tested, not just documented.
pub fn attempt_owner_notification(result: &MintResult, label: Option<&str>) -> (bool, String) {
    let _email = ignite_notifications::build_api_key_created_email(&ignite_notifications::ApiKeyCreatedDetails {
        owner_email: &result.user_email,
        owner_name: result.user_name.as_deref(),
        label,
        created_by: Some(&result.operator),
        created_via: Some("cli"),
    });
    (false, "SMTP transport is not implemented in the Rust port yet".to_string())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let email = match args.get(1) {
        Some(e) => e.clone(),
        None => {
            eprintln!("Usage: create-api-key <email> [label]");
            std::process::exit(1);
        }
    };
    let label = args.get(2).cloned();

    let db_path = env::var("IGNITE_DB_PATH").unwrap_or_else(|_| "ignite.db".to_string());
    let db = ignite_db_store::DbStore::open(std::path::Path::new(&db_path)).expect("failed to open db");

    let operator = default_operator();
    match mint_api_key(&db, &email, label.as_deref(), &operator) {
        Ok(result) => {
            println!("API key #{} created for {email}{}.", result.api_key_id, label.as_deref().map(|l| format!(" ({l})")).unwrap_or_default());
            println!("Recorded created_by={} in the audit log.", result.operator);
            println!();
            println!("{}", result.raw_key);
            println!();
            println!("Store this now — it will not be shown again. Use it as:");
            println!("  Authorization: Bearer {}", result.raw_key);

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
        db.create_local_user("real@example.com", Some("Real User"), "hashed-password");

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
    fn notification_is_honestly_reported_as_not_sent() {
        let (db, _dir) = open_test_db();
        db.create_local_user("owner@example.com", None, "hashed-password");
        let result = mint_api_key(&db, "owner@example.com", None, "test-operator").unwrap();
        let (sent, reason) = attempt_owner_notification(&result, None);
        assert!(!sent);
        assert!(reason.contains("SMTP"));
    }
}
