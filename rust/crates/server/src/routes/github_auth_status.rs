//! `GET /api/admin/settings/github-auth`: which GitHub credential Ignite
//! uses for org-bound work (org discovery, scans, gate statuses) and why.
//!
//! Every answer names where a setting came from: an environment variable
//! (a Kubernetes ConfigMap/Secret, a shell export or `<config dir>/.env`),
//! `config.json`, or a key file path. Nothing here returns a token or any
//! private-key material: for the key it reports only its source and its
//! format (PEM header kind, base64-wrapped, CRLF line endings), which is
//! what tells a broken deployment apart from a working one.
//!
//! `?recheck=1` forgets the App's cached installation lookups first, so a
//! just-installed App shows up without waiting for the cache to expire.

use crate::auth::{GithubTokenSource, RequireAuth};
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/admin/settings/github-auth", get(github_auth_status))
}

#[derive(Debug, Deserialize, Default)]
struct StatusQuery {
    #[serde(default)]
    recheck: Option<String>,
    /// An extra org to check besides the saved ones.
    #[serde(default)]
    org: Option<String>,
}

/// Shape of a private key value, without revealing any of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PemShape {
    RsaPkcs1,
    Pkcs8,
    EncryptedPkcs8,
    OtherPem,
    /// One line with literal `\n` sequences; Ignite turns them into newlines.
    EscapedNewlines,
    /// The PEM itself base64-encoded once more (a Secret value encoded by
    /// hand and then again by Kubernetes/Rancher).
    Base64Pem,
    NotPem,
}

impl PemShape {
    fn code(self) -> &'static str {
        match self {
            PemShape::RsaPkcs1 => "rsa_pkcs1",
            PemShape::Pkcs8 => "pkcs8",
            PemShape::EncryptedPkcs8 => "encrypted_pkcs8",
            PemShape::OtherPem => "other_pem",
            PemShape::EscapedNewlines => "escaped_newlines",
            PemShape::Base64Pem => "base64_pem",
            PemShape::NotPem => "not_pem",
        }
    }

    fn describe(self) -> &'static str {
        match self {
            PemShape::RsaPkcs1 => "PEM, \"BEGIN RSA PRIVATE KEY\" (the format GitHub generates)",
            PemShape::Pkcs8 => "PEM, \"BEGIN PRIVATE KEY\" (PKCS#8)",
            PemShape::EncryptedPkcs8 => "PEM, \"BEGIN ENCRYPTED PRIVATE KEY\": password-protected keys are not supported, use the unencrypted .pem GitHub generated",
            PemShape::OtherPem => "PEM, but not a private key (wrong file?)",
            PemShape::EscapedNewlines => "PEM on one line with literal \\n sequences (converted to newlines)",
            PemShape::Base64Pem => "base64-encoded PEM: the value was encoded twice. Kubernetes/Rancher already base64-encode Secret values, so store the raw .pem contents",
            PemShape::NotPem => "not a PEM: expected the .pem file's text, whose first line is a BEGIN RSA PRIVATE KEY header",
        }
    }
}

/// Classifies a private key value. Looks only at its header and encoding.
pub fn pem_shape(raw: &str) -> PemShape {
    let t = raw.trim_start();
    if let Some(rest) = t.strip_prefix("-----BEGIN ") {
        let single_line = !t.trim_end().contains('\n') && t.contains("\\n");
        return if rest.starts_with("RSA PRIVATE KEY-----") {
            if single_line { PemShape::EscapedNewlines } else { PemShape::RsaPkcs1 }
        } else if rest.starts_with("ENCRYPTED PRIVATE KEY-----") {
            PemShape::EncryptedPkcs8
        } else if rest.starts_with("PRIVATE KEY-----") {
            if single_line { PemShape::EscapedNewlines } else { PemShape::Pkcs8 }
        } else {
            PemShape::OtherPem
        };
    }
    // base64("-----BEGIN ") always starts with this.
    if t.starts_with("LS0tLS1CRUdJTi") {
        return PemShape::Base64Pem;
    }
    PemShape::NotPem
}

/// Whether an environment variable is present at all (even empty: an empty
/// value still overrides config.json).
fn env_present(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Whether `<dir>/.env` assigns `name` (presence only, the value is never read out).
fn dotenv_defines(config_dir: &Path, name: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(config_dir.join(".env")) else { return false };
    text.lines().any(|l| {
        let l = l.trim_start();
        let l = l.strip_prefix("export ").unwrap_or(l).trim_start();
        l.strip_prefix(name).is_some_and(|rest| rest.trim_start().starts_with('='))
    })
}

fn config_dir() -> PathBuf {
    let raw = std::env::var("IGNITE_CONFIG_DIR").map(PathBuf::from).unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
    std::fs::canonicalize(&raw).unwrap_or(raw)
}

fn config_path(dir: &Path) -> PathBuf {
    std::env::var("IGNITE_CONFIG_PATH").map(PathBuf::from).unwrap_or_else(|_| dir.join("config.json"))
}

/// `github.app.<field>` as written in config.json, when non-empty.
fn config_json_app_field(file: &Value, field: &str) -> bool {
    file.pointer(&format!("/github/app/{field}")).and_then(Value::as_str).is_some_and(|v| !v.trim().is_empty())
}

/// Where a `github.app.*` value came from, following `ignite-config`'s rule
/// that an env var (even an empty one) overrides config.json.
fn value_origin(env_name: &str, config_field: &str, file: &Value, dir: &Path, config_file: &Path) -> (String, bool) {
    match env_present(env_name) {
        Some(v) => {
            let mut s = format!("environment variable {env_name}");
            if v.trim().is_empty() {
                s.push_str(" (set but EMPTY, which overrides config.json; remove it or give it a value)");
            } else if dotenv_defines(dir, env_name) {
                s.push_str(&format!(" (also assigned in {}; a variable already in the process environment wins)", dir.join(".env").display()));
            } else {
                s.push_str(" (process environment: Kubernetes env/ConfigMap/Secret, shell export, or launchd/systemd unit)");
            }
            (s, !v.trim().is_empty())
        }
        None if config_json_app_field(file, config_field) => (format!("{} → github.app.{config_field}", config_file.display()), true),
        None => (format!("not set (no {env_name} env var, no github.app.{config_field} in {})", config_file.display()), false),
    }
}

fn source_code(s: GithubTokenSource) -> &'static str {
    match s {
        GithubTokenSource::ApiKey => "api_key",
        GithubTokenSource::GithubApp => "github_app",
        GithubTokenSource::UserConnection => "user_connection",
        GithubTokenSource::ServerEnv => "server_env",
    }
}

async fn github_auth_status(State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth, headers: HeaderMap, Query(q): Query<StatusQuery>) -> Response {
    let dir = config_dir();
    let cfg_file = config_path(&dir);
    let file: Value = std::fs::read_to_string(&cfg_file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let app_cfg = &state.config.github.app;

    // ---- GitHub App ----
    let (id_origin, id_set) = value_origin("GITHUB_APP_ID", "appId", &file, &dir, &cfg_file);
    let (key_origin, key_shape, key_crlf, key_path) = if !app_cfg.private_key.trim().is_empty() {
        let (origin, _) = value_origin("GITHUB_APP_PRIVATE_KEY", "privateKey", &file, &dir, &cfg_file);
        (origin, Some(pem_shape(&app_cfg.private_key)), app_cfg.private_key.contains('\r'), None)
    } else if !app_cfg.private_key_path.trim().is_empty() {
        let (origin, _) = value_origin("GITHUB_APP_PRIVATE_KEY_PATH", "privateKeyPath", &file, &dir, &cfg_file);
        let path = app_cfg.private_key_path.clone();
        let (shape, crlf, readable) = match std::fs::read_to_string(&path) {
            Ok(text) => (Some(pem_shape(&text)), text.contains('\r'), Ok(())),
            Err(e) => (None, false, Err(e.to_string())),
        };
        let file_state = match readable {
            Ok(()) => json!({ "path": path, "readable": true }),
            Err(e) => json!({ "path": path, "readable": false, "error": e }),
        };
        (format!("key file, path from {origin}"), shape, crlf, Some(file_state))
    } else {
        ("not set (no GITHUB_APP_PRIVATE_KEY / GITHUB_APP_PRIVATE_KEY_PATH env var, no github.app.privateKey / privateKeyPath in config.json)".to_string(), None, false, None)
    };
    let current_build = crate::state::build_github_app(&state.config);
    let build_error = current_build.as_ref().err().cloned();
    let loaded = state.github_app.is_some();
    let mut app_reasons: Vec<String> = Vec::new();
    if !id_set {
        app_reasons.push(format!("No App ID: {id_origin}. Without an App ID the App is ignored, even if a key is present."));
    } else if let Some(e) = &build_error {
        app_reasons.push(format!("App ID found ({id_origin}) but the App could not be built: {e}"));
    } else {
        app_reasons.push(format!("App ID {} from {id_origin}.", app_cfg.app_id.trim()));
        app_reasons.push(format!("Private key from {key_origin}."));
    }
    if let Some(shape) = key_shape {
        app_reasons.push(format!("Key format: {}.", shape.describe()));
    }
    if key_crlf {
        app_reasons.push("Key has Windows (CRLF) line endings; if it fails to parse, convert it with dos2unix.".to_string());
    }
    let restart_needed = id_set && build_error.is_none() && !loaded;
    if restart_needed {
        app_reasons.push("The configuration is valid now but the running server started without the App: restart the server/pod.".to_string());
    }

    let app = state.github_app.clone();
    if let Some(app) = &app {
        if q.recheck.as_deref().is_some_and(|v| v == "1" || v == "true") {
            app.clear_cache();
        }
    }
    let github_check = match &app {
        Some(app) => match app.app_info().await {
            Ok(info) => json!({
                "ok": true,
                "slug": info.get("slug"),
                "name": info.get("name"),
                "htmlUrl": info.get("html_url"),
                "permissions": info.get("permissions"),
            }),
            Err(e) => {
                let text = e.to_string();
                let hint = if text.contains("HTTP 401") {
                    " GitHub rejected the App JWT: the private key doesn't belong to this App ID, or the server clock is off by more than a minute."
                } else {
                    ""
                };
                json!({ "ok": false, "error": format!("{text}{hint}") })
            }
        },
        None => Value::Null,
    };

    // ---- Other sources ----
    let connection = state.db.get_github_connection(user.id);
    let user_connection = json!({
        "connected": connection.is_some(),
        "login": connection.as_ref().map(|c| c.github_login.clone()),
        "scope": connection.as_ref().and_then(|c| c.scope.clone()),
        "connectedAt": connection.as_ref().map(|c| c.connected_at.clone()),
    });
    let env_var = ["GH_TOKEN", "GITHUB_TOKEN"].into_iter().find(|n| std::env::var(n).is_ok_and(|v| !v.is_empty()));
    let api_key_token = crate::auth::resolve_effective_github_token_with_source(&headers, &state.db).is_some_and(|(_, s)| s == GithubTokenSource::ApiKey);
    let fallback = crate::auth::resolve_effective_github_token_with_source(&headers, &state.db).map(|(_, s)| s);
    let fallback_reason = |s: Option<GithubTokenSource>| -> String {
        match s {
            Some(GithubTokenSource::ApiKey) => "the GitHub token bound to the API key making this request".to_string(),
            Some(GithubTokenSource::UserConnection) => format!(
                "your connected GitHub account{} (an OAuth token: in a SAML SSO org it only works while you have an active SSO session, which is what the \"GitHub SSO authorization needed\" message means)",
                connection.as_ref().map(|c| format!(" @{}", c.github_login)).unwrap_or_default()
            ),
            Some(GithubTokenSource::ServerEnv) => format!("the server's {} environment variable", env_var.unwrap_or("GH_TOKEN")),
            _ => "nothing: no token is available".to_string(),
        }
    };

    // ---- Per org ----
    let mut orgs: Vec<String> = state.db.list_saved_orgs();
    if let Some(extra) = q.org.as_deref().map(str::trim).filter(|o| ignite_github_api::is_valid_github_owner(o)) {
        if !orgs.iter().any(|o| o.eq_ignore_ascii_case(extra)) {
            orgs.push(extra.to_string());
        }
    }
    let mut org_rows = Vec::new();
    for org in &orgs {
        let (app_status, app_error) = match &app {
            None => ("not_configured", None),
            Some(app) => match app.installation_token(org).await {
                Ok(Some(_)) => ("installed", None),
                Ok(None) => ("not_installed", None),
                Err(e) => ("error", Some(e.to_string())),
            },
        };
        let (effective, why) = if api_key_token {
            (Some(GithubTokenSource::ApiKey), "The request is authenticated by an API key with its own bound GitHub token, which always wins.".to_string())
        } else {
            match app_status {
                "installed" => (Some(GithubTokenSource::GithubApp), format!("The GitHub App is installed on {org}, so its installation token is used. Not tied to a person or an SSO session.")),
                "not_installed" => (fallback, format!("The GitHub App is configured but not installed on {org} (checked orgs/{org}/installation and users/{org}/installation), so Ignite falls back to {}. Install the App on {org} to fix it.", fallback_reason(fallback))),
                "error" => (fallback, format!("The GitHub App could not mint a token for {org} ({}), so Ignite falls back to {}.", app_error.clone().unwrap_or_default(), fallback_reason(fallback))),
                _ => (fallback, format!("No GitHub App is active on this server, so Ignite uses {}.", fallback_reason(fallback))),
            }
        };
        org_rows.push(json!({
            "org": org,
            "app": app_status,
            "appError": app_error,
            "effective": effective.map(source_code),
            "why": why,
        }));
    }

    Json(json!({
        "precedence": [
            "API key's bound GitHub token (only for requests made with that key)",
            "GitHub App installation token (when the App is installed on the org)",
            "Your connected GitHub account (OAuth; SAML SSO session required)",
            "Server GH_TOKEN / GITHUB_TOKEN",
        ],
        "configDir": dir.display().to_string(),
        "configFile": cfg_file.display().to_string(),
        "configFileFound": cfg_file.is_file(),
        "app": {
            "configured": id_set,
            "loaded": loaded,
            "restartNeeded": restart_needed,
            "appId": id_set.then(|| app_cfg.app_id.trim().to_string()),
            "appIdSource": id_origin,
            "keySource": key_origin,
            "keyFormat": key_shape.map(PemShape::code),
            "keyFormatDescription": key_shape.map(PemShape::describe),
            "keyHasCrlf": key_crlf,
            "keyFile": key_path,
            "error": build_error,
            "github": github_check,
            "reasons": app_reasons,
        },
        "userConnection": user_connection,
        "apiKeyBoundToken": api_key_token,
        "serverEnvToken": { "set": env_var.is_some(), "var": env_var },
        "fallback": fallback.map(source_code),
        "fallbackDescription": fallback_reason(fallback),
        "orgs": org_rows,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PEM-shaped fixture with a dummy body, assembled at runtime so the
    /// source holds no literal key header for a secret scanner to flag.
    fn pem(label: &str, sep: &str) -> String {
        let dashes = "-".repeat(5);
        format!("{dashes}BEGIN {label}{dashes}{sep}MIIE{sep}{dashes}END {label}{dashes}{sep}")
    }

    #[test]
    fn classifies_key_formats_without_reading_the_key() {
        assert_eq!(pem_shape(&pem("RSA PRIVATE KEY", "\n")), PemShape::RsaPkcs1);
        assert_eq!(pem_shape(&format!("  {}", pem("PRIVATE KEY", "\n"))), PemShape::Pkcs8);
        assert_eq!(pem_shape(&pem("RSA PRIVATE KEY", "\\n")), PemShape::EscapedNewlines);
        assert_eq!(pem_shape(&pem("ENCRYPTED PRIVATE KEY", "\n")), PemShape::EncryptedPkcs8);
        assert_eq!(pem_shape(&pem("CERTIFICATE", "\n")), PemShape::OtherPem);
        assert_eq!(pem_shape("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQo="), PemShape::Base64Pem);
        assert_eq!(pem_shape("hello"), PemShape::NotPem);
    }

    #[test]
    fn dotenv_presence_ignores_other_names_and_reads_no_values() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "# x\nexport GITHUB_APP_ID=1\nGITHUB_APP_ID_OTHER=2\n").unwrap();
        assert!(dotenv_defines(dir.path(), "GITHUB_APP_ID"));
        assert!(!dotenv_defines(dir.path(), "GITHUB_APP_PRIVATE_KEY"));
        assert!(!dotenv_defines(dir.path(), "GITHUB_APP"));
    }
}
