//! Admin settings for the org daily report (`/api/admin/settings/daily-report`).
//!
//! Values live in `ignite.db`'s `app_settings` table so an operator can
//! change them from the UI without editing `config.json` or restarting.
//! Precedence per key: a non-empty `app_settings` value, else the
//! `dailyReport.*` config value (config.json/env/defaults), so an existing
//! deployment's behavior is unchanged until something is saved here.
//!
//! The webhook token and any URL that can embed a secret (a Logic App
//! trigger URL carries `sig=`, an Azure container URL carries its SAS) are
//! never returned by `GET` — only a redacted form plus a "set" flag — and a
//! `POST` that omits a field leaves it untouched.

use crate::auth::RequireAuth;
use crate::routes::daily_report::{
    build_test_payload, parse_time, post_webhook, put_blob, redact_url, validate_azure_container_url, validate_https_url,
};
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ignite_config::DailyReportConfig;
use ignite_db_store::DbStore;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

pub const KEY_ENABLED: &str = "daily_report_enabled";
pub const KEY_TIME: &str = "daily_report_time";
pub const KEY_TO: &str = "daily_report_to";
pub const KEY_WEBHOOK_URL: &str = "daily_report_webhook_url";
pub const KEY_WEBHOOK_TOKEN: &str = "daily_report_webhook_token";
pub const KEY_AZURE_BLOB_URL: &str = "daily_report_azure_blob_container_url";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Db,
    Config,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Db => "db",
            Source::Config => "config",
        }
    }
}

/// The daily-report settings after applying DB-over-config precedence.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedDailyReport {
    pub enabled: bool,
    pub time: String,
    pub to: String,
    pub webhook_url: String,
    pub webhook_token: String,
    pub azure_blob_container_url: String,
    pub sources: Sources,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sources {
    pub enabled: Source,
    pub time: Source,
    pub to: Source,
    pub webhook_url: Source,
    pub webhook_token: Source,
    pub azure_blob_container_url: Source,
}

fn non_empty(raw: Option<String>) -> Option<String> {
    raw.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Pure resolver: `get` reads an `app_settings` key. `notifications_to` is the
/// last-resort recipient (`notifications.to`) when neither the DB nor
/// `dailyReport.to` names one.
pub fn resolve_with(get: impl Fn(&str) -> Option<String>, cfg: &DailyReportConfig, notifications_to: &str) -> ResolvedDailyReport {
    let pick = |key: &str, from_config: &str| -> (String, Source) {
        match non_empty(get(key)) {
            Some(v) => (v, Source::Db),
            None => (from_config.trim().to_string(), Source::Config),
        }
    };
    // Only "true"/"false" are meaningful; anything else falls through to config.
    let db_enabled = non_empty(get(KEY_ENABLED)).and_then(|v| match v.to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    });
    let (enabled, enabled_src) = match db_enabled {
        Some(v) => (v, Source::Db),
        None => (cfg.enabled, Source::Config),
    };
    let (time, time_src) = pick(KEY_TIME, &cfg.time);
    let (mut to, mut to_src) = pick(KEY_TO, &cfg.to);
    if to.is_empty() {
        to = notifications_to.trim().to_string();
        to_src = Source::Config;
    }
    let (webhook_url, webhook_url_src) = pick(KEY_WEBHOOK_URL, &cfg.webhook_url);
    let (webhook_token, webhook_token_src) = pick(KEY_WEBHOOK_TOKEN, &cfg.webhook_token);
    let (azure_blob_container_url, azure_src) = pick(KEY_AZURE_BLOB_URL, &cfg.azure_blob_container_url);
    ResolvedDailyReport {
        enabled,
        time: if time.is_empty() { "23:59".to_string() } else { time },
        to,
        webhook_url,
        webhook_token,
        azure_blob_container_url,
        sources: Sources { enabled: enabled_src, time: time_src, to: to_src, webhook_url: webhook_url_src, webhook_token: webhook_token_src, azure_blob_container_url: azure_src },
    }
}

pub fn resolve_daily_report_settings(db: &DbStore, cfg: &DailyReportConfig, notifications_to: &str) -> ResolvedDailyReport {
    resolve_with(|k| db.get_setting(k), cfg, notifications_to)
}

fn view(state: &AppState) -> Value {
    let r = resolve_daily_report_settings(&state.db, &state.config.daily_report, &state.config.notifications.to);
    json!({
        "settings": {
            "enabled": r.enabled,
            "time": r.time,
            "to": r.to,
            "webhookUrl": redact_url(&r.webhook_url),
            "webhookUrlSet": !r.webhook_url.is_empty(),
            "webhookTokenSet": !r.webhook_token.is_empty(),
            "azureBlobContainerUrl": redact_url(&r.azure_blob_container_url),
            "azureBlobContainerUrlSet": !r.azure_blob_container_url.is_empty(),
        },
        "sources": {
            "enabled": r.sources.enabled.as_str(),
            "time": r.sources.time.as_str(),
            "to": r.sources.to.as_str(),
            "webhookUrl": r.sources.webhook_url.as_str(),
            "webhookToken": r.sources.webhook_token.as_str(),
            "azureBlobContainerUrl": r.sources.azure_blob_container_url.as_str(),
        },
        "notificationsEnabled": state.config.notifications.enabled,
        "pdfBrowserAvailable": state.runner.binary_for("chrome").is_some(),
    })
}

fn bad_request(message: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message.into() }))).into_response()
}

/// `GET /api/admin/settings/daily-report`
async fn get_settings(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth) -> Response {
    Json(view(&state)).into_response()
}

/// Every field is optional: absent/`null` leaves the stored value alone, an
/// empty string clears it (so the config.json value applies again).
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct SettingsBody {
    enabled: Option<bool>,
    time: Option<String>,
    to: Option<String>,
    webhook_url: Option<String>,
    webhook_token: Option<String>,
    azure_blob_container_url: Option<String>,
}

fn validate_recipients(raw: &str) -> Result<(), String> {
    for addr in raw.split(',').map(str::trim).filter(|a| !a.is_empty()) {
        if !addr.contains('@') || addr.contains(char::is_whitespace) {
            return Err(format!("'{addr}' is not a valid email address."));
        }
    }
    Ok(())
}

/// Validates every provided field, returning the `(key, value)` writes.
/// Nothing is written unless all of them pass.
fn validate_body(body: &SettingsBody) -> Result<Vec<(&'static str, String)>, String> {
    let mut writes = Vec::new();
    if let Some(v) = body.enabled {
        writes.push((KEY_ENABLED, v.to_string()));
    }
    if let Some(v) = &body.time {
        let v = v.trim();
        if !v.is_empty() && parse_time(v).is_none() {
            return Err("Schedule time must be HH:MM (24-hour).".to_string());
        }
        writes.push((KEY_TIME, v.to_string()));
    }
    if let Some(v) = &body.to {
        validate_recipients(v)?;
        writes.push((KEY_TO, v.trim().to_string()));
    }
    if let Some(v) = &body.webhook_url {
        let v = v.trim();
        if !v.is_empty() {
            validate_https_url(v).map_err(|e| format!("Webhook URL: {e}"))?;
        }
        writes.push((KEY_WEBHOOK_URL, v.to_string()));
    }
    if let Some(v) = &body.webhook_token {
        writes.push((KEY_WEBHOOK_TOKEN, v.trim().to_string()));
    }
    if let Some(v) = &body.azure_blob_container_url {
        let v = v.trim();
        if !v.is_empty() {
            validate_azure_container_url(v).map_err(|e| format!("Azure Blob container URL: {e}"))?;
        }
        writes.push((KEY_AZURE_BLOB_URL, v.to_string()));
    }
    Ok(writes)
}

/// `POST /api/admin/settings/daily-report`
async fn save_settings(State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth, Json(body): Json<SettingsBody>) -> Response {
    let writes = match validate_body(&body) {
        Ok(w) => w,
        Err(e) => return bad_request(e),
    };
    let keys: Vec<&str> = writes.iter().map(|(k, _)| *k).collect();
    for (key, value) in &writes {
        state.db.set_setting(key, value);
    }
    // Key names only — values can be secrets.
    tracing::info!(actor = %user.email, keys = ?keys, "daily report settings updated");
    Json(view(&state)).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestBody {
    /// `webhook` or `azure_blob`.
    target: String,
    /// Unsaved form values to probe instead of the stored ones.
    webhook_url: Option<String>,
    webhook_token: Option<String>,
    azure_blob_container_url: Option<String>,
}

/// `POST /api/admin/settings/daily-report/test` — one-shot probe with a
/// sample payload. Uses the values in the body when given (so the form can
/// be tested before saving), else the stored ones. The stored webhook token
/// is only attached when the probed URL is the stored URL: pairing it with
/// a different, caller-supplied URL would hand the secret to that host.
async fn test_connection(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, Json(body): Json<TestBody>) -> Response {
    let stored = resolve_daily_report_settings(&state.db, &state.config.daily_report, &state.config.notifications.to);
    let client = crate::routes::daily_report::delivery_client();
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let result: Result<String, String> = match body.target.trim() {
        "webhook" => {
            let url = non_empty(body.webhook_url.clone()).unwrap_or_else(|| stored.webhook_url.clone());
            if url.is_empty() {
                return bad_request("No webhook URL to test.");
            }
            let token = non_empty(body.webhook_token.clone()).or_else(|| (url == stored.webhook_url && !stored.webhook_token.is_empty()).then(|| stored.webhook_token.clone()));
            match validate_https_url(&url) {
                Err(e) => Err(e),
                Ok(_) => post_webhook(&client, &url, token.as_deref(), &build_test_payload(&timestamp)).await.map(|_| format!("Webhook accepted the test payload ({}).", redact_url(&url))),
            }
        }
        "azure_blob" => {
            let url = non_empty(body.azure_blob_container_url.clone()).unwrap_or_else(|| stored.azure_blob_container_url.clone());
            if url.is_empty() {
                return bad_request("No Azure Blob container URL to test.");
            }
            let name = format!("reports/_ignite-connection-test/ignite-test-{}.json", timestamp.replace(':', "-"));
            let payload = serde_json::to_vec_pretty(&build_test_payload(&timestamp)).unwrap_or_default();
            put_blob(&client, &url, &name, "application/json", payload).await.map(|_| format!("Uploaded {name} to {}.", redact_url(&url)))
        }
        other => return bad_request(format!("Unknown test target '{other}' (use webhook or azure_blob).")),
    };
    match result {
        Ok(message) => Json(json!({ "ok": true, "message": message })).into_response(),
        Err(error) => {
            tracing::warn!(target = %body.target, error = %error, "daily report connection test failed");
            // 200 with ok:false: the probe ran, the remote said no.
            Json(json!({ "ok": false, "error": error })).into_response()
        }
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/admin/settings/daily-report", get(get_settings).post(save_settings))
        .route("/api/admin/settings/daily-report/test", post(test_connection))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn getter<'a>(map: &'a HashMap<&'a str, &'a str>) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| map.get(k).map(|v| v.to_string())
    }

    fn cfg() -> DailyReportConfig {
        DailyReportConfig {
            enabled: true,
            time: "06:30".into(),
            to: "cfg@acme.example".into(),
            webhook_url: "https://cfg.example/hook".into(),
            webhook_token: "cfg-token".into(),
            azure_blob_container_url: "https://acct.blob.core.windows.net/cfg?sig=x".into(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_db_falls_back_to_config_json_values() {
        let map = HashMap::new();
        let r = resolve_with(getter(&map), &cfg(), "notif@acme.example");
        assert!(r.enabled);
        assert_eq!(r.time, "06:30");
        assert_eq!(r.to, "cfg@acme.example");
        assert_eq!(r.webhook_url, "https://cfg.example/hook");
        assert_eq!(r.webhook_token, "cfg-token");
        assert_eq!(r.sources.enabled, Source::Config);
        assert_eq!(r.sources.webhook_url, Source::Config);
    }

    #[test]
    fn db_values_win_and_empty_db_values_do_not() {
        let map: HashMap<&str, &str> = [
            (KEY_ENABLED, "false"),
            (KEY_TIME, "02:15"),
            (KEY_TO, "  "), // blank → config
            (KEY_WEBHOOK_URL, "https://db.example/hook"),
            (KEY_WEBHOOK_TOKEN, ""), // cleared → config
        ]
        .into();
        let r = resolve_with(getter(&map), &cfg(), "notif@acme.example");
        assert!(!r.enabled, "a stored 'false' overrides config's true");
        assert_eq!(r.sources.enabled, Source::Db);
        assert_eq!(r.time, "02:15");
        assert_eq!(r.to, "cfg@acme.example");
        assert_eq!(r.sources.to, Source::Config);
        assert_eq!(r.webhook_url, "https://db.example/hook");
        assert_eq!(r.sources.webhook_url, Source::Db);
        assert_eq!(r.webhook_token, "cfg-token");
        assert_eq!(r.sources.webhook_token, Source::Config);
    }

    #[test]
    fn recipient_falls_back_to_notifications_to_then_defaults() {
        let map = HashMap::new();
        let r = resolve_with(getter(&map), &DailyReportConfig { to: String::new(), time: String::new(), ..Default::default() }, "notif@acme.example");
        assert_eq!(r.to, "notif@acme.example");
        assert_eq!(r.time, "23:59");
        assert!(!r.enabled);
    }

    #[test]
    fn an_unparseable_stored_enabled_flag_is_ignored() {
        let map: HashMap<&str, &str> = [(KEY_ENABLED, "yes")].into();
        assert!(resolve_with(getter(&map), &cfg(), "").enabled);
    }

    #[test]
    fn resolves_against_a_real_db() {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("t.db")).unwrap();
        let c = cfg();
        assert_eq!(resolve_daily_report_settings(&db, &c, "").webhook_url, "https://cfg.example/hook");
        db.set_setting(KEY_WEBHOOK_URL, "https://db.example/hook");
        db.set_setting(KEY_TIME, "01:00");
        let r = resolve_daily_report_settings(&db, &c, "");
        assert_eq!((r.webhook_url.as_str(), r.time.as_str()), ("https://db.example/hook", "01:00"));
        db.set_setting(KEY_WEBHOOK_URL, "");
        assert_eq!(resolve_daily_report_settings(&db, &c, "").webhook_url, "https://cfg.example/hook", "clearing restores the config value");
    }

    #[test]
    fn body_validation_rejects_bad_values_and_writes_nothing_partial() {
        let ok = validate_body(&SettingsBody { enabled: Some(true), time: Some("07:00".into()), webhook_url: Some("https://x.example/h".into()), ..Default::default() }).unwrap();
        assert_eq!(ok.len(), 3);
        assert!(validate_body(&SettingsBody { time: Some("7pm".into()), ..Default::default() }).is_err());
        assert!(validate_body(&SettingsBody { webhook_url: Some("http://x.example/h".into()), ..Default::default() }).is_err());
        assert!(validate_body(&SettingsBody { to: Some("a@x.com, nope".into()), ..Default::default() }).is_err());
        assert!(validate_body(&SettingsBody { azure_blob_container_url: Some("https://acct.blob.core.windows.net/?sig=x".into()), ..Default::default() }).is_err());
        let clear = validate_body(&SettingsBody { webhook_url: Some(String::new()), ..Default::default() }).unwrap();
        assert_eq!(clear, vec![(KEY_WEBHOOK_URL, String::new())], "empty string clears");
        assert!(validate_body(&SettingsBody::default()).unwrap().is_empty(), "absent fields are untouched");
    }
}
