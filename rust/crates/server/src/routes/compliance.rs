//! `GET /api/compliance/audit-pack` — SOC2/ISO27001-style evidence export:
//! pure aggregation over data the rest of this codebase already collects
//! (`overrides` — the change-management audit trail, `issue_first_seen` —
//! already backing SLA-breach math, `campaigns`), no new detection logic
//! and no new scan/check crate. Bundles four things an auditor asks for
//! in one call:
//!
//! - **Overrides in the requested window** — every risk acceptance (who,
//!   what, when, why), the row-level evidence itself.
//! - **MTTR by severity** — a defensible remediation-speed proxy: mean
//!   time from `issue_first_seen` to the override that accepted it. This
//!   measures time-to-formal-risk-acceptance specifically, not "time
//!   until the code was actually fixed" (Ignite doesn't currently record
//!   a distinct fixed-without-override timestamp) — reported as such.
//! - **SLA compliance snapshot** — reuses `list_onboarded_repo_summaries`'s
//!   already-computed `slaBreaches` per repo (a live/point-in-time count,
//!   not itself windowed by `from`/`to` — SOC2 control evidence is
//!   normally "as of report date" for this kind of metric anyway).
//! - **Campaign burndown** — reuses `list_campaigns` as-is.
//!
//! `from`/`to` are `YYYY-MM-DD` query params, defaulting to the last 90
//! days when omitted — a reasonable default reporting window, not a
//! magic compliance number; pass explicit dates for a real audit period.

use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "ok": false, "error": message.into() }))).into_response()
}

#[derive(Deserialize)]
struct AuditPackQuery {
    from: Option<String>,
    to: Option<String>,
}

/// Parses a `YYYY-MM-DD` query param into `(date_string, is_valid)` —
/// returns `None` for a missing/empty param (caller applies the default
/// window) and `Some(Err(..))` for a present-but-unparseable one, so a
/// typo'd date reports a clear 400 instead of silently falling back to
/// the default window.
fn parse_date_param(raw: Option<&str>) -> Result<Option<chrono::NaiveDate>, String> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").map(Some).map_err(|_| format!("Invalid date \"{s}\" — expected YYYY-MM-DD.")),
    }
}

async fn audit_pack(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Query(query): Query<AuditPackQuery>) -> Response {
    let to_date = match parse_date_param(query.to.as_deref()) {
        Ok(d) => d.unwrap_or_else(|| chrono::Utc::now().date_naive()),
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    let from_date = match parse_date_param(query.from.as_deref()) {
        Ok(Some(d)) => d,
        Ok(None) => to_date - chrono::Duration::days(90),
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    if from_date > to_date {
        return err(StatusCode::BAD_REQUEST, "from must not be after to.");
    }

    let from_bound = format!("{} 00:00:00", from_date.format("%Y-%m-%d"));
    let to_bound = format!("{} 23:59:59", to_date.format("%Y-%m-%d"));

    let overrides = state.db.list_overrides_in_range(&from_bound, &to_bound);
    let mut overrides_by_severity: HashMap<String, i64> = HashMap::new();
    for o in &overrides {
        *overrides_by_severity.entry(o.severity.clone()).or_insert(0) += 1;
    }
    let mttr = state.db.mttr_by_severity_in_range(&from_bound, &to_bound);

    let sla = &state.config.sla;
    let repo_summaries = state.db.list_onboarded_repo_summaries(sla.critical_days, sla.high_days, sla.medium_days);
    let total_sla_breaches: i64 = repo_summaries.iter().map(|r| r.sla_breaches).sum();
    let sla_by_repo: Vec<Value> = repo_summaries.iter().filter(|r| r.sla_breaches > 0).map(|r| json!({ "org": r.org, "repo": r.repo, "slaBreaches": r.sla_breaches })).collect();

    let campaigns = state.db.list_campaigns();

    Json(json!({
        "ok": true,
        "period": { "from": from_date.format("%Y-%m-%d").to_string(), "to": to_date.format("%Y-%m-%d").to_string() },
        "overrides": { "total": overrides.len(), "bySeverity": overrides_by_severity, "items": overrides },
        "mttr": {
            "note": "Time from first-detected to override (formal risk acceptance), not time-to-fix — Ignite doesn't currently record a distinct fixed-without-override timestamp.",
            "bySeverity": mttr,
        },
        "slaCompliance": { "totalBreaches": total_sla_breaches, "byRepo": sla_by_repo },
        "campaigns": campaigns,
    }))
    .into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/compliance/audit-pack", get(audit_pack))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state() -> Arc<AppState> {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        std::mem::forget(db_dir);
        Arc::new(AppState {
            runner: state::default_runner(),
            db,
            running_runs: parking_lot::Mutex::new(std::collections::HashMap::new()),
            pending_effectivations: parking_lot::Mutex::new(std::collections::HashMap::new()),
            review_gate: crate::review_gate::ReviewGate::default(),
            llm_config: state::default_llm_config(),
            config: ignite_config::Config::default(),
            package_hallucination_checker: state::default_package_hallucination_checker(),
            fix_pr_previews: parking_lot::Mutex::new(std::collections::HashMap::new()),
            audit_http: reqwest::Client::new(),
        })
    }

    async fn body_json(res: Response) -> Value {
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// A valid `Authorization: Bearer ignite_<key>` header for a freshly
    /// created local user in `state`'s db — `audit_pack` now requires
    /// `RequireAuth`.
    fn auth_header(state: &AppState) -> String {
        let user_id = state.db.create_local_user("tester@example.com", Some("Tester"), "unused-hash");
        let raw_key = ignite_auth::generate_api_key();
        state.db.create_api_key(user_id, &ignite_auth::hash_api_key(&raw_key), None, None, "test");
        format!("Bearer {raw_key}")
    }

    #[tokio::test]
    async fn audit_pack_requires_auth() {
        let app = router().with_state(test_state());
        let res = app.oneshot(Request::get("/api/compliance/audit-pack").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn audit_pack_defaults_to_a_90_day_window_when_no_dates_given() {
        let state = test_state();
        let auth = auth_header(&state);
        let app = router().with_state(state);
        let res = app.oneshot(Request::get("/api/compliance/audit-pack").header("Authorization", auth).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json = body_json(res).await;
        let from = chrono::NaiveDate::parse_from_str(json["period"]["from"].as_str().unwrap(), "%Y-%m-%d").unwrap();
        let to = chrono::NaiveDate::parse_from_str(json["period"]["to"].as_str().unwrap(), "%Y-%m-%d").unwrap();
        assert_eq!((to - from).num_days(), 90);
        assert_eq!(json["overrides"]["total"], 0);
        assert_eq!(json["campaigns"], json!([]));
    }

    #[tokio::test]
    async fn audit_pack_rejects_malformed_date() {
        let state = test_state();
        let auth = auth_header(&state);
        let app = router().with_state(state);
        let res = app.oneshot(Request::get("/api/compliance/audit-pack?from=not-a-date").header("Authorization", auth).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn audit_pack_rejects_from_after_to() {
        let state = test_state();
        let auth = auth_header(&state);
        let app = router().with_state(state);
        let res = app.oneshot(Request::get("/api/compliance/audit-pack?from=2026-06-01&to=2026-01-01").header("Authorization", auth).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn audit_pack_includes_overrides_and_mttr_in_the_requested_window() {
        let state = test_state();
        let project_id = state.db.create_project("job-1", "acme", "widgets", false, "ui", None);
        // `replace_project_issues` seeds `issue_first_seen` (INSERT OR
        // IGNORE, defaulting to `datetime('now')`) the same way a real
        // scan does — the public path, rather than reaching into
        // `db-store`'s private connection from this crate.
        let issue = ignite_db_store::IssueInput {
            id: "secret::a.js::1".to_string(),
            phase: Some(4),
            category: "secret".to_string(),
            severity: "error".to_string(),
            score: Some(9),
            summary: "hardcoded secret".to_string(),
            file: Some("a.js".to_string()),
            line: Some(1),
            snippet: None,
            cross_file: false,
            chain: None,
            cwe: None,
            owasp: None,
            tool: None,
            references: None,
            duplicate_ref: None,
        };
        state.db.replace_project_issues(project_id, &[issue], &std::collections::HashSet::new());
        state.db.add_override(ignite_db_store::AddOverrideArgs { project_id, job_id: "job-1", phase: 4, issue_id: "secret::a.js::1", category: "secret", severity: "error", summary: "hardcoded secret", file: Some("a.js"), line: Some(1), justification: "reviewed", actor_email: "dev@acme.com", actor_name: None, email_sent: false });

        let today = chrono::Utc::now().date_naive();
        let from = (today - chrono::Duration::days(1)).format("%Y-%m-%d").to_string();
        let to = (today + chrono::Duration::days(1)).format("%Y-%m-%d").to_string();

        let auth = auth_header(&state);
        let app = router().with_state(state);
        let res = app.oneshot(Request::get(format!("/api/compliance/audit-pack?from={from}&to={to}")).header("Authorization", auth).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json = body_json(res).await;
        assert_eq!(json["overrides"]["total"], 1);
        assert_eq!(json["overrides"]["bySeverity"]["error"], 1);
        assert_eq!(json["mttr"]["bySeverity"][0]["severity"], "error");
        assert_eq!(json["mttr"]["bySeverity"][0]["overrideCount"], 1);
        // First-seen and override both stamped "now" a moment apart — the
        // exact value isn't deterministic to the millisecond, just that
        // it's a small non-negative number of days.
        let avg = json["mttr"]["bySeverity"][0]["avgDaysToOverride"].as_f64().unwrap();
        assert!((0.0..1.0).contains(&avg), "{avg}");
    }
}
