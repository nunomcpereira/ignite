//! Per-org scheduled findings email, configured only in `config.json`:
//!
//! ```json
//! "orgReports": {
//!   "my-org":  { "cron": "0 8 * * MON", "recipients": "admins", "to": ["sec-team@x.com"] },
//!   "sap-*":   { "cron": "0 7 * * *",   "recipients": "fixed",  "to": ["sap-dl@x.com"] },
//!   "old-org": { "enabled": false }
//! }
//! ```
//!
//! When an org's cron fires, its daily-report email (latest scan per repo,
//! unjustified findings only — the same report as `daily_report.rs`) goes
//! either to the org's **GitHub owners** (`"admins"`, the default: members
//! with `role=admin`, each owner's public profile email, falling back to `to`
//! when none can be found) or only to the fixed distribution lists in `to`
//! (`"fixed"`). Org keys are case-insensitive; a `*` key applies to every org
//! saved in the GitHub Org view that it matches, and an exact key wins.
//!
//! Cron expressions are evaluated in the server's local time zone (same as
//! `dailyReport.time`): 5 fields (`min hour dom month dow`) or 6 with leading
//! seconds. Occurrences before the server started are never sent
//! retroactively; one missed while running is sent once on the next tick.
//! The last attempt per org is kept in `org_report_runs`.

use crate::auth::RequireAuth;
use crate::routes::daily_report::{run_daily_report, Channel, RunOptions};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use croner::Cron;
use ignite_config::OrgReportRecipients;
use once_cell::sync::Lazy;
use serde::Serialize;
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const TICK: Duration = Duration::from_secs(60);
const DB_TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

pub const SOURCE_GITHUB_OWNERS: &str = "github_admins";
pub const SOURCE_FALLBACK: &str = "fallback";
pub const SOURCE_FIXED: &str = "fixed";

/// Occurrences before this process started are never sent retroactively.
static STARTED_AT: Lazy<DateTime<Utc>> = Lazy::new(Utc::now);

/// One org's `orgReports` entry, with `to` normalized.
#[derive(Debug, Clone)]
pub struct OrgSchedule {
    pub enabled: bool,
    pub cron: String,
    pub recipients: OrgReportRecipients,
    pub to: Vec<String>,
    /// Set when an entry in `to` isn't a valid email (that entry is dropped).
    pub to_error: Option<String>,
}

fn mode_str(m: OrgReportRecipients) -> &'static str {
    match m {
        OrgReportRecipients::Admins => "admins",
        OrgReportRecipients::Fixed => "fixed",
    }
}

pub fn org_schedule(state: &AppState, org: &str) -> Option<OrgSchedule> {
    let c = state.config.org_report_for(org)?;
    let mut to = Vec::new();
    let mut to_error = None;
    for entry in &c.to {
        match parse_email_list(entry) {
            Ok(list) => to.extend(list),
            Err(e) => to_error = Some(e),
        }
    }
    to.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    Some(OrgSchedule { enabled: c.enabled, cron: c.cron.clone(), recipients: c.recipients, to, to_error })
}

/// Orgs an `orgReports` key can apply to: exact keys, plus every org saved
/// in the GitHub Org view (for wildcard keys). Lowercased, deduplicated.
fn candidate_orgs(state: &AppState) -> Vec<String> {
    let mut orgs: Vec<String> = state.config.org_reports.keys().filter(|k| !k.contains('*')).map(|k| k.trim().to_ascii_lowercase()).collect();
    if state.config.org_reports.keys().any(|k| k.contains('*')) {
        orgs.extend(state.db.list_saved_orgs());
    }
    orgs.sort();
    orgs.dedup();
    orgs.retain(|o| state.config.org_report_for(o).is_some());
    orgs
}

/// Parses a cron expression (5 or 6 fields).
pub fn parse_cron(expr: &str) -> Result<Cron, String> {
    let expr = expr.trim();
    if expr.is_empty() {
        return Err("cron expression is empty".to_string());
    }
    Cron::from_str(expr).map_err(|e| format!("invalid cron expression {expr:?}: {e}"))
}

fn parse_db_time(raw: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(raw, DB_TIME_FORMAT).ok().map(|n| Utc.from_utc_datetime(&n))
}

fn db_time(t: DateTime<Utc>) -> String {
    t.format(DB_TIME_FORMAT).to_string()
}

/// Next occurrence strictly after `after`.
pub fn next_occurrence(cron: &Cron, after: DateTime<Local>) -> Option<DateTime<Local>> {
    cron.find_next_occurrence(&after, false).ok()
}

/// True when the most recent occurrence at or before `now` is later than both
/// the last send and `not_before`.
pub fn is_due(cron: &Cron, now: DateTime<Local>, last_run_at: Option<DateTime<Utc>>, not_before: Option<DateTime<Utc>>) -> bool {
    let Ok(prev) = cron.find_previous_occurrence(&now, true) else { return false };
    let prev = prev.with_timezone(&Utc);
    let floor = [last_run_at, not_before].into_iter().flatten().max();
    floor.is_none_or(|f| prev > f)
}

/// Comma/semicolon/whitespace-separated list → trimmed, deduplicated
/// (case-insensitive) emails. Errors on anything that isn't `x@y`.
pub fn parse_email_list(raw: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for e in raw.split([',', ';', ' ', '\n', '\t']).map(str::trim).filter(|e| !e.is_empty()) {
        let valid = e.split_once('@').is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.'));
        if !valid {
            return Err(format!("invalid email address {e:?}"));
        }
        if !out.iter().any(|x| x.eq_ignore_ascii_case(e)) {
            out.push(e.to_string());
        }
    }
    Ok(out)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerInfo {
    login: String,
    email: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedRecipients {
    pub recipients: Vec<String>,
    /// `github_admins`, `fallback`, or `none` when neither yielded anyone.
    pub source: &'static str,
    owners: Vec<OwnerInfo>,
    /// Why the owners weren't used, when they weren't.
    pub note: Option<String>,
}

/// `Fixed`: the `to` list. `Admins`: the GitHub owners' public emails, else
/// the `to` list as fallback.
pub async fn resolve_recipients(state: &AppState, headers: &HeaderMap, org: &str, mode: OrgReportRecipients, to: &[String]) -> ResolvedRecipients {
    if mode == OrgReportRecipients::Fixed {
        let source = if to.is_empty() { "none" } else { SOURCE_FIXED };
        let note = to.is_empty().then(|| "no fixed recipients configured".to_string());
        return ResolvedRecipients { recipients: to.to_vec(), source, owners: Vec::new(), note };
    }
    let token = crate::auth::github_token_for_owner(state, headers, org).await;
    let (owners, note) = if token.is_empty() {
        (Vec::new(), Some("no GitHub token available to list the org owners".to_string()))
    } else {
        match ignite_github_api::GithubApi::new(&state.runner).gh_list_org_owner_emails(org, &token).await {
            Ok(list) => {
                let note = if list.is_empty() {
                    Some("GitHub returned no owners for this org".to_string())
                } else if list.iter().all(|(_, e)| e.is_none()) {
                    Some(format!("none of the {} org owner(s) has a public email on GitHub", list.len()))
                } else {
                    None
                };
                (list.into_iter().map(|(login, email)| OwnerInfo { login, email }).collect(), note)
            }
            Err(e) => (Vec::new(), Some(format!("could not list org owners: {}", one_line(&e.to_string())))),
        }
    };
    let mut owner_emails: Vec<String> = Vec::new();
    for e in owners.iter().filter_map(|o| o.email.as_deref()) {
        if !owner_emails.iter().any(|x| x.eq_ignore_ascii_case(e)) {
            owner_emails.push(e.to_string());
        }
    }
    if !owner_emails.is_empty() {
        return ResolvedRecipients { recipients: owner_emails, source: SOURCE_GITHUB_OWNERS, owners, note };
    }
    let source = if to.is_empty() { "none" } else { SOURCE_FALLBACK };
    ResolvedRecipients { recipients: to.to_vec(), source, owners, note }
}

fn one_line(s: &str) -> String {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() > 300 { format!("{}…", s.chars().take(300).collect::<String>()) } else { s }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendOutcome {
    sent: bool,
    recipients: Vec<String>,
    source: &'static str,
    note: Option<String>,
    error: Option<String>,
    reason: Option<String>,
    repos: usize,
    unjustified_findings: usize,
}

/// Resolves recipients, sends the org's report by email and records the
/// attempt on the schedule row (when one exists).
pub async fn send_org_report(state: &AppState, headers: &HeaderMap, org: &str, mode: OrgReportRecipients, to: &[String]) -> SendOutcome {
    let resolved = resolve_recipients(state, headers, org, mode, to).await;
    let now = Utc::now();
    let mut outcome = SendOutcome { sent: false, recipients: resolved.recipients.clone(), source: resolved.source, note: resolved.note.clone(), error: None, reason: None, repos: 0, unjustified_findings: 0 };
    if resolved.recipients.is_empty() {
        outcome.error = Some(match mode {
            OrgReportRecipients::Fixed => "no recipients: no fixed distribution list configured".to_string(),
            OrgReportRecipients::Admins => format!("no recipients: {}, and no fallback email is configured", resolved.note.as_deref().unwrap_or("no org owner email found")),
        });
    } else {
        let to = resolved.recipients.join(", ");
        let today = Local::now().date_naive().to_string();
        let outcomes = run_daily_report(state, &RunOptions { only_org: Some(org), date: &today, channels: vec![Channel::Email], to: Some(&to), ..Default::default() }).await;
        match outcomes.into_iter().next() {
            None => outcome.error = Some("no scanned repositories for this org — nothing to report".to_string()),
            Some(o) => {
                outcome.sent = o.email_sent;
                outcome.repos = o.repos;
                outcome.unjustified_findings = o.unjustified_findings;
                outcome.reason = o.reason;
                outcome.error = o.email_error;
                if !o.email_sent && outcome.error.is_none() {
                    outcome.error = Some(outcome.reason.clone().unwrap_or_else(|| "email not sent".to_string()));
                }
            }
        }
    }
    let recipients = (!outcome.recipients.is_empty()).then(|| outcome.recipients.join(", "));
    state.db.record_org_report_run(org, &db_time(now), recipients.as_deref(), Some(outcome.source), outcome.error.as_deref());
    if outcome.sent {
        tracing::info!(org, source = outcome.source, recipients = outcome.recipients.len(), "org findings report emailed");
    } else {
        tracing::warn!(org, error = ?outcome.error, "org findings report not sent");
    }
    outcome
}

/// Starts the per-minute schedule check. Call once at boot.
pub fn spawn_scheduler(state: Arc<AppState>) {
    Lazy::force(&STARTED_AT);
    if state.config.org_reports.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(TICK);
        let mut warned: std::collections::HashSet<String> = std::collections::HashSet::new();
        loop {
            interval.tick().await;
            let now = Local::now();
            for org in candidate_orgs(&state) {
                let Some(s) = org_schedule(&state, &org).filter(|s| s.enabled) else { continue };
                let cron = match parse_cron(&s.cron) {
                    Ok(c) => c,
                    Err(e) => {
                        if warned.insert(format!("{org}|{}", s.cron)) {
                            tracing::warn!(org, error = %e, "orgReports schedule skipped");
                        }
                        continue;
                    }
                };
                if let Some(e) = &s.to_error {
                    if warned.insert(format!("{org}|to|{e}")) {
                        tracing::warn!(org, error = %e, "orgReports: invalid address in `to` ignored");
                    }
                }
                let last = state.db.get_org_report_run(&org).and_then(|r| parse_db_time(&r.last_run_at));
                if !is_due(&cron, now, last, Some(*STARTED_AT)) {
                    continue;
                }
                // No request: org-owner lookup uses the GitHub App, else GH_TOKEN.
                send_org_report(&state, &HeaderMap::new(), &org, s.recipients, &s.to).await;
            }
        }
    });
}

fn schedule_json(state: &AppState, org: &str) -> serde_json::Value {
    let s = org_schedule(state, org);
    let cron_error = s.as_ref().and_then(|s| parse_cron(&s.cron).err());
    let next = s.as_ref().filter(|s| s.enabled).and_then(|s| parse_cron(&s.cron).ok()).and_then(|c| next_occurrence(&c, Local::now())).map(|t| t.to_rfc3339());
    json!({
        "org": org.to_ascii_lowercase(),
        "configured": s.is_some(),
        "enabled": s.as_ref().is_some_and(|s| s.enabled),
        "cron": s.as_ref().map(|s| s.cron.clone()),
        "cronError": cron_error,
        "recipients": s.as_ref().map(|s| mode_str(s.recipients)),
        "to": s.as_ref().map(|s| s.to.clone()).unwrap_or_default(),
        "toError": s.as_ref().and_then(|s| s.to_error.clone()),
        "nextRunAt": next,
        "lastRun": state.db.get_org_report_run(org),
    })
}

fn bad_request(message: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message.into() }))).into_response()
}

fn valid_org(org: &str) -> Result<(), Response> {
    if ignite_github_api::is_valid_github_owner(org) { Ok(()) } else { Err(bad_request("Invalid GitHub org name.")) }
}

fn time_zone() -> String {
    Local::now().format("UTC%:z").to_string()
}

/// Read-only view of every org `orgReports` applies to.
async fn list_schedules(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth) -> Response {
    let rows: Vec<serde_json::Value> = candidate_orgs(&state).iter().map(|o| schedule_json(&state, o)).collect();
    Json(json!({ "schedules": rows, "timeZone": time_zone() })).into_response()
}

async fn get_schedule(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, Path(org): Path<String>) -> Response {
    if let Err(r) = valid_org(&org) {
        return r;
    }
    Json(json!({ "schedule": schedule_json(&state, &org), "timeZone": time_zone() })).into_response()
}

fn not_configured(org: &str) -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": format!("No orgReports entry in config.json matches {org}.") }))).into_response()
}

/// Who would receive the report right now (no email sent).
async fn preview_recipients(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, headers: HeaderMap, Path(org): Path<String>) -> Response {
    if let Err(r) = valid_org(&org) {
        return r;
    }
    let Some(s) = org_schedule(&state, &org) else { return not_configured(&org) };
    Json(resolve_recipients(&state, &headers, &org, s.recipients, &s.to).await).into_response()
}

/// Sends the org's report now to its configured recipients (ignores
/// `enabled` and the cron).
async fn send_now(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, headers: HeaderMap, Path(org): Path<String>) -> Response {
    if let Err(r) = valid_org(&org) {
        return r;
    }
    let Some(s) = org_schedule(&state, &org) else { return not_configured(&org) };
    let outcome = send_org_report(&state, &headers, &org, s.recipients, &s.to).await;
    let status = if outcome.sent { StatusCode::OK } else { StatusCode::UNPROCESSABLE_ENTITY };
    (status, Json(outcome)).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/org-repos/report-schedules", get(list_schedules))
        .route("/api/org-repos/report-schedules/:org", get(get_schedule))
        .route("/api/org-repos/report-schedules/:org/recipients", get(preview_recipients))
        .route("/api/org-repos/report-schedules/:org/send", post(send_now))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Local> {
        Local.with_ymd_and_hms(y, mo, d, h, mi, 0).single().unwrap()
    }

    #[test]
    fn five_and_six_field_cron_parse_and_garbage_is_rejected() {
        assert!(parse_cron("0 9 * * MON").is_ok());
        assert!(parse_cron("0 0 9 * * *").is_ok());
        assert!(parse_cron("").is_err());
        assert!(parse_cron("every monday").is_err());
    }

    #[test]
    fn due_only_after_an_occurrence_newer_than_last_run_and_save() {
        let cron = parse_cron("0 9 * * *").unwrap();
        let utc = |t: DateTime<Local>| t.with_timezone(&Utc);
        // Saved at 10:00 today: today's 09:00 already passed — not sent retroactively.
        let saved = utc(local(2026, 10, 1, 10, 0));
        assert!(!is_due(&cron, local(2026, 10, 1, 10, 1), None, Some(saved)));
        // Next day 09:00: due.
        assert!(is_due(&cron, local(2026, 10, 2, 9, 0), None, Some(saved)));
        // Already sent at 09:00 that day: not due again.
        assert!(!is_due(&cron, local(2026, 10, 2, 9, 30), Some(utc(local(2026, 10, 2, 9, 0))), Some(saved)));
        // Server down over 09:00, back at 11:00: sent once.
        assert!(is_due(&cron, local(2026, 10, 3, 11, 0), Some(utc(local(2026, 10, 2, 9, 0))), Some(saved)));
        assert_eq!(next_occurrence(&cron, local(2026, 10, 1, 10, 0)), Some(local(2026, 10, 2, 9, 0)));
    }

    #[test]
    fn email_lists_are_split_deduplicated_and_validated() {
        assert_eq!(parse_email_list("a@x.com, b@y.org;A@x.com\nc@z.io").unwrap(), vec!["a@x.com", "b@y.org", "c@z.io"]);
        assert!(parse_email_list("").unwrap().is_empty());
        assert!(parse_email_list("not-an-email").is_err());
        assert!(parse_email_list("a@localhost").is_err());
    }
}
