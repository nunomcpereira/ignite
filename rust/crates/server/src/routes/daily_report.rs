//! Org-level daily findings report: once a day (default 23:59 server-local
//! time, `dailyReport.time`), email each org one digest listing every repo
//! and the findings on its most recent scan that nobody has justified yet
//! (`status = 'open'` — see `DbStore::list_latest_scan_unjustified_findings`).
//! Off by default (`dailyReport.enabled`); sending also needs
//! `notifications.enabled`. `POST /api/reports/daily/run` triggers the same
//! run on demand (`dryRun=true` previews without sending).
//!
//! Unlike the scan sweeps (which stay on an external timer so they don't
//! load the server), this only reads `ignite.db` and sends a few emails, so
//! it runs on a small in-process timer and needs no cron/launchd setup.

use crate::auth::RequireAuth;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chrono::{Local, NaiveTime};
use ignite_notifications::{DailyReportCodeLine, DailyReportDetails, DailyReportFinding, DailyReportRepo};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// `app_settings` key holding the local date (`YYYY-MM-DD`) of the last
/// scheduled run, so a restart later the same night doesn't send twice.
const LAST_RUN_SETTING: &str = "daily_report_last_run_date";
const TICK: Duration = Duration::from_secs(30);

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OrgReportOutcome {
    pub org: String,
    pub repos: usize,
    pub unjustified_findings: usize,
    pub sent: bool,
    pub reason: Option<String>,
    pub error: Option<String>,
    /// Only populated on a dry run, so the caller can preview the email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
}

/// `dailyReport.to` when set, else the general `notifications.to`.
fn resolve_recipient(state: &AppState) -> String {
    let own = state.config.daily_report.to.trim();
    if own.is_empty() { state.config.notifications.to.clone() } else { own.to_string() }
}

/// Builds and (unless `dry_run`) sends one report per org that has at
/// least one repo, or just `only_org` when given. One org's failure never
/// stops the others.
pub async fn run_daily_report(state: &AppState, only_org: Option<&str>, dry_run: bool, date: &str) -> Vec<OrgReportOutcome> {
    let all = state.db.list_latest_scan_unjustified_findings(only_org);
    let to = resolve_recipient(state);
    let mut outcomes = Vec::new();

    // `all` is ordered by org, so each org's repos are one contiguous run.
    let mut start = 0;
    while start < all.len() {
        let org = all[start].org.as_str();
        let end = start + all[start..].iter().take_while(|r| r.org == org).count();
        let org_repos = &all[start..end];
        start = end;

        let findings: Vec<Vec<DailyReportFinding>> = org_repos
            .iter()
            .map(|r| r.unjustified.iter().map(|i| DailyReportFinding { severity: &i.severity, category: &i.category, file: i.file.as_deref(), line: i.line, summary: &i.summary, score: i.score, code: code_context(i.snippet.as_ref()) }).collect())
            .collect();
        let repos: Vec<DailyReportRepo> = org_repos.iter().zip(&findings).map(|(r, f)| DailyReportRepo { repo: &r.repo, status: &r.status, last_scan_at: &r.last_scan_at, findings: f }).collect();
        let details = DailyReportDetails { org, date, repos: &repos };

        let mut outcome = OrgReportOutcome { org: org.to_string(), repos: repos.len(), unjustified_findings: findings.iter().map(Vec::len).sum(), sent: false, reason: None, error: None, subject: None, html: None };
        if dry_run {
            let email = ignite_notifications::build_daily_report_email(&details);
            outcome.subject = Some(email.subject);
            outcome.html = Some(email.html);
            outcome.reason = Some("dry run".to_string());
        } else {
            match ignite_notifications::send_daily_report_notification(&state.config.notifications, &to, &details).await {
                Ok(result) => {
                    outcome.sent = result.sent;
                    outcome.reason = result.reason;
                }
                Err(e) => {
                    tracing::warn!(org, error = %e, "daily report send failed");
                    outcome.error = Some(e.to_string());
                }
            }
        }
        outcomes.push(outcome);
    }
    outcomes
}

/// Most flagged lines shown for a multi-line finding (before/after context
/// is added on top), so one sprawling match can't dominate the email.
const MAX_FLAGGED_LINES: i64 = 5;

/// The flagged line plus one line of context on each side, from an issue's
/// stored snippet (`{ lines: [{ number, text }], highlightLine,
/// highlightEndLine? }`, see `ignite_fs_utils::Snippet` — captured with a
/// wider radius, so this narrows it). A multi-line match shows all its
/// lines (capped) with the same single line of context around them. Empty
/// when the issue has no usable snippet.
fn code_context(snippet: Option<&serde_json::Value>) -> Vec<DailyReportCodeLine> {
    let Some(snippet) = snippet else { return vec![] };
    let Some(first) = snippet.get("highlightLine").and_then(|v| v.as_i64()) else { return vec![] };
    let last = snippet.get("highlightEndLine").and_then(|v| v.as_i64()).unwrap_or(first).max(first).min(first + MAX_FLAGGED_LINES - 1);
    let Some(lines) = snippet.get("lines").and_then(|v| v.as_array()) else { return vec![] };
    lines
        .iter()
        .filter_map(|l| {
            let number = l.get("number")?.as_i64()?;
            let text = l.get("text")?.as_str()?;
            (number >= first - 1 && number <= last + 1).then(|| DailyReportCodeLine { number, text: text.to_string(), flagged: number >= first && number <= last })
        })
        .collect()
}

/// Parses `dailyReport.time` (`HH:MM`).
fn parse_time(raw: &str) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(raw.trim(), "%H:%M").ok()
}

/// True when the scheduled run for `today` is due: the configured time has
/// been reached and nothing has run yet today.
fn is_due(now: NaiveTime, target: NaiveTime, today: &str, last_run: Option<&str>) -> bool {
    now >= target && last_run != Some(today)
}

/// Starts the daily timer when `dailyReport.enabled`. Call once at boot.
pub fn spawn_scheduler(state: Arc<AppState>) {
    if !state.config.daily_report.enabled {
        return;
    }
    let Some(target) = parse_time(&state.config.daily_report.time) else {
        tracing::warn!(time = %state.config.daily_report.time, "dailyReport.time is not HH:MM — daily report disabled");
        return;
    };
    tracing::info!(%target, "daily report scheduled");
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(TICK);
        loop {
            interval.tick().await;
            let now = Local::now();
            let today = now.date_naive().to_string();
            if !is_due(now.time(), target, &today, state.db.get_setting(LAST_RUN_SETTING).as_deref()) {
                continue;
            }
            let outcomes = run_daily_report(&state, None, false, &today).await;
            // Recorded even when a send failed: retrying every tick against
            // a broken SMTP relay would only spam the logs (and any org
            // whose send did succeed would get it again).
            state.db.set_setting(LAST_RUN_SETTING, &today);
            let sent = outcomes.iter().filter(|o| o.sent).count();
            tracing::info!(orgs = outcomes.len(), sent, "daily report run finished");
        }
    });
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunQuery {
    org: Option<String>,
    #[serde(default)]
    dry_run: bool,
}

/// `POST /api/reports/daily/run[?org=<org>][&dryRun=true]`
async fn run_now(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, Query(query): Query<RunQuery>) -> Response {
    let today = Local::now().date_naive().to_string();
    let org = query.org.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let outcomes = run_daily_report(&state, org, query.dry_run, &today).await;
    Json(serde_json::json!({ "date": today, "dryRun": query.dry_run, "reports": outcomes })).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/reports/daily/run", post(run_now))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(h: u32, m: u32) -> NaiveTime {
        NaiveTime::from_hms_opt(h, m, 0).unwrap()
    }

    #[test]
    fn parses_hh_mm_and_rejects_garbage() {
        assert_eq!(parse_time("23:59"), Some(t(23, 59)));
        assert_eq!(parse_time(" 07:05 "), Some(t(7, 5)));
        assert_eq!(parse_time("25:00"), None);
        assert_eq!(parse_time("midnight"), None);
    }

    #[test]
    fn due_only_once_the_time_is_reached_and_not_already_run_today() {
        let target = t(23, 59);
        assert!(!is_due(t(23, 58), target, "2026-09-18", None), "before the configured time");
        assert!(is_due(t(23, 59), target, "2026-09-18", None));
        assert!(is_due(t(23, 59), target, "2026-09-18", Some("2026-09-17")), "yesterday's run doesn't count");
        assert!(!is_due(t(23, 59), target, "2026-09-18", Some("2026-09-18")), "already ran today");
    }

    fn snippet(start: i64, texts: &[&str], highlight: i64, end: Option<i64>) -> serde_json::Value {
        let lines: Vec<_> = texts.iter().enumerate().map(|(i, t)| serde_json::json!({ "number": start + i as i64, "text": t })).collect();
        let mut v = serde_json::json!({ "startLine": start, "lines": lines, "highlightLine": highlight });
        if let Some(e) = end {
            v["highlightEndLine"] = e.into();
        }
        v
    }

    #[test]
    fn code_context_narrows_a_wide_snippet_to_line_before_flagged_and_after() {
        let s = snippet(7, &["l7", "l8", "l9", "l10", "l11", "l12", "l13"], 10, None);
        let ctx = code_context(Some(&s));
        assert_eq!(ctx.iter().map(|l| (l.number, l.flagged)).collect::<Vec<_>>(), vec![(9, false), (10, true), (11, false)]);
        assert_eq!(ctx[1].text, "l10");
    }

    #[test]
    fn code_context_handles_file_edges_multiline_matches_and_missing_snippets() {
        // Flagged line is line 1: no line before it exists.
        let top = code_context(Some(&snippet(1, &["a", "b", "c", "d"], 1, None)));
        assert_eq!(top.iter().map(|l| l.number).collect::<Vec<_>>(), vec![1, 2]);
        // Multi-line match 3..4 keeps both flagged lines plus one of context each side.
        let multi = code_context(Some(&snippet(1, &["a", "b", "c", "d", "e", "f"], 3, Some(4))));
        assert_eq!(multi.iter().map(|l| (l.number, l.flagged)).collect::<Vec<_>>(), vec![(2, false), (3, true), (4, true), (5, false)]);
        // A huge multi-line match is capped.
        let texts: Vec<String> = (1..=30).map(|n| format!("l{n}")).collect();
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        let big = code_context(Some(&snippet(1, &refs, 5, Some(25))));
        assert_eq!(big.iter().filter(|l| l.flagged).count() as i64, MAX_FLAGGED_LINES);
        assert!(code_context(None).is_empty());
        assert!(code_context(Some(&serde_json::json!({ "lines": [] }))).is_empty());
    }

    fn state_with_db() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&dir.path().join("test.db")).unwrap();
        let state = AppState {
            runner: crate::state::default_runner(),
            db,
            running_runs: Default::default(),
            pending_effectivations: Default::default(),
            review_gate: crate::review_gate::ReviewGate::default(),
            llm_config: crate::state::default_llm_config(),
            config: ignite_config::Config::default(),
            package_hallucination_checker: crate::state::default_package_hallucination_checker(),
            fix_pr_previews: Default::default(),
            audit_http: reqwest::Client::new(),
        };
        (dir, state)
    }

    #[tokio::test]
    async fn one_report_per_org_with_counts_and_dry_run_preview() {
        let (_dir, state) = state_with_db();
        let acme = state.db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        state.db.replace_project_issues(
            acme,
            &[ignite_db_store::IssueInput { id: "secret::a.rs::1".into(), phase: Some(2), category: "secret".into(), severity: "error".into(), score: Some(9), summary: "hardcoded key".into(), file: Some("a.rs".into()), line: Some(1), snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: None, references: None, duplicate_ref: None }],
            &Default::default(),
        );
        state.db.create_project("job-2", "acme", "clean", false, "ui", None).unwrap();
        state.db.create_project("job-3", "other", "thing", false, "ui", None).unwrap();

        let outcomes = run_daily_report(&state, None, true, "2026-09-18").await;
        assert_eq!(outcomes.iter().map(|o| (o.org.as_str(), o.repos, o.unjustified_findings)).collect::<Vec<_>>(), vec![("acme", 2, 1), ("other", 1, 0)]);
        assert!(outcomes[0].html.as_deref().unwrap().contains("hardcoded key"));
        assert!(!outcomes[0].sent, "dry run never sends");

        let only_other = run_daily_report(&state, Some("other"), true, "2026-09-18").await;
        assert_eq!(only_other.len(), 1);
        assert_eq!(only_other[0].org, "other");
    }

    #[tokio::test]
    async fn real_run_is_skipped_not_failed_when_notifications_are_off() {
        let (_dir, state) = state_with_db();
        state.db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let outcomes = run_daily_report(&state, None, false, "2026-09-18").await;
        assert_eq!(outcomes.len(), 1);
        assert!(!outcomes[0].sent);
        assert!(outcomes[0].error.is_none());
        assert!(outcomes[0].reason.as_deref().unwrap().contains("disabled"));
    }
}
