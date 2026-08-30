//! Faithful port of `lib/scheduled-rechecks.js`'s pure, self-contained
//! pieces — `computeNextRunAt`'s date math and
//! `buildScheduledCheckFailureEmail`'s HTML builder. The orchestrating
//! `runScheduledRecheck`/`sweepScheduledRechecks` aren't ported: they
//! stitch together server.js pieces that don't exist as standalone Rust
//! crates yet (checkEnvFiles, checkCodeowners, the unit-test-runner
//! check, the ORT-based license/vulnerability checks, act/Docker-based
//! local CI, and the governance-workflow fetch) — porting them faithfully
//! needs those pieces to exist first, not a stubbed-out orchestrator.

use chrono::{DateTime, Datelike, Days, TimeZone, Timelike, Utc};

pub const SCHEDULE_INTERVALS: &[&str] = &["daily", "weekly", "monthly"];

/// Mirrors JS `Date.setMonth`'s overflow-normalization semantics exactly:
/// advancing the month keeps the same day-of-month number and lets any
/// overflow (e.g. day 31 in a 28/29/30-day month) spill into the
/// following month(s), rather than clamping or erroring.
fn add_one_month(from: DateTime<Utc>) -> DateTime<Utc> {
    let day = from.day();
    let target_month0 = from.month0() + 1; // 0-based, may be 12
    let target_year = from.year() + (target_month0 / 12) as i32;
    let target_month = target_month0 % 12 + 1; // back to 1-based
    let first_of_month = Utc.with_ymd_and_hms(target_year, target_month, 1, from.hour(), from.minute(), from.second()).single().expect("valid first-of-month");
    first_of_month + Days::new((day - 1) as u64)
}

pub fn compute_next_run_at(interval: &str, from: DateTime<Utc>) -> String {
    let next = match interval {
        "weekly" => from + Days::new(7),
        "monthly" => add_one_month(from),
        _ => from + Days::new(1), // 'daily', and the fallback for any unrecognized value
    };
    next.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn escape_html_mail(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

pub struct ScheduledFailureEmail {
    pub subject: String,
    pub html: String,
}

pub fn build_scheduled_check_failure_email(org: &str, repo: &str, error: &str) -> ScheduledFailureEmail {
    let subject = format!("[Ignite] \u{274c} Scheduled re-check failed — {org}/{repo}");
    let html = format!(
        "\n    <div style=\"font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:640px;margin:0 auto;color:#334155;\">\n      <h2 style=\"color:#e11d48;\">Ignite scheduled re-check failed</h2>\n      <p><strong>Repository:</strong> {}/{} (default branch)<br/>\n         <strong>Error:</strong> {}</p>\n      <p style=\"color:#94a3b8;font-size:12px;margin-top:24px;\">Sent by Ignite to this repository's CODEOWNERS contact(s) — update CODEOWNERS to change who receives this.</p>\n    </div>",
        escape_html_mail(org),
        escape_html_mail(repo),
        escape_html_mail(error),
    );
    ScheduledFailureEmail { subject, html }
}

pub struct DueProject {
    pub id: i64,
    pub org: String,
    pub repo: String,
}

impl From<ignite_db_store::DueScheduledProject> for DueProject {
    fn from(p: ignite_db_store::DueScheduledProject) -> Self {
        DueProject { id: p.id, org: p.org, repo: p.repo }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ymd(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 12, 0, 0).unwrap()
    }

    #[test]
    fn daily_adds_one_day() {
        let next = compute_next_run_at("daily", ymd(2026, 1, 15));
        assert!(next.starts_with("2026-01-16T12:00:00"));
    }

    #[test]
    fn unrecognized_interval_falls_back_to_daily() {
        let next = compute_next_run_at("hourly", ymd(2026, 1, 15));
        assert!(next.starts_with("2026-01-16T12:00:00"));
    }

    #[test]
    fn weekly_adds_seven_days() {
        let next = compute_next_run_at("weekly", ymd(2026, 1, 15));
        assert!(next.starts_with("2026-01-22T12:00:00"));
    }

    #[test]
    fn monthly_advances_month_keeping_day() {
        let next = compute_next_run_at("monthly", ymd(2026, 1, 15));
        assert!(next.starts_with("2026-02-15T12:00:00"));
    }

    #[test]
    fn monthly_overflows_into_following_month_like_js_date_setmonth() {
        // Jan 31 + 1 month: February has 28 days in 2026 (not a leap year),
        // so JS's Date.setMonth spills the extra 3 days into March 3rd.
        let next = compute_next_run_at("monthly", ymd(2026, 1, 31));
        assert!(next.starts_with("2026-03-03T12:00:00"));
    }

    #[test]
    fn monthly_rolls_over_year_boundary() {
        let next = compute_next_run_at("monthly", ymd(2026, 12, 15));
        assert!(next.starts_with("2027-01-15T12:00:00"));
    }

    #[test]
    fn failure_email_escapes_org_repo_and_error() {
        let email = build_scheduled_check_failure_email("<b>acme</b>", "widgets", "boom & bust");
        assert!(email.subject.contains("<b>acme</b>/widgets")); // subject is plain text, not HTML-escaped, matching JS
        assert!(email.html.contains("&lt;b&gt;acme&lt;/b&gt;"));
        assert!(email.html.contains("boom &amp; bust"));
    }
}
