//! Faithful port of `lib/notifications.js`'s email-building and sending
//! functions — pipeline-failure, override-audit-trail, API-key-creation,
//! and scheduled-recheck-failure notifications.
//!
//! Transport selection mirrors Node's `buildMailTransport`:
//! - If `smtp.host`, `smtp.user`, and `smtp.pass` are all non-empty,
//!   builds a real SMTP transport (TLS-on-connect when `smtp.secure`,
//!   STARTTLS otherwise).
//! - Otherwise falls back to the local `sendmail` binary, matching
//!   `nodemailer.createTransport({ sendmail: true })`.
//!
//! All `send_*` functions are **best-effort** — they return a
//! [`NotificationResult`] on success/short-circuit and a
//! [`NotificationError`] on transport failure, but callers must never
//! let a send failure abort pipeline execution, DB writes, or audit
//! trail persistence.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use std::collections::BTreeMap;

use ignite_config::NotificationsConfig;
use lettre::message::{header::ContentType, Mailbox};
use lettre::{
    AsyncSendmailTransport, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

// ---------------------------------------------------------------------------
// Result / error types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NotificationResult {
    pub sent: bool,
    pub to: Option<String>,
    pub reason: Option<String>,
}

impl NotificationResult {
    fn skipped(reason: impl Into<String>) -> Self {
        NotificationResult { sent: false, to: None, reason: Some(reason.into()) }
    }
    fn sent(to: impl Into<String>) -> Self {
        NotificationResult { sent: true, to: Some(to.into()), reason: None }
    }
}

#[derive(Debug)]
pub struct NotificationError {
    pub message: String,
}

impl std::fmt::Display for NotificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for NotificationError {}

impl From<lettre::transport::smtp::Error> for NotificationError {
    fn from(e: lettre::transport::smtp::Error) -> Self {
        NotificationError { message: e.to_string() }
    }
}

impl From<lettre::transport::sendmail::Error> for NotificationError {
    fn from(e: lettre::transport::sendmail::Error) -> Self {
        NotificationError { message: e.to_string() }
    }
}

impl From<lettre::error::Error> for NotificationError {
    fn from(e: lettre::error::Error) -> Self {
        NotificationError { message: e.to_string() }
    }
}

impl From<lettre::address::AddressError> for NotificationError {
    fn from(e: lettre::address::AddressError) -> Self {
        NotificationError { message: e.to_string() }
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Mirrors Node's `buildMailTransport()`: SMTP when credentials are fully
/// configured, sendmail binary fallback otherwise.
enum Transport {
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
    Sendmail(AsyncSendmailTransport<Tokio1Executor>),
}

fn build_transport(config: &NotificationsConfig) -> Transport {
    let smtp = &config.smtp;
    if !smtp.host.is_empty()
        && !smtp.user.is_empty()
        && smtp.pass.as_ref().map_or(false, |p| !p.is_empty())
    {
        let creds = lettre::transport::smtp::authentication::Credentials::new(
            smtp.user.clone(),
            smtp.pass.clone().unwrap_or_default(),
        );
        let transport = if smtp.secure {
            // Direct TLS on connect (port 465 convention)
            AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.host)
                .unwrap_or_else(|_| AsyncSmtpTransport::<Tokio1Executor>::relay("localhost").unwrap())
                .port(smtp.port)
                .credentials(creds)
                .build()
        } else {
            // STARTTLS upgrade (port 587 convention)
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp.host)
                .unwrap_or_else(|_| AsyncSmtpTransport::<Tokio1Executor>::starttls_relay("localhost").unwrap())
                .port(smtp.port)
                .credentials(creds)
                .build()
        };
        Transport::Smtp(transport)
    } else {
        // No SMTP credentials — fall back to local sendmail binary,
        // matching `nodemailer.createTransport({ sendmail: true })`.
        Transport::Sendmail(AsyncSendmailTransport::<Tokio1Executor>::new())
    }
}

/// Build a `lettre::Message` from subject + HTML body + from/to addresses.
fn build_message(
    from: &str,
    to: &str,
    subject: &str,
    html: &str,
) -> Result<Message, NotificationError> {
    let from_mbox: Mailbox = from.parse().map_err(|e: lettre::address::AddressError| {
        NotificationError { message: format!("invalid 'from' address {from:?}: {e}") }
    })?;
    // `to` may be a comma-separated list (same as Node's nodemailer accepts).
    // lettre's `Message::builder().to()` takes a single `Mailbox`, so we
    // set the raw `To` header directly for multi-recipient support.
    let to_mboxes: Vec<Mailbox> = to
        .split(',')
        .map(|addr| addr.trim())
        .filter(|a| !a.is_empty())
        .map(|a| a.parse::<Mailbox>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| NotificationError { message: format!("invalid 'to' address {to:?}: {e}") })?;
    if to_mboxes.is_empty() {
        return Err(NotificationError { message: "no valid recipient addresses".to_string() });
    }
    let mut builder = Message::builder()
        .from(from_mbox)
        .subject(subject);
    for mbox in to_mboxes {
        builder = builder.to(mbox);
    }
    let msg = builder
        .header(ContentType::TEXT_HTML)
        .body(html.to_string())?;
    Ok(msg)
}

/// Send a pre-built `lettre::Message` via the configured transport.
async fn send_message(
    config: &NotificationsConfig,
    message: Message,
) -> Result<(), NotificationError> {
    match build_transport(config) {
        Transport::Smtp(t) => {
            t.send(message).await?;
        }
        Transport::Sendmail(t) => {
            t.send(message).await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Existing pure HTML/subject builders (unchanged)
// ---------------------------------------------------------------------------

/// Strips CR/LF before interpolating into an email subject line —
/// unescaped newlines in an org/repo name would let it inject extra SMTP
/// headers into the message. `escape_html_mail` handles the HTML body's
/// own injection risk but doesn't touch `\r`/`\n`, so subject-line
/// construction needs this separately.
fn strip_crlf(s: &str) -> String {
    s.replace(['\r', '\n'], "")
}

pub fn escape_html_mail(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Caps a failed phase's log block to its last `MAX_LOG_LINES` lines — a
/// build that produced tens of megabytes of log output would otherwise
/// balloon the generated email to a size some SMTP relays reject outright,
/// and it's the *end* of the log (closest to the actual failure) that
/// matters most for triage anyway.
const MAX_LOG_LINES: usize = 100;

fn truncate_logs(logs: &[String]) -> String {
    if logs.len() <= MAX_LOG_LINES {
        return logs.join("\n");
    }
    let omitted = logs.len() - MAX_LOG_LINES;
    let tail = logs[logs.len() - MAX_LOG_LINES..].join("\n");
    format!("… ({omitted} earlier line(s) omitted) …\n{tail}")
}

#[derive(Debug, Clone)]
pub struct PhaseState {
    pub state: String,
    pub logs: Vec<String>,
}

impl Default for PhaseState {
    fn default() -> Self {
        PhaseState { state: "pending".to_string(), logs: vec![] }
    }
}

pub struct Email {
    pub subject: String,
    pub html: String,
}

fn phase_status_color(state: &str) -> &'static str {
    match state {
        "success" => "#059669",
        "failed" => "#e11d48",
        "running" => "#2563eb",
        _ => "#94a3b8",
    }
}

pub struct FailureEmailDetails<'a> {
    pub job_id: &'a str,
    pub org: &'a str,
    pub repo: &'a str,
    pub error: &'a str,
    pub failed_phase: i64,
    pub record: &'a BTreeMap<i64, PhaseState>,
    pub insight: Option<&'a str>,
}

pub fn build_failure_email(phase_titles: &BTreeMap<i64, String>, details: &FailureEmailDetails) -> Email {
    let empty = PhaseState::default();
    let rows: String = phase_titles
        .keys()
        .map(|id| {
            let ph = details.record.get(id).unwrap_or(&empty);
            let color = phase_status_color(&ph.state);
            // Both a custom `phases` title override (`config.json`) and
            // `ph.state` (set by whatever phase logic ran) are effectively
            // operator/config-controlled text reaching an HTML email
            // unescaped — a value containing markup could break the email
            // layout or inject HTML in a webmail client that renders it.
            let title = escape_html_mail(&phase_titles[id]);
            let state = escape_html_mail(&ph.state);
            format!(
                "<tr>\n          <td style=\"padding:6px 12px;border-bottom:1px solid #e2e8f0;\">Phase {id}</td>\n          <td style=\"padding:6px 12px;border-bottom:1px solid #e2e8f0;\">{title}</td>\n          <td style=\"padding:6px 12px;border-bottom:1px solid #e2e8f0;color:{color};font-weight:600;text-transform:uppercase;\">{state}</td>\n        </tr>"
            )
        })
        .collect();

    let failed_sections: String = details
        .record
        .iter()
        .filter(|(_, ph)| ph.state == "failed" && !ph.logs.is_empty())
        .map(|(id, ph)| {
            let title = escape_html_mail(phase_titles.get(id).map(String::as_str).unwrap_or("Unknown"));
            let logs = escape_html_mail(&truncate_logs(&ph.logs));
            format!(
                "\n        <h3 style=\"margin:24px 0 8px;color:#0f172a;\">Phase {id} — {title} logs</h3>\n        <pre style=\"background:#0f172a;color:#e2e8f0;padding:14px;border-radius:8px;font-size:12px;line-height:1.6;overflow-x:auto;white-space:pre-wrap;\">{logs}</pre>"
            )
        })
        .collect();

    let failed_phase_title = escape_html_mail(phase_titles.get(&details.failed_phase).map(String::as_str).unwrap_or("Unknown"));
    let subject = format!("[Ignite] \u{274c} Onboarding failed at Phase {} — {}/{}", details.failed_phase, strip_crlf(details.org), strip_crlf(details.repo));
    let insight_block = details
        .insight
        .map(|insight| {
            format!(
                "\n      <h3 style=\"margin:24px 0 8px;color:#0f172a;\">\u{1f916} AI insight</h3>\n      <div style=\"background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:14px;font-size:14px;line-height:1.6;white-space:pre-wrap;\">{}</div>",
                escape_html_mail(insight)
            )
        })
        .unwrap_or_default();

    let html = format!(
        "\n    <div style=\"font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:720px;margin:0 auto;color:#334155;\">\n      <h2 style=\"color:#e11d48;\">Ignite onboarding pipeline failed</h2>\n      <p><strong>Target:</strong> {}/{} (private)<br/>\n         <strong>Job:</strong> {}<br/>\n         <strong>Failed at:</strong> Phase {} — {failed_phase_title}<br/>\n         <strong>Error:</strong> {}</p>\n      <table style=\"border-collapse:collapse;width:100%;font-size:14px;\">\n        <tr style=\"background:#f1f5f9;\">\n          <th style=\"padding:6px 12px;text-align:left;\">#</th>\n          <th style=\"padding:6px 12px;text-align:left;\">Phase</th>\n          <th style=\"padding:6px 12px;text-align:left;\">Status</th>\n        </tr>\n        {rows}\n      </table>\n      {insight_block}\n      {failed_sections}\n      <p style=\"color:#94a3b8;font-size:12px;margin-top:24px;\">Sent by Ignite — staging files were cleaned up. Fix the violations and re-run the pipeline.</p>\n    </div>",
        escape_html_mail(details.org),
        escape_html_mail(details.repo),
        escape_html_mail(details.job_id),
        details.failed_phase,
        escape_html_mail(details.error),
    );

    Email { subject, html }
}

pub struct IssueLike<'a> {
    pub severity: &'a str,
    pub category: &'a str,
    pub file: Option<&'a str>,
    pub line: Option<i64>,
    pub summary: &'a str,
}

pub struct AppliedOverride<'a> {
    pub issue: IssueLike<'a>,
    pub justification: &'a str,
}

pub struct Actor<'a> {
    pub name: Option<&'a str>,
    pub email: &'a str,
}

pub struct OverrideEmailDetails<'a> {
    pub job_id: &'a str,
    pub org: &'a str,
    pub repo: &'a str,
    pub phase: i64,
    pub actor: Actor<'a>,
    pub applied: &'a [AppliedOverride<'a>],
}

pub fn build_override_email(phase_titles: &BTreeMap<i64, String>, details: &OverrideEmailDetails) -> Email {
    let rows: String = details
        .applied
        .iter()
        .map(|a| {
            let color = if a.issue.severity == "error" { "#e11d48" } else { "#b45309" };
            let location = format!("{}{}", escape_html_mail(a.issue.file.unwrap_or("")), a.issue.line.map(|l| format!(":{l}")).unwrap_or_default());
            format!(
                "\n        <tr>\n          <td style=\"padding:6px 12px;border-bottom:1px solid #e2e8f0;text-transform:uppercase;font-weight:600;color:{color};\">{}</td>\n          <td style=\"padding:6px 12px;border-bottom:1px solid #e2e8f0;\">{}</td>\n          <td style=\"padding:6px 12px;border-bottom:1px solid #e2e8f0;font-family:monospace;\">{location}</td>\n          <td style=\"padding:6px 12px;border-bottom:1px solid #e2e8f0;\">{}</td>\n          <td style=\"padding:6px 12px;border-bottom:1px solid #e2e8f0;\">{}</td>\n        </tr>",
                escape_html_mail(a.issue.severity),
                escape_html_mail(a.issue.category),
                escape_html_mail(a.issue.summary),
                escape_html_mail(a.justification),
            )
        })
        .collect();

    let error_count = details.applied.iter().filter(|a| a.issue.severity == "error").count();
    let phase_title = escape_html_mail(phase_titles.get(&details.phase).map(String::as_str).unwrap_or("Unknown"));
    let subject = format!("[Ignite] \u{26a0} {} guideline override(s) at Phase {} — {}/{}", details.applied.len(), details.phase, strip_crlf(details.org), strip_crlf(details.repo));
    let actor_display = escape_html_mail(details.actor.name.unwrap_or(details.actor.email));
    let html = format!(
        "\n    <div style=\"font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:760px;margin:0 auto;color:#334155;\">\n      <h2 style=\"color:#b45309;\">A developer overrode flagged guideline check(s)</h2>\n      <p><strong>Target:</strong> {}/{}<br/>\n         <strong>Job:</strong> {}<br/>\n         <strong>Phase:</strong> {} — {phase_title}<br/>\n         <strong>Overridden by:</strong> {actor_display} ({})<br/>\n         <strong>Blocking findings bypassed:</strong> {error_count} of {}</p>\n      <table style=\"border-collapse:collapse;width:100%;font-size:13px;\">\n        <tr style=\"background:#f1f5f9;\">\n          <th style=\"padding:6px 12px;text-align:left;\">Severity</th>\n          <th style=\"padding:6px 12px;text-align:left;\">Category</th>\n          <th style=\"padding:6px 12px;text-align:left;\">Location</th>\n          <th style=\"padding:6px 12px;text-align:left;\">Finding</th>\n          <th style=\"padding:6px 12px;text-align:left;\">Justification</th>\n        </tr>\n        {rows}\n      </table>\n      <p style=\"color:#94a3b8;font-size:12px;margin-top:24px;\">Sent by Ignite — this override is recorded in the project's audit log.</p>\n    </div>",
        escape_html_mail(details.org),
        escape_html_mail(details.repo),
        escape_html_mail(details.job_id),
        details.phase,
        escape_html_mail(details.actor.email),
        details.applied.len(),
    );

    Email { subject, html }
}

pub struct ApiKeyCreatedDetails<'a> {
    pub owner_email: &'a str,
    pub owner_name: Option<&'a str>,
    pub label: Option<&'a str>,
    pub created_by: Option<&'a str>,
    pub created_via: Option<&'a str>,
}

pub fn build_api_key_created_email(details: &ApiKeyCreatedDetails) -> Email {
    let subject = "[Ignite] A new API key was created for your account".to_string();
    let account = escape_html_mail(details.owner_name.unwrap_or(details.owner_email));
    let html = format!(
        "\n    <div style=\"font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:640px;margin:0 auto;color:#334155;\">\n      <h2 style=\"color:#b45309;\">A new API key was created for your Ignite account</h2>\n      <p><strong>Account:</strong> {account} ({})<br/>\n         <strong>Label:</strong> {}<br/>\n         <strong>Created via:</strong> {}<br/>\n         <strong>Created by:</strong> {}</p>\n      <p>This key can authenticate as you against the Ignite API without a browser\n         login. If you did not request this, revoke it immediately and notify\n         an administrator.</p>\n      <p style=\"color:#94a3b8;font-size:12px;margin-top:24px;\">Sent by Ignite — this event is recorded in the account's key audit log.</p>\n    </div>",
        escape_html_mail(details.owner_email),
        escape_html_mail(details.label.unwrap_or("(none)")),
        escape_html_mail(details.created_via.unwrap_or("cli")),
        escape_html_mail(details.created_by.unwrap_or("unknown")),
    );
    Email { subject, html }
}

// ---------------------------------------------------------------------------
// Send functions — the new transport-wired counterparts
// ---------------------------------------------------------------------------

/// Send a pipeline-failure notification email.
///
/// Mirrors Node's `sendFailureNotification`: short-circuits when
/// notifications are disabled or no recipient is configured, builds the
/// transport fresh per call, and returns the outcome.
pub async fn send_failure_notification(
    config: &NotificationsConfig,
    phase_titles: &BTreeMap<i64, String>,
    details: &FailureEmailDetails<'_>,
) -> Result<NotificationResult, NotificationError> {
    if !config.enabled || config.to.is_empty() {
        return Ok(NotificationResult::skipped(
            "notifications disabled or no recipient configured",
        ));
    }
    let email = build_failure_email(phase_titles, details);
    let message = build_message(&config.from, &config.to, &email.subject, &email.html)?;
    send_message(config, message).await?;
    tracing::info!(to = %config.to, "failure notification email sent");
    Ok(NotificationResult::sent(&config.to))
}

/// Send a guideline-override audit-trail notification email.
///
/// Mirrors Node's `sendOverrideNotification`: always notified (this is
/// the whole point of the override audit trail), gated only on
/// `enabled`/`to`.
pub async fn send_override_notification(
    config: &NotificationsConfig,
    phase_titles: &BTreeMap<i64, String>,
    details: &OverrideEmailDetails<'_>,
) -> Result<NotificationResult, NotificationError> {
    if !config.enabled || config.to.is_empty() {
        return Ok(NotificationResult::skipped(
            "notifications disabled or no recipient configured",
        ));
    }
    let email = build_override_email(phase_titles, details);
    let message = build_message(&config.from, &config.to, &email.subject, &email.html)?;
    send_message(config, message).await?;
    tracing::info!(to = %config.to, overrides = details.applied.len(), "override notification email sent");
    Ok(NotificationResult::sent(&config.to))
}

/// Send an API-key-creation notification to the key's **owner** (not the
/// admin `to` list).
///
/// Mirrors Node's `sendApiKeyCreatedNotification`: recipient is the
/// owner's email, not `config.to` — silent minting is exactly the
/// impersonation vector this guards against.
pub async fn send_api_key_created_notification(
    config: &NotificationsConfig,
    details: &ApiKeyCreatedDetails<'_>,
) -> Result<NotificationResult, NotificationError> {
    if !config.enabled || details.owner_email.is_empty() {
        return Ok(NotificationResult::skipped(
            "notifications disabled or no owner email",
        ));
    }
    let email = build_api_key_created_email(details);
    let message = build_message(&config.from, details.owner_email, &email.subject, &email.html)?;
    send_message(config, message).await?;
    tracing::info!(to = %details.owner_email, "API key creation notification email sent");
    Ok(NotificationResult::sent(details.owner_email))
}

/// Send a scheduled-recheck failure notification to per-repo CODEOWNERS
/// contacts (not the fixed admin `to` list).
///
/// Mirrors Node's `sendScheduledCheckFailureEmail` in
/// `lib/scheduled-rechecks.js`.
pub async fn send_scheduled_check_failure_notification(
    config: &NotificationsConfig,
    org: &str,
    repo: &str,
    error: &str,
    to: &str,
) -> Result<NotificationResult, NotificationError> {
    if !config.enabled {
        return Ok(NotificationResult::skipped("notifications disabled"));
    }
    let subject = format!(
        "[Ignite] \u{274c} Scheduled re-check failed — {}/{}",
        strip_crlf(org),
        strip_crlf(repo)
    );
    let html = format!(
        "\n    <div style=\"font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:720px;margin:0 auto;color:#334155;\">\n      <h2 style=\"color:#e11d48;\">Scheduled compliance re-check failed</h2>\n      <p><strong>Repository:</strong> {}/{}<br/>\n         <strong>Error:</strong> {}</p>\n      <p>The latest scheduled re-scan of this repository encountered an error.\n         Please investigate and re-trigger manually if needed.</p>\n      <p style=\"color:#94a3b8;font-size:12px;margin-top:24px;\">Sent by Ignite — this is an automated compliance monitoring alert.</p>\n    </div>",
        escape_html_mail(org),
        escape_html_mail(repo),
        escape_html_mail(error),
    );
    let message = build_message(&config.from, to, &subject, &html)?;
    send_message(config, message).await?;
    tracing::info!(%to, "scheduled-recheck failure notification email sent");
    Ok(NotificationResult::sent(to))
}

// ---------------------------------------------------------------------------
// Convenience: convert a HashMap<i64, (String, Vec<String>)> (the shape
// all three Logger/EventLog types use internally) into the BTreeMap<i64,
// PhaseState> that `build_failure_email` expects.
// ---------------------------------------------------------------------------

/// Convert a phase-record map (as stored by the pipeline Logger structs)
/// into the `BTreeMap<i64, PhaseState>` shape `build_failure_email` needs.
pub fn phase_records_to_state(
    records: &std::collections::HashMap<i64, (String, Vec<String>)>,
) -> BTreeMap<i64, PhaseState> {
    records
        .iter()
        .map(|(k, (state, logs))| {
            (*k, PhaseState { state: state.clone(), logs: logs.clone() })
        })
        .collect()
}

/// Convert from the route-local `PhaseRecord { state, logs }` HashMap
/// variant (used by `pipeline_validate.rs` and `pipeline_onboard.rs`
/// where the record is `HashMap<i64, PhaseRecord>` behind a Mutex).
///
/// Callers should extract their record into `Vec<(i64, String, Vec<String>)>`
/// and pass it here — this avoids coupling to each route's private
/// `PhaseRecord` type.
pub fn phase_tuples_to_state(
    tuples: &[(i64, String, Vec<String>)],
) -> BTreeMap<i64, PhaseState> {
    tuples
        .iter()
        .map(|(id, state, logs)| {
            (*id, PhaseState { state: state.clone(), logs: logs.clone() })
        })
        .collect()
}

/// Build a `BTreeMap<i64, String>` of phase titles from a slice of
/// `(id, title)` pairs — convenience for call sites that resolve phase
/// metadata via `resolve_phase_meta` and need to pass it to the email
/// builders.
pub fn phase_titles_map(meta: &[(i64, String)]) -> BTreeMap<i64, String> {
    meta.iter().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn titles() -> BTreeMap<i64, String> {
        BTreeMap::from([(1, "Structure audit".to_string()), (2, "Secret scan".to_string()), (3, "AI governance".to_string())])
    }

    #[test]
    fn escapes_html_special_chars() {
        assert_eq!(escape_html_mail("<script>a & b</script>"), "&lt;script&gt;a &amp; b&lt;/script&gt;");
    }

    #[test]
    fn failure_email_includes_phase_rows_and_error() {
        let mut record = BTreeMap::new();
        record.insert(1, PhaseState { state: "success".to_string(), logs: vec![] });
        record.insert(2, PhaseState { state: "failed".to_string(), logs: vec!["boom".to_string()] });
        let details = FailureEmailDetails { job_id: "job-1", org: "acme", repo: "widgets", error: "secret found", failed_phase: 2, record: &record, insight: None };
        let email = build_failure_email(&titles(), &details);
        assert!(email.subject.contains("Phase 2"));
        assert!(email.subject.contains("acme/widgets"));
        assert!(email.html.contains("Phase 2 — Secret scan logs"));
        assert!(email.html.contains("boom"));
        assert!(email.html.contains("secret found"));
    }

    #[test]
    fn failure_email_escapes_untrusted_fields() {
        let record = BTreeMap::new();
        let details = FailureEmailDetails { job_id: "job-1", org: "<b>acme</b>", repo: "widgets", error: "err", failed_phase: 1, record: &record, insight: None };
        let email = build_failure_email(&titles(), &details);
        assert!(!email.html.contains("<b>acme</b>"));
        assert!(email.html.contains("&lt;b&gt;acme&lt;/b&gt;"));
    }

    #[test]
    fn failure_email_includes_insight_block_only_when_present() {
        let record = BTreeMap::new();
        let with = FailureEmailDetails { job_id: "j", org: "a", repo: "b", error: "e", failed_phase: 1, record: &record, insight: Some("try X") };
        assert!(build_failure_email(&titles(), &with).html.contains("AI insight"));
        let without = FailureEmailDetails { job_id: "j", org: "a", repo: "b", error: "e", failed_phase: 1, record: &record, insight: None };
        assert!(!build_failure_email(&titles(), &without).html.contains("AI insight"));
    }

    #[test]
    fn override_email_counts_blocking_findings_and_subject() {
        let issue_a = IssueLike { severity: "error", category: "secret", file: Some("a.js"), line: Some(3), summary: "hardcoded key" };
        let issue_b = IssueLike { severity: "warning", category: "license", file: None, line: None, summary: "unclear license" };
        let applied = vec![AppliedOverride { issue: issue_a, justification: "rotated" }, AppliedOverride { issue: issue_b, justification: "reviewed" }];
        let details = OverrideEmailDetails { job_id: "job-1", org: "acme", repo: "widgets", phase: 4, actor: Actor { name: Some("Nuno"), email: "nuno@example.com" }, applied: &applied };
        let email = build_override_email(&titles(), &details);
        assert!(email.subject.contains("2 guideline override(s)"));
        assert!(email.html.contains("1 of 2"));
        assert!(email.html.contains("a.js:3"));
        assert!(email.html.contains("Nuno"));
    }

    #[test]
    fn api_key_email_uses_owner_email_when_no_name() {
        let details = ApiKeyCreatedDetails { owner_email: "nuno@example.com", owner_name: None, label: None, created_by: None, created_via: None };
        let email = build_api_key_created_email(&details);
        assert!(email.html.contains("nuno@example.com"));
        assert!(email.html.contains("(none)"));
        assert!(email.html.contains("cli"));
        assert!(email.html.contains("unknown"));
    }

    #[tokio::test]
    async fn send_failure_skips_when_disabled() {
        let config = NotificationsConfig::default();
        let titles = titles();
        let record = BTreeMap::new();
        let details = FailureEmailDetails { job_id: "j", org: "a", repo: "b", error: "e", failed_phase: 1, record: &record, insight: None };
        let result = send_failure_notification(&config, &titles, &details).await.unwrap();
        assert!(!result.sent);
        assert!(result.reason.unwrap().contains("disabled"));
    }

    #[tokio::test]
    async fn send_override_skips_when_disabled() {
        let config = NotificationsConfig::default();
        let titles = titles();
        let details = OverrideEmailDetails { job_id: "j", org: "a", repo: "b", phase: 4, actor: Actor { name: None, email: "x@y.com" }, applied: &[] };
        let result = send_override_notification(&config, &titles, &details).await.unwrap();
        assert!(!result.sent);
    }

    #[tokio::test]
    async fn send_api_key_created_skips_when_disabled() {
        let config = NotificationsConfig::default();
        let details = ApiKeyCreatedDetails { owner_email: "nuno@example.com", owner_name: None, label: None, created_by: None, created_via: None };
        let result = send_api_key_created_notification(&config, &details).await.unwrap();
        assert!(!result.sent);
    }

    #[test]
    fn build_message_rejects_empty_recipient() {
        let err = build_message("from@x.com", "", "subject", "<p>body</p>").unwrap_err();
        assert!(err.message.contains("no valid recipient"));
    }

    #[test]
    fn build_message_accepts_comma_separated_recipients() {
        let msg = build_message("from@x.com", "a@x.com, b@x.com", "subject", "<p>body</p>").unwrap();
        let headers = msg.headers().to_string();
        assert!(headers.contains("a@x.com"));
        assert!(headers.contains("b@x.com"));
    }

    #[test]
    fn phase_records_to_state_converts_correctly() {
        let mut records = std::collections::HashMap::new();
        records.insert(1, ("success".to_string(), vec!["ok".to_string()]));
        records.insert(2, ("failed".to_string(), vec!["err".to_string()]));
        let state = phase_records_to_state(&records);
        assert_eq!(state[&1].state, "success");
        assert_eq!(state[&2].logs, vec!["err"]);
    }
}
