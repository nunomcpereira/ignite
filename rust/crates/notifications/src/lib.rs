//! Faithful port of `lib/notifications.js`'s email-building functions —
//! pipeline-failure and override-audit-trail notifications. Only the pure
//! HTML/subject builders are ported here; `buildMailTransport`/
//! `send*Notification`'s actual SMTP send (nodemailer, with a sendmail
//! fallback) isn't wired up yet — needs a mail-transport crate decision
//! and the HTTP/background-job layer that would call it.

use std::collections::BTreeMap;

pub fn escape_html_mail(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
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
            let title = &phase_titles[id];
            format!(
                "<tr>\n          <td style=\"padding:6px 12px;border-bottom:1px solid #e2e8f0;\">Phase {id}</td>\n          <td style=\"padding:6px 12px;border-bottom:1px solid #e2e8f0;\">{title}</td>\n          <td style=\"padding:6px 12px;border-bottom:1px solid #e2e8f0;color:{color};font-weight:600;text-transform:uppercase;\">{}</td>\n        </tr>",
                ph.state
            )
        })
        .collect();

    let failed_sections: String = details
        .record
        .iter()
        .filter(|(_, ph)| ph.state == "failed" && !ph.logs.is_empty())
        .map(|(id, ph)| {
            let title = phase_titles.get(id).map(String::as_str).unwrap_or("Unknown");
            let logs = escape_html_mail(&ph.logs.join("\n"));
            format!(
                "\n        <h3 style=\"margin:24px 0 8px;color:#0f172a;\">Phase {id} — {title} logs</h3>\n        <pre style=\"background:#0f172a;color:#e2e8f0;padding:14px;border-radius:8px;font-size:12px;line-height:1.6;overflow-x:auto;white-space:pre-wrap;\">{logs}</pre>"
            )
        })
        .collect();

    let failed_phase_title = phase_titles.get(&details.failed_phase).map(String::as_str).unwrap_or("Unknown");
    let subject = format!("[Ignite] \u{274c} Onboarding failed at Phase {} — {}/{}", details.failed_phase, details.org, details.repo);
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
        details.job_id,
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
    let phase_title = phase_titles.get(&details.phase).map(String::as_str).unwrap_or("Unknown");
    let subject = format!("[Ignite] \u{26a0} {} guideline override(s) at Phase {} — {}/{}", details.applied.len(), details.phase, details.org, details.repo);
    let actor_display = escape_html_mail(details.actor.name.unwrap_or(details.actor.email));
    let html = format!(
        "\n    <div style=\"font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:760px;margin:0 auto;color:#334155;\">\n      <h2 style=\"color:#b45309;\">A developer overrode flagged guideline check(s)</h2>\n      <p><strong>Target:</strong> {}/{}<br/>\n         <strong>Job:</strong> {}<br/>\n         <strong>Phase:</strong> {} — {phase_title}<br/>\n         <strong>Overridden by:</strong> {actor_display} ({})<br/>\n         <strong>Blocking findings bypassed:</strong> {error_count} of {}</p>\n      <table style=\"border-collapse:collapse;width:100%;font-size:13px;\">\n        <tr style=\"background:#f1f5f9;\">\n          <th style=\"padding:6px 12px;text-align:left;\">Severity</th>\n          <th style=\"padding:6px 12px;text-align:left;\">Category</th>\n          <th style=\"padding:6px 12px;text-align:left;\">Location</th>\n          <th style=\"padding:6px 12px;text-align:left;\">Finding</th>\n          <th style=\"padding:6px 12px;text-align:left;\">Justification</th>\n        </tr>\n        {rows}\n      </table>\n      <p style=\"color:#94a3b8;font-size:12px;margin-top:24px;\">Sent by Ignite — this override is recorded in the project's audit log.</p>\n    </div>",
        escape_html_mail(details.org),
        escape_html_mail(details.repo),
        details.job_id,
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
}
