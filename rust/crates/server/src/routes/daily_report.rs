//! Org-level daily findings report: once a day (default 23:59 server-local
//! time, `dailyReport.time`), deliver each org one digest listing every repo
//! and the findings on its most recent scan that nobody has justified yet
//! (`status = 'open'` — see `DbStore::list_latest_scan_unjustified_findings`).
//! Off by default (`dailyReport.enabled`, or the same flag saved from the
//! admin UI into `app_settings` — see `settings.rs` for the precedence).
//! `POST /api/reports/daily/run` triggers the same run on demand
//! (`dryRun=true` previews without sending).
//!
//! Four delivery channels, each independent and best-effort (one failing
//! never aborts the others): `email` (HTML digest; needs
//! `notifications.enabled`), `pdf` (headless Chrome render), `webhook` (JSON
//! POST carrying a pre-built Microsoft Sentinel incident object) and
//! `azure_blob` (`.json` + `.pdf` PUT into a container via its SAS URL).
//!
//! Unlike the scan sweeps (which stay on an external timer so they don't
//! load the server), this only reads `ignite.db` and sends a few messages,
//! so it runs on a small in-process timer and needs no cron/launchd setup.
//!
//! Secrets (webhook token, SAS query strings, Logic App `sig=`) are never
//! logged or echoed in an error: every URL goes through `redact_url` first.

use crate::auth::RequireAuth;
use crate::routes::settings::{resolve_daily_report_settings, ResolvedDailyReport};
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Local, NaiveTime};
use ignite_notifications::{DailyReportCodeLine, DailyReportDetails, DailyReportFinding, DailyReportRepo};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

/// `app_settings` key holding the local date (`YYYY-MM-DD`) of the last
/// scheduled run, so a restart later the same night doesn't send twice.
const LAST_RUN_SETTING: &str = "daily_report_last_run_date";
const TICK: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Email,
    Pdf,
    Webhook,
    AzureBlob,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Email => "email",
            Channel::Pdf => "pdf",
            Channel::Webhook => "webhook",
            Channel::AzureBlob => "azure_blob",
        }
    }

    fn parse(raw: &str) -> Option<Channel> {
        match raw.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "email" => Some(Channel::Email),
            "pdf" => Some(Channel::Pdf),
            "webhook" | "sentinel" => Some(Channel::Webhook),
            "azure_blob" | "azure" | "blob" => Some(Channel::AzureBlob),
            _ => None,
        }
    }
}

/// Parses a comma-separated channel list; an empty string means "all
/// configured" (an empty result). Unknown names are an error, not ignored —
/// a typo'd channel silently doing nothing would look like a delivered report.
pub fn parse_channels(raw: &str) -> Result<Vec<Channel>, String> {
    let mut out = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let channel = Channel::parse(part).ok_or_else(|| format!("Unknown channel '{part}' (use email, pdf, webhook, azure_blob)."))?;
        if !out.contains(&channel) {
            out.push(channel);
        }
    }
    Ok(out)
}

#[derive(Debug, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct OrgReportOutcome {
    pub org: String,
    pub repos: usize,
    pub unjustified_findings: usize,
    /// True when at least one *delivery* channel (email, webhook, Azure
    /// Blob) succeeded. A generated PDF alone is not a delivery.
    pub sent: bool,
    /// Why the email was skipped, or "dry run".
    pub reason: Option<String>,
    /// All channel errors joined (each also has its own field below).
    pub error: Option<String>,
    pub email_sent: bool,
    pub email_error: Option<String>,
    pub webhook_sent: bool,
    pub webhook_error: Option<String>,
    pub azure_blob_sent: bool,
    pub azure_blob_error: Option<String>,
    pub pdf_generated: bool,
    pub pdf_error: Option<String>,
    /// Only populated on a dry run, so the caller can preview the email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    /// Dry run only: the exact JSON the webhook / Azure `.json` would carry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_payload: Option<Value>,
    /// Dry run only: the Sentinel incident description (markdown).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
    /// The full, uncapped report HTML the PDF is printed from (the emailed
    /// `html` caps findings per repo). Internal — never serialized.
    #[serde(skip)]
    pub pdf_html: Option<String>,
}

#[derive(Debug, Default)]
pub struct RunOptions<'a> {
    pub only_org: Option<&'a str>,
    pub dry_run: bool,
    /// Calendar date the report covers, `YYYY-MM-DD`.
    pub date: &'a str,
    /// Empty = every channel that is configured (email always, since it
    /// reports its own "skipped: notifications disabled" reason).
    pub channels: Vec<Channel>,
    /// One-off webhook URL; the stored token is *not* sent to it.
    pub webhook_url: Option<&'a str>,
    /// One-off recipient(s), replacing the resolved `to`.
    pub to: Option<&'a str>,
}

fn wants(opts: &RunOptions, channel: Channel, configured: bool) -> bool {
    if opts.channels.is_empty() {
        match channel {
            Channel::Email => true,
            Channel::Pdf => false,
            Channel::Webhook | Channel::AzureBlob => configured,
        }
    } else {
        opts.channels.contains(&channel)
    }
}

/// Builds and (unless `dry_run`) delivers one report per org that has at
/// least one repo, or just `only_org` when given. One org's failure never
/// stops the others.
pub async fn run_daily_report(state: &AppState, opts: &RunOptions<'_>) -> Vec<OrgReportOutcome> {
    let all = state.db.list_latest_scan_unjustified_findings(opts.only_org);
    let settings = resolve_daily_report_settings(&state.db, &state.config.daily_report, &state.config.notifications.to);
    let client = delivery_client();
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
        let details = DailyReportDetails { org, date: opts.date, repos: &repos };
        outcomes.push(deliver_org(state, &settings, &client, opts, &details).await);
    }
    outcomes
}

async fn deliver_org(state: &AppState, settings: &ResolvedDailyReport, client: &reqwest::Client, opts: &RunOptions<'_>, details: &DailyReportDetails<'_>) -> OrgReportOutcome {
    let org = details.org;
    let mut outcome = OrgReportOutcome { org: org.to_string(), repos: details.repos.len(), unjustified_findings: details.repos.iter().map(|r| r.findings.len()).sum(), ..Default::default() };
    let email = ignite_notifications::build_daily_report_email(details);
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let (payload, markdown) = build_sentinel_payload(details, &timestamp);

    if opts.dry_run {
        outcome.pdf_html = Some(ignite_notifications::build_daily_report_document(details).html);
        outcome.subject = Some(email.subject);
        outcome.html = Some(email.html);
        outcome.webhook_payload = Some(payload);
        outcome.markdown = Some(markdown);
        outcome.reason = Some("dry run".to_string());
        return outcome;
    }

    // ---- email ----
    if wants(opts, Channel::Email, true) {
        let to = opts.to.map(str::trim).filter(|t| !t.is_empty()).unwrap_or(&settings.to);
        match ignite_notifications::send_daily_report_notification(&state.config.notifications, to, details).await {
            Ok(result) => {
                outcome.email_sent = result.sent;
                outcome.reason = result.reason;
            }
            Err(e) => {
                tracing::warn!(org, error = %e, "daily report email failed");
                outcome.email_error = Some(e.to_string());
            }
        }
    }

    // ---- webhook / Sentinel ----
    let override_url = opts.webhook_url.map(str::trim).filter(|u| !u.is_empty());
    let webhook_url = override_url.unwrap_or(&settings.webhook_url);
    if wants(opts, Channel::Webhook, !webhook_url.is_empty()) {
        if webhook_url.is_empty() {
            outcome.webhook_error = Some("no webhook URL configured".to_string());
        } else {
            // The stored token belongs to the stored URL only.
            let token = (webhook_url == settings.webhook_url && !settings.webhook_token.is_empty()).then_some(settings.webhook_token.as_str());
            match validate_https_url(webhook_url) {
                Err(e) => outcome.webhook_error = Some(e),
                Ok(_) => match post_webhook(client, webhook_url, token, &payload).await {
                    Ok(()) => outcome.webhook_sent = true,
                    Err(e) => {
                        tracing::warn!(org, target = %redact_url(webhook_url), error = %e, "daily report webhook failed");
                        outcome.webhook_error = Some(e);
                    }
                },
            }
        }
    }

    // ---- PDF (its own channel, and the second Azure blob) ----
    let want_pdf = wants(opts, Channel::Pdf, false);
    let want_blob = wants(opts, Channel::AzureBlob, !settings.azure_blob_container_url.is_empty());
    let mut pdf_bytes: Option<Vec<u8>> = None;
    // No point launching a browser for a blob nobody can upload.
    if want_pdf || (want_blob && !settings.azure_blob_container_url.is_empty()) {
        if state.runner.binary_for("chrome").is_none() {
            let msg = "no Chrome/Chromium/Edge found on the server (or set dailyReport.pdfBrowserBinary)".to_string();
            if want_pdf {
                outcome.pdf_error = Some(msg);
            } else {
                tracing::info!(org, "Azure Blob report: PDF skipped, {msg}");
                outcome.pdf_error = Some(format!("PDF not uploaded: {msg}"));
            }
        } else {
            let document = ignite_notifications::build_daily_report_document(details);
            match render_pdf(&state.runner, &document.html).await {
                Ok(bytes) => {
                    outcome.pdf_generated = true;
                    pdf_bytes = Some(bytes);
                }
                Err(e) => {
                    tracing::warn!(org, error = %e, "daily report PDF render failed");
                    outcome.pdf_error = Some(e);
                }
            }
        }
    }

    // ---- Azure Blob ----
    if want_blob {
        if settings.azure_blob_container_url.is_empty() {
            outcome.azure_blob_error = Some("no Azure Blob container URL configured".to_string());
        } else {
            let container = settings.azure_blob_container_url.as_str();
            let json_name = blob_name(org, opts.date, "json");
            let body = serde_json::to_vec_pretty(&payload).unwrap_or_default();
            match put_blob(client, container, &json_name, "application/json", body).await {
                Ok(()) => outcome.azure_blob_sent = true,
                Err(e) => {
                    tracing::warn!(org, target = %redact_url(container), error = %e, "daily report Azure Blob JSON upload failed");
                    outcome.azure_blob_error = Some(e);
                }
            }
            if let Some(bytes) = pdf_bytes.take_if(|_| outcome.azure_blob_sent) {
                if let Err(e) = put_blob(client, container, &blob_name(org, opts.date, "pdf"), "application/pdf", bytes).await {
                    tracing::warn!(org, error = %e, "daily report Azure Blob PDF upload failed");
                    outcome.pdf_error = Some(format!("PDF upload to Azure Blob failed: {e}"));
                }
            }
        }
    }

    outcome.sent = outcome.email_sent || outcome.webhook_sent || outcome.azure_blob_sent;
    let errors: Vec<String> = [
        outcome.email_error.as_ref().map(|e| format!("email: {e}")),
        outcome.webhook_error.as_ref().map(|e| format!("webhook: {e}")),
        outcome.azure_blob_error.as_ref().map(|e| format!("azure_blob: {e}")),
        // A missing/failed PDF is only an *error* when PDF was asked for.
        outcome.pdf_error.as_ref().filter(|_| want_pdf).map(|e| format!("pdf: {e}")),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !errors.is_empty() {
        outcome.error = Some(errors.join("; "));
    }
    outcome
}

// ---------------- Sentinel payload ----------------

/// Sentinel incident severity from the report's highest finding score
/// (0-10, same scale as the override engine's).
pub fn sentinel_severity(max_score: f64) -> &'static str {
    if max_score >= 9.0 {
        "High"
    } else if max_score >= 7.0 {
        "Medium"
    } else if max_score >= 4.0 {
        "Low"
    } else {
        "Informational"
    }
}

/// Sentinel incident descriptions are limited to 5000 characters.
const MAX_INCIDENT_DESCRIPTION_CHARS: usize = 5000;
const MAX_TOP_FINDINGS: usize = 10;

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// The webhook body (also the Azure `.json` blob) plus the incident
/// description markdown it embeds. `timestamp` is RFC 3339 UTC.
pub fn build_sentinel_payload(details: &DailyReportDetails<'_>, timestamp: &str) -> (Value, String) {
    let all: Vec<(&DailyReportRepo, &DailyReportFinding)> = details.repos.iter().flat_map(|r| r.findings.iter().map(move |f| (r, f))).collect();
    let total = all.len();
    let highest = all.iter().map(|(_, f)| f.score.unwrap_or(0)).max().unwrap_or(0) as f64;
    let (mut critical, mut high, mut medium, mut low) = (0, 0, 0, 0);
    for (_, f) in &all {
        match f.score.unwrap_or(0) {
            s if s >= 9 => critical += 1,
            s if s >= 7 => high += 1,
            s if s >= 4 => medium += 1,
            _ => low += 1,
        }
    }
    let severity = sentinel_severity(highest);

    let mut top: Vec<&(&DailyReportRepo, &DailyReportFinding)> = all.iter().filter(|(_, f)| f.score.unwrap_or(0) >= 7).collect();
    top.sort_by(|a, b| b.1.score.unwrap_or(0).cmp(&a.1.score.unwrap_or(0)).then_with(|| a.0.repo.cmp(b.0.repo)));

    let mut md = format!(
        "**Ignite daily security report — {org} ({date})**\n\n- Repositories: {repos}\n- Unjustified findings: {total} (critical {critical}, high {high}, medium {medium}, low {low})\n- Highest score: {highest:.1}\n",
        org = details.org,
        date = details.date,
        repos = details.repos.len(),
    );
    if !top.is_empty() {
        md.push_str("\n### Top critical/high findings\n");
        for (repo, f) in top.iter().take(MAX_TOP_FINDINGS).map(|t| (t.0, t.1)) {
            let loc = match (f.file, f.line) {
                (Some(file), Some(line)) => format!("{file}:{line}"),
                (Some(file), None) => file.to_string(),
                _ => "(project-wide)".to_string(),
            };
            md.push_str(&format!("- **{}** `{}` `{}` — {} (score {})\n", repo.repo, loc, f.category, truncate_chars(&one_line(f.summary), 200), f.score.unwrap_or(0)));
        }
        if top.len() > MAX_TOP_FINDINGS {
            md.push_str(&format!("- …and {} more\n", top.len() - MAX_TOP_FINDINGS));
        }
    }
    let with_findings: Vec<&DailyReportRepo> = details.repos.iter().filter(|r| !r.findings.is_empty()).collect();
    if !with_findings.is_empty() {
        md.push_str("\n### Repositories with findings\n");
        for r in with_findings.iter().take(25) {
            md.push_str(&format!("- {} — {}\n", r.repo, r.findings.len()));
        }
        if with_findings.len() > 25 {
            md.push_str(&format!("- …and {} more\n", with_findings.len() - 25));
        }
    }
    let description = truncate_chars(&md, MAX_INCIDENT_DESCRIPTION_CHARS);

    let repos_json: Vec<Value> = details
        .repos
        .iter()
        .map(|r| {
            let shown: Vec<Value> = r
                .findings
                .iter()
                .map(|f| json!({ "severity": f.severity, "category": f.category, "file": f.file, "line": f.line, "summary": one_line(f.summary), "score": f.score }))
                .collect();
            json!({
                "repo": r.repo,
                "status": r.status,
                "lastScanAt": r.last_scan_at,
                "unjustifiedFindings": r.findings.len(),
                "findings": shown,
            })
        })
        .collect();

    let payload = json!({
        "event": "ignite.daily_report",
        "org": details.org,
        "date": details.date,
        "timestamp": timestamp,
        "reposCount": details.repos.len(),
        "unjustifiedFindingsCount": total,
        "highestScore": highest,
        "severityCounts": { "critical": critical, "high": high, "medium": medium, "low": low },
        "sentinelIncident": {
            "title": format!("[Ignite] Daily Security Report: {} ({} unjustified finding{})", details.org, total, if total == 1 { "" } else { "s" }),
            "severity": severity,
            "description": description,
            "classification": "TruePositive",
            "status": "New",
            "labels": ["Ignite", "AppSec", details.org],
        },
        "repos": repos_json,
    });
    (payload, md)
}

/// Sample body for the admin "Test connection" probe. Same envelope as a
/// real report so a Logic App's parsing can be validated, but clearly a test.
pub fn build_test_payload(timestamp: &str) -> Value {
    json!({
        "event": "ignite.test",
        "org": "ignite-connection-test",
        "date": timestamp.get(..10).unwrap_or(timestamp),
        "timestamp": timestamp,
        "reposCount": 0,
        "unjustifiedFindingsCount": 0,
        "highestScore": 0.0,
        "severityCounts": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
        "sentinelIncident": {
            "title": "[Ignite] Connection test",
            "severity": "Informational",
            "description": "Test payload from Ignite's admin settings. No action needed.",
            "classification": "BenignPositive",
            "status": "Closed",
            "labels": ["Ignite", "Test"],
        },
        "repos": [],
    })
}

// ---------------- delivery transports ----------------

/// HTTP client for outbound deliveries: bounded time, and no redirects — a
/// configured endpoint bouncing us elsewhere would forward the report (and
/// possibly the bearer token) to a host nobody configured.
pub fn delivery_client() -> reqwest::Client {
    reqwest::Client::builder().timeout(Duration::from_secs(60)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_default()
}

/// `raw` without its query string/fragment (which is where SAS tokens and
/// Logic App `sig=` values live), marked `?…` when something was dropped.
/// Safe to log or return to a browser. Unparseable input yields `<invalid url>`.
pub fn redact_url(raw: &str) -> String {
    if raw.trim().is_empty() {
        return String::new();
    }
    match url::Url::parse(raw.trim()) {
        Ok(mut u) => {
            let had_secret = u.query().is_some() || u.fragment().is_some();
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.set_query(None);
            u.set_fragment(None);
            if had_secret { format!("{u}?…") } else { u.to_string() }
        }
        Err(_) => "<invalid url>".to_string(),
    }
}

pub fn validate_https_url(raw: &str) -> Result<url::Url, String> {
    let u = url::Url::parse(raw.trim()).map_err(|_| "not a valid URL".to_string())?;
    if u.scheme() != "https" {
        return Err("must be an https:// URL".to_string());
    }
    if u.host_str().is_none_or(str::is_empty) {
        return Err("URL has no host".to_string());
    }
    Ok(u)
}

/// A container SAS URL must be https and name a container (`/<container>`).
pub fn validate_azure_container_url(raw: &str) -> Result<url::Url, String> {
    let u = validate_https_url(raw)?;
    if u.path_segments().is_none_or(|mut s| s.all(str::is_empty)) {
        return Err("must include the container name (https://<account>.blob.core.windows.net/<container>?<sas>)".to_string());
    }
    Ok(u)
}

/// `<container URL>/<blob_name>?<sas>`: the blob name's segments are
/// appended (percent-encoded) to the container path and the SAS query
/// string is carried over unchanged.
pub fn azure_blob_url(container_url: &str, blob_name: &str) -> Result<String, String> {
    let mut u = validate_azure_container_url(container_url)?;
    u.path_segments_mut().map_err(|_| "URL cannot be a base".to_string())?.pop_if_empty().extend(blob_name.split('/').filter(|s| !s.is_empty()));
    Ok(u.to_string())
}

/// `reports/{org}/{date}/ignite-report-{org}-{date}.{ext}`
pub fn blob_name(org: &str, date: &str, ext: &str) -> String {
    format!("reports/{org}/{date}/ignite-report-{org}-{date}.{ext}")
}

fn response_snippet(body: &str) -> String {
    truncate_chars(&one_line(body), 200)
}

/// POSTs `payload` as JSON. `token`, when given, is sent as a bearer token.
/// Errors never contain the URL (reqwest's are stripped with `without_url`).
pub async fn post_webhook(client: &reqwest::Client, url: &str, token: Option<&str>, payload: &Value) -> Result<(), String> {
    let mut req = client.post(url).header(header::CONTENT_TYPE, "application/json").header("X-Ignite-Client", "daily-report").json(payload);
    if let Some(t) = token.map(str::trim).filter(|t| !t.is_empty()) {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.map_err(|e| e.without_url().to_string())?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let body = resp.text().await.unwrap_or_default();
    Err(format!("webhook answered HTTP {status}: {}", response_snippet(&body)))
}

/// PUTs `bytes` as a block blob at `blob_name` inside the SAS-authorized container.
pub async fn put_blob(client: &reqwest::Client, container_url: &str, blob_name: &str, content_type: &str, bytes: Vec<u8>) -> Result<(), String> {
    let url = azure_blob_url(container_url, blob_name)?;
    let resp = client
        .put(url)
        .header("x-ms-blob-type", "BlockBlob")
        .header(header::CONTENT_TYPE, content_type)
        .body(bytes)
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let body = resp.text().await.unwrap_or_default();
    Err(format!("Azure Blob answered HTTP {status}: {}", response_snippet(&body)))
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
pub fn parse_time(raw: &str) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(raw.trim(), "%H:%M").ok()
}

/// True when the scheduled run for `today` is due: the configured time has
/// been reached and nothing has run yet today.
fn is_due(now: NaiveTime, target: NaiveTime, today: &str, last_run: Option<&str>) -> bool {
    now >= target && last_run != Some(today)
}

/// Starts the daily timer. Call once at boot. It always runs and re-resolves
/// the settings every tick (a cheap `app_settings` read), so enabling the
/// report or changing its time from the admin UI takes effect without a restart.
pub fn spawn_scheduler(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(TICK);
        let mut warned_time = String::new();
        loop {
            interval.tick().await;
            let settings = resolve_daily_report_settings(&state.db, &state.config.daily_report, &state.config.notifications.to);
            if !settings.enabled {
                continue;
            }
            let Some(target) = parse_time(&settings.time) else {
                if warned_time != settings.time {
                    tracing::warn!(time = %settings.time, "daily report time is not HH:MM — scheduled run skipped");
                    warned_time = settings.time.clone();
                }
                continue;
            };
            let now = Local::now();
            let today = now.date_naive().to_string();
            if !is_due(now.time(), target, &today, state.db.get_setting(LAST_RUN_SETTING).as_deref()) {
                continue;
            }
            let outcomes = run_daily_report(&state, &RunOptions { date: &today, ..Default::default() }).await;
            // Recorded even when a send failed: retrying every tick against
            // a broken SMTP relay would only spam the logs (and any org
            // whose send did succeed would get it again).
            state.db.set_setting(LAST_RUN_SETTING, &today);
            let sent = outcomes.iter().filter(|o| o.sent).count();
            tracing::info!(orgs = outcomes.len(), sent, "daily report run finished");
        }
    });
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RunQuery {
    org: Option<String>,
    #[serde(default)]
    dry_run: bool,
    /// Comma-separated: email,pdf,webhook,azure_blob.
    channels: Option<String>,
    webhook_url: Option<String>,
    to: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(untagged)]
enum ChannelsField {
    List(Vec<String>),
    Csv(String),
    #[default]
    None,
}

/// Optional JSON body; each field, when present, wins over the query string.
/// Preferred for `webhookUrl` (it can embed a secret, and query strings end
/// up in access logs).
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RunBody {
    org: Option<String>,
    dry_run: Option<bool>,
    #[serde(default)]
    channels: ChannelsField,
    webhook_url: Option<String>,
    to: Option<String>,
}

fn bad_request(message: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message.into() }))).into_response()
}

/// `POST /api/reports/daily/run[?org=<org>][&channels=email,webhook][&dryRun=true][&webhookUrl=…][&to=…]`
/// (or the same fields as a JSON body).
async fn run_now(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, Query(query): Query<RunQuery>, body: Bytes) -> Response {
    let body: RunBody = if body.iter().all(u8::is_ascii_whitespace) {
        RunBody::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(b) => b,
            Err(e) => return bad_request(format!("Invalid JSON body: {e}")),
        }
    };
    let dry_run = body.dry_run.unwrap_or(query.dry_run);
    let org = body.org.or(query.org);
    let org = org.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if let Some(org) = org {
        if !ignite_github_api::is_valid_github_owner(org) {
            return bad_request("Invalid GitHub org name.");
        }
    }
    let channels_raw = match body.channels {
        ChannelsField::List(list) => list.join(","),
        ChannelsField::Csv(csv) => csv,
        ChannelsField::None => query.channels.unwrap_or_default(),
    };
    let channels = match parse_channels(&channels_raw) {
        Ok(c) => c,
        Err(e) => return bad_request(e),
    };
    let webhook_url = body.webhook_url.or(query.webhook_url);
    if let Some(url) = webhook_url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        if let Err(e) = validate_https_url(url) {
            return bad_request(format!("webhookUrl: {e}"));
        }
    }
    let to = body.to.or(query.to);
    let today = Local::now().date_naive().to_string();
    let names: Vec<&str> = channels.iter().map(|c| c.as_str()).collect();
    let opts = RunOptions { only_org: org, dry_run, date: &today, channels, webhook_url: webhook_url.as_deref(), to: to.as_deref() };
    let outcomes = run_daily_report(&state, &opts).await;
    Json(json!({ "date": today, "dryRun": dry_run, "channels": names, "reports": outcomes })).into_response()
}

/// The browser used for PDF export: `configured` when set, else the first
/// Chromium-family executable found (macOS app bundles, then common names
/// on `PATH`). `None` when there is none — the export then answers 501.
pub fn detect_pdf_browser(configured: &str) -> Option<String> {
    let configured = configured.trim();
    if !configured.is_empty() {
        return Some(configured.to_string());
    }
    const MAC_APPS: &[&str] = &[
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    ];
    if let Some(found) = MAC_APPS.iter().find(|p| std::path::Path::new(p).is_file()) {
        return Some((*found).to_string());
    }
    let path = std::env::var_os("PATH")?;
    ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "microsoft-edge"]
        .iter()
        .find_map(|name| std::env::split_paths(&path).map(|dir| dir.join(name)).find(|p| p.is_file()))
        .map(|p| p.to_string_lossy().into_owned())
}

/// True once `bytes` look like a finished PDF (header present, `%%EOF` trailer written).
fn is_complete_pdf(bytes: &[u8]) -> bool {
    let tail = &bytes[bytes.len().saturating_sub(64)..];
    bytes.starts_with(b"%PDF") && String::from_utf8_lossy(tail).trim_end().ends_with("%%EOF")
}

/// Polls until `path` holds a complete PDF (see `is_complete_pdf`) and returns it.
/// Never gives up on its own — callers race it against the browser's timeout.
async fn wait_for_pdf(path: &std::path::Path) -> Vec<u8> {
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if let Ok(bytes) = std::fs::read(path) {
            if is_complete_pdf(&bytes) {
                return bytes;
            }
        }
    }
}

/// Prints `html` to PDF with headless Chrome (`--print-to-pdf`) inside a
/// throwaway directory (also its profile dir), via the shared `ToolRunner`
/// like every other external tool.
///
/// Recent Chrome (seen on 153, macOS) writes the PDF within seconds and then
/// never exits, so waiting for the process would always burn the whole
/// timeout. Instead the output file is watched and, once it is a complete
/// PDF, the run future is dropped — `ToolRunner` spawns with `kill_on_drop`,
/// which ends the lingering browser.
async fn render_pdf(runner: &ignite_tool_runner::ToolRunner, html: &str) -> Result<Vec<u8>, String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let html_path = dir.path().join("report.html");
    let pdf_path = dir.path().join("report.pdf");
    std::fs::write(&html_path, html).map_err(|e| e.to_string())?;
    let args = vec![
        "--headless=new".to_string(),
        "--disable-gpu".to_string(),
        "--no-pdf-header-footer".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        format!("--user-data-dir={}", dir.path().join("profile").display()),
        format!("--print-to-pdf={}", pdf_path.display()),
        format!("file://{}", html_path.display()),
    ];
    let opts = ignite_tool_runner::RunToolOptions { timeout_ms: Some(300_000), ..Default::default() };
    let cwd = dir.path().to_string_lossy().into_owned();
    tokio::select! {
        result = runner.run_tool("chrome", &args, &cwd, opts) => {
            result.map_err(|e| e.to_string())?;
            let bytes = std::fs::read(&pdf_path).map_err(|e| format!("the browser produced no PDF: {e}"))?;
            if is_complete_pdf(&bytes) { Ok(bytes) } else { Err("the browser produced an incomplete PDF".to_string()) }
        }
        bytes = wait_for_pdf(&pdf_path) => Ok(bytes),
    }
}

#[derive(Deserialize)]
struct PdfQuery {
    org: String,
}

/// `GET /api/reports/daily/pdf?org=<org>` — the same report the email
/// carries (built as a dry run), returned as a PDF download.
async fn export_pdf(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, Query(query): Query<PdfQuery>) -> Response {
    let org = query.org.trim().to_string();
    if !ignite_github_api::is_valid_github_owner(&org) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid GitHub org name." }))).into_response();
    }
    let today = Local::now().date_naive().to_string();
    let outcomes = run_daily_report(&state, &RunOptions { only_org: Some(&org), dry_run: true, date: &today, ..Default::default() }).await;
    let Some(outcome) = outcomes.into_iter().find(|o| o.pdf_html.is_some()) else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": format!("{org} has no scanned repositories yet — nothing to report.") }))).into_response();
    };
    if state.runner.binary_for("chrome").is_none() {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({ "error": "PDF export needs Chrome, Chromium or Edge on the server (or set dailyReport.pdfBrowserBinary in config.json)." })),
        )
            .into_response();
    }
    match render_pdf(&state.runner, outcome.pdf_html.as_deref().unwrap_or_default()).await {
        Ok(bytes) => {
            let safe_org: String = outcome.org.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')).collect();
            let disposition = format!("attachment; filename=\"ignite-report-{safe_org}-{today}.pdf\"");
            ([(header::CONTENT_TYPE, "application/pdf".to_string()), (header::CONTENT_DISPOSITION, disposition)], bytes).into_response()
        }
        Err(e) => {
            tracing::warn!(org = %org, error = %e, "report PDF export failed");
            (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": format!("PDF export failed: {e}") }))).into_response()
        }
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/reports/daily/run", post(run_now)).route("/api/reports/daily/pdf", get(export_pdf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(h: u32, m: u32) -> NaiveTime {
        NaiveTime::from_hms_opt(h, m, 0).unwrap()
    }

    #[test]
    fn only_a_finished_pdf_counts_as_rendered() {
        assert!(is_complete_pdf(b"%PDF-1.4\n...\n%%EOF\n"));
        assert!(!is_complete_pdf(b"%PDF-1.4\n...half written"));
        assert!(!is_complete_pdf(b"<html>%%EOF"));
        assert!(!is_complete_pdf(b""));
    }

    #[tokio::test]
    async fn wait_for_pdf_returns_once_the_file_is_complete_without_any_process_exiting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.pdf");
        let writer_path = path.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            std::fs::write(&writer_path, b"%PDF-1.4\npartial").unwrap();
            tokio::time::sleep(Duration::from_millis(400)).await;
            std::fs::write(&writer_path, b"%PDF-1.4\nbody\n%%EOF\n").unwrap();
        });
        let bytes = tokio::time::timeout(Duration::from_secs(5), wait_for_pdf(&path)).await.expect("should finish");
        assert!(bytes.ends_with(b"%%EOF\n"));
    }

    /// Real browser, real `ToolRunner`: proves the render returns promptly even
    /// though Chrome may never exit on its own. Skips when no browser is installed.
    #[tokio::test]
    async fn render_pdf_returns_a_real_pdf_promptly_with_a_real_browser() {
        let Some(browser) = detect_pdf_browser("").filter(|b| std::path::Path::new(b).is_file()) else {
            eprintln!("skipping: no Chrome/Chromium/Edge installed");
            return;
        };
        let runner = ignite_tool_runner::ToolRunner::new([("chrome", browser)].into());
        let started = std::time::Instant::now();
        let bytes = render_pdf(&runner, "<html><body><h1>Ignite</h1></body></html>").await.expect("render");
        assert!(is_complete_pdf(&bytes));
        assert!(started.elapsed() < Duration::from_secs(45), "took {:?}", started.elapsed());
    }

    #[test]
    fn parses_hh_mm_and_rejects_garbage() {
        assert_eq!(parse_time("23:59"), Some(t(23, 59)));
        assert_eq!(parse_time(" 07:05 "), Some(t(7, 5)));
        assert_eq!(parse_time("25:00"), None);
        assert_eq!(parse_time("midnight"), None);
    }

    #[test]
    fn a_configured_pdf_browser_wins_over_auto_detection() {
        assert_eq!(detect_pdf_browser("  /opt/custom/chrome  ").as_deref(), Some("/opt/custom/chrome"));
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

        let outcomes = run_daily_report(&state, &RunOptions { dry_run: true, date: "2026-09-18", ..Default::default() }).await;
        assert_eq!(outcomes.iter().map(|o| (o.org.as_str(), o.repos, o.unjustified_findings)).collect::<Vec<_>>(), vec![("acme", 2, 1), ("other", 1, 0)]);
        assert!(outcomes[0].html.as_deref().unwrap().contains("hardcoded key"));
        assert!(!outcomes[0].sent, "dry run never sends");

        let only_other = run_daily_report(&state, &RunOptions { only_org: Some("other"), dry_run: true, date: "2026-09-18", ..Default::default() }).await;
        assert_eq!(only_other.len(), 1);
        assert_eq!(only_other[0].org, "other");
    }

    #[tokio::test]
    async fn real_run_is_skipped_not_failed_when_notifications_are_off() {
        let (_dir, state) = state_with_db();
        state.db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let outcomes = run_daily_report(&state, &RunOptions { date: "2026-09-18", ..Default::default() }).await;
        assert_eq!(outcomes.len(), 1);
        assert!(!outcomes[0].sent);
        assert!(outcomes[0].error.is_none());
        assert!(outcomes[0].reason.as_deref().unwrap().contains("disabled"));
    }

    // ---------------- Sentinel payload / Azure / channels ----------------

    fn finding<'a>(severity: &'a str, summary: &'a str, score: i64) -> DailyReportFinding<'a> {
        DailyReportFinding { severity, category: "secret", file: Some("a.rs"), line: Some(3), summary, score: Some(score), code: vec![] }
    }

    fn payload_for(scores: &[i64]) -> (Value, String) {
        let findings: Vec<DailyReportFinding> = scores.iter().map(|s| finding("error", "leaked key", *s)).collect();
        let repos = [DailyReportRepo { repo: "widgets", status: "success", last_scan_at: "2026-09-19 10:00:00", findings: &findings }];
        build_sentinel_payload(&DailyReportDetails { org: "acme-corp", date: "2026-09-19", repos: &repos }, "2026-09-19T14:00:00Z")
    }

    #[test]
    fn sentinel_severity_follows_the_highest_score() {
        assert_eq!(sentinel_severity(9.5), "High");
        assert_eq!(sentinel_severity(9.0), "High");
        assert_eq!(sentinel_severity(8.9), "Medium");
        assert_eq!(sentinel_severity(7.0), "Medium");
        assert_eq!(sentinel_severity(6.0), "Low");
        assert_eq!(sentinel_severity(4.0), "Low");
        assert_eq!(sentinel_severity(3.0), "Informational");
        assert_eq!(sentinel_severity(0.0), "Informational");
    }

    #[test]
    fn sentinel_payload_has_the_documented_shape() {
        let (p, md) = payload_for(&[10, 8, 5, 2]);
        assert_eq!(p["event"], "ignite.daily_report");
        assert_eq!(p["org"], "acme-corp");
        assert_eq!(p["date"], "2026-09-19");
        assert_eq!(p["timestamp"], "2026-09-19T14:00:00Z");
        assert_eq!(p["reposCount"], 1);
        assert_eq!(p["unjustifiedFindingsCount"], 4);
        assert_eq!(p["highestScore"], 10.0);
        assert_eq!(p["severityCounts"], json!({ "critical": 1, "high": 1, "medium": 1, "low": 1 }));
        let inc = &p["sentinelIncident"];
        assert_eq!(inc["title"], "[Ignite] Daily Security Report: acme-corp (4 unjustified findings)");
        assert_eq!(inc["severity"], "High");
        assert_eq!(inc["classification"], "TruePositive");
        assert_eq!(inc["status"], "New");
        assert_eq!(inc["labels"], json!(["Ignite", "AppSec", "acme-corp"]));
        assert_eq!(inc["description"], md.as_str());
        assert!(md.contains("Top critical/high findings") && md.contains("widgets"));
        assert_eq!(p["repos"][0]["repo"], "widgets");
        assert_eq!(p["repos"][0]["findings"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn incident_severity_tracks_max_score_and_empty_reports_are_informational() {
        assert_eq!(payload_for(&[9, 1]).0["sentinelIncident"]["severity"], "High");
        assert_eq!(payload_for(&[7, 6]).0["sentinelIncident"]["severity"], "Medium");
        assert_eq!(payload_for(&[5]).0["sentinelIncident"]["severity"], "Low");
        assert_eq!(payload_for(&[2]).0["sentinelIncident"]["severity"], "Informational");
        let (empty, _) = payload_for(&[]);
        assert_eq!(empty["sentinelIncident"]["severity"], "Informational");
        assert_eq!(empty["sentinelIncident"]["title"], "[Ignite] Daily Security Report: acme-corp (0 unjustified findings)");
        assert_eq!(payload_for(&[9]).0["sentinelIncident"]["title"], "[Ignite] Daily Security Report: acme-corp (1 unjustified finding)");
    }

    #[test]
    fn a_huge_repo_lists_every_finding_in_the_payload_and_only_the_incident_text_is_capped() {
        let (p, _) = payload_for(&vec![8; 120]);
        assert_eq!(p["unjustifiedFindingsCount"], 120);
        assert_eq!(p["repos"][0]["unjustifiedFindings"], 120);
        assert_eq!(p["repos"][0]["findings"].as_array().unwrap().len(), 120);
        assert!(p["sentinelIncident"]["description"].as_str().unwrap().chars().count() <= MAX_INCIDENT_DESCRIPTION_CHARS);
    }

    #[test]
    fn azure_blob_url_appends_the_blob_path_and_keeps_the_sas_query() {
        let sas = "sv=2022-11-02&sp=w&sig=abc%2Bdef%3D";
        let url = azure_blob_url(&format!("https://acct.blob.core.windows.net/reports-container?{sas}"), &blob_name("acme", "2026-09-19", "json")).unwrap();
        assert_eq!(url, format!("https://acct.blob.core.windows.net/reports-container/reports/acme/2026-09-19/ignite-report-acme-2026-09-19.json?{sas}"));
        // Trailing slash on the container, no double slash.
        let slash = azure_blob_url(&format!("https://acct.blob.core.windows.net/c/?{sas}"), "reports/x.pdf").unwrap();
        assert_eq!(slash, format!("https://acct.blob.core.windows.net/c/reports/x.pdf?{sas}"));
        // A blob name with odd characters is encoded, never able to add a query.
        let odd = azure_blob_url("https://acct.blob.core.windows.net/c?sig=1", "a b?x=1/y#z.json").unwrap();
        assert!(odd.contains("a%20b%3Fx=1/y%23z.json") || odd.contains("a%20b%3Fx=1/y%23z.json?"), "{odd}");
        assert!(odd.ends_with("?sig=1"));
    }

    #[test]
    fn azure_blob_url_rejects_non_https_and_container_less_urls() {
        assert!(azure_blob_url("http://acct.blob.core.windows.net/c?sig=1", "x.json").is_err());
        assert!(azure_blob_url("https://acct.blob.core.windows.net/?sig=1", "x.json").is_err());
        assert!(azure_blob_url("not a url", "x.json").is_err());
    }

    #[test]
    fn blob_names_follow_the_reports_org_date_convention() {
        assert_eq!(blob_name("acme", "2026-09-19", "pdf"), "reports/acme/2026-09-19/ignite-report-acme-2026-09-19.pdf");
    }

    #[test]
    fn redact_url_drops_secrets_from_query_userinfo_and_fragment() {
        assert_eq!(redact_url("https://acct.blob.core.windows.net/c?sv=1&sig=SECRET"), "https://acct.blob.core.windows.net/c?…");
        assert_eq!(redact_url("https://prod-1.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?api-version=2016&sig=SECRET"), "https://prod-1.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?…");
        assert_eq!(redact_url("https://user:pw@x.example/hook"), "https://x.example/hook");
        assert_eq!(redact_url("https://x.example/hook"), "https://x.example/hook");
        assert_eq!(redact_url(""), "");
        assert!(!redact_url("garbage SECRET").contains("SECRET"));
    }

    #[test]
    fn channel_lists_parse_aliases_and_reject_unknown_names() {
        assert_eq!(parse_channels("email, Sentinel ,azure-blob,pdf,email").unwrap(), vec![Channel::Email, Channel::Webhook, Channel::AzureBlob, Channel::Pdf]);
        assert!(parse_channels("").unwrap().is_empty());
        assert!(parse_channels("email,carrier-pigeon").unwrap_err().contains("carrier-pigeon"));
    }

    #[tokio::test]
    async fn dry_run_previews_the_webhook_payload_and_sends_nothing() {
        let (_dir, state) = state_with_db();
        state.db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let out = run_daily_report(&state, &RunOptions { dry_run: true, date: "2026-09-19", ..Default::default() }).await;
        let o = &out[0];
        assert_eq!(o.webhook_payload.as_ref().unwrap()["event"], "ignite.daily_report");
        assert!(o.markdown.as_deref().unwrap().contains("acme"));
        assert!(!o.sent && !o.webhook_sent && !o.azure_blob_sent && !o.email_sent);
    }

    #[tokio::test]
    async fn an_explicitly_requested_unconfigured_channel_reports_its_own_error_without_aborting_others() {
        let (_dir, state) = state_with_db();
        state.db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let out = run_daily_report(&state, &RunOptions { date: "2026-09-19", channels: vec![Channel::Webhook, Channel::AzureBlob, Channel::Email], ..Default::default() }).await;
        let o = &out[0];
        assert_eq!(o.webhook_error.as_deref(), Some("no webhook URL configured"));
        assert_eq!(o.azure_blob_error.as_deref(), Some("no Azure Blob container URL configured"));
        assert!(o.reason.as_deref().unwrap().contains("disabled"), "email still ran and reported its own skip");
        assert!(!o.sent);
        assert!(o.error.as_deref().unwrap().contains("webhook:"));
    }

    #[tokio::test]
    async fn an_http_webhook_override_is_refused_without_a_request() {
        let (_dir, state) = state_with_db();
        state.db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let out = run_daily_report(&state, &RunOptions { date: "d", channels: vec![Channel::Webhook], webhook_url: Some("http://127.0.0.1:1/h"), ..Default::default() }).await;
        assert!(out[0].webhook_error.as_deref().unwrap().contains("https"));
        assert!(!out[0].webhook_sent);
    }

    /// One-shot local HTTP server: answers `status_line` and hands back the raw request it saw.
    async fn one_shot_server(status_line: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook?sig=SECRET", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = sock.read(&mut chunk).await.unwrap();
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(head_end) = text.find("\r\n\r\n") {
                    let len = text.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
                    if buf.len() >= head_end + 4 + len {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            sock.write_all(format!("{status_line}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope").as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buf).to_string()
        });
        (url, handle)
    }

    #[tokio::test]
    async fn post_webhook_sends_json_with_a_bearer_token() {
        let (url, server) = one_shot_server("HTTP/1.1 200 OK").await;
        post_webhook(&delivery_client(), &url, Some("tok-123"), &json!({ "event": "ignite.daily_report" })).await.unwrap();
        let req = server.await.unwrap().to_ascii_lowercase();
        assert!(req.starts_with("post /hook?sig=secret"));
        assert!(req.contains("authorization: bearer tok-123"));
        assert!(req.contains("content-type: application/json"));
        assert!(req.contains("\"event\":\"ignite.daily_report\""));
    }

    #[tokio::test]
    async fn a_failing_webhook_reports_the_status_and_never_the_url() {
        let (url, _server) = one_shot_server("HTTP/1.1 500 Internal Server Error").await;
        let err = post_webhook(&delivery_client(), &url, None, &json!({})).await.unwrap_err();
        assert!(err.contains("500"), "{err}");
        assert!(!err.contains("SECRET") && !err.contains("127.0.0.1"), "URL leaked: {err}");
        // Connection failure: reqwest's own message embeds the URL, so it must be stripped.
        let err = post_webhook(&delivery_client(), "http://127.0.0.1:1/x?sig=SECRET", None, &json!({})).await.unwrap_err();
        assert!(!err.contains("SECRET"), "URL leaked: {err}");
    }
}
