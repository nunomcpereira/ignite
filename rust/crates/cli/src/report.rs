//! `ignite report [org] [--channels email,webhook,azure_blob,pdf] [--webhook-url URL]
//! [--output report.pdf] [--markdown findings.md [--repo name]] [--json] [--dry-run] [--base-url URL]` — triggers the org
//! daily findings report (`POST /api/reports/daily/run`) and/or downloads it as
//! a PDF (`GET /api/reports/daily/pdf`), then prints a per-channel delivery table.
//!
//! Exit codes: 0 = every requested channel succeeded (or dry run), 1 = a channel
//! failed / nothing was delivered, 2 = couldn't reach the server or bad usage.

use serde_json::{json, Value};

pub struct ReportArgs {
    pub org: Option<String>,
    pub channels: Option<String>,
    pub webhook_url: Option<String>,
    pub output: Option<String>,
    /// Write the org's findings (Ignite `.ignite/acknowledgments.md` format) here.
    pub markdown: Option<String>,
    /// With `markdown`: export just this repo's raw acknowledgments file.
    pub repo: Option<String>,
    pub json: bool,
    pub dry_run: bool,
    pub base_url: String,
}

fn normalize_channel(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "sentinel" => "webhook".to_string(),
        "azure" | "blob" => "azure_blob".to_string(),
        other => other.to_string(),
    }
}

/// `(server-side channels, wants the PDF file)`. `--output` without
/// `--channels` means "just give me the PDF".
pub fn split_channels(channels: Option<&str>, output: Option<&str>) -> Result<(Vec<String>, bool), String> {
    let mut list: Vec<String> = channels.unwrap_or("").split(',').map(normalize_channel).filter(|c| !c.is_empty()).collect();
    for c in &list {
        if !matches!(c.as_str(), "email" | "pdf" | "webhook" | "azure_blob") {
            return Err(format!("unknown channel '{c}' (use email, pdf, webhook, azure_blob)"));
        }
    }
    let has_pdf = list.iter().any(|c| c == "pdf");
    if output.is_some() && channels.is_none() {
        return Ok((vec![], true));
    }
    if output.is_some() && !has_pdf {
        return Err("--output writes the PDF, so --channels must include pdf".to_string());
    }
    list.dedup();
    Ok((list.into_iter().filter(|c| c != "pdf" || output.is_none()).collect(), has_pdf && output.is_some()))
}

/// One row per channel that ran (or was explicitly requested):
/// `(channel, status, detail)`.
pub fn channel_rows(report: &Value, requested: &[String], dry_run: bool) -> Vec<(String, String, String)> {
    let flag = |k: &str| report.get(k).and_then(Value::as_bool).unwrap_or(false);
    let text = |k: &str| report.get(k).and_then(Value::as_str).map(str::to_string);
    let asked = |c: &str| requested.iter().any(|r| r == c);
    let mut rows = Vec::new();
    let mut push = |channel: &str, sent_word: &str, sent: bool, error: Option<String>, note: Option<String>, always: bool| {
        if dry_run {
            if always || sent || error.is_some() {
                rows.push((channel.to_string(), "dry run".to_string(), String::new()));
            }
            return;
        }
        if sent {
            rows.push((channel.to_string(), sent_word.to_string(), String::new()));
        } else if let Some(e) = error {
            rows.push((channel.to_string(), "failed".to_string(), e));
        } else if always {
            rows.push((channel.to_string(), "skipped".to_string(), note.unwrap_or_default()));
        }
    };
    push("email", "sent", flag("emailSent"), text("emailError"), text("reason"), requested.is_empty() || asked("email"));
    push("webhook", "sent", flag("webhookSent"), text("webhookError"), None, asked("webhook"));
    push("azure_blob", "sent", flag("azureBlobSent"), text("azureBlobError"), None, asked("azure_blob"));
    push("pdf", "generated", flag("pdfGenerated"), text("pdfError").filter(|_| asked("pdf")), None, asked("pdf"));
    rows
}

pub fn render_table(date: &str, reports: &[Value], requested: &[String], dry_run: bool) -> String {
    let mut out = format!("Ignite daily report — {date}{}\n", if dry_run { " (dry run)" } else { "" });
    if reports.is_empty() {
        out.push_str("  no scanned repositories — nothing to report\n");
        return out;
    }
    out.push_str(&format!("{:<24} {:>5} {:>8}  {:<11} {:<10} {}\n", "ORG", "REPOS", "FINDINGS", "CHANNEL", "STATUS", "DETAIL"));
    for r in reports {
        let org = r.get("org").and_then(Value::as_str).unwrap_or("?");
        let repos = r.get("repos").and_then(Value::as_i64).unwrap_or(0);
        let findings = r.get("unjustifiedFindings").and_then(Value::as_i64).unwrap_or(0);
        let rows = channel_rows(r, requested, dry_run);
        if rows.is_empty() {
            out.push_str(&format!("{org:<24} {repos:>5} {findings:>8}  {:<11} {:<10}\n", "-", "no channel"));
        }
        for (i, (channel, status, detail)) in rows.iter().enumerate() {
            let (o, rp, f) = if i == 0 { (org.to_string(), repos.to_string(), findings.to_string()) } else { (String::new(), String::new(), String::new()) };
            out.push_str(format!("{o:<24} {rp:>5} {f:>8}  {channel:<11} {status:<10} {detail}").trim_end());
            out.push('\n');
        }
    }
    out
}

/// Non-zero when any channel failed, or (real run) no org delivered anything.
pub fn exit_code(reports: &[Value], requested: &[String], dry_run: bool) -> i32 {
    if dry_run {
        return 0;
    }
    let failed = reports.iter().any(|r| channel_rows(r, requested, false).iter().any(|(_, status, _)| status == "failed"));
    let delivered = reports.iter().any(|r| r.get("sent").and_then(Value::as_bool).unwrap_or(false) || r.get("pdfGenerated").and_then(Value::as_bool).unwrap_or(false));
    if failed || (!reports.is_empty() && !delivered) { 1 } else { 0 }
}

fn with_auth(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match std::env::var("IGNITE_API_KEY") {
        Ok(key) => req.header("Authorization", format!("Bearer {key}")),
        Err(_) => req,
    }
}

async fn download_pdf(client: &reqwest::Client, base_url: &str, org: &str, path: &str) -> Result<usize, String> {
    download_file(client, &format!("{base_url}/api/reports/daily/pdf"), &[("org", org)], path).await
}

/// Findings as Markdown in Ignite's `.ignite/acknowledgments.md` format.
async fn download_markdown(client: &reqwest::Client, base_url: &str, org: &str, repo: Option<&str>, path: &str) -> Result<usize, String> {
    let mut query = vec![("org", org)];
    if let Some(repo) = repo {
        query.push(("repo", repo));
    }
    download_file(client, &format!("{base_url}/api/reports/daily/markdown"), &query, path).await
}

async fn download_file(client: &reqwest::Client, url: &str, query: &[(&str, &str)], path: &str) -> Result<usize, String> {
    let base_url = url.split("/api/").next().unwrap_or(url);
    let req = with_auth(client.get(url).query(query).header("X-Ignite-Client", "cli"));
    let resp = req.send().await.map_err(|e| format!("could not reach Ignite server at {base_url}: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        return Err(body.get("error").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| format!("HTTP {status}")));
    }
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    std::fs::write(path, &bytes).map_err(|e| format!("could not write {path}: {e}"))?;
    Ok(bytes.len())
}

pub async fn run(args: ReportArgs) -> i32 {
    if let Some(path) = args.markdown.as_deref() {
        let Some(org) = args.org.as_deref() else {
            eprintln!("ignite report: --markdown needs an org: ignite report <org> --markdown findings.md [--repo name]");
            return 2;
        };
        return match download_markdown(&reqwest::Client::new(), &args.base_url, org, args.repo.as_deref(), path).await {
            Ok(bytes) => {
                println!("Findings written to {path} ({bytes} bytes)");
                0
            }
            Err(e) => {
                eprintln!("ignite report: Markdown export failed: {e}");
                1
            }
        };
    }
    let (channels, want_pdf_file) = match split_channels(args.channels.as_deref(), args.output.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ignite report: {e}");
            return 2;
        }
    };
    if want_pdf_file && args.org.is_none() {
        eprintln!("ignite report: the PDF export needs an org: ignite report <org> --channels pdf --output report.pdf");
        return 2;
    }
    let client = reqwest::Client::new();
    let mut pdf_note = None;
    if let (true, Some(org), Some(path)) = (want_pdf_file, args.org.as_deref(), args.output.as_deref()) {
        match download_pdf(&client, &args.base_url, org, path).await {
            Ok(bytes) => pdf_note = Some(format!("PDF written to {path} ({bytes} bytes)")),
            Err(e) => {
                eprintln!("ignite report: PDF export failed: {e}");
                return 1;
            }
        }
    }
    // PDF-only request: nothing to send server-side.
    let pdf_only = args.channels.is_some() && channels.is_empty() || (args.channels.is_none() && want_pdf_file);
    if pdf_only {
        if let Some(note) = pdf_note {
            if args.json {
                println!("{}", json!({ "pdf": args.output, "org": args.org }));
            } else {
                println!("{note}");
            }
        }
        return 0;
    }

    let mut body = json!({ "dryRun": args.dry_run, "channels": channels });
    if let Some(obj) = body.as_object_mut() {
        if let Some(org) = &args.org {
            obj.insert("org".into(), json!(org));
        }
        if let Some(url) = &args.webhook_url {
            obj.insert("webhookUrl".into(), json!(url));
        }
    }
    let req = with_auth(client.post(format!("{}/api/reports/daily/run", args.base_url)).header("X-Ignite-Client", "cli").json(&body));
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Could not reach Ignite server at {}: {e}. Is it running?", args.base_url);
            return 2;
        }
    };
    let status = resp.status();
    let Some(result): Option<Value> = resp.json().await.ok() else {
        eprintln!("Ignite server returned a non-JSON response (HTTP {status}).");
        return 2;
    };
    if !status.is_success() {
        eprintln!("ignite report: {}", result.get("error").and_then(Value::as_str).unwrap_or("request failed"));
        return if status.as_u16() == 401 { 2 } else { 1 };
    }
    let reports: Vec<Value> = result.get("reports").and_then(Value::as_array).cloned().unwrap_or_default();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
    } else {
        let date = result.get("date").and_then(Value::as_str).unwrap_or("");
        print!("{}", render_table(date, &reports, &channels, args.dry_run));
        if let Some(note) = pdf_note {
            println!("{note}");
        }
        if args.dry_run {
            for r in &reports {
                if let (Some(org), Some(sev)) = (r.get("org").and_then(Value::as_str), r.pointer("/webhookPayload/sentinelIncident/severity").and_then(Value::as_str)) {
                    println!("  {org}: Sentinel incident severity would be {sev}");
                }
            }
        }
    }
    exit_code(&reports, &channels, args.dry_run)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn channel_splitting_handles_aliases_pdf_and_output() {
        assert_eq!(split_channels(Some("email,sentinel,azure"), None).unwrap(), (strs(&["email", "webhook", "azure_blob"]), false));
        assert_eq!(split_channels(Some("pdf"), Some("r.pdf")).unwrap(), (vec![], true));
        assert_eq!(split_channels(Some("pdf,webhook"), Some("r.pdf")).unwrap(), (strs(&["webhook"]), true));
        assert_eq!(split_channels(None, Some("r.pdf")).unwrap(), (vec![], true));
        assert_eq!(split_channels(Some("pdf"), None).unwrap(), (strs(&["pdf"]), false), "pdf without --output stays server-side");
        assert!(split_channels(Some("email"), Some("r.pdf")).is_err());
        assert!(split_channels(Some("pigeon"), None).is_err());
        assert_eq!(split_channels(None, None).unwrap(), (vec![], false));
    }

    fn report() -> Value {
        json!({
            "org": "acme", "repos": 3, "unjustifiedFindings": 8, "sent": true,
            "emailSent": false, "reason": "notifications disabled or no recipient configured", "emailError": null,
            "webhookSent": true, "webhookError": null,
            "azureBlobSent": false, "azureBlobError": "Azure Blob answered HTTP 403: AuthenticationFailed",
            "pdfGenerated": false, "pdfError": null,
        })
    }

    #[test]
    fn rows_show_success_failure_and_skip_reasons() {
        let rows = channel_rows(&report(), &strs(&["webhook", "azure_blob"]), false);
        assert_eq!(rows[0], ("webhook".into(), "sent".into(), String::new()));
        assert_eq!(rows[1].1, "failed");
        assert!(rows[1].2.contains("403"));
        assert_eq!(rows.len(), 2, "email wasn't asked for");
        let default_rows = channel_rows(&report(), &[], false);
        assert_eq!(default_rows[0].0, "email");
        assert_eq!(default_rows[0].1, "skipped");
        assert!(default_rows[0].2.contains("disabled"));
    }

    #[test]
    fn table_lists_orgs_and_channels() {
        let table = render_table("2026-09-19", &[report()], &strs(&["webhook", "azure_blob"]), false);
        assert!(table.contains("ORG") && table.contains("acme") && table.contains("webhook") && table.contains("failed"));
        assert!(render_table("d", &[], &[], false).contains("nothing to report"));
    }

    #[test]
    fn exit_code_flags_failures_and_undelivered_runs() {
        let webhook_only = json!({ "org": "acme", "sent": true, "webhookSent": true, "webhookError": null });
        assert_eq!(exit_code(&[webhook_only], &strs(&["webhook"]), false), 0);
        assert_eq!(exit_code(&[report()], &strs(&["webhook", "azure_blob"]), false), 1, "azure failed");
        assert_eq!(exit_code(&[report()], &strs(&["azure_blob"]), true), 0, "dry runs never fail");
        let nothing = json!({ "org": "a", "sent": false, "emailSent": false, "reason": "disabled" });
        assert_eq!(exit_code(&[nothing], &[], false), 1);
        assert_eq!(exit_code(&[], &[], false), 0);
    }
}
