//! MCP server exposing the company AI validation guidelines, faithful
//! port of `mcp-server.js`. Tools: list_guidelines, get_guideline,
//! check_guidelines, check_project (all local, backed directly by
//! ignite-guidelines), plus check_dependency_licenses,
//! check_dependency_vulnerabilities, get_sarif_report, onboard_project,
//! resolve_review_decision, effectivate_project, preview_fix_pr,
//! apply_fix_pr (thin proxies to a running Ignite server, same "MCP
//! process never touches git/gh/the manifest parsers directly" pattern
//! as the JS original).
//!
//! Both transports are ported: `MCP_TRANSPORT=stdio` (default, spawned
//! as a child process by an editor/agent) and `MCP_TRANSPORT=http`
//! (one long-lived server on `MCP_HTTP_PORT`, default 51338, all
//! clients connect over Streamable HTTP at `POST/GET /mcp`), faithful
//! to `mcp-server.js`'s `main()`.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use ignite_guidelines::catalog::Severity;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler, ServiceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

fn ignite_base_url() -> String {
    std::env::var("IGNITE_BASE_URL").unwrap_or_else(|_| "http://localhost:51337".to_string()).trim_end_matches('/').to_string()
}

/// Long pipeline runs (onboard) are started with `async: true` and polled,
/// rather than held open as one HTTP request that a proxy or idle timeout can
/// drop. `IGNITE_MCP_ASYNC=0` restores the single blocking request.
fn async_runs_enabled() -> bool {
    !matches!(std::env::var("IGNITE_MCP_ASYNC").as_deref(), Ok("0") | Ok("false"))
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// What the server answered to an `async: true` start request.
#[derive(Debug, PartialEq)]
enum AsyncStart {
    /// `202` with a job id: poll it.
    Job(String),
    /// Anything else — an immediate 401/403/400, or a server that ignored
    /// `async` and ran synchronously: the body is the final response.
    Immediate,
}

fn classify_async_start(http_status: u16, body: &Value) -> AsyncStart {
    match (http_status, body.get("jobId").and_then(|v| v.as_str())) {
        (202, Some(job_id)) if body.get("async").and_then(|v| v.as_bool()).unwrap_or(false) => AsyncStart::Job(job_id.to_string()),
        _ => AsyncStart::Immediate,
    }
}

/// One poll of `GET /api/pipeline/:jobId/async-result`.
#[derive(Debug, PartialEq)]
enum PollOutcome {
    Running,
    /// The finished response, exactly as the synchronous call would have returned it.
    Done(Value),
    /// The poll itself failed (unknown job, not the caller's job, non-JSON).
    Error(String),
}

fn interpret_poll(http_status: u16, body: Option<&Value>) -> PollOutcome {
    let Some(body) = body else { return PollOutcome::Error(format!("Ignite server returned a non-JSON response (HTTP {http_status}) while polling the job.")) };
    match http_status {
        202 => PollOutcome::Running,
        200 => PollOutcome::Done(body.get("result").cloned().unwrap_or(Value::Null)),
        _ => PollOutcome::Error(serde_json::to_string_pretty(body).unwrap_or_default()),
    }
}

fn ignite_api_key() -> Option<String> {
    std::env::var("IGNITE_API_KEY").ok()
}

/// Set once, before `axum::serve` starts accepting connections in
/// `run_http()` — never touched in stdio mode. Stdio is a local child
/// process an editor/agent spawns on the same machine (the same trust
/// boundary as running the CLI directly), so it needs no additional
/// gating; the HTTP transport instead accepts connections from anywhere
/// on the network by default (see `mcp_http_bind_host`'s own doc comment),
/// so a mutating/gate-overriding tool call arriving over it must prove it
/// holds the same `IGNITE_API_KEY` this MCP process itself uses to talk to
/// the Ignite server.
static HTTP_TRANSPORT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Constant-time-ish comparison isn't the point here (both sides come from
/// process env/JSON-RPC params, not a length-revealing timing side
/// channel worth defending against in this threat model) — this just
/// centralizes the "does the caller's key match the configured one" check
/// used by every mutating tool below.
fn authorized_for_mutation(supplied: Option<&str>) -> bool {
    if !HTTP_TRANSPORT.load(std::sync::atomic::Ordering::Relaxed) {
        return true; // stdio: trusted local caller, no gating
    }
    match (ignite_api_key(), supplied) {
        (Some(configured), Some(supplied)) => !configured.is_empty() && configured == supplied,
        _ => false,
    }
}

const MUTATION_AUTH_ERROR: &str = "This action modifies repository state or overrides compliance gates and requires an IGNITE_API_KEY.";

fn text_result(text: String, is_error: bool) -> CallToolResult {
    if is_error {
        CallToolResult::error(vec![ContentBlock::text(text)])
    } else {
        CallToolResult::success(vec![ContentBlock::text(text)])
    }
}

#[derive(Debug, Clone)]
pub struct IgniteMcp {
    _tool_router: ToolRouter<Self>,
    http: reqwest::Client,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct ListGuidelinesRequest {
    /// Filter by category.
    category: Option<String>,
    /// "error" or "warning".
    severity: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct GetGuidelineRequest {
    /// Guideline id, e.g. "no-hardcoded-secrets".
    id: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct CheckGuidelinesRequest {
    /// The source code to check.
    content: String,
    /// File path or name (used to infer language/extension), e.g. "src/agent.py".
    path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct CheckProjectRequest {
    /// Absolute path to the project root to scan.
    project_path: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct ProjectPathRequest {
    /// Absolute path to the project root to scan.
    project_path: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct GxpLink {
    name: Option<String>,
    url: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct OverrideEntry {
    issue_id: String,
    justification: String,
}

/// Every backend override endpoint (`pipeline_onboard.rs`, `effectivate.rs`,
/// `pipeline_interactive/handlers.rs`) reads each entry's id via
/// `o.get("issueId")` — this crate's `OverrideEntry` keeps `issue_id`
/// snake_case (matching every other MCP tool-arg field's incoming schema
/// casing, e.g. `dry_run`/`run_local_ci`), so passing `Vec<OverrideEntry>`
/// straight through `serde_json::json!()` would serialize `"issue_id"` and
/// every submitted override would silently match no issue (`unwrap_or("")`
/// on the backend). Explicit remapping here, mirroring how every scalar
/// field elsewhere in this file is manually renamed from its snake_case
/// Rust field to the backend's camelCase JSON key when forwarding.
fn overrides_to_json(overrides: &Option<Vec<OverrideEntry>>) -> Value {
    match overrides {
        Some(list) => serde_json::Value::Array(list.iter().map(|o| serde_json::json!({ "issueId": o.issue_id, "justification": o.justification })).collect()),
        None => serde_json::Value::Array(vec![]),
    }
}

#[cfg(test)]
mod overrides_to_json_tests {
    use super::*;

    #[test]
    fn overrides_to_json_uses_camel_case_issue_id_key() {
        // Regression: the backend (pipeline_onboard.rs/effectivate.rs/
        // pipeline_interactive/handlers.rs) reads each entry via
        // `o.get("issueId")`. Serializing `OverrideEntry` directly would
        // emit its Rust field name "issue_id" instead, silently dropping
        // every override submitted through the MCP tools.
        let overrides = Some(vec![OverrideEntry { issue_id: "secret::app.js::1".to_string(), justification: "reviewed".to_string() }]);
        let json = overrides_to_json(&overrides);
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0].get("issueId").and_then(|v| v.as_str()), Some("secret::app.js::1"));
        assert!(arr[0].get("issue_id").is_none(), "must not emit the snake_case key");
        assert_eq!(arr[0].get("justification").and_then(|v| v.as_str()), Some("reviewed"));
    }

    #[test]
    fn overrides_to_json_none_becomes_empty_array() {
        assert_eq!(overrides_to_json(&None), serde_json::json!([]));
    }

    #[test]
    fn daily_report_markdown_reports_each_channel_outcome() {
        let result = serde_json::json!({ "date": "2026-09-19", "reports": [{
            "org": "acme", "repos": 2, "unjustifiedFindings": 5, "reason": "notifications disabled",
            "emailSent": false, "emailError": null,
            "webhookSent": true, "webhookError": null,
            "azureBlobSent": false, "azureBlobError": "Azure Blob answered HTTP 403",
        }]});
        let md = format_daily_report(&result, false);
        assert!(md.contains("## acme — 2 repo(s), 5 unjustified finding(s)"));
        assert!(md.contains("Webhook / Sentinel: ok"));
        assert!(md.contains("Azure Blob: FAILED — Azure Blob answered HTTP 403"));
        assert!(md.contains("Email: skipped — notifications disabled"));
    }

    #[test]
    fn daily_report_dry_run_markdown_previews_the_sentinel_incident() {
        let result = serde_json::json!({ "date": "d", "reports": [{
            "org": "acme", "repos": 1, "unjustifiedFindings": 1, "markdown": "**summary**",
            "webhookPayload": { "sentinelIncident": { "severity": "High" }, "severityCounts": { "critical": 1 } },
        }]});
        let md = format_daily_report(&result, true);
        assert!(md.contains("dry run"));
        assert!(md.contains("Sentinel incident severity: **High**"));
        assert!(md.contains("**summary**"));
        assert!(format_daily_report(&serde_json::json!({ "date": "d", "reports": [] }), false).contains("nothing to report"));
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct Actor {
    email: String,
    name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct OnboardProjectRequest {
    /// Absolute path to the project root to onboard.
    project_path: String,
    /// GitHub organization to create the repository in.
    org: String,
    /// Repository name to create.
    repo: String,
    /// If true, run all checks but skip repo provisioning and push. Default false.
    dry_run: Option<bool>,
    /// Whether this is a GxP-regulated process requiring validation documents. Default false.
    gxp: Option<bool>,
    /// Required when gxp=true: links to validation documents.
    gxp_links: Option<Vec<GxpLink>>,
    /// Run phase 5 org governance workflows locally via act. Default true.
    run_local_ci: Option<bool>,
    /// How to treat unoverridden LLM warnings. Default "continue".
    warning_decision: Option<String>,
    /// Pre-authorized overrides for flagged issues, keyed by issue id.
    overrides: Option<Vec<OverrideEntry>>,
    /// Required if overrides are submitted and the Ignite server has no logged-in session.
    actor: Option<Actor>,
    /// Optional retry key. Re-sending the identical request with the same key returns the run it already started (`idempotent: true`, with its jobId/projectId/repoUrl) instead of scanning or pushing again; the same key with a different body (e.g. after adding overrides) is a 409 — use a new key for a new attempt.
    idempotency_key: Option<String>,
    /// Required when this server is reachable over the network (MCP_TRANSPORT=http) and dryRun is not true — must match the server's own IGNITE_API_KEY. Not needed for a local stdio connection.
    api_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct ResolveReviewDecisionRequest {
    /// The paused job id (from the SSE stream's review_required event).
    job_id: String,
    /// true to continue past the pause, false to stop the run.
    proceed: bool,
    /// Overrides to apply for blocking issues raised at the pause, keyed by issue id.
    overrides: Option<Vec<OverrideEntry>>,
    /// Required if overrides are submitted and the Ignite server has no logged-in session or API key.
    actor: Option<Actor>,
    /// Required when this server is reachable over the network (MCP_TRANSPORT=http) — must match the server's own IGNITE_API_KEY. Not needed for a local stdio connection.
    api_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct EffectivateProjectRequest {
    /// The numeric project id returned by the earlier onboard_project(dryRun: true) call.
    project_id: i64,
    /// Overrides for any blocking issue still open since the simulation, keyed by issue id.
    overrides: Option<Vec<OverrideEntry>>,
    /// Required if overrides are submitted and the Ignite server has no logged-in session or API key.
    actor: Option<Actor>,
    /// Required when this server is reachable over the network (MCP_TRANSPORT=http) — must match the server's own IGNITE_API_KEY. Not needed for a local stdio connection.
    api_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct PreviewFixPrRequest {
    /// The scan job id to propose fixes for — the "jobId" field from a prior onboard_project call (dryRun or real) against the same repo.
    job_id: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct GetSarifReportRequest {
    /// The scan job id (from a prior onboard_project/check_project-style run against the Ignite server). Exactly one of job_id, project_id, or org+repo must be given.
    job_id: Option<String>,
    /// The numeric project id (e.g. from an onboard_project(dryRun: true) response).
    project_id: Option<i64>,
    /// GitHub org — pass together with repo to fetch findings from that repository's most recent scan.
    org: Option<String>,
    /// GitHub repo name — pass together with org.
    repo: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct ApplyFixPrRequest {
    /// Same job id passed to preview_fix_pr.
    job_id: String,
    /// The candidate list from preview_fix_pr's response, copied verbatim (trim it to whichever fixes you want included) — each entry must keep its exact original shape (issueId, file, startLine, endLine, original, replacement, etc.), so re-embed the JSON objects as returned rather than reconstructing them.
    candidates: Vec<Value>,
    /// Required when this server is reachable over the network (MCP_TRANSPORT=http) — must match the server's own IGNITE_API_KEY. Not needed for a local stdio connection.
    api_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct RunDailyReportRequest {
    /// GitHub org to report on. Omit to report on every org with scanned repositories.
    org: Option<String>,
    /// Delivery channels: any of "email", "webhook" (Microsoft Sentinel), "azure_blob", "pdf". Omit to use every channel configured on the server.
    channels: Option<Vec<String>>,
    /// true to preview only (nothing is sent) — returns the Sentinel payload and incident markdown.
    dry_run: Option<bool>,
    /// Absolute or relative path (must end in .pdf) to save the org's PDF report to. Requires `org`.
    save_pdf_path: Option<String>,
    /// Required when this server is reachable over the network (MCP_TRANSPORT=http) and the call sends a report or writes a file — must match the server's own IGNITE_API_KEY. Not needed for a local stdio connection or a dry run.
    api_key: Option<String>,
}

/// Markdown summary of `POST /api/reports/daily/run`'s response.
fn format_daily_report(result: &Value, dry_run: bool) -> String {
    let date = result.get("date").and_then(|v| v.as_str()).unwrap_or("?");
    let mut out = format!("# Ignite daily report — {date}{}\n", if dry_run { " (dry run — nothing sent)" } else { "" });
    let reports = result.get("reports").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if reports.is_empty() {
        out.push_str("\nNo scanned repositories — nothing to report.\n");
        return out;
    }
    for r in &reports {
        let text = |k: &str| r.get(k).and_then(|v| v.as_str());
        let flag = |k: &str| r.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
        let num = |k: &str| r.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
        out.push_str(&format!("\n## {} — {} repo(s), {} unjustified finding(s)\n\n", text("org").unwrap_or("?"), num("repos"), num("unjustifiedFindings")));
        if dry_run {
            if let Some(sev) = r.pointer("/webhookPayload/sentinelIncident/severity").and_then(|v| v.as_str()) {
                out.push_str(&format!("- Sentinel incident severity: **{sev}**\n"));
            }
            if let Some(counts) = r.pointer("/webhookPayload/severityCounts") {
                out.push_str(&format!("- Severity counts: `{counts}`\n"));
            }
            if let Some(md) = text("markdown") {
                out.push_str(&format!("\n### Incident description preview\n\n{md}\n"));
            }
            continue;
        }
        for (label, sent_key, err_key) in [("Email", "emailSent", "emailError"), ("Webhook / Sentinel", "webhookSent", "webhookError"), ("Azure Blob", "azureBlobSent", "azureBlobError"), ("PDF", "pdfGenerated", "pdfError")] {
            if flag(sent_key) {
                out.push_str(&format!("- {label}: ok\n"));
            } else if let Some(e) = text(err_key) {
                out.push_str(&format!("- {label}: FAILED — {e}\n"));
            }
        }
        if let Some(reason) = text("reason") {
            if !flag("emailSent") && text("emailError").is_none() {
                out.push_str(&format!("- Email: skipped — {reason}\n"));
            }
        }
    }
    out
}

#[tool_router]
impl IgniteMcp {
    fn new() -> Self {
        Self { _tool_router: Self::tool_router(), http: reqwest::Client::new() }
    }

    /// Shared by every proxy tool below — same "thin proxy to a running
    /// Ignite server" pattern as the JS original's proxyToIgnite, so this
    /// process itself never needs the manifest parsers/deps.dev client/
    /// git+gh push path loaded directly.
    async fn proxy_to_ignite(&self, endpoint: &str, body: Value) -> Result<CallToolResult, McpError> {
        let base_url = ignite_base_url();
        let mut req = self.http.post(format!("{base_url}{endpoint}")).header("Content-Type", "application/json").header("X-Ignite-Client", "mcp").json(&body);
        if let Some(key) = ignite_api_key() {
            req = req.header("Authorization", format!("Bearer {key}"));
        }
        let response = match req.send().await {
            Ok(r) => r,
            Err(e) => return Ok(text_result(format!("Could not reach Ignite server at {base_url}: {e}. Is it running (\"npm start\"/the Rust server binary)?"), true)),
        };
        let status = response.status();
        let result: Option<Value> = response.json().await.ok();
        let Some(result) = result else {
            return Ok(text_result(format!("Ignite server returned a non-JSON response (HTTP {status})."), true));
        };
        let is_error = !result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        Ok(text_result(serde_json::to_string_pretty(&result).unwrap_or_default(), is_error))
    }

    /// `proxy_to_ignite` for the long-running pipeline endpoints: starts the
    /// run with `async: true` and polls `GET /api/pipeline/:jobId/async-result`
    /// until it finishes, so one slow run isn't one fragile HTTP request. The
    /// caller still makes a single tool call and gets the same response the
    /// blocking call would have produced. A transient network error while
    /// polling is retried; if the wait budget (`IGNITE_MCP_MAX_WAIT_SECS`,
    /// default 3600) runs out, the job id is reported and re-sending the same
    /// request with the same `idempotencyKey` returns the run rather than
    /// starting another.
    async fn proxy_to_ignite_polling(&self, endpoint: &str, mut body: Value) -> Result<CallToolResult, McpError> {
        if !async_runs_enabled() {
            return self.proxy_to_ignite(endpoint, body).await;
        }
        body["async"] = Value::Bool(true);
        let base_url = ignite_base_url();
        let with_auth = |req: reqwest::RequestBuilder| match ignite_api_key() {
            Some(key) => req.header("Authorization", format!("Bearer {key}")),
            None => req,
        };
        let start = match with_auth(self.http.post(format!("{base_url}{endpoint}")).header("Content-Type", "application/json").header("X-Ignite-Client", "mcp").json(&body)).send().await {
            Ok(r) => r,
            Err(e) => return Ok(text_result(format!("Could not reach Ignite server at {base_url}: {e}. Is it running?"), true)),
        };
        let start_status = start.status().as_u16();
        let Some(start_body): Option<Value> = start.json().await.ok() else {
            return Ok(text_result(format!("Ignite server returned a non-JSON response (HTTP {start_status})."), true));
        };
        let job_id = match classify_async_start(start_status, &start_body) {
            AsyncStart::Job(id) => id,
            AsyncStart::Immediate => {
                let is_error = !start_body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                return Ok(text_result(serde_json::to_string_pretty(&start_body).unwrap_or_default(), is_error));
            }
        };

        let poll_every = std::time::Duration::from_millis(env_u64("IGNITE_MCP_POLL_MS", 2000).max(50));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(env_u64("IGNITE_MCP_MAX_WAIT_SECS", 3600));
        let poll_url = format!("{base_url}/api/pipeline/{}/async-result", urlencoding::encode(&job_id));
        let mut consecutive_failures = 0u32;
        loop {
            tokio::time::sleep(poll_every).await;
            let response = match with_auth(self.http.get(&poll_url).header("X-Ignite-Client", "mcp")).send().await {
                Ok(r) => r,
                Err(e) => {
                    consecutive_failures += 1;
                    if consecutive_failures >= 5 {
                        return Ok(text_result(format!("Lost contact with the Ignite server at {base_url} while waiting for job {job_id}: {e}. The run may still be going — re-send the same request with the same idempotency_key to get it back."), true));
                    }
                    continue;
                }
            };
            consecutive_failures = 0;
            let http_status = response.status().as_u16();
            let body: Option<Value> = response.json().await.ok();
            match interpret_poll(http_status, body.as_ref()) {
                PollOutcome::Running => {
                    if std::time::Instant::now() >= deadline {
                        return Ok(text_result(format!("Still running after the wait budget. Job id: {job_id}. Re-send the same request with the same idempotency_key to get the run (it reports inProgress while it is still going)."), true));
                    }
                }
                PollOutcome::Done(result) => {
                    let is_error = !result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                    return Ok(text_result(serde_json::to_string_pretty(&result).unwrap_or_default(), is_error));
                }
                PollOutcome::Error(message) => return Ok(text_result(message, true)),
            }
        }
    }

    /// Same "POST kicks off, GET .../status reports progress" pattern the
    /// browser frontend already polls for a fix-PR preview job — the
    /// initial POST returns immediately with `done: false` and empty
    /// `candidates` while the server computes fixes in the background
    /// (each finding needs its own LLM call). Returning that immediate
    /// response straight to an MCP caller (as `proxy_to_ignite` would)
    /// always reports zero candidates; this polls `GET .../preview/status`
    /// until `done: true` (or a generous timeout) before handing back the
    /// real result.
    async fn proxy_to_ignite_and_poll(&self, start_endpoint: &str, status_endpoint: &str) -> Result<CallToolResult, McpError> {
        // The initial response's success payload is never returned to the
        // caller — it's always `done: false` with no candidates yet, and
        // the polled status response below is the freshest/authoritative
        // one. An error here (bad job id, auth failure, network failure)
        // is real and must surface now — otherwise the polling loop below
        // just hits the same failure against `status_endpoint` and reports
        // a confusing "no such job" instead of the actual cause.
        let started = self.proxy_to_ignite(start_endpoint, serde_json::json!({})).await?;
        if started.is_error == Some(true) {
            return Ok(started);
        }
        let base_url = ignite_base_url();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            let mut req = self.http.get(format!("{base_url}{status_endpoint}")).header("X-Ignite-Client", "mcp");
            if let Some(key) = ignite_api_key() {
                req = req.header("Authorization", format!("Bearer {key}"));
            }
            let response = match req.send().await {
                Ok(r) => r,
                Err(e) => return Ok(text_result(format!("Could not reach Ignite server at {base_url}: {e}."), true)),
            };
            let status = response.status();
            let Some(result): Option<Value> = response.json().await.ok() else {
                return Ok(text_result(format!("Ignite server returned a non-JSON response (HTTP {status}) from {status_endpoint}."), true));
            };
            if !result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                // A real error from the status endpoint (e.g. "no such
                // job") — surface it rather than looping forever.
                let is_error = true;
                return Ok(text_result(serde_json::to_string_pretty(&result).unwrap_or_default(), is_error));
            }
            if result.get("done").and_then(|v| v.as_bool()).unwrap_or(false) {
                return Ok(text_result(serde_json::to_string_pretty(&result).unwrap_or_default(), false));
            }
            if std::time::Instant::now() >= deadline {
                return Ok(text_result("Timed out waiting for the fix-PR preview job to finish (120s). Call preview_fix_pr again to check its current status.".to_string(), true));
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }

    /// GET (not POST) proxy for endpoints that return a raw document body
    /// rather than the `{"ok": ...}`-wrapped envelope every other route
    /// this MCP server talks to uses — the SARIF endpoints (`sarif.rs`)
    /// return the SARIF document itself with no such wrapper, so
    /// `proxy_to_ignite`'s `ok`-field success/failure check doesn't apply
    /// here; a 200 is success, anything else is the error body verbatim.
    async fn proxy_get_ignite(&self, endpoint: &str) -> Result<CallToolResult, McpError> {
        let base_url = ignite_base_url();
        let mut req = self.http.get(format!("{base_url}{endpoint}")).header("X-Ignite-Client", "mcp");
        if let Some(key) = ignite_api_key() {
            req = req.header("Authorization", format!("Bearer {key}"));
        }
        let response = match req.send().await {
            Ok(r) => r,
            Err(e) => return Ok(text_result(format!("Could not reach Ignite server at {base_url}: {e}."), true)),
        };
        let status = response.status();
        let is_error = !status.is_success();
        let Some(result): Option<Value> = response.json().await.ok() else {
            return Ok(text_result(format!("Ignite server returned a non-JSON response (HTTP {status}) from {endpoint}."), true));
        };
        Ok(text_result(serde_json::to_string_pretty(&result).unwrap_or_default(), is_error))
    }

    #[tool(
        description = "Run the org-level security findings report: delivers each org's unjustified findings (findings on the latest scan of every repo that nobody has justified) to email, a Microsoft Sentinel webhook, Azure Blob Storage and/or PDF. dry_run previews the Sentinel incident payload without sending anything. Optionally saves the org's PDF report to save_pdf_path. Requires a running Ignite server."
    )]
    async fn run_daily_report(&self, Parameters(req): Parameters<RunDailyReportRequest>) -> Result<CallToolResult, McpError> {
        let dry_run = req.dry_run.unwrap_or(false);
        let save_path = req.save_pdf_path.as_deref().map(str::trim).filter(|p| !p.is_empty());
        // Sending to external channels and writing a file are the mutating
        // parts; a dry run with no file is read-only.
        if (!dry_run || save_path.is_some()) && !authorized_for_mutation(req.api_key.as_deref()) {
            return Ok(text_result(MUTATION_AUTH_ERROR.to_string(), true));
        }
        if let Some(path) = save_path {
            if !path.to_ascii_lowercase().ends_with(".pdf") {
                return Ok(text_result("save_pdf_path must end in .pdf".to_string(), true));
            }
            if req.org.as_deref().map(str::trim).unwrap_or("").is_empty() {
                return Ok(text_result("save_pdf_path needs an org (the PDF is per-org).".to_string(), true));
            }
        }
        let base_url = ignite_base_url();
        let mut body = serde_json::json!({ "dryRun": dry_run, "channels": req.channels.clone().unwrap_or_default() });
        if let (Some(obj), Some(org)) = (body.as_object_mut(), req.org.as_deref().map(str::trim).filter(|o| !o.is_empty())) {
            obj.insert("org".to_string(), serde_json::json!(org));
        }
        let mut http = self.http.post(format!("{base_url}/api/reports/daily/run")).header("X-Ignite-Client", "mcp").json(&body);
        if let Some(key) = ignite_api_key() {
            http = http.header("Authorization", format!("Bearer {key}"));
        }
        let response = match http.send().await {
            Ok(r) => r,
            Err(e) => return Ok(text_result(format!("Could not reach Ignite server at {base_url}: {e}. Is it running?"), true)),
        };
        let status = response.status();
        let Some(result): Option<Value> = response.json().await.ok() else {
            return Ok(text_result(format!("Ignite server returned a non-JSON response (HTTP {status})."), true));
        };
        if !status.is_success() {
            return Ok(text_result(result.get("error").and_then(|v| v.as_str()).unwrap_or("Report request failed.").to_string(), true));
        }
        let mut text = format_daily_report(&result, dry_run);
        let mut is_error = result.get("reports").and_then(|v| v.as_array()).is_some_and(|rs| rs.iter().any(|r| r.get("error").is_some_and(|e| !e.is_null())));

        if let (Some(path), Some(org)) = (save_path, req.org.as_deref().map(str::trim)) {
            let mut pdf_req = self.http.get(format!("{base_url}/api/reports/daily/pdf")).query(&[("org", org)]).header("X-Ignite-Client", "mcp");
            if let Some(key) = ignite_api_key() {
                pdf_req = pdf_req.header("Authorization", format!("Bearer {key}"));
            }
            match pdf_req.send().await {
                Ok(r) if r.status().is_success() => match r.bytes().await {
                    Ok(bytes) => match std::fs::write(path, &bytes) {
                        Ok(()) => text.push_str(&format!("\nPDF saved to `{path}` ({} bytes).\n", bytes.len())),
                        Err(e) => {
                            is_error = true;
                            text.push_str(&format!("\nCould not write PDF to `{path}`: {e}\n"));
                        }
                    },
                    Err(e) => {
                        is_error = true;
                        text.push_str(&format!("\nPDF download failed: {e}\n"));
                    }
                },
                Ok(r) => {
                    is_error = true;
                    let code = r.status();
                    let detail = r.json::<Value>().await.ok().and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string)).unwrap_or_default();
                    text.push_str(&format!("\nPDF export failed (HTTP {code}): {detail}\n"));
                }
                Err(e) => {
                    is_error = true;
                    text.push_str(&format!("\nPDF download failed: {e}\n"));
                }
            }
        }
        Ok(text_result(text, is_error))
    }

    #[tool(description = "List the company AI/security validation guidelines, optionally filtered by category or severity.")]
    async fn list_guidelines(&self, Parameters(req): Parameters<ListGuidelinesRequest>) -> Result<CallToolResult, McpError> {
        let severity = match req.severity.as_deref() {
            Some("error") => Some(Severity::Error),
            Some("warning") => Some(Severity::Warning),
            _ => None,
        };
        let results = ignite_guidelines::catalog::list_guidelines(req.category.as_deref(), severity);
        Ok(CallToolResult::success(vec![ContentBlock::text(serde_json::to_string_pretty(&results).unwrap_or_default())]))
    }

    #[tool(description = "Retrieve the full detail (description, rationale, remediation) of one guideline by id.")]
    async fn get_guideline(&self, Parameters(req): Parameters<GetGuidelineRequest>) -> Result<CallToolResult, McpError> {
        match ignite_guidelines::catalog::get_guideline(&req.id) {
            Some(g) => Ok(CallToolResult::success(vec![ContentBlock::text(serde_json::to_string_pretty(g).unwrap_or_default())])),
            None => Ok(text_result(format!("No guideline with id \"{}\".", req.id), true)),
        }
    }

    #[tool(description = "Check a code snippet or file content against the automated guidelines and return any violations.")]
    async fn check_guidelines(&self, Parameters(req): Parameters<CheckGuidelinesRequest>) -> Result<CallToolResult, McpError> {
        let violations = ignite_guidelines::checks::check_content(&req.content, req.path.as_deref().unwrap_or(""));
        let summary = if violations.is_empty() { "No violations found.".to_string() } else { format!("{} violation(s) found.", violations.len()) };
        let is_error = violations.iter().any(|v| v.severity == Severity::Error);
        Ok(text_result(format!("{summary}\n{}", serde_json::to_string_pretty(&violations).unwrap_or_default()), is_error))
    }

    #[tool(description = "Walk a project directory on disk and check every source file against the automated guidelines.")]
    async fn check_project(&self, Parameters(req): Parameters<CheckProjectRequest>) -> Result<CallToolResult, McpError> {
        // In `MCP_TRANSPORT=http` mode this tool is reachable from the
        // network with no auth/CORS/path confinement of its own —
        // `sanitize_absolute_project_path` (the same check every
        // server-side path-accepting route already applies) at minimum
        // rejects control-character injection and requires a real
        // absolute path, rather than handing whatever string a remote
        // caller sent straight to a directory walk + file reads.
        let root = match ignite_tool_runner::sanitize_absolute_project_path(&req.project_path) {
            Ok(p) => p,
            Err(e) => return Ok(text_result(format!("Invalid project_path: {e}"), true)),
        };
        match ignite_guidelines::checks::check_project(&root) {
            Ok(result) => {
                let summary = format!("Scanned {} file(s). {} violation(s) found.", result.scanned, result.violations.len());
                let is_error = result.violations.iter().any(|v| v.severity == Severity::Error);
                Ok(text_result(format!("{summary}\n{}", serde_json::to_string_pretty(&result.violations).unwrap_or_default()), is_error))
            }
            Err(e) => Ok(text_result(format!("Could not scan {}: {e}", req.project_path), true)),
        }
    }

    #[tool(
        description = "Scan a local project directory's dependency manifests and every LICENSE/LICENCE file in the tree for commercial/proprietary/copyleft licensing risk. Same scan Ignite's onboarding pipeline runs automatically in Phase 3. Requires a running Ignite server reachable at IGNITE_BASE_URL."
    )]
    async fn check_dependency_licenses(&self, Parameters(req): Parameters<ProjectPathRequest>) -> Result<CallToolResult, McpError> {
        self.proxy_to_ignite("/api/dependencies/check", serde_json::json!({ "projectPath": req.project_path })).await
    }

    #[tool(
        description = "Scan a local project directory's dependency manifests for known CVE/GHSA vulnerabilities via deps.dev's aggregated OSV advisory data. Requires a running Ignite server reachable at IGNITE_BASE_URL."
    )]
    async fn check_dependency_vulnerabilities(&self, Parameters(req): Parameters<ProjectPathRequest>) -> Result<CallToolResult, McpError> {
        self.proxy_to_ignite("/api/dependencies/vulnerabilities", serde_json::json!({ "projectPath": req.project_path })).await
    }

    #[tool(
        description = "Retrieve the SARIF 2.1.0 findings report for a prior scan, identified by exactly one of job_id, project_id, or org+repo (the latter resolves to that repository's most recently scanned project). Same document GitHub's code-scanning/sarifs upload uses, suitable for uploading by hand (gh api .../code-scanning/sarifs) or feeding into another SARIF-consuming tool. Requires a running Ignite server reachable at IGNITE_BASE_URL."
    )]
    async fn get_sarif_report(&self, Parameters(req): Parameters<GetSarifReportRequest>) -> Result<CallToolResult, McpError> {
        let identifiers_given = [req.job_id.is_some(), req.project_id.is_some(), req.org.is_some() || req.repo.is_some()].iter().filter(|v| **v).count();
        if identifiers_given != 1 {
            return Ok(text_result("Pass exactly one of: job_id, project_id, or org+repo.".to_string(), true));
        }
        let endpoint = if let Some(job_id) = req.job_id.as_deref() {
            format!("/api/pipeline/{}/sarif", urlencoding::encode(job_id))
        } else if let Some(project_id) = req.project_id {
            format!("/api/projects/{project_id}/sarif")
        } else {
            match (req.org.as_deref(), req.repo.as_deref()) {
                (Some(org), Some(repo)) => format!("/api/repositories/{}/{}/sarif", urlencoding::encode(org), urlencoding::encode(repo)),
                _ => return Ok(text_result("Both org and repo are required together.".to_string(), true)),
            }
        };
        self.proxy_get_ignite(&endpoint).await
    }

    #[tool(
        description = "Run all Ignite onboarding checks against a local project directory, and — if every check passes — provision a private GitHub repo and push the code. Set dryRun=true to run every check without pushing; a successful dry run returns `projectId` and `effectivatable: true`, which is what effectivate_project takes. Every response carries `coverage` and `policyDecision`; a refused run carries `blocked`, `blockReason` (unresolved_findings | pending_approval | incomplete_coverage | policy_blocked), `overridable` and `nextAction`. A real (non-dry) run needs a GitHub token on the Ignite server side: one bound to the API key (`create-api-key --github-token-env`), the key owner's connected GitHub account, or the server's GH_TOKEN/GITHUB_TOKEN — the `gh` CLI's own login is NOT used (a 401 with `code: github_token_missing` lists the remedies)."
    )]
    async fn onboard_project(&self, Parameters(req): Parameters<OnboardProjectRequest>) -> Result<CallToolResult, McpError> {
        // Dry runs (checks-only, no provisioning/push) stay frictionless
        // even over the network — but only when they're genuinely
        // read-only. `dryRun: true` on the server still persists any
        // submitted overrides to ignite.db, flips issue states, and
        // writes audit-log entries (only the provision/push step is
        // actually skipped) — so a dry run carrying overrides needs the
        // same mutation authorization a real onboard does; it's the
        // overrides that mutate state, not dry_run's own value.
        let has_overrides = req.overrides.as_ref().is_some_and(|o| !o.is_empty());
        if (!req.dry_run.unwrap_or(false) || has_overrides) && !authorized_for_mutation(req.api_key.as_deref()) {
            return Ok(text_result(MUTATION_AUTH_ERROR.to_string(), true));
        }
        self.proxy_to_ignite_polling(
            "/api/pipeline/onboard",
            serde_json::json!({
                "projectPath": req.project_path,
                "org": req.org,
                "repo": req.repo,
                "dryRun": req.dry_run,
                "gxp": req.gxp,
                "gxpLinks": req.gxp_links,
                "runLocalCi": req.run_local_ci,
                "warningDecision": req.warning_decision,
                "overrides": overrides_to_json(&req.overrides),
                "actor": req.actor,
                "idempotencyKey": req.idempotency_key,
            }),
        )
        .await
    }

    #[tool(
        description = "Continue or stop a pipeline run that paused waiting for review — a run started via the browser-driven interactive endpoint that hit an overridable issue. Not needed for onboard_project calls. Requires a running Ignite server."
    )]
    async fn resolve_review_decision(&self, Parameters(req): Parameters<ResolveReviewDecisionRequest>) -> Result<CallToolResult, McpError> {
        if !authorized_for_mutation(req.api_key.as_deref()) {
            return Ok(text_result(MUTATION_AUTH_ERROR.to_string(), true));
        }
        let endpoint = format!("/api/pipeline/{}/review-decision", urlencoding::encode(&req.job_id));
        self.proxy_to_ignite(&endpoint, serde_json::json!({ "proceed": req.proceed, "overrides": overrides_to_json(&req.overrides), "actor": req.actor })).await
    }

    #[tool(
        description = "Provision + push the exact snapshot already validated by a prior onboard_project(dryRun: true) call (use its `projectId`), without re-running phases 1-5. The snapshot is kept for 24h and survives a server restart; if it has expired the call returns 404 `no_pending_simulation` — re-run the dry run. Needs a GitHub token on the server side (bound to the API key, the key owner's connected account, or the server's GH_TOKEN/GITHUB_TOKEN; `gh` CLI login is not used). A refused call carries `blocked`, `blockReason`, `overridable` and `nextAction`; `pending_approval` also lists `pendingOverrides` for a different reviewer to approve."
    )]
    async fn effectivate_project(&self, Parameters(req): Parameters<EffectivateProjectRequest>) -> Result<CallToolResult, McpError> {
        if !authorized_for_mutation(req.api_key.as_deref()) {
            return Ok(text_result(MUTATION_AUTH_ERROR.to_string(), true));
        }
        let endpoint = format!("/api/projects/{}/effectivate", req.project_id);
        self.proxy_to_ignite(&endpoint, serde_json::json!({ "overrides": overrides_to_json(&req.overrides), "actor": req.actor })).await
    }

    #[tool(
        description = "Preview LLM-proposed fixes for every open finding from a prior scan job — no git/GitHub involved yet, just candidate diffs to review. Pass the returned candidates (trimmed to whichever you accept) to apply_fix_pr to actually open a PR. Requires a running Ignite server."
    )]
    async fn preview_fix_pr(&self, Parameters(req): Parameters<PreviewFixPrRequest>) -> Result<CallToolResult, McpError> {
        let job_id = urlencoding::encode(&req.job_id);
        let start_endpoint = format!("/api/pipeline/{job_id}/fix-pr/preview");
        let status_endpoint = format!("/api/pipeline/{job_id}/fix-pr/preview/status");
        self.proxy_to_ignite_and_poll(&start_endpoint, &status_endpoint).await
    }

    #[tool(
        description = "Open one pull request applying the given fix candidates from a prior preview_fix_pr call — clones the repo's already-provisioned default branch, applies every candidate, pushes a branch, and opens a real PR. Only pass candidates that have actually been reviewed and approved; this is not reversible from here (a human can still close/reject the PR on GitHub). Requires a running Ignite server with `gh` authenticated and the target repo already on GitHub."
    )]
    async fn apply_fix_pr(&self, Parameters(req): Parameters<ApplyFixPrRequest>) -> Result<CallToolResult, McpError> {
        if !authorized_for_mutation(req.api_key.as_deref()) {
            return Ok(text_result(MUTATION_AUTH_ERROR.to_string(), true));
        }
        let endpoint = format!("/api/pipeline/{}/fix-pr/apply", urlencoding::encode(&req.job_id));
        self.proxy_to_ignite(&endpoint, serde_json::json!({ "candidates": req.candidates })).await
    }
}

#[tool_handler]
impl ServerHandler for IgniteMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

/// Adapts rmcp's `StreamableHttpService` (a `tower_service::Service` over
/// `http_body_util::combinators::BoxBody`) onto axum's expected
/// `Response = axum::response::Response`, so it can be mounted with
/// `Router::route_service`. Faithful to `mcp-server.js`'s single `app.all
/// ('/mcp', ...)` handler backed by the SDK's `StreamableHTTPServerTransport`.
struct AxumStreamableHttp<S, M>(
    rmcp::transport::streamable_http_server::tower::StreamableHttpService<S, M>,
);

impl<S, M> Clone for AxumStreamableHttp<S, M> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S, M> tower_service::Service<axum::extract::Request> for AxumStreamableHttp<S, M>
where
    S: ServerHandler + Send + 'static,
    M: rmcp::transport::streamable_http_server::session::SessionManager,
{
    type Response = axum::response::Response;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        <rmcp::transport::streamable_http_server::tower::StreamableHttpService<S, M> as tower_service::Service<axum::extract::Request>>::poll_ready(&mut self.0, cx)
    }

    fn call(&mut self, req: axum::extract::Request) -> Self::Future {
        let mut inner = self.0.clone();
        Box::pin(async move {
            let resp = tower_service::Service::call(&mut inner, req).await?;
            Ok(resp.map(axum::body::Body::new))
        })
    }
}

fn mcp_http_port() -> u16 {
    std::env::var("MCP_HTTP_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(51338)
}

/// Pulled out as its own function so a test can pin this regression
/// directly: `run_http` previously hardcoded `"127.0.0.1"` inline, which
/// silently broke every connection arriving through Docker's port-forward
/// NAT (see the module-level comment on the real `TcpListener::bind` call
/// below) — a bug no unit test caught because the existing HTTP-transport
/// test builds its own listener/router rather than calling `run_http`
/// itself. mcp-server.js's real behavior (`app.listen(port)`, no host
/// argument) binds all interfaces by default.
fn mcp_http_bind_host() -> &'static str {
    "0.0.0.0"
}

async fn run_http() -> anyhow::Result<()> {
    HTTP_TRANSPORT.store(true, std::sync::atomic::Ordering::Relaxed);
    let port = mcp_http_port();
    let session_manager = std::sync::Arc::new(
        rmcp::transport::streamable_http_server::session::local::LocalSessionManager::default(),
    );
    let service = rmcp::transport::streamable_http_server::tower::StreamableHttpService::new(
        || Ok(IgniteMcp::new()),
        session_manager,
        Default::default(),
    );
    let mut app = axum::Router::new().route_service("/mcp", AxumStreamableHttp(service));
    // Every per-tool mutation already checks its own `apiKey` param
    // (`authorized_for_mutation`), but that check runs *inside* a tool
    // call — MCP's own `tools/list` (served automatically by `rmcp`'s
    // `#[tool_handler]` before any of our tool bodies ever run) has no
    // gate at all in HTTP mode, which binds every interface by design
    // (see `mcp_http_bind_host`'s own doc comment). An unauthenticated
    // network caller could otherwise enumerate every tool name/
    // description/schema and learn exactly which mutating operations
    // exist before ever presenting a credential. Gated on `IGNITE_API_KEY`
    // being set at all — an operator who hasn't minted one is assumed to
    // be running this locally/behind their own network boundary, same as
    // every other env-var-gated default in this codebase.
    if let Ok(key) = std::env::var("IGNITE_API_KEY") {
        if !key.is_empty() {
            app = app.layer(axum::middleware::from_fn(move |req: axum::extract::Request, next: axum::middleware::Next| {
                let key = key.clone();
                async move {
                    let authorized = req.headers().get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(|v| v == format!("Bearer {key}")).unwrap_or(false);
                    if authorized {
                        next.run(req).await
                    } else {
                        axum::http::Response::builder().status(axum::http::StatusCode::UNAUTHORIZED).body(axum::body::Body::empty()).unwrap()
                    }
                }
            }));
        }
    }
    // mcp-server.js's `app.listen(port, ...)` (no host argument) binds all
    // interfaces by default, same as any bare Express `listen(port)` call —
    // unlike guidelines-api.js, which deliberately binds 127.0.0.1 and adds
    // its own loopback-only request middleware as defense in depth (see
    // crates/guidelines-api/src/main.rs). Binding to 127.0.0.1 here instead
    // was a real regression: found via a live docker-compose deployment
    // (the same container docker-compose.yml already exposes port 51338
    // from) where an external client got "Connection reset by peer" — the
    // process was refusing every connection arriving through Docker's
    // port-forward NAT because it wasn't listening on any interface that
    // traffic actually arrives on.
    let listener = tokio::net::TcpListener::bind((mcp_http_bind_host(), port)).await?;
    eprintln!("[mcp] ai-validation-guidelines listening on http://{}:{port}/mcp (Streamable HTTP)", mcp_http_bind_host());
    axum::serve(listener, app).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mode = std::env::var("MCP_TRANSPORT").unwrap_or_else(|_| "stdio".to_string()).to_lowercase();

    match mode.as_str() {
        "stdio" => {
            let server = IgniteMcp::new().serve(rmcp::transport::stdio()).await?;
            server.waiting().await?;
            Ok(())
        }
        "http" => run_http().await,
        other => anyhow::bail!("Unknown MCP_TRANSPORT \"{other}\". Use \"stdio\" or \"http\"."),
    }
}

#[cfg(test)]
mod http_transport_tests {
    use super::*;
    use serde_json::json;

    /// Pins the real regression: `run_http` used to hardcode
    /// `TcpListener::bind(("127.0.0.1", port))`, which refused every
    /// connection arriving through Docker's port-forward NAT — confirmed
    /// live against the actual docker-compose container (see
    /// MIGRATION_STATUS.md). mcp-server.js's real behavior
    /// (`app.listen(port)`, no host argument) binds all interfaces.
    #[test]
    fn http_transport_binds_all_interfaces_not_loopback_only() {
        assert_eq!(mcp_http_bind_host(), "0.0.0.0", "must bind all interfaces like mcp-server.js's app.listen(port) with no host argument, not loopback-only");
    }

    /// Real end-to-end JSON-RPC handshake over Streamable HTTP: spawns the
    /// actual server on an ephemeral port, does initialize + tools/list +
    /// a real tools/call for the local (no-network) `list_guidelines` tool.
    #[tokio::test]
    async fn http_transport_serves_real_jsonrpc_handshake() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let session_manager = std::sync::Arc::new(
            rmcp::transport::streamable_http_server::session::local::LocalSessionManager::default(),
        );
        let service = rmcp::transport::streamable_http_server::tower::StreamableHttpService::new(
            || Ok(IgniteMcp::new()),
            session_manager,
            Default::default(),
        );
        let app = axum::Router::new().route_service("/mcp", AxumStreamableHttp(service));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("http://{addr}/mcp");
        let client = reqwest::Client::new();

        let init_resp = client
            .post(&url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "0.0.1"}
                }
            }))
            .send()
            .await
            .unwrap();
        assert!(init_resp.status().is_success(), "initialize failed: {}", init_resp.status());
        let session_id = init_resp
            .headers()
            .get("mcp-session-id")
            .expect("server must issue a session id on initialize")
            .to_str()
            .unwrap()
            .to_string();
        let init_body: Value = parse_sse_or_json(init_resp).await;
        assert!(init_body["result"]["serverInfo"].is_object());

        // Required by the spec before any further requests on this session.
        client
            .post(&url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id)
            .json(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .send()
            .await
            .unwrap();

        let list_resp = client
            .post(&url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id)
            .json(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
            .send()
            .await
            .unwrap();
        assert!(list_resp.status().is_success());
        let list_body: Value = parse_sse_or_json(list_resp).await;
        let tools = list_body["result"]["tools"].as_array().unwrap();
        assert!(tools.iter().any(|t| t["name"] == "list_guidelines"));

        let call_resp = client
            .post(&url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "list_guidelines", "arguments": {}}
            }))
            .send()
            .await
            .unwrap();
        assert!(call_resp.status().is_success());
        let call_body: Value = parse_sse_or_json(call_resp).await;
        assert!(call_body["result"]["content"].is_array());
    }

    /// The transport responds with either a plain JSON body or a
    /// `text/event-stream` body carrying one `data:` JSON payload,
    /// depending on the negotiated protocol version. Handle both.
    async fn parse_sse_or_json(resp: reqwest::Response) -> Value {
        let content_type = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let text = resp.text().await.unwrap();
        if content_type.contains("text/event-stream") {
            // The stream may lead with a priming `data: \nretry: ...`
            // keep-alive event before the real JSON-RPC payload — skip
            // empty `data:` lines and take the first non-empty one.
            let data_line = text
                .lines()
                .filter(|l| l.starts_with("data:"))
                .map(|l| l.trim_start_matches("data:").trim())
                .find(|d| !d.is_empty())
                .expect("SSE body must contain a non-empty data: line");
            serde_json::from_str(data_line).unwrap()
        } else {
            serde_json::from_str(&text).unwrap()
        }
    }

    /// `authorized_for_mutation`'s own gating logic — the HTTP-vs-stdio
    /// switch and the actual key comparison — independent of the
    /// heavier full-server tests below.
    #[test]
    fn stdio_transport_never_gates_mutation() {
        HTTP_TRANSPORT.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(authorized_for_mutation(None), "a local stdio caller must never need an api_key");
    }

    #[test]
    fn http_transport_rejects_missing_or_wrong_key() {
        std::env::set_var("IGNITE_API_KEY", "test-secret-key");
        HTTP_TRANSPORT.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(!authorized_for_mutation(None), "no key supplied must be rejected");
        assert!(!authorized_for_mutation(Some("wrong-key")), "a mismatched key must be rejected");
        assert!(authorized_for_mutation(Some("test-secret-key")), "the exact configured key must be accepted");
        HTTP_TRANSPORT.store(false, std::sync::atomic::Ordering::Relaxed);
        std::env::remove_var("IGNITE_API_KEY");
    }

    #[test]
    fn http_transport_rejects_every_key_when_server_has_none_configured() {
        std::env::remove_var("IGNITE_API_KEY");
        HTTP_TRANSPORT.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(!authorized_for_mutation(Some("anything")), "no server-side key configured means nothing can be a valid key");
        HTTP_TRANSPORT.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Real end-to-end regression test for BUG-046: a mutating tool
    /// (`resolve_review_decision`) called over the HTTP transport with no
    /// `api_key` must be rejected by the tool handler itself — never
    /// proxied to the Ignite server — while a read-only tool
    /// (`list_guidelines`) keeps working with no key at all, matching the
    /// "frictionless for advisory/read-only tools" requirement.
    #[tokio::test]
    async fn http_transport_blocks_unauthenticated_mutating_tool_call() {
        std::env::set_var("IGNITE_API_KEY", "regression-test-key");
        HTTP_TRANSPORT.store(true, std::sync::atomic::Ordering::Relaxed);

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let session_manager = std::sync::Arc::new(
            rmcp::transport::streamable_http_server::session::local::LocalSessionManager::default(),
        );
        let service = rmcp::transport::streamable_http_server::tower::StreamableHttpService::new(
            || Ok(IgniteMcp::new()),
            session_manager,
            Default::default(),
        );
        let app = axum::Router::new().route_service("/mcp", AxumStreamableHttp(service));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("http://{addr}/mcp");
        let client = reqwest::Client::new();

        let init_resp = client
            .post(&url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "0.0.1"}
                }
            }))
            .send()
            .await
            .unwrap();
        let session_id = init_resp.headers().get("mcp-session-id").unwrap().to_str().unwrap().to_string();
        let _ = parse_sse_or_json(init_resp).await;

        client
            .post(&url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id)
            .json(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .send()
            .await
            .unwrap();

        // No api_key supplied: must be rejected without ever reaching out
        // to an Ignite server (there isn't one running for this test).
        let call_resp = client
            .post(&url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "resolve_review_decision", "arguments": {"job_id": "abc", "proceed": true}}
            }))
            .send()
            .await
            .unwrap();
        let call_body: Value = parse_sse_or_json(call_resp).await;
        let text = call_body["result"]["content"][0]["text"].as_str().unwrap_or("");
        assert!(text.contains("requires an IGNITE_API_KEY"), "expected the mutation-auth rejection, got: {text}");
        assert_eq!(call_body["result"]["isError"], json!(true));

        // Read-only tool still works over the same session with no key.
        let list_resp = client
            .post(&url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "list_guidelines", "arguments": {}}
            }))
            .send()
            .await
            .unwrap();
        let list_body: Value = parse_sse_or_json(list_resp).await;
        assert_ne!(list_body["result"]["isError"], json!(true), "read-only tools must stay frictionless with no api_key");

        HTTP_TRANSPORT.store(false, std::sync::atomic::Ordering::Relaxed);
        std::env::remove_var("IGNITE_API_KEY");
    }

    #[test]
    fn an_async_start_is_only_a_job_when_the_server_says_202_with_a_job_id() {
        let started = serde_json::json!({ "ok": true, "async": true, "jobId": "abc" });
        assert_eq!(classify_async_start(202, &started), AsyncStart::Job("abc".to_string()));
        // An older server ignores `async` and answers synchronously.
        assert_eq!(classify_async_start(200, &serde_json::json!({ "ok": true, "jobId": "abc" })), AsyncStart::Immediate);
        // An immediate refusal is the final answer, not a job.
        assert_eq!(classify_async_start(403, &serde_json::json!({ "ok": false, "code": "scope_denied" })), AsyncStart::Immediate);
        assert_eq!(classify_async_start(202, &serde_json::json!({ "ok": true })), AsyncStart::Immediate, "no job id, nothing to poll");
    }

    #[test]
    fn polling_distinguishes_running_done_and_a_failed_poll() {
        assert_eq!(interpret_poll(202, Some(&serde_json::json!({ "state": "running" }))), PollOutcome::Running);
        let done = serde_json::json!({ "ok": true, "state": "done", "httpStatus": 400, "result": { "ok": false, "blocked": true } });
        assert_eq!(interpret_poll(200, Some(&done)), PollOutcome::Done(serde_json::json!({ "ok": false, "blocked": true })), "the pipeline's own failure is returned as the result, not as a poll error");
        assert!(matches!(interpret_poll(404, Some(&serde_json::json!({ "code": "unknown_job" }))), PollOutcome::Error(m) if m.contains("unknown_job")));
        assert!(matches!(interpret_poll(200, None), PollOutcome::Error(_)));
    }
}
