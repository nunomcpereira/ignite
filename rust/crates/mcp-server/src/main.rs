//! MCP server exposing the company AI validation guidelines, faithful
//! port of `mcp-server.js`. Tools: list_guidelines, get_guideline,
//! check_guidelines, check_project (all local, backed directly by
//! ignite-guidelines), plus check_dependency_licenses,
//! check_dependency_vulnerabilities, onboard_project,
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
struct ApplyFixPrRequest {
    /// Same job id passed to preview_fix_pr.
    job_id: String,
    /// The candidate list from preview_fix_pr's response, copied verbatim (trim it to whichever fixes you want included) — each entry must keep its exact original shape (issueId, file, startLine, endLine, original, replacement, etc.), so re-embed the JSON objects as returned rather than reconstructing them.
    candidates: Vec<Value>,
    /// Required when this server is reachable over the network (MCP_TRANSPORT=http) — must match the server's own IGNITE_API_KEY. Not needed for a local stdio connection.
    api_key: Option<String>,
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
        let root = std::path::Path::new(&req.project_path);
        match ignite_guidelines::checks::check_project(root) {
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
        description = "Run all Ignite onboarding checks against a local project directory, and — if every check passes — provision a private GitHub repo and push the code. Set dryRun=true to run every check without pushing. Requires a running Ignite server with `gh` authenticated."
    )]
    async fn onboard_project(&self, Parameters(req): Parameters<OnboardProjectRequest>) -> Result<CallToolResult, McpError> {
        // Dry runs (checks-only, no provisioning/push) stay frictionless
        // even over the network — only a real onboard actually mutates
        // anything.
        if !req.dry_run.unwrap_or(false) && !authorized_for_mutation(req.api_key.as_deref()) {
            return Ok(text_result(MUTATION_AUTH_ERROR.to_string(), true));
        }
        self.proxy_to_ignite(
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
        description = "Provision + push the exact snapshot already validated by a prior onboard_project(dryRun: true) call, without re-running phases 1-5. Requires a running Ignite server with `gh` authenticated, and the caller's GitHub account connected."
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
        let endpoint = format!("/api/pipeline/{}/fix-pr/preview", urlencoding::encode(&req.job_id));
        self.proxy_to_ignite(&endpoint, serde_json::json!({})).await
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
    let app = axum::Router::new().route_service("/mcp", AxumStreamableHttp(service));
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
                "params": {"name": "resolve_review_decision", "arguments": {"jobId": "abc", "proceed": true}}
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
}
