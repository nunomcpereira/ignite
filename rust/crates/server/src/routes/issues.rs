//! /api/issues/{explain,suggest-fix} — faithful port of routes/issues.js.
//! `llmAvailableCached`'s process-lifetime cache isn't ported (see
//! ignite-llm-client's module doc) — every request re-probes availability.

use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use ignite_llm_client::LlmError;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const ISSUE_EXPLAIN_PROMPT: &str = "You are explaining one single flagged code issue to a non-technical reader (e.g. a project manager), using the exact code snippet shown.\nWrite 2-4 sentences in plain language with no jargon: what is concretely wrong in THIS snippet, why it matters in the real world, and what should change. Do not just restate the technical summary you were given — actually explain it. Do not discuss anything beyond this one issue.";

const ISSUE_SUGGEST_FIX_PROMPT: &str = "You are a senior software engineer proposing a concrete fix for one single flagged code issue, using the exact numbered code snippet shown.\nPropose a corrected replacement for ONLY the exact line range shown in the snippet (from its first to its last numbered line) — do not rewrite the whole file, do not renumber lines, do not add lines outside that range.\nRespond in EXACTLY this plain-text format and nothing else — no JSON, no code fences, no text before or after:\nEXPLANATION: <1-3 sentences: what changed and why it fixes the issue>\nREPLACEMENT:\n<the corrected text for that exact line range, copied verbatim with no escaping, newline-separated, no line-number prefixes>\nIf you cannot safely propose a fix from the snippet alone, respond:\nEXPLANATION: <why not>\nREPLACEMENT: NONE";

#[derive(Debug, Clone)]
struct SnippetLine {
    number: i64,
    text: String,
}

#[derive(Debug, Clone)]
struct Snippet {
    start_line: i64,
    lines: Vec<SnippetLine>,
}

#[derive(Debug, Clone)]
struct ParsedIssue {
    category: String,
    severity: String,
    file: Option<String>,
    line: Option<i64>,
    summary: String,
    snippet: Option<Snippet>,
}

fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn parse_issue_from_body(body: &Value) -> Option<ParsedIssue> {
    let category = body.get("category").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let summary_raw = body.get("summary").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if category.is_empty() || summary_raw.is_empty() {
        return None;
    }
    let severity = match body.get("severity").and_then(|v| v.as_str()) {
        Some("error") => "error".to_string(),
        Some("warning") => "warning".to_string(),
        _ => "warning".to_string(),
    };
    let file = body.get("file").and_then(|v| v.as_str()).map(|s| truncate_chars(s, 500));
    let line = body.get("line").and_then(|v| v.as_i64());
    let summary = truncate_chars(&summary_raw, 500);
    let snippet = body.get("snippet").and_then(|s| {
        let lines_val = s.get("lines")?.as_array()?;
        let lines = lines_val
            .iter()
            .map(|l| SnippetLine { number: l.get("number").and_then(|v| v.as_i64()).unwrap_or(0), text: l.get("text").and_then(|v| v.as_str()).unwrap_or("").to_string() })
            .collect();
        Some(Snippet { start_line: s.get("startLine").and_then(|v| v.as_i64()).unwrap_or(1), lines })
    });
    Some(ParsedIssue { category, severity, file, line, summary, snippet })
}

/// Cached in the DB by a stable hash of the issue's identity, so opening
/// the same finding again — even in a different run — never re-triggers
/// the LLM call.
fn issue_explanation_hash(issue: &ParsedIssue) -> String {
    let key = format!("{}|{}|{}|{}", issue.category, issue.file.as_deref().unwrap_or(""), issue.line.unwrap_or(0), issue.summary);
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn code_block(snippet: &Option<Snippet>) -> String {
    match snippet {
        Some(s) if !s.lines.is_empty() => truncate_chars(&s.lines.iter().map(|l| format!("{}: {}", l.number, l.text)).collect::<Vec<_>>().join("\n"), 4000),
        _ => "(no code snippet available)".to_string(),
    }
}

fn issue_user_prompt(issue: &ParsedIssue) -> String {
    format!(
        "Category: {}\nSeverity: {}\nLocation: {}{}\nTechnical summary: {}\n\nCode:\n{}",
        issue.category,
        issue.severity,
        issue.file.as_deref().unwrap_or("unknown"),
        issue.line.map(|l| format!(":{l}")).unwrap_or_default(),
        issue.summary,
        code_block(&issue.snippet)
    )
}

fn friendly_llm_error_message(e: &LlmError) -> String {
    match e {
        LlmError::Timeout(ms) => format!("The AI took too long to respond (over {}s) and the request was cancelled. Try again, or check whether the local LLM is overloaded.", (*ms as f64 / 1000.0).round() as u64),
        LlmError::NetworkError(msg) => format!("Could not reach the AI service: {msg}"),
        LlmError::HttpError(status) => format!("The AI service returned an error (HTTP {status})."),
        LlmError::EmptyResponse => "The AI returned an empty response.".to_string(),
        LlmError::NonJsonOutput => "The AI response did not match the expected format.".to_string(),
    }
}

static CODE_FENCE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)^```(?:\w+)?\s*(.*?)\s*```$").unwrap());
static SUGGEST_FIX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)EXPLANATION:\s*(.*?)\n\s*REPLACEMENT:\s*(.*)$").unwrap());

fn strip_code_fence(text: &str) -> String {
    let trimmed = text.trim();
    match CODE_FENCE_RE.captures(trimmed) {
        Some(c) => c[1].to_string(),
        None => trimmed.to_string(),
    }
}

/// Trims fully-blank leading/trailing lines without disturbing the
/// indentation of the code itself.
fn trim_block_lines(raw: &str) -> String {
    let normalized = raw.replace("\r\n", "\n");
    let mut lines: Vec<&str> = normalized.split('\n').collect();
    while lines.first().map(|l| l.trim().is_empty()).unwrap_or(false) {
        lines.remove(0);
    }
    while lines.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
        lines.pop();
    }
    lines.join("\n")
}

struct FixResponse {
    explanation: String,
    replacement: Option<String>,
}

fn parse_suggest_fix_response(text: &str) -> Result<FixResponse, &'static str> {
    let trimmed = strip_code_fence(text);
    let Some(m) = SUGGEST_FIX_RE.captures(&trimmed) else {
        return Err("The AI response did not match the expected fix format.");
    };
    let explanation = m[1].trim().to_string();
    let replacement_block = trim_block_lines(&strip_code_fence(&m[2]));
    let replacement = if replacement_block.to_uppercase() == "NONE" { None } else { Some(replacement_block) };
    Ok(FixResponse { explanation, replacement })
}

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

async fn explain(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> Response {
    let Some(issue) = parse_issue_from_body(&body) else {
        return err(StatusCode::BAD_REQUEST, "category and summary are required.".to_string());
    };

    let hash = issue_explanation_hash(&issue);
    if let Some(cached) = state.db.get_cached_issue_explanation(&hash) {
        return Json(json!({ "ok": true, "explanation": cached, "cached": true })).into_response();
    }

    let http = reqwest::Client::new();
    if !ignite_llm_client::llm_available(&http, &state.llm_config).await {
        return Json(json!({ "ok": true, "explanation": Value::Null, "cached": false, "reason": "AI explanation service unavailable." })).into_response();
    }

    let user = issue_user_prompt(&issue);
    let label = format!("issue-explain {}:{}:{}", issue.category, issue.file.as_deref().unwrap_or("?"), issue.line.unwrap_or(0));
    match ignite_llm_client::llm_complete(&ignite_llm_client::LlmCompleteRequest { client: &http, config: &state.llm_config, system_prompt: ISSUE_EXPLAIN_PROMPT, user_content: &user, temperature: 0.3, timeout_ms: 60_000, label: &label }, |_| {}).await {
        Ok(explanation) => {
            state.db.cache_issue_explanation(&hash, &explanation);
            Json(json!({ "ok": true, "explanation": explanation, "cached": false })).into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "error": friendly_llm_error_message(&e) }))).into_response(),
    }
}

async fn suggest_fix(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> Response {
    let Some(issue) = parse_issue_from_body(&body) else {
        return err(StatusCode::BAD_REQUEST, "category and summary are required.".to_string());
    };
    let Some(snippet) = &issue.snippet else {
        return err(StatusCode::BAD_REQUEST, "A code snippet is required to suggest a fix.".to_string());
    };
    if snippet.lines.is_empty() {
        return Json(json!({ "ok": true, "suggestion": Value::Null })).into_response();
    }

    let http = reqwest::Client::new();
    if !ignite_llm_client::llm_available(&http, &state.llm_config).await {
        return Json(json!({ "ok": true, "suggestion": Value::Null, "reason": "AI fix suggestion service unavailable." })).into_response();
    }

    let user = issue_user_prompt(&issue);
    let label = format!("issue-suggest-fix {}:{}:{}", issue.category, issue.file.as_deref().unwrap_or("?"), issue.line.unwrap_or(0));
    match ignite_llm_client::llm_complete(&ignite_llm_client::LlmCompleteRequest { client: &http, config: &state.llm_config, system_prompt: ISSUE_SUGGEST_FIX_PROMPT, user_content: &user, temperature: 0.2, timeout_ms: 60_000, label: &label }, |_| {}).await {
        Ok(text) => match parse_suggest_fix_response(&text) {
            Ok(parsed) => {
                let start_line = snippet.start_line;
                let end_line = snippet.start_line + snippet.lines.len() as i64 - 1;
                Json(json!({ "ok": true, "suggestion": { "explanation": parsed.explanation, "replacement": parsed.replacement, "startLine": start_line, "endLine": end_line } })).into_response()
            }
            Err(msg) => (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "error": msg }))).into_response(),
        },
        Err(e) => (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "error": friendly_llm_error_message(&e) }))).into_response(),
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/issues/explain", post(explain)).route("/api/issues/suggest-fix", post(suggest_fix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_issue_from_body_requires_category_and_summary() {
        assert!(parse_issue_from_body(&json!({})).is_none());
        assert!(parse_issue_from_body(&json!({"category": "secret"})).is_none());
        assert!(parse_issue_from_body(&json!({"summary": "x"})).is_none());
    }

    #[test]
    fn parse_issue_from_body_defaults_severity_to_warning() {
        let issue = parse_issue_from_body(&json!({"category": "secret", "summary": "found one"})).unwrap();
        assert_eq!(issue.severity, "warning");
    }

    #[test]
    fn parse_issue_from_body_parses_snippet() {
        let body = json!({"category": "secret", "summary": "found", "snippet": {"startLine": 5, "lines": [{"number": 5, "text": "const x = 1;"}]}});
        let issue = parse_issue_from_body(&body).unwrap();
        let snippet = issue.snippet.unwrap();
        assert_eq!(snippet.start_line, 5);
        assert_eq!(snippet.lines.len(), 1);
    }

    #[test]
    fn issue_explanation_hash_is_stable_for_same_identity() {
        let a = parse_issue_from_body(&json!({"category": "secret", "summary": "found", "file": "a.js", "line": 3})).unwrap();
        let b = parse_issue_from_body(&json!({"category": "secret", "summary": "found", "file": "a.js", "line": 3})).unwrap();
        assert_eq!(issue_explanation_hash(&a), issue_explanation_hash(&b));
    }

    #[test]
    fn issue_explanation_hash_differs_for_different_identity() {
        let a = parse_issue_from_body(&json!({"category": "secret", "summary": "found", "file": "a.js", "line": 3})).unwrap();
        let b = parse_issue_from_body(&json!({"category": "secret", "summary": "found", "file": "b.js", "line": 3})).unwrap();
        assert_ne!(issue_explanation_hash(&a), issue_explanation_hash(&b));
    }

    #[test]
    fn parse_suggest_fix_response_extracts_explanation_and_replacement() {
        let text = "EXPLANATION: renamed the variable\nREPLACEMENT:\nconst safe = 1;\n";
        let parsed = parse_suggest_fix_response(text).unwrap();
        assert_eq!(parsed.explanation, "renamed the variable");
        assert_eq!(parsed.replacement.as_deref(), Some("const safe = 1;"));
    }

    #[test]
    fn parse_suggest_fix_response_treats_none_as_no_replacement() {
        let text = "EXPLANATION: cannot safely fix\nREPLACEMENT: NONE";
        let parsed = parse_suggest_fix_response(text).unwrap();
        assert_eq!(parsed.replacement, None);
    }

    #[test]
    fn parse_suggest_fix_response_strips_code_fence() {
        let text = "```\nEXPLANATION: fixed it\nREPLACEMENT:\nconst x = 1;\n```";
        let parsed = parse_suggest_fix_response(text).unwrap();
        assert_eq!(parsed.explanation, "fixed it");
    }

    #[test]
    fn parse_suggest_fix_response_errors_on_unrecognized_format() {
        assert!(parse_suggest_fix_response("not the expected format at all").is_err());
    }

    #[test]
    fn friendly_llm_error_message_covers_every_variant() {
        assert!(friendly_llm_error_message(&LlmError::Timeout(60_000)).contains("60s"));
        assert!(friendly_llm_error_message(&LlmError::NetworkError("boom".to_string())).contains("boom"));
        assert!(friendly_llm_error_message(&LlmError::HttpError(500)).contains("500"));
        assert!(friendly_llm_error_message(&LlmError::EmptyResponse).contains("empty"));
    }
}
