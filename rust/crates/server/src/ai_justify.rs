//! Auto-justification of low-risk blocking findings at the final review
//! gate — `config.ai_auto_justify` (see its own doc comment in
//! `ignite-config`). Runs strictly after exact-match carry-forward from a
//! previous scan of the same repo (`db_store::get_carry_forward_overrides`)
//! has already claimed everything it can; this only ever sees findings
//! carry-forward left behind, and only ever offers the model findings
//! whose category is on the configured allowlist — the model drafts a
//! justification, it never gets a vote on which categories are eligible.

use ignite_config::AiAutoJustifyConfig;
use ignite_llm_client::{llm_available, llm_complete, LlmClientConfig};
use ignite_override_engine::Issue;
use std::collections::HashMap;

const SYSTEM_PROMPT: &str = r#"You are drafting override justifications for a code-compliance gate. You will be given a JSON array of findings, each with "id", "category", "summary", "file", "line", and (when available) "code" — the actual matched source line, for you to judge whether this is a false positive. For each finding you are highly confident is safe to acknowledge as-is (a false positive, or a genuinely low/no-risk finding needing no source change), include it in your reply. Never include a finding you are unsure about — omitting it is always safe, a wrong justification is not.

Reply with ONLY a JSON object of this exact shape, no prose, no markdown fence:
{"justifications": [{"id": "<the finding's id, copied exactly>", "justification": "<one sentence, specific to this finding, suitable as an audit-log entry>"}]}

If none are safe to acknowledge, reply {"justifications": []}."#;

#[derive(Debug, serde::Deserialize)]
struct JustifyEntry {
    id: String,
    justification: String,
}

#[derive(Debug, serde::Deserialize)]
struct JustifyResponse {
    #[serde(default)]
    justifications: Vec<JustifyEntry>,
}

/// Returns `issue_id -> justification` for findings the model was willing
/// to justify, already filtered back down to `config.categories` — never
/// trust the response's own category framing, only the id it echoes back,
/// matched against the eligible set built here.
pub async fn suggest_justifications(config: &AiAutoJustifyConfig, llm_config: &LlmClientConfig, issues: &[Issue], mut log: impl FnMut(&str)) -> HashMap<String, String> {
    let mut result = HashMap::new();
    if !config.enabled || config.categories.is_empty() {
        return result;
    }

    let eligible: Vec<&Issue> = issues.iter().filter(|i| config.categories.iter().any(|c| c == &i.category)).take(config.max_findings_per_request.max(1)).collect();
    if eligible.is_empty() {
        return result;
    }

    let http = reqwest::Client::new();
    if !llm_available(&http, llm_config).await {
        log("[ai-justify] skipped — configured LLM endpoint is unavailable.");
        return result;
    }

    let eligible_ids: std::collections::HashSet<&str> = eligible.iter().map(|i| i.id.as_str()).collect();
    // The actual matched line is only ever handed to a *local* model — for
    // openai/anthropic/azure-foundry a finding's raw code (which, for a
    // `secret` finding that turns out NOT to be a false positive, is a real
    // credential) would otherwise leave this machine to a third-party API
    // before any human has reviewed it. Without it, the model only has the
    // category/summary text to go on, which is enough for categories like
    // `semantic-sast` (the summary itself is usually self-explanatory) but
    // not for judging whether a matched secret value is a false positive.
    let include_code = llm_config.provider == ignite_llm_client::Provider::Local;
    let payload: Vec<serde_json::Value> = eligible
        .iter()
        .map(|i| {
            let mut v = serde_json::json!({ "id": i.id, "category": i.category, "summary": i.summary, "file": i.file, "line": i.line });
            if include_code {
                if let Some(code) = highlighted_snippet_line(i.snippet.as_ref()) {
                    v.as_object_mut().unwrap().insert("code".to_string(), serde_json::json!(code));
                }
            }
            v
        })
        .collect();
    let user_content = serde_json::to_string(&payload).unwrap_or_else(|_| "[]".to_string());

    match llm_complete(&ignite_llm_client::LlmCompleteRequest { client: &http, config: llm_config, system_prompt: SYSTEM_PROMPT, user_content: &user_content, temperature: 0.0, timeout_ms: 60_000, label: "ai-justify" }, &mut log).await {
        Ok(text) => {
            let cleaned = text.trim().trim_start_matches("```json").trim_start_matches("```").trim_end_matches("```").trim();
            match serde_json::from_str::<JustifyResponse>(cleaned) {
                Ok(parsed) => {
                    for entry in parsed.justifications {
                        let justification = entry.justification.trim();
                        if justification.is_empty() {
                            continue;
                        }
                        // Server-side allowlist check: only accept ids we
                        // actually offered, so the model can't justify a
                        // finding outside the categories it was scoped to.
                        if eligible_ids.contains(entry.id.as_str()) {
                            result.insert(entry.id, justification.to_string());
                        }
                    }
                }
                Err(e) => log(&format!("[ai-justify] could not parse LLM response as JSON — skipping this batch: {e}")),
            }
        }
        Err(e) => log(&format!("[ai-justify] request failed — skipping this batch: {e}")),
    }

    result
}

/// Pulls the single highlighted line's text out of an `Issue::snippet`
/// blob (`{ lines: [{ number, text }], highlightLine }`, see
/// `ignite_fs_utils::Snippet`) — kept as a loose `serde_json::Value` on
/// `Issue` itself, so this re-parses it rather than adding a dependency
/// on `fs-utils` just for this one lookup.
fn highlighted_snippet_line(snippet: Option<&serde_json::Value>) -> Option<String> {
    let snippet = snippet?;
    let highlight_line = snippet.get("highlightLine")?.as_i64()?;
    snippet.get("lines")?.as_array()?.iter().find_map(|line| {
        if line.get("number")?.as_i64()? == highlight_line {
            line.get("text")?.as_str().map(str::to_string)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ignite_override_engine::Severity;

    fn issue(id: &str, category: &str) -> Issue {
        Issue {
            id: id.to_string(),
            category: category.to_string(),
            severity: Severity::Error,
            score: 6,
            summary: "Unrecognized license".to_string(),
            file: Some("requirements.txt".to_string()),
            line: Some(9),
            snippet: None,
            cross_file: false,
            chain: None,
            duplicate_ref: None,
            cwe: None,
            owasp: None,
            tool: None,
            references: Default::default(),
        }
    }

    #[tokio::test]
    async fn disabled_config_short_circuits_without_any_network_call() {
        let config = AiAutoJustifyConfig { enabled: false, ..Default::default() };
        let issues = vec![issue("license-compliance::requirements.txt::0::PyMuPDF", "license-compliance")];
        let out = suggest_justifications(&config, &default_llm_config(), &issues, |_| {}).await;
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn no_eligible_category_short_circuits_without_any_network_call() {
        let config = AiAutoJustifyConfig { enabled: true, categories: vec!["license-compliance".to_string()], max_findings_per_request: 50 };
        let issues = vec![issue("secret::app.js::5", "secret")];
        let out = suggest_justifications(&config, &default_llm_config(), &issues, |_| {}).await;
        assert!(out.is_empty());
    }

    fn default_llm_config() -> LlmClientConfig {
        LlmClientConfig {
            provider: ignite_llm_client::Provider::Local,
            openai_api_key: String::new(),
            openai_base_url: String::new(),
            openai_model: String::new(),
            anthropic_api_key: String::new(),
            anthropic_base_url: String::new(),
            anthropic_model: String::new(),
            azure_foundry_api_key: String::new(),
            azure_foundry_endpoint: String::new(),
            azure_foundry_deployment: String::new(),
            azure_foundry_api_version: String::new(),
            scan_url: "http://127.0.0.1:1".to_string(),
            scan_model: String::new(),
        }
    }
}
