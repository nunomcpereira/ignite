//! Shared local-LLM/OpenAI chat-completions client. Faithful port of
//! `lib/llm-client.js`'s `llmTarget`/`llmChat`/`llmAvailable`/`llmComplete`.
//! `llmAvailableCached`/`logLlmExchange` (a per-process cache + a debug
//! trace log, both server-process-lifetime concerns) aren't ported —
//! deferred to when the HTTP server's own process-lifetime state exists.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone)]
pub enum Provider {
    Local,
    OpenAi,
}

#[derive(Debug, Clone)]
pub struct LlmClientConfig {
    pub provider: Provider,
    pub openai_api_key: String,
    pub openai_base_url: String,
    pub openai_model: String,
    pub scan_url: String,
    pub scan_model: String,
}

pub struct LlmTarget {
    pub url: String,
    pub model: String,
    pub auth_header: Option<String>,
}

/// Resolves the effective chat-completions endpoint/model/auth for
/// whichever provider is configured.
pub fn llm_target(config: &LlmClientConfig) -> LlmTarget {
    match config.provider {
        Provider::OpenAi => {
            let base = config.openai_base_url.trim_end_matches('/');
            LlmTarget { url: format!("{}/chat/completions", base), model: config.openai_model.clone(), auth_header: Some(format!("Bearer {}", config.openai_api_key)) }
        }
        Provider::Local => LlmTarget { url: format!("{}/v1/chat/completions", config.scan_url), model: config.scan_model.clone(), auth_header: None },
    }
}

#[derive(Debug, Error)]
pub enum LlmError {
    #[error("LLM request timed out after {0}ms")]
    Timeout(u64),
    #[error("Could not reach the LLM endpoint: {0}")]
    NetworkError(String),
    #[error("LLM endpoint returned HTTP {0}")]
    HttpError(u16),
    #[error("LLM returned an empty response")]
    EmptyResponse,
    #[error("LLM returned non-JSON output; skipping chunk.")]
    NonJsonOutput,
}

#[derive(Debug, Deserialize)]
pub struct LlmFinding {
    pub file: Option<String>,
    pub line: Option<i64>,
    pub category: Option<String>,
    pub level: Option<String>,
    pub issue: Option<String>,
    pub recommendation: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FindingsResponse {
    #[serde(default)]
    findings: Vec<LlmFinding>,
}

#[derive(Debug, Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Debug, Serialize)]
struct ResponseFormat<'a> {
    #[serde(rename = "type")]
    format_type: &'a str,
}

#[derive(Debug, Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    stream: bool,
    temperature: f64,
    response_format: ResponseFormat<'a>,
    messages: Vec<ChatMessage<'a>>,
}

/// Sends `source_block` through `system_prompt` and parses the model's
/// `{"findings": [...]}` JSON response. `log` receives the same
/// `[llm] → .../← ...` trace lines the JS original prints, for a phase's
/// live log stream.
pub async fn llm_chat(client: &reqwest::Client, config: &LlmClientConfig, source_block: &str, system_prompt: &str, label: &str, mut log: impl FnMut(&str)) -> Result<Vec<LlmFinding>, LlmError> {
    let timeout_ms: u64 = 300_000;
    let target = llm_target(config);
    let provider_label = format!("{} [{}]", label, if matches!(config.provider, Provider::OpenAi) { "openai" } else { "local" });
    log(&format!("[llm] → {} POST {} model={} timeout={}ms payload={} chars", provider_label, target.url, target.model, timeout_ms, source_block.len()));
    let started_at = std::time::Instant::now();

    let mut req = client.post(&target.url).timeout(Duration::from_millis(timeout_ms)).json(&ChatRequest {
        model: &target.model,
        stream: false,
        temperature: 0.0,
        response_format: ResponseFormat { format_type: "json_object" },
        messages: vec![ChatMessage { role: "system", content: system_prompt }, ChatMessage { role: "user", content: source_block }],
    });
    if let Some(auth) = &target.auth_header {
        req = req.header("Authorization", auth);
    }

    let response = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let elapsed = started_at.elapsed().as_millis();
            if e.is_timeout() {
                log(&format!("[llm] ← {} TIMED OUT in {}ms", provider_label, elapsed));
                return Err(LlmError::Timeout(timeout_ms));
            }
            log(&format!("[llm] ← {} FAILED in {}ms — {}", provider_label, elapsed, e));
            return Err(LlmError::NetworkError(e.to_string()));
        }
    };

    let elapsed = started_at.elapsed().as_millis();
    if !response.status().is_success() {
        let status = response.status().as_u16();
        log(&format!("[llm] ← {} HTTP ERROR in {}ms — {}", provider_label, elapsed, status));
        return Err(LlmError::HttpError(status));
    }

    let data: serde_json::Value = response.json().await.map_err(|e| LlmError::NetworkError(e.to_string()))?;
    let text = data.get("choices").and_then(|c| c.get(0)).and_then(|c| c.get("message")).and_then(|m| m.get("content")).and_then(|c| c.as_str()).unwrap_or("").to_string();
    log(&format!("[llm] ← {} OK in {}ms — {} chars returned", provider_label, elapsed, text.len()));

    let parsed: FindingsResponse = serde_json::from_str(&text).map_err(|_| LlmError::NonJsonOutput)?;
    Ok(parsed.findings)
}

/// Health/availability probe: for OpenAI, just confirms the API key is
/// configured (no cheap health probe worth spending a request on); for the
/// local provider, hits `<scan_url>/health`.
#[derive(Debug, Serialize)]
struct ChatRequestPlain<'a> {
    model: &'a str,
    stream: bool,
    temperature: f64,
    messages: Vec<ChatMessage<'a>>,
}

/// Faithful port of `lib/llm-client.js`'s `llmComplete` — a free-text
/// chat completion (no JSON response-format constraint), backing Studio's
/// AI-explain/AI-suggest-fix features. Unlike `llm_chat`, the caller
/// picks its own temperature/timeout per use case.
pub async fn llm_complete(client: &reqwest::Client, config: &LlmClientConfig, system_prompt: &str, user_content: &str, temperature: f64, timeout_ms: u64, label: &str, mut log: impl FnMut(&str)) -> Result<String, LlmError> {
    let target = llm_target(config);
    let provider_label = format!("{} [{}]", label, if matches!(config.provider, Provider::OpenAi) { "openai" } else { "local" });
    log(&format!("[llm] → {} POST {} model={} timeout={}ms chars={}", provider_label, target.url, target.model, timeout_ms, user_content.len()));
    let started_at = std::time::Instant::now();

    let mut req = client.post(&target.url).timeout(Duration::from_millis(timeout_ms)).json(&ChatRequestPlain {
        model: &target.model,
        stream: false,
        temperature,
        messages: vec![ChatMessage { role: "system", content: system_prompt }, ChatMessage { role: "user", content: user_content }],
    });
    if let Some(auth) = &target.auth_header {
        req = req.header("Authorization", auth);
    }

    let response = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let elapsed = started_at.elapsed().as_millis();
            if e.is_timeout() {
                log(&format!("[llm] ← {} TIMED OUT in {}ms", provider_label, elapsed));
                return Err(LlmError::Timeout(timeout_ms));
            }
            log(&format!("[llm] ← {} FAILED in {}ms — {}", provider_label, elapsed, e));
            return Err(LlmError::NetworkError(e.to_string()));
        }
    };

    let elapsed = started_at.elapsed().as_millis();
    if !response.status().is_success() {
        let status = response.status().as_u16();
        log(&format!("[llm] ← {} HTTP ERROR in {}ms — {}", provider_label, elapsed, status));
        return Err(LlmError::HttpError(status));
    }

    let data: serde_json::Value = response.json().await.map_err(|e| LlmError::NetworkError(e.to_string()))?;
    let text = data.get("choices").and_then(|c| c.get(0)).and_then(|c| c.get("message")).and_then(|m| m.get("content")).and_then(|c| c.as_str()).unwrap_or("").trim().to_string();
    log(&format!("[llm] ← {} OK in {}ms — {} chars returned", provider_label, elapsed, text.len()));
    if text.is_empty() {
        return Err(LlmError::EmptyResponse);
    }
    Ok(text)
}

pub async fn llm_available(client: &reqwest::Client, config: &LlmClientConfig) -> bool {
    if matches!(config.provider, Provider::OpenAi) {
        return !config.openai_api_key.is_empty();
    }
    let url = format!("{}/health", config.scan_url);
    match client.get(&url).timeout(Duration::from_secs(3)).send().await {
        Ok(r) => r.status().is_success(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_config() -> LlmClientConfig {
        LlmClientConfig { provider: Provider::Local, openai_api_key: String::new(), openai_base_url: String::new(), openai_model: String::new(), scan_url: "http://127.0.0.1:9999".to_string(), scan_model: "test-model".to_string() }
    }

    fn openai_config() -> LlmClientConfig {
        LlmClientConfig { provider: Provider::OpenAi, openai_api_key: "sk-test".to_string(), openai_base_url: "https://api.openai.com/v1/".to_string(), openai_model: "gpt-4o-mini".to_string(), scan_url: String::new(), scan_model: String::new() }
    }

    #[test]
    fn llm_target_local_has_no_auth_header() {
        let target = llm_target(&local_config());
        assert_eq!(target.url, "http://127.0.0.1:9999/v1/chat/completions");
        assert_eq!(target.model, "test-model");
        assert!(target.auth_header.is_none());
    }

    #[test]
    fn llm_target_openai_strips_trailing_slash_and_sets_bearer_auth() {
        let target = llm_target(&openai_config());
        assert_eq!(target.url, "https://api.openai.com/v1/chat/completions");
        assert_eq!(target.auth_header.as_deref(), Some("Bearer sk-test"));
    }

    #[tokio::test]
    async fn llm_available_openai_checks_api_key_presence_only() {
        let client = reqwest::Client::new();
        assert!(llm_available(&client, &openai_config()).await);
        let mut no_key = openai_config();
        no_key.openai_api_key = String::new();
        assert!(!llm_available(&client, &no_key).await);
    }

    #[tokio::test]
    async fn llm_available_local_returns_false_when_endpoint_unreachable() {
        let client = reqwest::Client::new();
        assert!(!llm_available(&client, &local_config()).await);
    }

    #[tokio::test]
    async fn llm_chat_network_error_when_endpoint_unreachable() {
        let client = reqwest::Client::new();
        let mut logs = Vec::new();
        let result = llm_chat(&client, &local_config(), "source", "system prompt", "chat", |l| logs.push(l.to_string())).await;
        assert!(matches!(result, Err(LlmError::NetworkError(_))));
        assert!(logs.iter().any(|l| l.contains("→ chat [local]")));
    }

    #[tokio::test]
    async fn llm_complete_network_error_when_endpoint_unreachable() {
        let client = reqwest::Client::new();
        let mut logs = Vec::new();
        let result = llm_complete(&client, &local_config(), "system prompt", "user content", 0.2, 5000, "complete", |l| logs.push(l.to_string())).await;
        assert!(matches!(result, Err(LlmError::NetworkError(_))));
        assert!(logs.iter().any(|l| l.contains("→ complete [local]")));
    }
}
