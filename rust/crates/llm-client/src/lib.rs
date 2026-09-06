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
    /// Anthropic's Messages API (`/v1/messages`) — a different request/
    /// response shape from the OpenAI-compatible chat-completions path
    /// the other two providers share, so it's branched separately in
    /// `llm_chat`/`llm_complete`/`llm_available` rather than folded into
    /// `llm_target`/`ChatRequest`.
    Anthropic,
    /// Azure AI Foundry (formerly Azure OpenAI Service). Shares the
    /// OpenAI-compatible chat-completions request/response body, but the
    /// URL is per-resource/per-deployment
    /// (`{endpoint}/openai/deployments/{deployment}/chat/completions?api-version=...`)
    /// and auth is an `api-key` header, not `Authorization: Bearer` — so
    /// like Anthropic it's branched separately rather than folded into
    /// `llm_target`'s bearer-auth path.
    AzureFoundry,
}

#[derive(Debug, Clone)]
pub struct LlmClientConfig {
    pub provider: Provider,
    pub openai_api_key: String,
    pub openai_base_url: String,
    pub openai_model: String,
    pub anthropic_api_key: String,
    pub anthropic_base_url: String,
    pub anthropic_model: String,
    pub azure_foundry_api_key: String,
    /// Resource endpoint, e.g. `https://my-resource.openai.azure.com` —
    /// no `/openai/deployments/...` suffix (that's built in `llm_target`).
    pub azure_foundry_endpoint: String,
    pub azure_foundry_deployment: String,
    pub azure_foundry_api_version: String,
    pub scan_url: String,
    pub scan_model: String,
}

/// Anthropic API version pinned on every request, per Anthropic's own
/// versioning scheme (unrelated to the model version).
const ANTHROPIC_VERSION: &str = "2023-06-01";
/// Anthropic's Messages API requires `max_tokens`; the OpenAI-compatible
/// path this client otherwise uses has no equivalent required field.
/// Sized for a single issue explanation/suggested-fix reply, not a
/// multi-file scan response.
const ANTHROPIC_MAX_TOKENS: u32 = 4096;

pub struct LlmTarget {
    pub url: String,
    pub model: String,
    pub auth_header: Option<String>,
}

/// Resolves the effective chat-completions endpoint/model/auth for
/// whichever OpenAI-compatible provider is configured. Anthropic and Azure
/// Foundry aren't resolved here — see their `Provider` doc comments.
pub fn llm_target(config: &LlmClientConfig) -> LlmTarget {
    match config.provider {
        Provider::OpenAi => {
            let base = config.openai_base_url.trim_end_matches('/');
            LlmTarget { url: format!("{}/chat/completions", base), model: config.openai_model.clone(), auth_header: Some(format!("Bearer {}", config.openai_api_key)) }
        }
        Provider::Anthropic => {
            let base = config.anthropic_base_url.trim_end_matches('/');
            LlmTarget { url: format!("{}/messages", base), model: config.anthropic_model.clone(), auth_header: None }
        }
        Provider::AzureFoundry => azure_foundry_target(config),
        Provider::Local => LlmTarget { url: format!("{}/v1/chat/completions", config.scan_url), model: config.scan_model.clone(), auth_header: None },
    }
}

/// `auth_header` is always `None` here — Azure Foundry authenticates via
/// an `api-key` header, not `Authorization`, so callers branch on
/// `is_azure_foundry` and set it themselves, same as the Anthropic path.
fn azure_foundry_target(config: &LlmClientConfig) -> LlmTarget {
    let base = config.azure_foundry_endpoint.trim_end_matches('/');
    let url = format!("{}/openai/deployments/{}/chat/completions?api-version={}", base, config.azure_foundry_deployment, config.azure_foundry_api_version);
    LlmTarget { url, model: config.azure_foundry_deployment.clone(), auth_header: None }
}

fn provider_label(provider: &Provider) -> &'static str {
    match provider {
        Provider::OpenAi => "openai",
        Provider::Anthropic => "anthropic",
        Provider::AzureFoundry => "azure-foundry",
        Provider::Local => "local",
    }
}

#[derive(Debug, Serialize)]
struct AnthropicMessage<'a> {
    role: &'a str,
    content: &'a str,
}

/// No `temperature` field — current-generation Claude models (Opus 5,
/// Sonnet 5, the 4.6+ family) run adaptive thinking by default and reject
/// any explicit sampling parameter (`temperature`/`top_p`/`top_k`) with a
/// 400 (`"temperature" is deprecated for this model.`) once thinking is
/// on. The two OpenAI-compatible providers still take a per-call
/// temperature (`llm_chat`'s fixed 0.0, `llm_complete`'s caller-supplied
/// value) — only the Anthropic path drops it instead of forwarding it.
#[derive(Debug, Serialize)]
struct AnthropicRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    system: &'a str,
    messages: Vec<AnthropicMessage<'a>>,
}

/// Extracts and concatenates every `text` content block from an Anthropic
/// Messages API response (`{"content": [{"type": "text", "text": "..."}]}`).
fn anthropic_response_text(data: &serde_json::Value) -> String {
    data.get("content")
        .and_then(|c| c.as_array())
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default()
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
    let is_anthropic = matches!(config.provider, Provider::Anthropic);
    let is_azure_foundry = matches!(config.provider, Provider::AzureFoundry);
    let target = if is_anthropic { LlmTarget { url: format!("{}/messages", config.anthropic_base_url.trim_end_matches('/')), model: config.anthropic_model.clone(), auth_header: None } } else { llm_target(config) };
    let provider_label = format!("{} [{}]", label, provider_label(&config.provider));
    log(&format!("[llm] → {} POST {} model={} timeout={}ms payload={} chars", provider_label, target.url, target.model, timeout_ms, source_block.len()));
    let started_at = std::time::Instant::now();

    // Anthropic's Messages API keeps the system prompt in a top-level
    // `system` field (not a `role: "system"` message) and has no
    // `response_format` — the JSON-only instruction has to live in the
    // prompt text itself, same as it already does for the local/OpenAI
    // system prompts passed in by callers.
    let req = if is_anthropic {
        client.post(&target.url).timeout(Duration::from_millis(timeout_ms)).header("x-api-key", &config.anthropic_api_key).header("anthropic-version", ANTHROPIC_VERSION).json(&AnthropicRequest {
            model: &target.model,
            max_tokens: ANTHROPIC_MAX_TOKENS,
            system: system_prompt,
            messages: vec![AnthropicMessage { role: "user", content: source_block }],
        })
    } else {
        let mut r = client.post(&target.url).timeout(Duration::from_millis(timeout_ms)).json(&ChatRequest {
            model: &target.model,
            stream: false,
            temperature: 0.0,
            response_format: ResponseFormat { format_type: "json_object" },
            messages: vec![ChatMessage { role: "system", content: system_prompt }, ChatMessage { role: "user", content: source_block }],
        });
        r = if is_azure_foundry { r.header("api-key", &config.azure_foundry_api_key) } else if let Some(auth) = &target.auth_header { r.header("Authorization", auth) } else { r };
        r
    };

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
    let text = if is_anthropic { anthropic_response_text(&data) } else { data.get("choices").and_then(|c| c.get(0)).and_then(|c| c.get("message")).and_then(|m| m.get("content")).and_then(|c| c.as_str()).unwrap_or("").to_string() };
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
    let is_anthropic = matches!(config.provider, Provider::Anthropic);
    let is_azure_foundry = matches!(config.provider, Provider::AzureFoundry);
    let target = if is_anthropic { LlmTarget { url: format!("{}/messages", config.anthropic_base_url.trim_end_matches('/')), model: config.anthropic_model.clone(), auth_header: None } } else { llm_target(config) };
    let provider_label = format!("{} [{}]", label, provider_label(&config.provider));
    log(&format!("[llm] → {} POST {} model={} timeout={}ms chars={}", provider_label, target.url, target.model, timeout_ms, user_content.len()));
    let started_at = std::time::Instant::now();

    let req = if is_anthropic {
        client.post(&target.url).timeout(Duration::from_millis(timeout_ms)).header("x-api-key", &config.anthropic_api_key).header("anthropic-version", ANTHROPIC_VERSION).json(&AnthropicRequest {
            model: &target.model,
            max_tokens: ANTHROPIC_MAX_TOKENS,
            system: system_prompt,
            messages: vec![AnthropicMessage { role: "user", content: user_content }],
        })
    } else {
        let mut r = client.post(&target.url).timeout(Duration::from_millis(timeout_ms)).json(&ChatRequestPlain {
            model: &target.model,
            stream: false,
            temperature,
            messages: vec![ChatMessage { role: "system", content: system_prompt }, ChatMessage { role: "user", content: user_content }],
        });
        r = if is_azure_foundry { r.header("api-key", &config.azure_foundry_api_key) } else if let Some(auth) = &target.auth_header { r.header("Authorization", auth) } else { r };
        r
    };

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
    let text = if is_anthropic { anthropic_response_text(&data) } else { data.get("choices").and_then(|c| c.get(0)).and_then(|c| c.get("message")).and_then(|m| m.get("content")).and_then(|c| c.as_str()).unwrap_or("").to_string() }.trim().to_string();
    log(&format!("[llm] ← {} OK in {}ms — {} chars returned", provider_label, elapsed, text.len()));
    if text.is_empty() {
        return Err(LlmError::EmptyResponse);
    }
    Ok(text)
}

pub async fn llm_available(client: &reqwest::Client, config: &LlmClientConfig) -> bool {
    match config.provider {
        Provider::OpenAi => return !config.openai_api_key.is_empty(),
        Provider::Anthropic => return !config.anthropic_api_key.is_empty(),
        Provider::AzureFoundry => {
            return !config.azure_foundry_api_key.is_empty() && !config.azure_foundry_endpoint.is_empty() && !config.azure_foundry_deployment.is_empty();
        }
        Provider::Local => {}
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
        LlmClientConfig { provider: Provider::Local, openai_api_key: String::new(), openai_base_url: String::new(), openai_model: String::new(), anthropic_api_key: String::new(), anthropic_base_url: String::new(), anthropic_model: String::new(), azure_foundry_api_key: String::new(), azure_foundry_endpoint: String::new(), azure_foundry_deployment: String::new(), azure_foundry_api_version: String::new(), scan_url: "http://127.0.0.1:9999".to_string(), scan_model: "test-model".to_string() }
    }

    fn openai_config() -> LlmClientConfig {
        LlmClientConfig { provider: Provider::OpenAi, openai_api_key: "sk-test".to_string(), openai_base_url: "https://api.openai.com/v1/".to_string(), openai_model: "gpt-4o-mini".to_string(), anthropic_api_key: String::new(), anthropic_base_url: String::new(), anthropic_model: String::new(), azure_foundry_api_key: String::new(), azure_foundry_endpoint: String::new(), azure_foundry_deployment: String::new(), azure_foundry_api_version: String::new(), scan_url: String::new(), scan_model: String::new() }
    }

    fn anthropic_config() -> LlmClientConfig {
        LlmClientConfig { provider: Provider::Anthropic, openai_api_key: String::new(), openai_base_url: String::new(), openai_model: String::new(), anthropic_api_key: "sk-ant-test".to_string(), anthropic_base_url: "https://api.anthropic.com/v1/".to_string(), anthropic_model: "claude-opus-5".to_string(), azure_foundry_api_key: String::new(), azure_foundry_endpoint: String::new(), azure_foundry_deployment: String::new(), azure_foundry_api_version: String::new(), scan_url: String::new(), scan_model: String::new() }
    }

    fn azure_foundry_config() -> LlmClientConfig {
        LlmClientConfig {
            provider: Provider::AzureFoundry,
            openai_api_key: String::new(),
            openai_base_url: String::new(),
            openai_model: String::new(),
            anthropic_api_key: String::new(),
            anthropic_base_url: String::new(),
            anthropic_model: String::new(),
            azure_foundry_api_key: "az-test".to_string(),
            azure_foundry_endpoint: "https://my-resource.openai.azure.com/".to_string(),
            azure_foundry_deployment: "gpt-4o-deployment".to_string(),
            azure_foundry_api_version: "2024-10-21".to_string(),
            scan_url: String::new(),
            scan_model: String::new(),
        }
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
    async fn llm_available_anthropic_checks_api_key_presence_only() {
        let client = reqwest::Client::new();
        assert!(llm_available(&client, &anthropic_config()).await);
        let mut no_key = anthropic_config();
        no_key.anthropic_api_key = String::new();
        assert!(!llm_available(&client, &no_key).await);
    }

    #[test]
    fn llm_target_azure_foundry_builds_deployment_scoped_url_with_no_auth_header() {
        let target = llm_target(&azure_foundry_config());
        assert_eq!(target.url, "https://my-resource.openai.azure.com/openai/deployments/gpt-4o-deployment/chat/completions?api-version=2024-10-21");
        assert_eq!(target.model, "gpt-4o-deployment");
        assert!(target.auth_header.is_none(), "Azure Foundry authenticates via an api-key header, set separately by callers");
    }

    #[tokio::test]
    async fn llm_available_azure_foundry_requires_key_endpoint_and_deployment() {
        let client = reqwest::Client::new();
        assert!(llm_available(&client, &azure_foundry_config()).await);
        let mut missing_deployment = azure_foundry_config();
        missing_deployment.azure_foundry_deployment = String::new();
        assert!(!llm_available(&client, &missing_deployment).await);
    }

    #[tokio::test]
    async fn llm_complete_network_error_when_azure_foundry_endpoint_unreachable() {
        let client = reqwest::Client::new();
        let mut cfg = azure_foundry_config();
        cfg.azure_foundry_endpoint = "http://127.0.0.1:9999".to_string();
        let mut logs = Vec::new();
        let result = llm_complete(&client, &cfg, "system prompt", "user content", 0.2, 5000, "complete", |l| logs.push(l.to_string())).await;
        assert!(matches!(result, Err(LlmError::NetworkError(_))));
        assert!(logs.iter().any(|l| l.contains("→ complete [azure-foundry]") && l.contains("/openai/deployments/gpt-4o-deployment/")));
    }

    #[tokio::test]
    async fn llm_complete_network_error_when_anthropic_endpoint_unreachable() {
        let client = reqwest::Client::new();
        let mut cfg = anthropic_config();
        cfg.anthropic_base_url = "http://127.0.0.1:9999".to_string();
        let mut logs = Vec::new();
        let result = llm_complete(&client, &cfg, "system prompt", "user content", 0.2, 5000, "complete", |l| logs.push(l.to_string())).await;
        assert!(matches!(result, Err(LlmError::NetworkError(_))));
        assert!(logs.iter().any(|l| l.contains("→ complete [anthropic]") && l.contains("/messages")));
    }

    #[test]
    fn anthropic_response_text_concatenates_text_blocks() {
        let data = serde_json::json!({"content": [{"type": "text", "text": "hello "}, {"type": "text", "text": "world"}]});
        assert_eq!(anthropic_response_text(&data), "hello world");
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
