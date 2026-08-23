use ignite_db_store::IssueRow;
use ignite_tool_runner::ToolRunner;
use std::collections::HashMap;
use std::sync::Mutex;

/// Placeholder for the in-flight SSE pipeline job map (`runningRuns` in
/// server.js) — populated once the streaming pipeline endpoint
/// (routes/pipeline-interactive.js) is ported. Until then every job id
/// falls through to the DB-backed completed-job lookup, same as a job
/// that already finished.
pub struct LiveRun {
    pub all_issues: Vec<IssueRow>,
}

pub struct AppState {
    pub runner: ToolRunner,
    pub db: ignite_db_store::DbStore,
    pub running_runs: Mutex<HashMap<String, LiveRun>>,
    pub llm_config: ignite_llm_client::LlmClientConfig,
}

/// Local-LLM provider pointed at `CONFIG.llm`'s defaults — OpenAI-provider
/// config.json/env wiring isn't ported yet, so this always resolves to
/// the local provider today.
pub fn default_llm_config() -> ignite_llm_client::LlmClientConfig {
    let llm = ignite_config::LlmConfig::default();
    ignite_llm_client::LlmClientConfig { provider: ignite_llm_client::Provider::Local, openai_api_key: String::new(), openai_base_url: String::new(), openai_model: String::new(), scan_url: llm.url, scan_model: llm.model }
}

pub fn default_runner() -> ToolRunner {
    fn bin(name: &'static str) -> (&'static str, String) {
        (name, name.to_string())
    }
    let binaries: HashMap<&'static str, String> = [
        bin("trivy"),
        bin("checkov"),
        bin("hadolint"),
        bin("syft"),
        bin("cosign"),
        bin("semgrep"),
        bin("bearer"),
        bin("jscpd"),
        bin("gocloc"),
        bin("spectral"),
        bin("guarddog"),
        bin("codeql"),
        bin("picklescan"),
        bin("oasdiff"),
        bin("gitleaks"),
        bin("rm"),
    ]
    .into_iter()
    .collect();
    ToolRunner::new(binaries)
}
