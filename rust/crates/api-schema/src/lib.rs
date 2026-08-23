//! API schema lint via Spectral. Faithful port of `checks/api-schema.js`.
//! Spectral has no directory-scan mode — it only lints files explicitly
//! passed on the command line — so this does its own discovery: any
//! .yaml/.yml/.json file whose top-level content declares
//! openapi/swagger/asyncapi (a content sniff, not a filename convention).

use ignite_fs_utils::{build_snippet, looks_binary, relative_to_root, walk_files, Snippet, SnippetOptions};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::path::Path;

static API_SCHEMA_TOP_LEVEL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?m)^\s*"?(openapi|swagger|asyncapi)"?\s*:"#).unwrap());

pub struct ApiSchemaConfig {
    pub enabled: bool,
    pub ruleset: String,
}

impl Default for ApiSchemaConfig {
    fn default() -> Self {
        ApiSchemaConfig { enabled: true, ruleset: String::new() }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiSchemaFinding {
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Snippet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiSchemaResult {
    pub findings: Vec<ApiSchemaFinding>,
    pub engine: &'static str,
}

pub async fn spectral_tooling(runner: &ToolRunner) -> bool {
    runner
        .run_tool("spectral", &["--version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default())
        .await
        .is_ok()
}

pub fn discover_api_schema_files(root: &Path) -> std::io::Result<Vec<String>> {
    let mut files = Vec::new();
    for file in walk_files(root)? {
        let ext = file.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        if !["yaml", "yml", "json"].contains(&ext.as_str()) {
            continue;
        }
        let Ok(buffer) = std::fs::read(&file) else { continue };
        if looks_binary(&buffer) {
            continue;
        }
        let content = String::from_utf8_lossy(&buffer);
        if API_SCHEMA_TOP_LEVEL_RE.is_match(&content) {
            let rel = file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
            files.push(rel);
        }
    }
    Ok(files)
}

fn severity_for(spectral_severity: i64) -> &'static str {
    match spectral_severity {
        0 => "error",
        _ => "warning",
    }
}

pub async fn check_api_schemas(root: &Path, runner: &ToolRunner, config: &ApiSchemaConfig) -> std::io::Result<ApiSchemaResult> {
    let tooling_ok = config.enabled && spectral_tooling(runner).await;
    if !tooling_ok {
        return Ok(ApiSchemaResult { findings: vec![], engine: "disabled" });
    }

    let rel_files = discover_api_schema_files(root)?;
    if rel_files.is_empty() {
        return Ok(ApiSchemaResult { findings: vec![], engine: "spectral" });
    }

    let mut args = vec!["lint".to_string()];
    args.extend(rel_files);
    args.extend(["--ruleset".to_string(), config.ruleset.clone(), "--format".to_string(), "json".to_string(), "-q".to_string()]);

    let output = match runner.run_tool("spectral", &args, &root.to_string_lossy(), RunToolOptions { allowed_exit_codes: vec![0, 1], ..Default::default() }).await {
        Ok(o) => o,
        Err(_) => return Ok(ApiSchemaResult { findings: vec![], engine: "disabled" }),
    };

    let results: Vec<serde_json::Value> = if output.stdout.trim().is_empty() {
        vec![]
    } else {
        match serde_json::from_str(&output.stdout) {
            Ok(v) => v,
            Err(_) => return Ok(ApiSchemaResult { findings: vec![], engine: "disabled" }),
        }
    };

    let mut findings = Vec::new();
    for r in results {
        let source = r.get("source").and_then(|s| s.as_str()).unwrap_or("");
        let rel_file = relative_to_root(root, source).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        let line = r.get("range").and_then(|rg| rg.get("start")).and_then(|s| s.get("line")).and_then(|l| l.as_i64()).unwrap_or(0) as usize + 1;
        let content = std::fs::read_to_string(root.join(&rel_file)).ok();
        let severity = r.get("severity").and_then(|s| s.as_i64()).map(severity_for).unwrap_or("warning");
        let kind = r.get("code").map(|c| match c {
            serde_json::Value::String(s) => s.to_lowercase(),
            other => other.to_string().to_lowercase(),
        }).unwrap_or_else(|| "api-schema-lint".to_string());
        let message = r.get("message").and_then(|m| m.as_str()).unwrap_or("API schema lint finding").to_string();
        findings.push(ApiSchemaFinding {
            file: rel_file,
            line,
            kind,
            tool: "spectral",
            severity,
            message,
            code: content.as_deref().and_then(|c| build_snippet(c, line, SnippetOptions::default())),
        });
    }

    Ok(ApiSchemaResult { findings, engine: "spectral" })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    fn runner_with_spectral() -> ToolRunner {
        let mut binaries = HashMap::new();
        binaries.insert("spectral", "spectral".to_string());
        ToolRunner::new(binaries)
    }

    #[test]
    fn discovers_openapi_file_by_content_sniff_not_filename() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("weird-name.yaml"), "openapi: 3.0.0\ninfo:\n  title: x\n").unwrap();
        fs::write(root.join("not-a-schema.yaml"), "foo: bar\n").unwrap();
        fs::write(root.join("data.json"), "{}\n").unwrap();

        let files = discover_api_schema_files(root).unwrap();
        assert_eq!(files, vec!["weird-name.yaml".to_string()]);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn discovers_asyncapi_and_swagger_too() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.yaml"), "asyncapi: 2.0.0\n").unwrap();
        fs::write(root.join("s.json"), "{\n  \"swagger\": \"2.0\"\n}\n").unwrap();

        let mut files = discover_api_schema_files(root).unwrap();
        files.sort();
        assert_eq!(files, vec!["a.yaml".to_string(), "s.json".to_string()]);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn severity_zero_maps_to_error_others_to_warning() {
        assert_eq!(severity_for(0), "error");
        assert_eq!(severity_for(1), "warning");
        assert_eq!(severity_for(2), "warning");
        assert_eq!(severity_for(3), "warning");
    }

    #[tokio::test]
    async fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        let config = ApiSchemaConfig { enabled: false, ..Default::default() };
        let result = check_api_schemas(dir.path(), &ToolRunner::new(HashMap::new()), &config).await.unwrap();
        assert_eq!(result.engine, "disabled");
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn real_spectral_binary_end_to_end() {
        let mut check = std::process::Command::new("spectral");
        check.arg("--version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: spectral not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        // Missing `info.description`/`operationId` etc. trips spectral:oas
        // built-in rules even with an empty custom --ruleset arg (spectral
        // falls back to its default ruleset when none is found on disk).
        fs::write(
            root.join("openapi.yaml"),
            "openapi: 3.0.0\ninfo:\n  title: Test API\n  version: 1.0.0\npaths:\n  /ping:\n    get:\n      responses:\n        '200':\n          description: ok\n",
        )
        .unwrap();

        fs::write(root.join(".spectral.yaml"), "extends: spectral:oas\n").unwrap();
        let config = ApiSchemaConfig { enabled: true, ruleset: root.join(".spectral.yaml").to_string_lossy().into_owned() };
        let result = check_api_schemas(root, &runner_with_spectral(), &config).await.unwrap();
        assert_eq!(result.engine, "spectral");
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}
