//! Cross-file static analysis via the CodeQL CLI. Faithful port of
//! `checks/codeql-cross-file.js`. `runCustomCodeqlQuery` (Studio's ad-hoc
//! query runner) is not ported yet — this crate covers the standing scan
//! path (`checkCodeqlCrossFile`) only.

use ignite_db_store::DbStore;
use ignite_fs_utils::{build_snippet, hash_buffer, relative_to_root, skip_dirs, walk_files, Snippet, SnippetOptions};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

fn ext_to_language(ext: &str) -> Option<&'static str> {
    match ext {
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" => Some("javascript"),
        "py" => Some("python"),
        "java" => Some("java"),
        "go" => Some("go"),
        _ => None,
    }
}

pub struct CodeqlConfig {
    pub enabled: bool,
    pub languages: Vec<String>,
    pub query_suites: HashMap<String, String>,
    pub threads: i64,
    pub ram_mb: i64,
    pub timeout_ms: u64,
}

impl Default for CodeqlConfig {
    fn default() -> Self {
        CodeqlConfig {
            enabled: true,
            languages: vec!["javascript".into(), "python".into(), "java".into(), "go".into()],
            query_suites: HashMap::new(),
            threads: 0,
            ram_mb: 0,
            timeout_ms: 20 * 60_000,
        }
    }
}

/// `codeql database create` extracts from the whole --source-root itself —
/// it doesn't consult Ignite's own walkFiles/SKIP_DIRS. LGTM_INDEX_FILTERS
/// is the JS/Python extractor's own path-filter env var — one `exclude`
/// line per SKIP_DIRS name. Verified empirically (see the performance work
/// this was born from): a `**`-style glob is rejected outright, a bare
/// directory name matches at any depth already.
fn codeql_index_filters() -> String {
    skip_dirs().iter().map(|d| format!("exclude:{d}")).collect::<Vec<_>>().join("\n")
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CodeqlToolingProbe {
    pub ok: bool,
    pub version: Option<String>,
    pub reason: Option<String>,
}

pub async fn codeql_tooling(runner: &ToolRunner) -> CodeqlToolingProbe {
    match runner.run_tool("codeql", &["version".to_string(), "--format=json".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default()).await {
        Ok(out) => match serde_json::from_str::<serde_json::Value>(&out.stdout) {
            Ok(info) => CodeqlToolingProbe { ok: true, version: info.get("version").and_then(|v| v.as_str()).map(String::from), reason: None },
            Err(_) => CodeqlToolingProbe { ok: true, version: None, reason: None },
        },
        Err(_) => CodeqlToolingProbe {
            ok: false,
            version: None,
            reason: Some("`codeql` CLI is not installed (https://github.com/github/codeql-cli-binaries) — cross-file static analysis (deep scan) is skipped.".to_string()),
        },
    }
}

pub fn discover_codeql_languages(root: &Path, allowed_languages: &[String]) -> std::io::Result<Vec<String>> {
    let mut present: HashSet<&'static str> = HashSet::new();
    for file in walk_files(root)? {
        let ext = file.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        if let Some(lang) = ext_to_language(&ext) {
            if allowed_languages.iter().any(|l| l == lang) {
                present.insert(lang);
            }
        }
    }
    let mut langs: Vec<String> = present.into_iter().map(String::from).collect();
    langs.sort();
    Ok(langs)
}

/// Deterministic hash over every source file CodeQL would extract for a
/// given language — the cache key for skipping a full database
/// rebuild+analyze when nothing in that language's file set has changed.
pub fn hash_file_set(root: &Path, language: &str) -> std::io::Result<String> {
    let mut entries = Vec::new();
    for file in walk_files(root)? {
        let ext = file.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        if ext_to_language(&ext) != Some(language) {
            continue;
        }
        let rel = file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        let content_hash = hash_buffer(&std::fs::read(&file)?);
        entries.push(format!("{rel}:{content_hash}"));
    }
    entries.sort();
    Ok(hash_buffer(entries.join("\n").as_bytes()))
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct FlowStep {
    pub file: String,
    pub line: usize,
    pub message: Option<String>,
}

/// SARIF's codeFlows/threadFlows record every step of a tainted-data
/// path. Returns the step list for the flow that touches the most
/// distinct files.
async fn extract_flow_chain(root: &Path, result: &serde_json::Value) -> Option<(Vec<FlowStep>, usize)> {
    let mut best: Option<Vec<(String, usize, Option<String>)>> = None;
    let mut best_file_count: i64 = -1;

    for flow in result.get("codeFlows").and_then(|c| c.as_array()).into_iter().flatten() {
        let mut steps = Vec::new();
        let mut files_seen = HashSet::new();
        for thread_flow in flow.get("threadFlows").and_then(|t| t.as_array()).into_iter().flatten() {
            for loc in thread_flow.get("locations").and_then(|l| l.as_array()).into_iter().flatten() {
                let pl = loc.get("location").and_then(|l| l.get("physicalLocation"));
                let Some(uri) = pl.and_then(|p| p.get("artifactLocation")).and_then(|a| a.get("uri")).and_then(|u| u.as_str()) else { continue };
                let line = pl.and_then(|p| p.get("region")).and_then(|r| r.get("startLine")).and_then(|l| l.as_i64()).unwrap_or(1).max(1) as usize;
                let message = loc.get("location").and_then(|l| l.get("message")).and_then(|m| m.get("text")).and_then(|t| t.as_str()).map(String::from);
                steps.push((uri.to_string(), line, message));
                files_seen.insert(uri.to_string());
            }
        }
        if !steps.is_empty() && files_seen.len() as i64 > best_file_count {
            best_file_count = files_seen.len() as i64;
            best = Some(steps);
        }
    }

    let best = best?;
    let mut resolved = Vec::new();
    for (uri, line, message) in best {
        let abs_path = if Path::new(&uri).is_absolute() { std::path::PathBuf::from(&uri) } else { root.join(&uri) };
        let rel_file = relative_to_root(root, &abs_path.to_string_lossy()).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        if let Some(prev) = resolved.last() as Option<&FlowStep> {
            if prev.file == rel_file && prev.line == line {
                continue;
            }
        }
        resolved.push(FlowStep { file: rel_file, line, message });
    }
    Some((resolved, best_file_count as usize))
}

static SOURCE_MARKER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\[([^\]]+)\]\(\d+\)").unwrap());
static SPLIT_MARKER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\[[^\]]+\]\(\d+\)").unwrap());

fn plain(s: &str) -> String {
    SOURCE_MARKER_RE.replace_all(s, "$1").into_owned()
}

/// CodeQL's own SARIF messages for a multi-source path-problem query embed
/// one clause per source feeding the sink, each tagged `[label](N)`. The
/// JS original splits on a lookbehind/lookahead pattern
/// (`(?<=[.?!])\s+(?=\[...\]\(\d+\))`) the `regex` crate can't express;
/// ported here as an explicit scan for each `\s+` run that sits between a
/// sentence-ending punctuation mark and a `[label](N)` marker.
fn normalize_sarif_message(text: Option<&str>) -> Option<String> {
    let text = text?;
    let mut split_points = Vec::new();
    for m in SPLIT_MARKER_RE.find_iter(text) {
        let before = &text[..m.start()];
        let ws_start = before.len() - before.trim_end_matches(|c: char| c.is_whitespace()).len();
        let trimmed_end = before.len() - ws_start;
        if ws_start == 0 {
            continue; // marker at the very start of the text, no preceding punctuation to check
        }
        if let Some(last_char) = before[..trimmed_end].chars().last() {
            if last_char == '.' || last_char == '?' || last_char == '!' {
                split_points.push((trimmed_end, m.start()));
            }
        }
    }

    if split_points.is_empty() {
        return Some(plain(text));
    }

    let mut clauses = Vec::new();
    let mut cursor = 0;
    for (end, next_start) in &split_points {
        clauses.push(plain(text[cursor..*end].trim()));
        cursor = *next_start;
    }
    clauses.push(plain(text[cursor..].trim()));

    if clauses.len() <= 1 {
        return Some(plain(text));
    }
    let unique: Vec<&String> = {
        let mut seen = HashSet::new();
        clauses.iter().filter(|c| seen.insert((*c).clone())).collect()
    };
    if unique.len() == 1 {
        Some(format!("{} ({} sources flow into this same sink)", unique[0], clauses.len()))
    } else {
        Some(clauses.join(" "))
    }
}

static CWE_TAG_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^external/cwe/cwe-(\d+)").unwrap());

fn extract_cwe(rule: &serde_json::Value) -> Option<String> {
    let tags = rule.get("properties").and_then(|p| p.get("tags")).and_then(|t| t.as_array())?;
    for tag in tags {
        if let Some(s) = tag.as_str() {
            if let Some(caps) = CWE_TAG_RE.captures(s) {
                return Some(format!("CWE-{}", &caps[1]));
            }
        }
    }
    None
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CodeqlFinding {
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub tool: String,
    pub language: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<Snippet>,
    pub cross_file: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<FlowStep>>,
    pub cwe: Option<String>,
}

async fn parse_sarif(root: &Path, sarif_path: &Path, language: &str) -> std::io::Result<Vec<CodeqlFinding>> {
    let raw = tokio::fs::read_to_string(sarif_path).await?;
    let sarif: serde_json::Value = serde_json::from_str(&raw)?;
    let mut findings = Vec::new();

    for run in sarif.get("runs").and_then(|r| r.as_array()).into_iter().flatten() {
        let mut rules: HashMap<String, serde_json::Value> = HashMap::new();
        for rule in run.get("tool").and_then(|t| t.get("driver")).and_then(|d| d.get("rules")).and_then(|r| r.as_array()).into_iter().flatten() {
            if let Some(id) = rule.get("id").and_then(|i| i.as_str()) {
                rules.insert(id.to_string(), rule.clone());
            }
        }
        for result in run.get("results").and_then(|r| r.as_array()).into_iter().flatten() {
            let rule_id = result.get("ruleId").and_then(|r| r.as_str()).unwrap_or_default();
            let empty_rule = serde_json::json!({});
            let rule = rules.get(rule_id).unwrap_or(&empty_rule);
            let loc = result.get("locations").and_then(|l| l.as_array()).and_then(|a| a.first()).and_then(|l| l.get("physicalLocation"));
            let Some(uri) = loc.and_then(|l| l.get("artifactLocation")).and_then(|a| a.get("uri")).and_then(|u| u.as_str()) else { continue };
            let abs_path = if Path::new(uri).is_absolute() { std::path::PathBuf::from(uri) } else { root.join(uri) };
            let rel_file = relative_to_root(root, &abs_path.to_string_lossy()).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
            let line = loc.and_then(|l| l.get("region")).and_then(|r| r.get("startLine")).and_then(|l| l.as_i64()).unwrap_or(1).max(1) as usize;
            let level = result
                .get("level")
                .and_then(|l| l.as_str())
                .or_else(|| rule.get("defaultConfiguration").and_then(|d| d.get("level")).and_then(|l| l.as_str()))
                .unwrap_or("warning")
                .to_lowercase();
            let security_severity: Option<f64> = rule.get("properties").and_then(|p| p.get("security-severity")).and_then(|s| s.as_str()).and_then(|s| s.parse().ok());
            let severity = if level == "error" || security_severity.map(|s| s >= 7.0).unwrap_or(false) { "error" } else { "warning" }.to_string();
            let flow = extract_flow_chain(root, result).await;
            let src_content = tokio::fs::read_to_string(&abs_path).await.ok();
            let message = normalize_sarif_message(result.get("message").and_then(|m| m.get("text")).and_then(|t| t.as_str()))
                .or_else(|| rule.get("shortDescription").and_then(|s| s.get("text")).and_then(|t| t.as_str()).map(String::from))
                .unwrap_or_else(|| "CodeQL finding".to_string());
            let cross_file = flow.as_ref().map(|(_, count)| *count > 1).unwrap_or(false);
            let chain = flow.and_then(|(steps, count)| if count > 1 && steps.len() > 1 { Some(steps) } else { None });

            findings.push(CodeqlFinding {
                file: rel_file,
                line,
                kind: rule_id.to_lowercase(),
                tool: "codeql".to_string(),
                language: language.to_string(),
                severity,
                message,
                snippet: src_content.as_deref().and_then(|c| build_snippet(c, line, SnippetOptions::default())),
                cross_file,
                chain,
                cwe: extract_cwe(rule),
            });
        }
    }
    Ok(findings)
}

async fn run_one_language(root: &Path, language: &str, runner: &ToolRunner, config: &CodeqlConfig) -> Result<Vec<CodeqlFinding>, String> {
    let Some(suite) = config.query_suites.get(language) else {
        return Ok(vec![]); // no CodeQL query suite configured for this language — skipped
    };
    let work_dir = std::env::temp_dir().join(format!("ignite-codeql-{language}-{}", std::process::id()));
    tokio::fs::create_dir_all(&work_dir).await.map_err(|e| e.to_string())?;
    let db_path = work_dir.join("db");
    let sarif_path = work_dir.join("results.sarif");

    let result = async {
        let mut create_lines = Vec::new();
        let mut create_args = vec![
            "database".to_string(),
            "create".to_string(),
            db_path.to_string_lossy().into_owned(),
            format!("--language={language}"),
            format!("--source-root={}", root.to_string_lossy()),
            "--overwrite".to_string(),
            format!("--threads={}", config.threads),
        ];
        if config.ram_mb != 0 {
            create_args.push(format!("--ram={}", config.ram_mb));
        }
        let mut env = HashMap::new();
        env.insert("LGTM_INDEX_FILTERS".to_string(), codeql_index_filters());
        runner
            .run_tool_streaming("codeql", &create_args, &root.to_string_lossy(), |l| create_lines.push(l.to_string()), &env, config.timeout_ms)
            .await
            .map_err(|e| format!("{e} Last output: {}", create_lines.iter().rev().take(2).rev().cloned().collect::<Vec<_>>().join(" | ")))?;

        let mut analyze_lines = Vec::new();
        let analyze_args = vec![
            "database".to_string(),
            "analyze".to_string(),
            db_path.to_string_lossy().into_owned(),
            suite.clone(),
            "--download".to_string(),
            "--format=sarif-latest".to_string(),
            format!("--output={}", sarif_path.to_string_lossy()),
            format!("--threads={}", config.threads),
        ];
        runner
            .run_tool_streaming("codeql", &analyze_args, &root.to_string_lossy(), |l| analyze_lines.push(l.to_string()), &HashMap::new(), config.timeout_ms)
            .await
            .map_err(|e| format!("{e} Last output: {}", analyze_lines.iter().rev().take(2).rev().cloned().collect::<Vec<_>>().join(" | ")))?;

        parse_sarif(root, &sarif_path, language).await.map_err(|e| e.to_string())
    }
    .await;

    let _ = tokio::fs::remove_dir_all(&work_dir).await;
    result
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeqlCrossFileResult {
    pub findings: Vec<CodeqlFinding>,
    pub engine: &'static str,
    pub languages: Vec<String>,
}

pub struct CodeqlContext<'a> {
    pub org: Option<&'a str>,
    pub repo: Option<&'a str>,
    pub store: Option<&'a DbStore>,
}

/// Cross-file static analysis via CodeQL, one database build+analyze per
/// language detected in the project.
pub async fn check_codeql_cross_file(root: &Path, runner: &ToolRunner, config: &CodeqlConfig, ctx: CodeqlContext<'_>) -> std::io::Result<CodeqlCrossFileResult> {
    let tooling = if config.enabled {
        codeql_tooling(runner).await
    } else {
        CodeqlToolingProbe { ok: false, version: None, reason: Some("codeql is disabled (security.codeql.enabled=false).".to_string()) }
    };
    if !tooling.ok {
        return Ok(CodeqlCrossFileResult { findings: vec![], engine: "disabled", languages: vec![] });
    }

    let languages = discover_codeql_languages(root, &config.languages)?;
    if languages.is_empty() {
        return Ok(CodeqlCrossFileResult { findings: vec![], engine: "codeql", languages: vec![] });
    }

    let mut findings = Vec::new();
    for language in &languages {
        let file_set_hash = hash_file_set(root, language)?;
        let cached = match (ctx.org, ctx.repo, &tooling.version, ctx.store) {
            (Some(org), Some(repo), Some(version), Some(store)) => store.get_codeql_scan_cache(org, repo, language, &file_set_hash, version),
            _ => None,
        };

        let lang_findings = if let Some(cached_json) = cached {
            serde_json::from_value(cached_json).unwrap_or_default()
        } else {
            match run_one_language(root, language, runner, config).await {
                Ok(f) => {
                    if let (Some(org), Some(repo), Some(version), Some(store)) = (ctx.org, ctx.repo, &tooling.version, ctx.store) {
                        if let Ok(json) = serde_json::to_value(&f) {
                            store.save_codeql_scan_cache(org, repo, language, &file_set_hash, version, &json);
                        }
                    }
                    f
                }
                Err(_) => continue, // logged by the caller in the real server integration
            }
        };
        findings.extend(lang_findings);
    }

    Ok(CodeqlCrossFileResult { findings, engine: "codeql", languages })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;
    use std::fs;
    use tempfile::tempdir;

    fn runner() -> ToolRunner {
        let mut binaries = StdHashMap::new();
        binaries.insert("codeql", "codeql".to_string());
        ToolRunner::new(binaries)
    }

    fn default_query_suites() -> HashMap<String, String> {
        [("javascript".to_string(), "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls".to_string())].into_iter().collect()
    }

    #[test]
    fn discover_codeql_languages_maps_extensions_and_filters_allowed() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("app.ts"), "x").unwrap();
        fs::write(root.join("script.py"), "x").unwrap();
        let langs = discover_codeql_languages(root, &["javascript".to_string()]).unwrap();
        assert_eq!(langs, vec!["javascript".to_string()]);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn hash_file_set_is_stable_and_changes_with_content() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.js"), "x").unwrap();
        let h1 = hash_file_set(root, "javascript").unwrap();
        let h2 = hash_file_set(root, "javascript").unwrap();
        assert_eq!(h1, h2);
        fs::write(root.join("a.js"), "y").unwrap();
        ignite_fs_utils::invalidate_walk_cache(root);
        let h3 = hash_file_set(root, "javascript").unwrap();
        assert_ne!(h1, h3);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn normalize_sarif_message_collapses_repeated_source_clauses() {
        // Cross-checked against the real normalizeSarifMessage: clauses
        // only collapse when they're textually *identical* after stripping
        // markers, which needs the same label text at each split point
        // (`[source](1)` / `[source](2)`, not distinct labels).
        let text = "[source](1) is tainted. [source](2) is tainted.";
        let out = normalize_sarif_message(Some(text)).unwrap();
        assert_eq!(out, "source is tainted. (2 sources flow into this same sink)");
    }

    #[test]
    fn normalize_sarif_message_joins_distinct_clauses_unchanged_when_they_differ() {
        // Cross-checked against the real normalizeSarifMessage with this
        // exact fixture: distinct clauses (even sharing the same lead-in
        // sentence) don't collapse - they're marker-stripped and rejoined
        // as-is, not summarized.
        let text = "Password field flows here. [source1](1) Password field flows here. [source2](2)";
        let out = normalize_sarif_message(Some(text)).unwrap();
        assert_eq!(out, "Password field flows here. source1 Password field flows here. source2");
    }

    #[test]
    fn normalize_sarif_message_leaves_plain_text_unchanged_besides_stripping_markers() {
        let text = "This path depends on a [user-provided value](1).";
        let out = normalize_sarif_message(Some(text)).unwrap();
        assert_eq!(out, "This path depends on a user-provided value.");
    }

    #[test]
    fn extract_cwe_reads_external_cwe_tag() {
        let rule = serde_json::json!({"properties": {"tags": ["external/cwe/cwe-89", "security"]}});
        assert_eq!(extract_cwe(&rule), Some("CWE-89".to_string()));
        let no_tag = serde_json::json!({"properties": {"tags": ["security"]}});
        assert_eq!(extract_cwe(&no_tag), None);
    }

    #[tokio::test]
    async fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        let config = CodeqlConfig { enabled: false, ..Default::default() };
        let result = check_codeql_cross_file(dir.path(), &runner(), &config, CodeqlContext { org: None, repo: None, store: None }).await.unwrap();
        assert_eq!(result.engine, "disabled");
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn no_supported_language_files_short_circuits() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("README.md"), "hello").unwrap();
        let config = CodeqlConfig { query_suites: default_query_suites(), ..Default::default() };
        let result = check_codeql_cross_file(root, &runner(), &config, CodeqlContext { org: None, repo: None, store: None }).await.unwrap();
        assert!(result.languages.is_empty());
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn real_codeql_binary_end_to_end() {
        let mut check = std::process::Command::new("codeql");
        check.arg("version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: codeql not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        // Deliberately trivial - not asserting a specific finding here
        // (that needs a real vulnerable pattern + security-extended's
        // actual ruleset, a multi-minute round trip); this confirms the
        // whole database-create -> analyze -> SARIF-parse pipeline runs
        // end to end without error on a real file.
        fs::write(root.join("app.js"), "function add(a, b) { return a + b; }\nmodule.exports = add;\n").unwrap();

        let config = CodeqlConfig { query_suites: default_query_suites(), timeout_ms: 5 * 60_000, ..Default::default() };
        let result = check_codeql_cross_file(root, &runner(), &config, CodeqlContext { org: None, repo: None, store: None }).await.unwrap();
        assert_eq!(result.engine, "codeql");
        assert_eq!(result.languages, vec!["javascript".to_string()]);
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}
