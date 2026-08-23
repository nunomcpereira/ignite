//! Flags LangChain/LangGraph-style `.invoke()`/`.stream()` calls with no
//! `recursion_limit` guard (unbounded agent-loop risk). Faithful port of
//! `checks/ai-governance.js`.
//!
//! The JS original threads a DB-backed per-file scan cache
//! (`loadFileScanCache`/`saveFileScanCache`) through this check, keyed by
//! `(org, repo, checkName)`. Ported here as an optional pre-loaded map the
//! caller supplies and an output map of fresh entries the caller persists
//! — same data, same cache-hit behavior, but decoupled from `ignite-db-store`
//! so this crate can be tested (and used) without a database at hand.

use ignite_fs_utils::{build_snippet, hash_buffer, looks_binary, walk_files, Snippet, SnippetOptions};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

static AI_INVOKE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b([A-Za-z_$][\w.]*)\.(invoke|stream|ainvoke|astream)\(").unwrap());

// `.invoke(`/`.stream(` are common method names far beyond agent
// frameworks (httpx/requests-style HTTP clients, RxJS, generic RPC
// dispatchers, ...) — only flag a file that actually references one of
// these frameworks elsewhere.
static AGENT_FRAMEWORK_HINT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(langchain|langgraph|autogen|crewai)\b").unwrap());

// Even inside a file that genuinely uses LangChain/LangGraph elsewhere, an
// httpx/requests-style HTTP client is commonly named client/http/session/
// etc, and calling .stream(/.invoke( on *that* object is still not an
// agent invocation.
static GENERIC_CLIENT_RECEIVER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^(client|http|httpclient|session|conn|connection|resp|response|req|request)$").unwrap());

// Test files exercise mocked/stubbed AI calls — the runaway-execution risk
// this guideline exists for is a production-runtime concern, not a
// testing one.
static TEST_FILE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(^|/)(tests?|__tests__|spec)/|(^|/)(test_[^/]+\.py|[^/]+_test\.py|[^/]+\.(test|spec)\.[jt]sx?)$").unwrap());

#[derive(Debug, Clone, Serialize)]
pub struct GovernanceFinding {
    pub file: String,
    pub line: usize,
    pub snippet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Snippet>,
}

#[derive(Debug, Clone)]
pub struct CachedFileEntry {
    pub hash: String,
    pub findings: Vec<GovernanceFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiGovernanceResult {
    pub findings: Vec<GovernanceFinding>,
    pub scanned: usize,
    pub cache_hits: usize,
}

fn scan_file_content(content: &str, rel: &str) -> Vec<GovernanceFinding> {
    let mut findings = Vec::new();
    if !(AGENT_FRAMEWORK_HINT_RE.is_match(content) && !content.contains("recursion_limit")) {
        return findings; // governed — compliant otherwise
    }
    for (i, line) in content.split('\n').enumerate() {
        let Some(m) = AI_INVOKE_RE.captures(line) else { continue };
        let receiver_full = &m[1];
        let receiver = receiver_full.rsplit('.').next().unwrap_or(receiver_full);
        if GENERIC_CLIENT_RECEIVER_RE.is_match(receiver) {
            continue;
        }
        let whole_match = m.get(0).unwrap();
        let line_no = i + 1;
        let snippet_text = line.trim().chars().take(120).collect::<String>();
        findings.push(GovernanceFinding {
            file: rel.to_string(),
            line: line_no,
            snippet: snippet_text,
            code: build_snippet(
                content,
                line_no,
                SnippetOptions { col_start: Some(whole_match.start()), col_end: Some(whole_match.end()), ..Default::default() },
            ),
        });
    }
    findings
}

/// `prev_cache`: this (org, repo)'s cache from a previous run, keyed by
/// project-relative path. Returns the findings plus a fresh cache map the
/// caller should persist (replacing the previous one wholesale, same
/// "drop stale entries for deleted/renamed files" behavior as the JS
/// original's `replaceFileScanCache`).
pub fn check_ai_governance(root: &Path, prev_cache: &HashMap<String, CachedFileEntry>) -> std::io::Result<(AiGovernanceResult, HashMap<String, CachedFileEntry>)> {
    let files = walk_files(root)?;
    let mut findings = Vec::new();
    let mut new_cache = HashMap::new();
    let mut scanned = 0usize;
    let mut cache_hits = 0usize;

    for file in &files {
        let ext = file.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        if !["py", "js", "ts"].contains(&ext.as_str()) {
            continue;
        }
        let rel = file.strip_prefix(root).unwrap_or(file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        if TEST_FILE_RE.is_match(&rel) {
            continue;
        }
        let Ok(buffer) = std::fs::read(file) else { continue };
        if looks_binary(&buffer) {
            continue;
        }
        scanned += 1;
        let hash = hash_buffer(&buffer);

        let file_findings = if let Some(cached) = prev_cache.get(&rel) {
            if cached.hash == hash {
                cache_hits += 1;
                cached.findings.clone()
            } else {
                let content = String::from_utf8_lossy(&buffer);
                scan_file_content(&content, &rel)
            }
        } else {
            let content = String::from_utf8_lossy(&buffer);
            scan_file_content(&content, &rel)
        };

        new_cache.insert(rel, CachedFileEntry { hash, findings: file_findings.clone() });
        findings.extend(file_findings);
    }

    Ok((AiGovernanceResult { findings, scanned, cache_hits }, new_cache))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn empty_cache() -> HashMap<String, CachedFileEntry> {
        HashMap::new()
    }

    #[test]
    fn flags_ungoverned_invoke_call_in_a_langgraph_file() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(
            root.join("agent.ts"),
            "import { StateGraph } from 'langgraph';\nconst result = await graph.invoke(input);\n",
        )
        .unwrap();

        let (result, _) = check_ai_governance(root, &empty_cache()).unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].line, 2);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn governed_call_with_recursion_limit_present_is_not_flagged() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(
            root.join("agent.ts"),
            "import { StateGraph } from 'langgraph';\nconst result = await graph.invoke(input, { recursion_limit: 25 });\n",
        )
        .unwrap();

        let (result, _) = check_ai_governance(root, &empty_cache()).unwrap();
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn file_with_no_agent_framework_hint_is_never_flagged() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("http.ts"), "const result = await client.invoke(input);\n").unwrap();

        let (result, _) = check_ai_governance(root, &empty_cache()).unwrap();
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn generic_client_receiver_inside_a_langchain_file_is_not_flagged() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(
            root.join("mixed.ts"),
            "import { LangChain } from 'langchain';\nasync function f() {\n  async with httpx.AsyncClient() as client {\n    await client.stream('POST', url, payload);\n  }\n}\n",
        )
        .unwrap();

        let (result, _) = check_ai_governance(root, &empty_cache()).unwrap();
        assert!(result.findings.is_empty(), "receiver named 'client' should be excluded even in a langchain-hinted file");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn test_files_are_excluded_even_with_agent_framework_reference() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("test")).unwrap();
        fs::write(
            root.join("test/agent.test.ts"),
            "import { StateGraph } from 'langgraph';\nconst result = await graph.invoke(input);\n",
        )
        .unwrap();

        let (result, _) = check_ai_governance(root, &empty_cache()).unwrap();
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn cache_hit_reuses_findings_when_content_hash_is_unchanged() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let content = "import { StateGraph } from 'langgraph';\nconst result = await graph.invoke(input);\n";
        fs::write(root.join("agent.ts"), content).unwrap();

        let (first, cache1) = check_ai_governance(root, &empty_cache()).unwrap();
        assert_eq!(first.cache_hits, 0);
        let (second, _) = check_ai_governance(root, &cache1).unwrap();
        assert_eq!(second.cache_hits, 1);
        assert_eq!(second.findings.len(), first.findings.len());
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}
