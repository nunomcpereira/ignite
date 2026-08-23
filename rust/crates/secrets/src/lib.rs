//! Regex-based secret scan + optional gitleaks supplement. Faithful port
//! of `checks/secrets.js`.
//!
//! gitleaks itself is an external subprocess (`gitleaks detect ...`) — as
//! with git-churn in `ignite-complexity-health`, running it is left to the
//! caller (once the tool-runner/server integration exists); this crate
//! exposes `parse_gitleaks_report` (pure JSON parsing) and
//! `merge_gitleaks_findings` (the gitignore/allowlist/dedup filtering the
//! JS original applies to gitleaks' raw results) so the whole non-process
//! part of that path is still ported and tested.

use ignite_fs_utils::{
    build_snippet, hash_buffer, is_gitignored, load_gitignore_patterns, looks_binary, walk_files, IgnorePattern, Snippet,
    SnippetOptions, BINARY_EXTENSIONS, SECRET_SCAN_CODE_EXTS,
};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

// Captures the quote char (if any) separately from the value so callers
// can tell a string literal from a bare identifier/property-access
// reference.
static SECRET_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)(password|aws_secret|api_key|token|private_key)\s*[:=]\s*(['"]?)([a-zA-Z0-9_\-.~]{10,})"#).unwrap());

static SECRET_SCAN_PATH_SKIP_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^(?:\.ignite-review\.md|(?:\.claude|\.github)/skills/.*\.md)$").unwrap());
static PLACEHOLDER_SECRET_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bghp_x{6,}\b|\bsecret-key-here\b|fcm-token-[a-z0-9-]*\.\.\.").unwrap());
static IDENTIFIER_CHAIN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$").unwrap());
static COMMENT_CODE_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*#\s*Code:\s*").unwrap());

fn normalize_rel_path(rel_path: &str) -> String {
    rel_path.replace('\\', "/")
}

pub fn should_skip_secret_file(rel_path: &str) -> bool {
    SECRET_SCAN_PATH_SKIP_RE.is_match(&normalize_rel_path(rel_path))
}

pub fn looks_like_reference_value(value: &str) -> bool {
    IDENTIFIER_CHAIN_RE.is_match(value)
}

pub fn matches_known_public_key_pattern(patterns: &[Regex], value: &str, line_text: &str) -> bool {
    patterns.iter().any(|re| re.is_match(value) || re.is_match(line_text))
}

pub struct IgnoreLineArgs<'a> {
    pub quote: &'a str,
    pub value: &'a str,
}

pub fn should_ignore_secret_line(known_public_key_patterns: &[Regex], rel_path: &str, line_text: &str, args: IgnoreLineArgs) -> bool {
    // .ignite-review.md repeats previous findings in "# Code:" lines.
    if COMMENT_CODE_LINE_RE.is_match(line_text) {
        return true;
    }
    if PLACEHOLDER_SECRET_RE.is_match(line_text) || PLACEHOLDER_SECRET_RE.is_match(args.value) {
        return true;
    }
    // A dotted identifier chain is a reference, not an inline literal.
    if args.quote.is_empty() && looks_like_reference_value(args.value) {
        return true;
    }
    if matches_known_public_key_pattern(known_public_key_patterns, args.value, line_text) {
        return true;
    }
    should_skip_secret_file(rel_path)
}

fn get_highlighted_line_text(snippet: &Option<Snippet>) -> String {
    let Some(snippet) = snippet else { return String::new() };
    snippet
        .lines
        .iter()
        .find(|l| l.number == snippet.highlight_line)
        .map(|l| l.text.clone())
        .unwrap_or_default()
}

pub fn is_likely_secret_value(quote: &str, ext: &str) -> bool {
    !quote.is_empty() || !SECRET_SCAN_CODE_EXTS.contains(&ext)
}

#[derive(Debug, Clone, Default)]
pub struct GitleaksAllowlist {
    pub regexes: Vec<Regex>,
    pub paths: Vec<Regex>,
}

/// Pulls the top-level `[allowlist]` table out of a gitleaks.toml —
/// deliberately not `[rules.allowlist]` (per-rule), just the global one.
/// Hand-rolled rather than a TOML dependency: only two array fields
/// (`regexes`, `paths`) of quoted strings are needed.
pub fn parse_gitleaks_allowlist(text: &str) -> GitleaksAllowlist {
    static TABLE_HEADER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\[allowlist\]\s*(#.*)?$").unwrap());
    static NEXT_TABLE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\[").unwrap());
    static ITEM_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"'''([\s\S]*?)'''|"""([\s\S]*?)"""|'([^'\n]*)'|"([^"\n]*)""#).unwrap());

    let lines: Vec<&str> = text.split('\n').collect();
    let Some(start_idx) = lines.iter().position(|l| TABLE_HEADER_RE.is_match(l.trim())) else {
        return GitleaksAllowlist::default();
    };
    let mut block_lines = Vec::new();
    for line in &lines[start_idx + 1..] {
        if NEXT_TABLE_RE.is_match(line.trim()) {
            break;
        }
        block_lines.push(*line);
    }
    let block = block_lines.join("\n");

    let extract_array = |field: &str| -> Vec<Regex> {
        let field_re = Regex::new(&format!(r"(?s){field}\s*=\s*\[([\s\S]*?)\]")).unwrap();
        let Some(arr_match) = field_re.captures(&block) else { return vec![] };
        let mut items = Vec::new();
        for cap in ITEM_RE.captures_iter(&arr_match[1]) {
            let raw = cap.get(1).or_else(|| cap.get(2)).or_else(|| cap.get(3)).or_else(|| cap.get(4)).map(|m| m.as_str());
            if let Some(raw) = raw {
                if let Ok(re) = Regex::new(raw) {
                    items.push(re);
                }
            }
        }
        items
    };

    GitleaksAllowlist { regexes: extract_array("regexes"), paths: extract_array("paths") }
}

pub fn load_gitleaks_allowlist(root: &Path, explicit_config_path: Option<&Path>) -> GitleaksAllowlist {
    let candidate_path = explicit_config_path.map(|p| p.to_path_buf()).unwrap_or_else(|| root.join(".gitleaks.toml"));
    match std::fs::read_to_string(&candidate_path) {
        Ok(text) => parse_gitleaks_allowlist(&text),
        Err(_) => GitleaksAllowlist::default(), // no gitleaks.toml — nothing to honor
    }
}

pub fn is_allowlisted(allowlist: &GitleaksAllowlist, rel_path: &str, line_text: &str) -> bool {
    allowlist.paths.iter().any(|re| re.is_match(rel_path)) || allowlist.regexes.iter().any(|re| re.is_match(line_text))
}

pub async fn gitleaks_tooling(runner: &ignite_tool_runner::ToolRunner) -> bool {
    runner.run_tool("gitleaks", &["version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), ignite_tool_runner::RunToolOptions::default()).await.is_ok()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Snippet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedFileEntry {
    pub hash: String,
    pub findings: Vec<SecretFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecretsResult {
    pub findings: Vec<SecretFinding>,
    pub scanned: usize,
    pub cache_hits: usize,
    pub gitignored_skipped: usize,
}

pub struct SecretsConfig {
    pub known_public_key_patterns: Vec<Regex>,
    pub max_scan_file_bytes: u64,
    pub gitleaks_config_path: Option<std::path::PathBuf>,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        SecretsConfig { known_public_key_patterns: vec![], max_scan_file_bytes: 5 * 1024 * 1024, gitleaks_config_path: None }
    }
}

fn scan_file_for_secrets(
    content: &str,
    rel: &str,
    ext: &str,
    allowlist: &GitleaksAllowlist,
    known_public_key_patterns: &[Regex],
) -> Vec<SecretFinding> {
    let mut findings = Vec::new();
    for (i, line) in content.split('\n').enumerate() {
        let Some(m) = SECRET_RE.captures(line) else { continue };
        let keyword = &m[1];
        let quote = m.get(2).map(|g| g.as_str()).unwrap_or("");
        let value = &m[3];
        if !is_likely_secret_value(quote, ext) {
            continue;
        }
        if is_allowlisted(allowlist, rel, line) {
            continue;
        }
        if should_ignore_secret_line(known_public_key_patterns, rel, line, IgnoreLineArgs { quote, value }) {
            continue;
        }
        let whole = m.get(0).unwrap();
        let line_no = i + 1;
        findings.push(SecretFinding {
            file: rel.to_string(),
            line: line_no,
            kind: keyword.to_lowercase(),
            tool: "built-in".to_string(),
            code: build_snippet(content, line_no, SnippetOptions { col_start: Some(whole.start()), col_end: Some(whole.end()), ..Default::default() }),
        });
    }
    findings
}

/// `prev_cache`: this (org, repo)'s cache from a previous run. Returns the
/// findings plus a fresh cache map the caller should persist.
pub fn check_secrets(
    root: &Path,
    config: &SecretsConfig,
    prev_cache: &HashMap<String, CachedFileEntry>,
) -> std::io::Result<(SecretsResult, HashMap<String, CachedFileEntry>)> {
    let gitignore_patterns = load_gitignore_patterns(root);
    let allowlist = load_gitleaks_allowlist(root, config.gitleaks_config_path.as_deref());

    let files = walk_files(root)?;
    let mut findings = Vec::new();
    let mut new_cache = HashMap::new();
    let mut scanned = 0usize;
    let mut cache_hits = 0usize;
    let mut gitignored_skipped = 0usize;

    for file in &files {
        // Note: ignite_fs_utils::BINARY_EXTENSIONS/SECRET_SCAN_CODE_EXTS are
        // stored without a leading dot (unlike the JS originals' `.js`-style
        // Sets) - `ext` is kept dot-free throughout this function to match.
        let ext = file.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        if BINARY_EXTENSIONS.contains(&ext.as_str()) {
            continue;
        }
        let rel = file.strip_prefix(root).unwrap_or(file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        if should_skip_secret_file(&rel) {
            continue;
        }
        if !gitignore_patterns.is_empty() && is_gitignored(&gitignore_patterns, &rel) {
            gitignored_skipped += 1;
            continue;
        }

        let Ok(metadata) = std::fs::metadata(file) else { continue };
        if metadata.len() > config.max_scan_file_bytes {
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
                scan_file_for_secrets(&content, &rel, &ext, &allowlist, &config.known_public_key_patterns)
            }
        } else {
            let content = String::from_utf8_lossy(&buffer);
            scan_file_for_secrets(&content, &rel, &ext, &allowlist, &config.known_public_key_patterns)
        };

        new_cache.insert(rel, CachedFileEntry { hash, findings: file_findings.clone() });
        findings.extend(file_findings);
    }

    Ok((SecretsResult { findings, scanned, cache_hits, gitignored_skipped }, new_cache))
}

// --- gitleaks report parsing (pure — subprocess execution stays with the caller) ---

#[derive(Debug, Clone)]
pub struct GitleaksRawResult {
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub code: Option<Snippet>,
}

/// Parses gitleaks' `--report-format json` output into the same finding
/// shape the built-in scan uses. `read_file_content` lets the caller
/// supply file contents (already-read staged files) without this crate
/// doing its own I/O beyond parsing.
pub fn parse_gitleaks_report(json: &str, root: &Path, read_file_content: impl Fn(&Path) -> Option<String>) -> Vec<GitleaksRawResult> {
    if json.trim().is_empty() {
        return vec![];
    }
    let Ok(results) = serde_json::from_str::<Vec<serde_json::Value>>(json) else { return vec![] };
    results
        .into_iter()
        .map(|r| {
            let raw_file = r.get("File").or_else(|| r.get("file")).and_then(|v| v.as_str()).unwrap_or("");
            let resolved = root.join(raw_file);
            let rel_file = resolved.strip_prefix(root).unwrap_or(&resolved).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
            let line = r
                .get("StartLine")
                .and_then(|v| v.as_i64())
                .or_else(|| r.get("startLine").and_then(|v| v.as_i64()))
                .unwrap_or(0) as usize;
            let col_start = r.get("StartColumn").and_then(|v| v.as_i64()).map(|c| (c - 1) as usize);
            let col_end = r.get("EndColumn").and_then(|v| v.as_i64()).map(|c| c as usize);
            let kind = r
                .get("RuleID")
                .or_else(|| r.get("ruleID"))
                .and_then(|v| v.as_str())
                .unwrap_or("secret")
                .to_lowercase();
            let code = read_file_content(&root.join(&rel_file))
                .and_then(|content| build_snippet(&content, line, SnippetOptions { col_start, col_end, ..Default::default() }));
            GitleaksRawResult { file: rel_file, line, kind, code }
        })
        .collect()
}

/// Applies the same gitignore/allowlist/path-skip filtering the built-in
/// scan uses, then dedups against findings the regex scan already
/// reported at the same file:line — gitleaks routinely re-finds the exact
/// same literal the regex pass already caught.
pub fn merge_gitleaks_findings(
    existing: &[SecretFinding],
    gitleaks: &[GitleaksRawResult],
    gitignore_patterns: &[IgnorePattern],
    known_public_key_patterns: &[Regex],
) -> Vec<SecretFinding> {
    let mut seen: HashSet<String> = existing.iter().map(|f| format!("{}:{}", f.file, f.line)).collect();
    let mut added = Vec::new();
    for f in gitleaks {
        if should_skip_secret_file(&f.file) {
            continue;
        }
        if !gitignore_patterns.is_empty() && is_gitignored(gitignore_patterns, &f.file) {
            continue;
        }
        let line_text = get_highlighted_line_text(&f.code);
        if should_ignore_secret_line(known_public_key_patterns, &f.file, &line_text, IgnoreLineArgs { quote: "", value: "" }) {
            continue;
        }
        let key = format!("{}:{}", f.file, f.line);
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);
        added.push(SecretFinding { file: f.file.clone(), line: f.line, kind: f.kind.clone(), tool: "gitleaks".to_string(), code: f.code.clone() });
    }
    added
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn gitleaks_tooling_reports_false_when_binary_unresolved() {
        let runner = ignite_tool_runner::ToolRunner::new(StdHashMap::new());
        // "gitleaks" isn't a FIXED_COMMANDS entry and no binary is registered here,
        // so resolution fails regardless of whether gitleaks is actually installed.
        assert!(!gitleaks_tooling(&runner).await);
    }

    fn empty_cache() -> HashMap<String, CachedFileEntry> {
        HashMap::new()
    }
    fn cfg() -> SecretsConfig {
        SecretsConfig::default()
    }

    #[test]
    fn flags_a_hardcoded_api_key_literal() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("config.js"), "const api_key = 'sk-proj-abcdefghijklmnop';\n").unwrap();

        let (result, _) = check_secrets(root, &cfg(), &empty_cache()).unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].kind, "api_key");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn does_not_flag_an_identifier_reference_as_a_secret() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("app.js"), "const token = response.data.access_token;\n").unwrap();

        let (result, _) = check_secrets(root, &cfg(), &empty_cache()).unwrap();
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn unquoted_literal_in_config_style_file_is_still_flagged() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        // .env-style: unquoted RHS in a config file is a real literal, not
        // identifier syntax (unlike a .js file).
        fs::write(root.join(".env"), "API_KEY=abcdefghijklmnopqrstuvwxyz\n").unwrap();

        let (result, _) = check_secrets(root, &cfg(), &empty_cache()).unwrap();
        assert_eq!(result.findings.len(), 1);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn known_public_key_pattern_suppresses_a_finding() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("config.js"), "const api_key = 'AIzaSyDPublicFirebaseWebKey123';\n").unwrap();

        let mut config = cfg();
        config.known_public_key_patterns = vec![Regex::new(r"^AIzaSy").unwrap()];
        let (result, _) = check_secrets(root, &config, &empty_cache()).unwrap();
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn gitignored_file_is_skipped_and_counted() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join(".gitignore"), "secret.js\n").unwrap();
        fs::write(root.join("secret.js"), "const api_key = 'sk-proj-abcdefghijklmnop';\n").unwrap();

        let (result, _) = check_secrets(root, &cfg(), &empty_cache()).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.gitignored_skipped, 1);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn placeholder_secret_is_not_flagged() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("docs.md"), "token: ghp_xxxxxxxxxxxxxxxxxxxx\n").unwrap();

        let (result, _) = check_secrets(root, &cfg(), &empty_cache()).unwrap();
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn cache_hit_reuses_findings_when_hash_unchanged() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("config.js"), "const api_key = 'sk-proj-abcdefghijklmnop';\n").unwrap();

        let (first, cache1) = check_secrets(root, &cfg(), &empty_cache()).unwrap();
        assert_eq!(first.cache_hits, 0);
        let (second, _) = check_secrets(root, &cfg(), &cache1).unwrap();
        assert_eq!(second.cache_hits, 1);
        assert_eq!(second.findings.len(), 1);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn parse_gitleaks_allowlist_extracts_regexes_and_paths() {
        // Deliberately no `[...]` character class inside either quoted
        // pattern here — the field-extraction regex (both in this port and
        // the real JS original: `${field}\s*=\s*\[([\s\S]*?)\]`) is
        // non-greedy up to the first `]`, so a bracket *inside* one of the
        // quoted items (e.g. `[0-9]+`) truncates the array early on both
        // sides identically. Verified against the live parseGitleaksAllowlist
        // with exactly that fixture: it also only extracts 1 of 2 items —
        // a real, shared quirk in the JS original, not a porting bug, so
        // it's exercised separately below rather than papered over here.
        let toml = r#"
title = "gitleaks config"

[allowlist]
regexes = [
  '''example-key-prefix''',
  "another-pattern",
]
paths = [
  '''test/fixtures/.*''',
]

[[rules]]
id = "generic-api-key"
"#;
        let allowlist = parse_gitleaks_allowlist(toml);
        assert_eq!(allowlist.regexes.len(), 2);
        assert_eq!(allowlist.paths.len(), 1);
        assert!(allowlist.paths[0].is_match("test/fixtures/data.json"));
    }

    #[test]
    fn parse_gitleaks_allowlist_truncates_early_on_a_bracket_inside_a_quoted_pattern() {
        // Cross-checked against the real parseGitleaksAllowlist with this
        // exact fixture: it returns the same single truncated item, not 2 —
        // both implementations stop at the first `]`, which here is the
        // character class's own closing bracket, not the array's.
        let toml = "[allowlist]\nregexes = [\n  '''example-key-[0-9]+''',\n  \"another-pattern\",\n]\n";
        let allowlist = parse_gitleaks_allowlist(toml);
        assert_eq!(allowlist.regexes.len(), 1);
    }

    #[test]
    fn parse_gitleaks_report_resolves_relative_paths_and_columns() {
        let json = r#"[{"File": "src/app.js", "StartLine": 5, "StartColumn": 10, "EndColumn": 20, "RuleID": "generic-api-key"}]"#;
        let root = Path::new("/tmp/fake-root");
        let results = parse_gitleaks_report(json, root, |_| Some("line1\nline2\nline3\nline4\nsecret here\n".to_string()));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file, "src/app.js");
        assert_eq!(results[0].line, 5);
        assert_eq!(results[0].kind, "generic-api-key");
    }

    #[test]
    fn merge_gitleaks_findings_dedupes_against_existing_regex_findings() {
        let existing = vec![SecretFinding { file: "a.js".into(), line: 3, kind: "api_key".into(), tool: "built-in".to_string(), code: None }];
        let gitleaks = vec![
            GitleaksRawResult { file: "a.js".into(), line: 3, kind: "generic-api-key".into(), code: None }, // dupe
            GitleaksRawResult { file: "b.js".into(), line: 7, kind: "aws-secret".into(), code: None },      // new
        ];
        let merged = merge_gitleaks_findings(&existing, &gitleaks, &[], &[]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].file, "b.js");
    }
}
