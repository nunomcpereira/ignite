//! Regex-based secret scan + optional gitleaks supplement. Faithful port
//! of `checks/secrets.js`.
//!
//! `run_gitleaks_scan` shells out to the real `gitleaks detect` binary and
//! parses its report (via `parse_gitleaks_report`); `merge_gitleaks_findings`
//! applies the same gitignore/allowlist/dedup filtering the JS original
//! applies to gitleaks' raw results. The caller (`phase4-orchestrator`) is
//! responsible for calling `run_gitleaks_scan` + `merge_gitleaks_findings`
//! after `check_secrets` when `security.gitleaks.enabled` is set.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use ignite_fs_utils::{
    build_snippet, hash_buffer, is_gitignored, load_gitignore_patterns, looks_binary, walk_files, IgnorePattern, Snippet,
    SnippetOptions, BINARY_EXTENSIONS, SECRET_SCAN_CODE_EXTS,
};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Replaces `test_pattern_against_sample`'s previous `Result<_, String>`
/// — its one caller (`routes/custom_secret_patterns.rs`) only ever
/// forwards the rendered message into a 400 response body, never matches
/// on it, so `Display` is what matters. `From<String>` lets the existing
/// `.map_err(|e| format!(...))?` site keep working unchanged.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PatternTestError(String);

impl From<String> for PatternTestError {
    fn from(s: String) -> Self {
        PatternTestError(s)
    }
}

// Captures the quote char (if any) separately from the value so callers
// can tell a string literal from a bare identifier/property-access
// reference. `[a-z0-9_]*` after the keyword lets it match inside a longer
// compound identifier (`AWS_SECRET_ACCESS_KEY`, `JWT_SECRET_KEY`) instead of
// requiring the keyword to sit immediately before `=`/`:` — the original
// pattern missed exactly those because "aws_secret"/"secret" was followed
// by more identifier characters, not straight into the separator. The
// value charset also allows `/` and `+` (base64/AWS-secret alphabet).
static SECRET_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)(password|passwd|pwd|secret|aws_secret|access_key|api_key|apikey|token|private_key|credential|jwt)[a-z0-9_]*\s*[:=]\s*(['"]?)([a-zA-Z0-9_\-.~/+]{10,})"#).unwrap());

// A connection-string's embedded `user:password@host` userinfo carries a
// real credential regardless of what the surrounding variable is named
// (`DATABASE_URL` matches none of SECRET_RE's keywords) — checked
// independently of SECRET_RE for exactly that reason. Both `[^...]*` groups
// are greedy so a password that itself contains `@` (e.g.
// `P@ssw0rd@host`) still resolves to the *last* `@` as the userinfo/host
// boundary, matching how a real URI parser reads it.
static URI_CREDENTIAL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)[a-z][a-z0-9+.\-]*://([^\s'"/@]+):([^\s'"]{6,})@"#).unwrap());

static SECRET_SCAN_PATH_SKIP_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^(?:\.ignite-review\.md|(?:\.claude|\.github)/skills/.*\.md)$").unwrap());
static PLACEHOLDER_SECRET_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bghp_x{6,}\b|\bsecret-key-here\b|fcm-token-[a-z0-9-]*\.\.\.").unwrap());
static IDENTIFIER_CHAIN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$").unwrap());
static COMMENT_CODE_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*#\s*Code:\s*").unwrap());

/// Bump this whenever `scan_file_for_secrets`'s detection logic changes in
/// a way that could produce different findings for the same file bytes —
/// see the comment where it's used in `check_secrets`.
const SECRET_DETECTOR_VERSION: &str = "v2";

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

    // Deliberately not `field\s*=\s*\[([\s\S]*?)\]` — a non-greedy match
    // up to the *first* `]` truncates the array as soon as any quoted
    // regex item itself contains a `]` (a character class like
    // `[a-z0-9]`), silently discarding every entry after it. Instead,
    // walk quoted items one at a time from just after `[` and only stop
    // at an actual unquoted `]` (or malformed input).
    let extract_array = |field: &str| -> Vec<Regex> {
        let start_re = Regex::new(&format!(r"{field}\s*=\s*\[")).unwrap();
        let Some(start) = start_re.find(&block) else { return vec![] };
        let rest = &block[start.end()..];
        let mut items = Vec::new();
        let mut pos = 0;
        loop {
            while rest[pos..].starts_with(|c: char| c.is_whitespace() || c == ',') {
                pos += rest[pos..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            }
            if pos >= rest.len() || rest[pos..].starts_with(']') {
                break;
            }
            let Some(cap) = ITEM_RE.captures(&rest[pos..]) else { break };
            let Some(full) = cap.get(0) else { break };
            if full.start() != 0 {
                break; // next thing isn't a quoted item or `]` — malformed, bail
            }
            let raw = cap.get(1).or_else(|| cap.get(2)).or_else(|| cap.get(3)).or_else(|| cap.get(4)).map(|m| m.as_str());
            if let Some(raw) = raw {
                if let Ok(re) = Regex::new(raw) {
                    items.push(re);
                }
            }
            pos += full.end();
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
    pub gitleaks_enabled: bool,
    pub gitleaks_scan_history: bool,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        SecretsConfig { known_public_key_patterns: vec![], max_scan_file_bytes: 5 * 1024 * 1024, gitleaks_config_path: None, gitleaks_enabled: false, gitleaks_scan_history: false }
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
        if let Some(m) = SECRET_RE.captures(line) {
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
            continue;
        }

        // No `keyword = value` match on this line — still check for a
        // connection-string's embedded userinfo credential, which
        // SECRET_RE can never catch since the variable holding it (e.g.
        // `DATABASE_URL`) carries none of its keywords.
        if let Some(m) = URI_CREDENTIAL_RE.captures(line) {
            let value = &m[2];
            if is_allowlisted(allowlist, rel, line) {
                continue;
            }
            if should_ignore_secret_line(known_public_key_patterns, rel, line, IgnoreLineArgs { quote: "\"", value }) {
                continue;
            }
            let whole = m.get(0).unwrap();
            let line_no = i + 1;
            findings.push(SecretFinding {
                file: rel.to_string(),
                line: line_no,
                kind: "connection-string credential".to_string(),
                tool: "built-in".to_string(),
                code: build_snippet(content, line_no, SnippetOptions { col_start: Some(whole.start()), col_end: Some(whole.end()), ..Default::default() }),
            });
        }
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
        // Folding SECRET_DETECTOR_VERSION into the stored hash means a
        // detection-logic change (a broadened SECRET_RE, a new pattern like
        // URI_CREDENTIAL_RE) invalidates every previously cached entry
        // automatically — a pure content hash can't tell "this file is
        // unchanged" from "this file is unchanged, but we'd now flag more
        // in it", and a cache hit would otherwise keep serving pre-fix
        // results (missing findings) forever until the file itself edits.
        let hash = format!("{}:{SECRET_DETECTOR_VERSION}", hash_buffer(&buffer));

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

/// Runs `gitleaks detect` against `root` and parses its JSON report.
/// Soft-fails (returns no findings) on any missing-binary/timeout/parse
/// error, mirroring `checks/secrets.js`'s `runGitleaksScan` — a
/// misconfigured or absent gitleaks install must never break the pipeline.
pub async fn run_gitleaks_scan(
    root: &Path,
    runner: &ignite_tool_runner::ToolRunner,
    config_path: Option<&Path>,
) -> Vec<GitleaksRawResult> {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    );
    let report_path = std::env::temp_dir().join(format!("ignite-gitleaks-{unique}.json"));

    let mut args = vec![
        "detect".to_string(),
        "--source".to_string(),
        root.to_string_lossy().into_owned(),
        "--no-git".to_string(),
        "--report-format".to_string(),
        "json".to_string(),
        "--report-path".to_string(),
        report_path.to_string_lossy().into_owned(),
        "--exit-code".to_string(),
        "0".to_string(),
    ];
    if let Some(cp) = config_path {
        args.push("--config".to_string());
        args.push(cp.to_string_lossy().into_owned());
    }

    let run_result = runner
        .run_tool(
            "gitleaks",
            &args,
            &root.to_string_lossy(),
            ignite_tool_runner::RunToolOptions { timeout_ms: Some(10 * 60_000), ..Default::default() },
        )
        .await;

    let results = if run_result.is_err() {
        vec![]
    } else {
        match std::fs::read_to_string(&report_path) {
            Ok(raw) => parse_gitleaks_report(&raw, root, |p| std::fs::read_to_string(p).ok()),
            Err(_) => vec![], // no report written (e.g. nothing found on some gitleaks versions)
        }
    };
    let _ = std::fs::remove_file(&report_path);
    results
}

/// Like `run_gitleaks_scan` but scans full git commit history instead of
/// just the current working tree — the one class of secret a
/// working-tree-only scan structurally can't catch: a credential that was
/// committed, then removed in a later commit, is still exposed to anyone
/// who clones the repo. Requires a real `.git` directory (no-op — returns
/// no findings — on a checkout with no git history, e.g. an uploaded ZIP)
/// and omits `--no-git`/`--source` restrictions so gitleaks walks every
/// commit reachable from HEAD.
pub async fn run_gitleaks_history_scan(
    root: &Path,
    runner: &ignite_tool_runner::ToolRunner,
    config_path: Option<&Path>,
) -> Vec<GitleaksRawResult> {
    if !root.join(".git").exists() {
        return vec![];
    }

    let unique = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    );
    let report_path = std::env::temp_dir().join(format!("ignite-gitleaks-history-{unique}.json"));

    let mut args = vec![
        "detect".to_string(),
        "--source".to_string(),
        root.to_string_lossy().into_owned(),
        "--report-format".to_string(),
        "json".to_string(),
        "--report-path".to_string(),
        report_path.to_string_lossy().into_owned(),
        "--exit-code".to_string(),
        "0".to_string(),
    ];
    if let Some(cp) = config_path {
        args.push("--config".to_string());
        args.push(cp.to_string_lossy().into_owned());
    }

    // Full-history scans of a real project can take much longer than a
    // working-tree-only scan — a generous timeout so a large history
    // doesn't get silently truncated to "no findings" on a slow disk/CI
    // runner, without hanging the pipeline indefinitely on a broken repo.
    let run_result = runner
        .run_tool(
            "gitleaks",
            &args,
            &root.to_string_lossy(),
            ignite_tool_runner::RunToolOptions { timeout_ms: Some(30 * 60_000), ..Default::default() },
        )
        .await;

    let results = if run_result.is_err() {
        vec![]
    } else {
        match std::fs::read_to_string(&report_path) {
            Ok(raw) => parse_gitleaks_report(&raw, root, |p| std::fs::read_to_string(p).ok()),
            Err(_) => vec![],
        }
    };
    let _ = std::fs::remove_file(&report_path);
    results
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
    merge_gitleaks_findings_as(existing, gitleaks, gitignore_patterns, known_public_key_patterns, "gitleaks")
}

/// Same filtering/dedup as `merge_gitleaks_findings`, but for
/// `run_gitleaks_history_scan` results — tagged with a distinct tool name
/// (`"gitleaks-history"`) so callers/UI can tell "still in the working
/// tree today" apart from "only in a past commit, already removed".
pub fn merge_gitleaks_history_findings(
    existing: &[SecretFinding],
    gitleaks: &[GitleaksRawResult],
    gitignore_patterns: &[IgnorePattern],
    known_public_key_patterns: &[Regex],
) -> Vec<SecretFinding> {
    merge_gitleaks_findings_as(existing, gitleaks, gitignore_patterns, known_public_key_patterns, "gitleaks-history")
}

fn merge_gitleaks_findings_as(
    existing: &[SecretFinding],
    gitleaks: &[GitleaksRawResult],
    gitignore_patterns: &[IgnorePattern],
    known_public_key_patterns: &[Regex],
    tool: &str,
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
        added.push(SecretFinding { file: f.file.clone(), line: f.line, kind: f.kind.clone(), tool: tool.to_string(), code: f.code.clone() });
    }
    added
}

// --- custom secret patterns: playground + retroactive-sweep config builder ---

/// One operator-authored custom secret pattern (GHAS "custom pattern"
/// parity) — just a name and a regex; storage/CRUD lives in `db-store`
/// (`ignite-secrets` stays decoupled from the SQLite layer, same as every
/// other check crate).
#[derive(Debug, Clone)]
pub struct CustomSecretPattern {
    pub name: String,
    pub regex: String,
}

/// One match `test_pattern_against_sample` found — the "playground"
/// response: enough to highlight the match in a UI (byte offsets into
/// `sample`) without re-running the regex client-side.
#[derive(Debug, Clone, PartialEq)]
pub struct PatternMatch {
    pub start: usize,
    pub end: usize,
    pub matched_text: String,
}

/// A pattern this long has no legitimate secret-detection use and only
/// makes an already-linear-time regex engine do needlessly large amounts
/// of work per call — reject outright rather than spend cycles compiling
/// it.
const MAX_CUSTOM_PATTERN_LEN: usize = 2_000;
/// Caps how much sample text the playground actually searches — this is
/// an interactive "try it out" tool, not a scanner; a multi-megabyte
/// paste is almost certainly a mistake, not a real use case.
const MAX_PLAYGROUND_SAMPLE_LEN: usize = 100_000;
/// Caps how many matches a single playground call returns — a pattern
/// that's too loose (matches every character, say) shouldn't make the
/// response unbounded.
const MAX_PLAYGROUND_MATCHES: usize = 200;

/// Compiles `regex_str` and runs it against `sample`, returning every
/// match's position and text — the "playground" GHAS's custom-pattern
/// editor offers before an operator saves a pattern for real use. Unlike
/// backtracking regex engines (PCRE, the one behind GHAS's own custom
/// patterns), Rust's `regex` crate — the same one every other pattern in
/// this codebase already uses — guarantees linear-time matching with no
/// catastrophic-backtracking failure mode, so this is safe to run
/// synchronously against arbitrary operator-supplied input; the length
/// caps below exist for sane response sizes, not because of a ReDoS risk.
pub fn test_pattern_against_sample(regex_str: &str, sample: &str) -> Result<Vec<PatternMatch>, PatternTestError> {
    if regex_str.is_empty() {
        return Err("Pattern must not be empty.".to_string().into());
    }
    if regex_str.len() > MAX_CUSTOM_PATTERN_LEN {
        return Err(format!("Pattern is too long (max {MAX_CUSTOM_PATTERN_LEN} characters).").into());
    }
    let re = Regex::new(regex_str).map_err(|e| format!("Invalid regex: {e}"))?;
    let truncated = if sample.len() > MAX_PLAYGROUND_SAMPLE_LEN {
        // A byte-offset slice can land mid-codepoint on multi-byte UTF-8
        // input — walk back to the nearest char boundary at or before the
        // cap rather than panicking.
        let mut end = MAX_PLAYGROUND_SAMPLE_LEN;
        while end > 0 && !sample.is_char_boundary(end) {
            end -= 1;
        }
        &sample[..end]
    } else {
        sample
    };
    Ok(re.find_iter(truncated).take(MAX_PLAYGROUND_MATCHES).map(|m| PatternMatch { start: m.start(), end: m.end(), matched_text: m.as_str().to_string() }).collect())
}

/// A rule id gitleaks accepts: lowercased, non-alphanumerics collapsed to
/// a single `-`, trimmed of leading/trailing `-` — falls back to
/// `"custom-pattern"` if that leaves nothing (an all-symbols name).
fn gitleaks_rule_id(name: &str) -> String {
    let mut id = String::new();
    let mut last_was_dash = false;
    for ch in name.to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            id.push(ch);
            last_was_dash = false;
        } else if !last_was_dash && !id.is_empty() {
            id.push('-');
            last_was_dash = true;
        }
    }
    while id.ends_with('-') {
        id.pop();
    }
    if id.is_empty() {
        "custom-pattern".to_string()
    } else {
        id
    }
}

/// Builds a minimal gitleaks config (TOML) carrying one `[[rules]]` per
/// pattern — what lets a custom pattern reuse gitleaks' own scan engine
/// (`run_gitleaks_scan`/`run_gitleaks_history_scan`) instead of this
/// crate needing a second, parallel git-history-walking implementation.
/// The regex goes in a TOML literal string (`'''...'''`) specifically so
/// it needs no backslash/quote escaping — a raw regex pasted by an
/// operator (backslashes, quotes, anything) round-trips byte-for-byte.
///
/// `base_config_path` controls what `[extend]` layers under the custom
/// rules: `None` extends gitleaks' own built-in ruleset (`useDefault =
/// true`) — the playground/sweep-pattern callers' case, where there's no
/// separate operator config to preserve. `Some(path)` instead extends
/// that path (`security.gitleaks.configPath`, when a deployment already
/// has its own gitleaks config) via `[extend].path` — used when wiring
/// custom patterns into the live working-tree/history scan, so an
/// operator's own tuned config (allowlists, extra rules) stays in effect
/// underneath the custom patterns rather than being silently replaced by
/// gitleaks' stock defaults. Either way this only ever adds one `extend`
/// hop — a custom pattern *adds* detection, it doesn't replace whichever
/// baseline was already in effect.
pub fn build_gitleaks_config_for_patterns(patterns: &[CustomSecretPattern], base_config_path: Option<&Path>) -> String {
    let mut toml = String::from("title = \"ignite-custom-secret-patterns\"\n\n[extend]\n");
    match base_config_path {
        Some(p) => {
            let escaped = p.display().to_string().replace('\\', "\\\\").replace('"', "\\\"");
            toml.push_str(&format!("path = \"{escaped}\"\n\n"));
        }
        None => toml.push_str("useDefault = true\n\n"),
    }
    let mut seen_ids: HashSet<String> = HashSet::new();
    for p in patterns {
        let mut id = gitleaks_rule_id(&p.name);
        // Two patterns named "AWS Key" and "aws key" would otherwise
        // collide on the same slug — gitleaks requires unique rule ids
        // within one config, so disambiguate deterministically instead of
        // silently dropping the second rule.
        if !seen_ids.insert(id.clone()) {
            let mut n = 2;
            while !seen_ids.insert(format!("{id}-{n}")) {
                n += 1;
            }
            id = format!("{id}-{n}");
        }
        let description = p.name.replace('\\', "\\\\").replace('"', "\\\"");
        toml.push_str(&format!("[[rules]]\nid = \"{id}\"\ndescription = \"{description}\"\nregex = '''{}'''\n\n", p.regex));
    }
    toml
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

    #[tokio::test]
    async fn run_gitleaks_history_scan_no_ops_without_a_git_directory() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("config.js"), "const api_key = 'sk-proj-abcdefghijklmnop';\n").unwrap();
        let runner = ignite_tool_runner::ToolRunner::new(StdHashMap::new());
        // No .git directory at all — must return no findings without even
        // attempting to run gitleaks, regardless of whether it's installed.
        let results = run_gitleaks_history_scan(root, &runner, None).await;
        assert!(results.is_empty());
    }

    #[test]
    fn merge_gitleaks_history_findings_tags_tool_distinctly_from_working_tree_gitleaks() {
        let existing = vec![];
        let history = vec![GitleaksRawResult { file: "old-secret.js".into(), line: 4, kind: "generic-api-key".into(), code: None }];
        let merged = merge_gitleaks_history_findings(&existing, &history, &[], &[]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].tool, "gitleaks-history");
    }

    #[test]
    fn merge_gitleaks_history_findings_dedupes_against_working_tree_findings_at_same_location() {
        let existing = vec![SecretFinding { file: "a.js".into(), line: 3, kind: "api_key".into(), tool: "gitleaks".to_string(), code: None }];
        let history = vec![GitleaksRawResult { file: "a.js".into(), line: 3, kind: "generic-api-key".into(), code: None }];
        let merged = merge_gitleaks_history_findings(&existing, &history, &[], &[]);
        assert!(merged.is_empty());
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
        fs::write(root.join("config.js"), format!("const api_key = '{}';\n", "sk-proj-abcdefghijklmnop")).unwrap();

        let (result, _) = check_secrets(root, &cfg(), &empty_cache()).unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].kind, "api_key");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn does_not_flag_an_identifier_reference_as_a_secret() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("app.js"), format!("const token = {};\n", "response.data.access_token")).unwrap();

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
        fs::write(root.join(".env"), format!("API_KEY={}\n", "abcdefghijklmnopqrstuvwxyz")).unwrap();

        let (result, _) = check_secrets(root, &cfg(), &empty_cache()).unwrap();
        assert_eq!(result.findings.len(), 1);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    /// Real gap: `AWS_SECRET_ACCESS_KEY`/`JWT_SECRET_KEY`-shaped compound
    /// identifiers weren't flagged at all — the keyword had to sit
    /// immediately before `=`, so anything after "aws_secret"/"secret" in
    /// the variable name (`_ACCESS_KEY`, `_KEY`) broke the match.
    #[test]
    fn flags_compound_identifiers_with_trailing_keyword_suffix() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(
            root.join("config.py"),
            "AWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\nJWT_SECRET_KEY = \"super_secret_production_signing_key_do_not_share_12345\"\n",
        )
        .unwrap();

        let (result, _) = check_secrets(root, &cfg(), &empty_cache()).unwrap();
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.findings[0].kind, "aws_secret");
        assert_eq!(result.findings[1].kind, "jwt");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    /// Real gap: a connection string's embedded `user:password@host`
    /// carries a real credential regardless of what the variable is named
    /// (`DATABASE_URL` matches none of SECRET_RE's keywords) — including
    /// when the password itself contains an `@`, which must resolve to the
    /// *last* `@` as the userinfo/host boundary, same as a real URI parser.
    #[test]
    fn flags_a_password_embedded_in_a_connection_string() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        // example.com is IANA/RFC 2606-reserved for documentation - never a
        // real host - and the password is labeled as a placeholder outright,
        // so this can't be mistaken for a live credential by a scanner (ours
        // or a third party's) that only sees the string, not this comment.
        fs::write(
            root.join("config.py"),
            "DATABASE_URL = \"postgresql://testuser:not-a-real-pw@x@example.com:5432/testdb\"\n",
        )
        .unwrap();

        let (result, _) = check_secrets(root, &cfg(), &empty_cache()).unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].kind, "connection-string credential");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn known_public_key_pattern_suppresses_a_finding() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("config.js"), format!("const api_key = '{}';\n", "AIzaSyDPublicFirebaseWebKey123")).unwrap();

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
        fs::write(root.join("secret.js"), format!("const api_key = '{}';\n", "sk-proj-abcdefghijklmnop")).unwrap();

        let (result, _) = check_secrets(root, &cfg(), &empty_cache()).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.gitignored_skipped, 1);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn placeholder_secret_is_not_flagged() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("docs.md"), format!("token: {}\n", "ghp_xxxxxxxxxxxxxxxxxxxx")).unwrap();

        let (result, _) = check_secrets(root, &cfg(), &empty_cache()).unwrap();
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn cache_hit_reuses_findings_when_hash_unchanged() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("config.js"), format!("const api_key = '{}';\n", "sk-proj-abcdefghijklmnop")).unwrap();

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

    #[test]
    fn test_pattern_against_sample_finds_all_matches() {
        let matches = test_pattern_against_sample(r"sk_live_[a-zA-Z0-9]{16,}", "key one: sk_live_abcdef0123456789, key two: sk_live_zzzzzz9999999999").unwrap();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].matched_text, "sk_live_abcdef0123456789");
        assert_eq!(matches[1].matched_text, "sk_live_zzzzzz9999999999");
    }

    #[test]
    fn test_pattern_against_sample_reports_match_offsets() {
        let matches = test_pattern_against_sample("abc", "xxabcxx").unwrap();
        assert_eq!(matches, vec![PatternMatch { start: 2, end: 5, matched_text: "abc".to_string() }]);
    }

    #[test]
    fn test_pattern_against_sample_returns_empty_for_no_match() {
        assert!(test_pattern_against_sample("nomatch", "hello world").unwrap().is_empty());
    }

    #[test]
    fn test_pattern_against_sample_rejects_invalid_regex() {
        let err = test_pattern_against_sample("(unclosed", "sample").unwrap_err();
        assert!(err.to_string().contains("Invalid regex"), "{err}");
    }

    #[test]
    fn test_pattern_against_sample_rejects_empty_pattern() {
        assert!(test_pattern_against_sample("", "sample").is_err());
    }

    #[test]
    fn test_pattern_against_sample_rejects_oversized_pattern() {
        let huge = "a".repeat(MAX_CUSTOM_PATTERN_LEN + 1);
        let err = test_pattern_against_sample(&huge, "sample").unwrap_err();
        assert!(err.to_string().contains("too long"), "{err}");
    }

    #[test]
    fn test_pattern_against_sample_caps_match_count() {
        let sample = "a".repeat(MAX_PLAYGROUND_MATCHES * 2);
        let matches = test_pattern_against_sample("a", &sample).unwrap();
        assert_eq!(matches.len(), MAX_PLAYGROUND_MATCHES);
    }

    #[test]
    fn gitleaks_rule_id_slugifies_and_falls_back_on_all_symbols() {
        assert_eq!(gitleaks_rule_id("AWS Key v2"), "aws-key-v2");
        assert_eq!(gitleaks_rule_id("  leading/trailing!! "), "leading-trailing");
        assert_eq!(gitleaks_rule_id("***"), "custom-pattern");
    }

    #[test]
    fn build_gitleaks_config_for_patterns_needs_no_regex_escaping() {
        let patterns = vec![CustomSecretPattern { name: "Internal Token".to_string(), regex: r#"tok_\d{4}"[a-z]+"#.to_string() }];
        let toml = build_gitleaks_config_for_patterns(&patterns, None);
        assert!(toml.contains(r#"regex = '''tok_\d{4}"[a-z]+'''"#), "{toml}");
        assert!(toml.contains("[[rules]]"));
        assert!(toml.contains("id = \"internal-token\""));
        assert!(toml.contains("useDefault = true"));
    }

    #[test]
    fn build_gitleaks_config_for_patterns_disambiguates_colliding_slugs() {
        let patterns = vec![CustomSecretPattern { name: "AWS Key".to_string(), regex: "a".to_string() }, CustomSecretPattern { name: "aws key".to_string(), regex: "b".to_string() }];
        let toml = build_gitleaks_config_for_patterns(&patterns, None);
        assert!(toml.contains("id = \"aws-key\""));
        assert!(toml.contains("id = \"aws-key-2\""));
    }

    #[test]
    fn build_gitleaks_config_for_patterns_extends_a_base_config_path_instead_of_defaults() {
        let patterns = vec![CustomSecretPattern { name: "Internal Token".to_string(), regex: "tok_.*".to_string() }];
        let toml = build_gitleaks_config_for_patterns(&patterns, Some(Path::new("/etc/ignite/gitleaks.toml")));
        assert!(toml.contains("path = \"/etc/ignite/gitleaks.toml\""), "{toml}");
        assert!(!toml.contains("useDefault"), "{toml}");
    }
}
