//! Mechanical checks for the automated subset of the guideline catalog.
//! Faithful port of `guidelines/checks.js`, mirroring the same detection
//! patterns Ignite's onboarding pipeline (server.js) uses so the same
//! rules apply whether checked locally during development or later
//! during onboarding CI. Deliberately its own file walk (own SKIP_DIRS/
//! BINARY_EXTENSIONS), independent of `ignite-fs-utils`, matching the JS
//! original's own separate, smaller local implementation.

use crate::catalog::guidelines;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;

static SECRET_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)(password|aws_secret|api_key|token|private_key)\s*[:=]\s*['" \t]*[a-zA-Z0-9_\-.~]{10,}"#).unwrap());
static AI_INVOKE_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b([A-Za-z_$][\w.]*)\.(invoke|stream|ainvoke|astream)\(").unwrap());
static AGENT_FRAMEWORK_HINT_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(langchain|langgraph|autogen|crewai)\b").unwrap());
static GENERIC_CLIENT_RECEIVER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^(client|http|httpclient|session|conn|connection|resp|response|req|request)$").unwrap());
static TEST_FILE_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(^|/)(tests?|__tests__|spec)/|(^|/)(test_[^/]+\.py|[^/]+_test\.py|[^/]+\.(test|spec)\.[jt]sx?)$").unwrap());

static INJECTION_SINK_REGEXES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"\beval\(").unwrap(),
        Regex::new(r"new Function\(").unwrap(),
        Regex::new(r#"\bexec\(\s*[`'"]"#).unwrap(),
        Regex::new(r"child_process\.(exec|execSync)\(").unwrap(),
        Regex::new(r"\bpickle\.loads?\(").unwrap(),
        Regex::new(r"os\.system\(").unwrap(),
        Regex::new(r"subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True").unwrap(),
    ]
});

// `yaml.load(` not followed (same line) by `Loader = yaml.SafeLoader` — the
// `regex` crate has no lookahead support, so this pair is checked as a
// separate per-line post-match exclusion (see no_insecure_deserialization)
// rather than folded into one regex like the JS original's negative
// lookahead.
static YAML_LOAD_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"yaml\.load\(").unwrap());
static YAML_SAFE_LOADER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"Loader\s*=\s*yaml\.SafeLoader").unwrap());
static INSECURE_DESERIALIZATION_REGEXES: Lazy<Vec<Regex>> = Lazy::new(|| vec![Regex::new(r"\bpickle\.loads?\(").unwrap(), Regex::new(r"vm\.runInNewContext\(").unwrap()]);

// `http://` to a non-loopback host — the `regex` crate has no negative-
// lookahead support for `(?!localhost|127\.0\.0\.1|0\.0\.0\.0)`, so this
// matches the URL generically and excludes loopback hosts by string check
// afterward (see no_plaintext_http_egress).
static PLAINTEXT_HTTP_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r#"['"]http://[^'"]+['"]"#).unwrap());
// Faithful-port note: the JS negative lookahead `(?!localhost|127\.0\.0\.1|
// 0\.0\.0\.0)` is a bare string-prefix check at the position right after
// "http://" — NOT hostname-boundary aware. "http://localhost.evil.com" is
// therefore silently excluded by the JS original too (confirmed live) since
// it starts with the literal string "localhost", even though it's a real
// remote host. Preserved here as-is rather than "fixed" to a boundary-aware
// check, since the port's goal is faithful parity, not a security fix that
// would diverge the two implementations' behavior.
const LOOPBACK_HOST_PREFIXES: &[&str] = &["localhost", "127.0.0.1", "0.0.0.0"];

static SQL_INJECTION_REGEXES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"(?i)f['"][^'"]*\b(select|insert|update|delete)\b[^'"]*\{"#).unwrap(),
        Regex::new(r"(?i)`[^`]*\b(select|insert|update|delete)\b[^`]*\$\{").unwrap(),
        Regex::new(r#"(?i)['"][^'"]*\b(select|insert|update|delete)\b[^'"]*['"]\s*\+\s*\S"#).unwrap(),
        Regex::new(r#"(?i)\+\s*['"][^'"]*\b(select|insert|update|delete)\b"#).unwrap(),
    ]
});

static XSS_SINK_REGEXES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"dangerouslySetInnerHTML").unwrap(),
        Regex::new(r"\.innerHTML\s*=").unwrap(),
        Regex::new(r"document\.write\(").unwrap(),
        Regex::new(r"\{\{.*\|\s*safe\s*\}\}").unwrap(),
        Regex::new(r"\bMarkup\(").unwrap(),
    ]
});

static WEAK_CRYPTO_REGEXES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"(?i)crypto\.createHash\(\s*['"](md5|sha1)['"]\s*\)"#).unwrap(),
        Regex::new(r"(?i)hashlib\.(md5|sha1)\(").unwrap(),
        Regex::new(r#"(?i)MessageDigest\.getInstance\(\s*['"](MD5|SHA-?1)['"]\s*\)"#).unwrap(),
        Regex::new(r#"(?i)createCipheriv\(\s*['"]des"#).unwrap(),
        Regex::new(r#"(?i)Cipher\.getInstance\(\s*['"](DES|[^'"]*/ECB/)"#).unwrap(),
    ]
});
// hashlib.md5()/sha1() flagged unconditionally *unless* the call passes
// Python 3.9+'s usedforsecurity=False — a negative lookahead the `regex`
// crate can't express directly, so this is checked as a separate
// post-match exclusion below rather than folded into the regex itself.
static USED_FOR_SECURITY_FALSE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"usedforsecurity\s*=\s*False").unwrap());
static HASHLIB_MD5_SHA1_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)hashlib\.(md5|sha1)\(([^)]*)").unwrap());

static SSRF_SINK_REGEXES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)\b(fetch|axios(?:\.\w+)?)\(\s*(req|request)\.[^,)]*\)").unwrap(),
        Regex::new(r"(?i)\brequests\.\w+\(\s*(req|request)\.[^,)]*\)").unwrap(),
    ]
});

static CSRF_DISABLED_REGEXES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![Regex::new(r"@csrf_exempt").unwrap(), Regex::new(r"skip_before_action\s*:verify_authenticity_token").unwrap(), Regex::new(r"(?i)csrf\s*:\s*false").unwrap()]
});

// A third-party action pinned to a mutable ref, excluding same-repo
// (`./...`) and `actions/*`-published actions. The `regex` crate has no
// negative-lookahead support for `(?!\.\/|actions\/)`, so the action-name
// exclusion is checked manually after the match (see
// no_unpinned_gha_action) rather than folded into the regex itself.
static UNPINNED_GHA_ACTION_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"uses:\s*([^@\s]+)@(main|master|latest|v?\d+(?:\.\d+)*)\s*$").unwrap());
static GHA_WORKFLOW_PATH_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$").unwrap());

static BINARY_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff", ".pdf", ".zip", ".gz", ".tar", ".bz2", ".7z", ".rar", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4",
        ".mov", ".avi", ".mkv", ".wav", ".ogg", ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".class", ".pyc", ".wasm", ".jar", ".db", ".sqlite", ".sqlite3",
    ]
    .into_iter()
    .collect()
});

static SKIP_DIRS: Lazy<HashSet<&'static str>> = Lazy::new(|| ["node_modules", ".git", ".next", "dist", "build", "__pycache__", ".venv", "venv", "vendor", ".idea", ".vscode"].into_iter().collect());

pub const MAX_SCAN_FILE_BYTES: u64 = 5 * 1024 * 1024;

pub fn looks_binary(buffer: &[u8]) -> bool {
    buffer[..buffer.len().min(8192)].contains(&0)
}

struct Hit {
    line: usize,
    snippet: String,
    receiver: Option<String>,
}

fn scan_lines(content: &str, regex: &Regex) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (i, line) in content.split('\n').enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(m) = regex.captures(line) {
            let snippet: String = line.trim().chars().take(160).collect();
            let receiver = m.get(1).map(|g| g.as_str().to_string());
            hits.push(Hit { line: i + 1, snippet, receiver });
        }
    }
    hits
}

fn scan_lines_all(content: &str, regexes: &[Regex]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for re in regexes {
        hits.extend(scan_lines(content, re));
    }
    hits
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckHit {
    pub line: usize,
    pub snippet: String,
    pub kind: Option<String>,
}

fn ai_recursion_limit(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if TEST_FILE_REGEX.is_match(rel_path) {
        return vec![];
    }
    if !AGENT_FRAMEWORK_HINT_REGEX.is_match(content) {
        return vec![];
    }
    if content.contains("recursion_limit") {
        return vec![];
    }
    scan_lines(content, &AI_INVOKE_REGEX)
        .into_iter()
        .filter(|h| {
            let receiver = h.receiver.as_deref().unwrap_or("");
            let last_segment = receiver.rsplit('.').next().unwrap_or(receiver);
            !GENERIC_CLIENT_RECEIVER_RE.is_match(last_segment)
        })
        .map(|h| CheckHit { line: h.line, snippet: h.snippet, kind: None })
        .collect()
}

fn no_hardcoded_secrets(content: &str) -> Vec<CheckHit> {
    scan_lines(content, &SECRET_REGEX)
        .into_iter()
        .map(|h| CheckHit { line: h.line, snippet: h.snippet, kind: h.receiver.map(|r| r.to_lowercase()) })
        .collect()
}

fn no_weak_crypto(content: &str) -> Vec<CheckHit> {
    let mut hits: Vec<CheckHit> = Vec::new();
    for (i, line) in content.split('\n').enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(m) = HASHLIB_MD5_SHA1_RE.captures(line) {
            let args = m.get(2).map(|g| g.as_str()).unwrap_or("");
            if !USED_FOR_SECURITY_FALSE_RE.is_match(args) {
                hits.push(CheckHit { line: i + 1, snippet: line.trim().chars().take(160).collect(), kind: None });
            }
        }
        for re in [&*WEAK_CRYPTO_REGEXES.get(0).unwrap(), &WEAK_CRYPTO_REGEXES[2], &WEAK_CRYPTO_REGEXES[3], &WEAK_CRYPTO_REGEXES[4]] {
            if re.is_match(line) {
                hits.push(CheckHit { line: i + 1, snippet: line.trim().chars().take(160).collect(), kind: None });
            }
        }
    }
    hits
}

fn no_insecure_deserialization(content: &str) -> Vec<CheckHit> {
    let mut hits: Vec<CheckHit> = plain(scan_lines_all(content, &INSECURE_DESERIALIZATION_REGEXES));
    for (i, line) in content.split('\n').enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if YAML_LOAD_RE.is_match(line) && !YAML_SAFE_LOADER_RE.is_match(line) {
            hits.push(CheckHit { line: i + 1, snippet: line.trim().chars().take(160).collect(), kind: None });
        }
    }
    hits
}

fn no_plaintext_http_egress(content: &str) -> Vec<CheckHit> {
    let mut hits = Vec::new();
    for (i, line) in content.split('\n').enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(m) = PLAINTEXT_HTTP_REGEX.find(line) {
            let matched = m.as_str();
            let url = matched.trim_matches(|c| c == '\'' || c == '"');
            let host_part = url.strip_prefix("http://").unwrap_or(url);
            let is_loopback_prefix = LOOPBACK_HOST_PREFIXES.iter().any(|p| host_part.starts_with(p));
            if !is_loopback_prefix {
                hits.push(CheckHit { line: i + 1, snippet: line.trim().chars().take(160).collect(), kind: None });
            }
        }
    }
    hits
}

fn no_unpinned_gha_action(content: &str, rel_path: &str) -> Vec<CheckHit> {
    let normalized = rel_path.replace('\\', "/");
    if !GHA_WORKFLOW_PATH_RE.is_match(&normalized) {
        return vec![];
    }
    let mut hits = Vec::new();
    for (i, line) in content.split('\n').enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let Some(m) = UNPINNED_GHA_ACTION_REGEX.captures(line) else { continue };
        let action_name = m.get(1).map(|g| g.as_str()).unwrap_or("");
        if action_name.starts_with("./") || action_name.starts_with("actions/") {
            continue;
        }
        hits.push(CheckHit { line: i + 1, snippet: line.trim().chars().take(160).collect(), kind: None });
    }
    hits
}

fn no_committed_env_files(rel_path: &str) -> Vec<CheckHit> {
    let base = Path::new(rel_path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if base == ".env" || base.starts_with(".env.") {
        vec![CheckHit { line: 0, snippet: rel_path.to_string(), kind: None }]
    } else {
        vec![]
    }
}

fn plain(hits: Vec<Hit>) -> Vec<CheckHit> {
    hits.into_iter().map(|h| CheckHit { line: h.line, snippet: h.snippet, kind: None }).collect()
}

/// One function per automated guideline (`checkId` in catalog.rs).
pub fn run_check(check_id: &str, content: &str, rel_path: &str) -> Option<Vec<CheckHit>> {
    Some(match check_id {
        "aiRecursionLimit" => ai_recursion_limit(content, rel_path),
        "noHardcodedSecrets" => no_hardcoded_secrets(content),
        "noInjectionSinks" => plain(scan_lines_all(content, &INJECTION_SINK_REGEXES)),
        "noInsecureDeserialization" => no_insecure_deserialization(content),
        "noPlaintextHttpEgress" => no_plaintext_http_egress(content),
        "noSqlInjection" => plain(scan_lines_all(content, &SQL_INJECTION_REGEXES)),
        "noXssSinks" => plain(scan_lines_all(content, &XSS_SINK_REGEXES)),
        "noWeakCrypto" => no_weak_crypto(content),
        "noSsrfSinks" => plain(scan_lines_all(content, &SSRF_SINK_REGEXES)),
        "noCsrfDisabled" => plain(scan_lines_all(content, &CSRF_DISABLED_REGEXES)),
        "noUnpinnedGhaAction" => no_unpinned_gha_action(content, rel_path),
        "noCommittedEnvFiles" => no_committed_env_files(rel_path),
        _ => return None,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    pub guideline_id: &'static str,
    pub category: &'static str,
    pub severity: crate::catalog::Severity,
    pub title: &'static str,
    pub file: String,
    pub line: usize,
    pub snippet: String,
}

/// Check a single in-memory file (code snippet or full file) against every
/// automated guideline that applies to its extension.
pub fn check_content(content: &str, rel_path: &str) -> Vec<Violation> {
    let ext = Path::new(rel_path).extension().map(|e| format!(".{}", e.to_string_lossy().to_lowercase())).unwrap_or_default();
    let mut violations = Vec::new();

    for g in guidelines() {
        let Some(check_id) = g.check_id else { continue };
        if !g.applies_to.contains(&"*") && !g.applies_to.contains(&ext.as_str()) {
            continue;
        }
        let Some(hits) = run_check(check_id, content, rel_path) else { continue };
        for hit in hits {
            violations.push(Violation { guideline_id: g.id, category: g.category, severity: g.severity, title: g.title, file: rel_path.to_string(), line: hit.line, snippet: hit.snippet });
        }
    }
    violations
}

fn walk_files(root: &Path, out: &mut Vec<std::path::PathBuf>) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(root)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let full = entry.path();
        if file_type.is_dir() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if SKIP_DIRS.contains(name.as_str()) {
                continue;
            }
            walk_files(&full, out)?;
        } else if file_type.is_file() {
            out.push(full);
        }
    }
    Ok(())
}

pub struct ProjectCheckResult {
    pub violations: Vec<Violation>,
    pub scanned: usize,
}

/// Walk a project directory and apply every automated guideline.
pub fn check_project(root: &Path) -> std::io::Result<ProjectCheckResult> {
    let mut files = Vec::new();
    walk_files(root, &mut files)?;

    let mut violations = Vec::new();
    let mut scanned = 0;
    let env_files_guideline = guidelines().iter().find(|g| g.check_id == Some("noCommittedEnvFiles")).expect("noCommittedEnvFiles guideline exists");

    for file in &files {
        let rel_path = file.strip_prefix(root).unwrap_or(file).to_string_lossy().into_owned();
        let ext = file.extension().map(|e| format!(".{}", e.to_string_lossy().to_lowercase())).unwrap_or_default();

        for hit in no_committed_env_files(&rel_path) {
            violations.push(Violation {
                guideline_id: env_files_guideline.id,
                category: env_files_guideline.category,
                severity: env_files_guideline.severity,
                title: env_files_guideline.title,
                file: rel_path.clone(),
                line: hit.line,
                snippet: hit.snippet,
            });
        }

        if BINARY_EXTENSIONS.contains(ext.as_str()) {
            continue;
        }
        let Ok(metadata) = std::fs::metadata(file) else { continue };
        if metadata.len() > MAX_SCAN_FILE_BYTES {
            continue;
        }
        let Ok(buffer) = std::fs::read(file) else { continue };
        if looks_binary(&buffer) {
            continue;
        }

        scanned += 1;
        let content = String::from_utf8_lossy(&buffer);
        for v in check_content(&content, &rel_path) {
            if v.guideline_id == "no-committed-env-files" {
                continue; // already handled above
            }
            violations.push(v);
        }
    }

    Ok(ProjectCheckResult { violations, scanned })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn ai_recursion_limit_flags_ungoverned_langchain_invoke() {
        let content = "import langchain\nchain.invoke(x)\n";
        let hits = run_check("aiRecursionLimit", content, "app.py").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, 2);
    }

    #[test]
    fn ai_recursion_limit_ignores_generic_client_receiver() {
        let content = "import langchain\nclient.stream('POST', url)\n";
        let hits = run_check("aiRecursionLimit", content, "app.py").unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn ai_recursion_limit_ignores_files_without_framework_hint() {
        let content = "client.invoke(x)\n";
        let hits = run_check("aiRecursionLimit", content, "app.py").unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn ai_recursion_limit_ignores_governed_calls() {
        let content = "import langchain\nchain.invoke(x, {'recursion_limit': 10})\n";
        let hits = run_check("aiRecursionLimit", content, "app.py").unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn ai_recursion_limit_ignores_test_files() {
        let content = "import langchain\nchain.invoke(x)\n";
        let hits = run_check("aiRecursionLimit", content, "tests/test_chain.py").unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn no_hardcoded_secrets_flags_and_extracts_kind() {
        let content = "api_key = \"sk-abcdefghijklmnop\"\n";
        let hits = run_check("noHardcodedSecrets", content, "app.py").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind.as_deref(), Some("api_key"));
    }

    #[test]
    fn no_weak_crypto_flags_md5_but_respects_usedforsecurity_false() {
        let insecure = "h = hashlib.md5(data).hexdigest()\n";
        assert_eq!(run_check("noWeakCrypto", insecure, "app.py").unwrap().len(), 1);

        let etag = "h = hashlib.md5(data, usedforsecurity=False).hexdigest()\n";
        assert_eq!(run_check("noWeakCrypto", etag, "app.py").unwrap().len(), 0);
    }

    #[test]
    fn no_weak_crypto_flags_js_createhash_sha1() {
        let content = "crypto.createHash('sha1').update(x)\n";
        assert_eq!(run_check("noWeakCrypto", content, "app.js").unwrap().len(), 1);
    }

    #[test]
    fn no_unpinned_gha_action_only_applies_to_workflow_files() {
        let content = "    uses: someorg/foo@main\n";
        assert!(run_check("noUnpinnedGhaAction", content, "random.yaml").unwrap().is_empty());
        let hits = run_check("noUnpinnedGhaAction", content, ".github/workflows/ci.yml").unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn no_unpinned_gha_action_ignores_sha_pinned_and_actions_namespace() {
        let sha_pinned = "    uses: owner/action@1234567890abcdef1234567890abcdef12345678\n";
        assert!(run_check("noUnpinnedGhaAction", sha_pinned, ".github/workflows/ci.yml").unwrap().is_empty());
    }

    #[test]
    fn no_committed_env_files_flags_dotenv_variants() {
        assert_eq!(run_check("noCommittedEnvFiles", "", ".env").unwrap().len(), 1);
        assert_eq!(run_check("noCommittedEnvFiles", "", ".env.production").unwrap().len(), 1);
        assert_eq!(run_check("noCommittedEnvFiles", "", ".env.example").unwrap().len(), 1);
        assert!(run_check("noCommittedEnvFiles", "", "config.env.js").unwrap().is_empty());
    }

    #[test]
    fn no_sql_injection_flags_fstring_and_concatenation() {
        let fstring = "q = f\"SELECT * FROM users WHERE id={user_id}\"\n";
        assert!(!run_check("noSqlInjection", fstring, "app.py").unwrap().is_empty());
        let concat = "q = \"SELECT * FROM users WHERE id=\" + user_id\n";
        assert!(!run_check("noSqlInjection", concat, "app.py").unwrap().is_empty());
    }

    #[test]
    fn no_plaintext_http_egress_allows_loopback_flags_remote() {
        assert!(run_check("noPlaintextHttpEgress", "url = 'http://localhost:3000/x'\n", "app.js").unwrap().is_empty());
        assert!(!run_check("noPlaintextHttpEgress", "url = 'http://example.com/x'\n", "app.js").unwrap().is_empty());
    }

    #[test]
    fn no_plaintext_http_egress_prefix_quirk_matches_live_js() {
        // Confirmed against the live JS checks.js: its negative lookahead is
        // a bare string-prefix check, not hostname-boundary aware, so this
        // deceptive host is silently excluded in both ports.
        assert!(run_check("noPlaintextHttpEgress", "url = 'http://localhost.evil.com/x'\n", "app.js").unwrap().is_empty());
        assert!(run_check("noPlaintextHttpEgress", "url = 'http://127.0.0.19.evil.com/x'\n", "app.js").unwrap().is_empty());
    }

    #[test]
    fn check_content_filters_by_extension() {
        let content = "uses: owner/action@main\n";
        // A GHA-only guideline shouldn't fire for a .py file at all.
        let violations = check_content(content, "app.py");
        assert!(!violations.iter().any(|v| v.guideline_id == "no-unpinned-gha-action"));
    }

    #[test]
    fn check_project_walks_directory_and_flags_env_file_and_secret() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join(".env"), "SECRET=x\n").unwrap();
        fs::write(root.join("app.py"), "api_key = \"sk-abcdefghijklmnop\"\n").unwrap();
        fs::create_dir_all(root.join("node_modules")).unwrap();
        fs::write(root.join("node_modules/skip.py"), "api_key = \"sk-abcdefghijklmnop\"\n").unwrap();

        let result = check_project(root).unwrap();
        assert!(result.violations.iter().any(|v| v.guideline_id == "no-committed-env-files"));
        assert!(result.violations.iter().any(|v| v.guideline_id == "no-hardcoded-secrets" && v.file == "app.py"));
        assert!(!result.violations.iter().any(|v| v.file.contains("node_modules")));
        // .env is content-readable (not binary, under size limit) so it's
        // still counted in `scanned` — only its *violation* is deduped
        // against the filename-only pass above, not the scan itself.
        assert_eq!(result.scanned, 2);
    }
}
