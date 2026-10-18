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

// `yaml.load(` not paired with a safe `Loader=` argument anywhere within
// its own (possibly multi-line) call — the `regex` crate has no lookahead
// support, so this pair is checked as a separate post-match exclusion over
// the whole balanced call span (see no_insecure_deserialization) rather
// than folded into one regex like the JS original's negative lookahead.
static YAML_LOAD_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"yaml\.load\(").unwrap());
// Matches `Loader=yaml.SafeLoader` as well as the C-accelerated
// `CSafeLoader`/`CBaseLoader` variants and an unqualified `SafeLoader`/
// `BaseLoader` reached via `from yaml import SafeLoader` — all of these
// are real, safe PyYAML loaders, not just the one exact spelling.
static YAML_SAFE_LOADER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"Loader\s*=\s*(?:yaml\.)?C?(?:Safe|Base)Loader\b").unwrap());
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

// Any `uses:` reference; whether it's pinned is decided in
// no_unpinned_gha_action (only a full 40-hex commit SHA, or a docker://
// image with an @sha256: digest, counts as pinned; `./` local actions are
// exempt).
static GHA_USES_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r##"^\s*(?:-\s+)?uses:\s*['"]?([^\s'"#]+)"##).unwrap());
static GHA_FULL_SHA_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9a-f]{40}$").unwrap());
// Attacker-controllable context (GitHub's "untrusted input" list): titles,
// bodies, commit messages/authors, branch names.
static GHA_UNTRUSTED_EXPR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        r"\$\{\{[^}]*\bgithub\.(?:head_ref\b|event\.(?:",
        r"issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))",
        r"|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)",
        r"|pages\b[^}]*\.page_name|commits\b[^}]*\.(?:message|author\.(?:email|name))",
        r"|head_commit\.(?:message|author\.(?:email|name))",
        r"|workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.(?:email|name)))))"
    ))
    .unwrap()
});
// `run:` (shell step) or `script:` (actions/github-script) key; group 1 is
// the key's indent, group 2 the inline value (empty or a `|`/`>` block marker).
static GHA_SCRIPT_KEY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(\s*)(?:-\s+)?(?:run|script):\s*(.*)$").unwrap());
static GHA_PR_TARGET_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^\s*(?:-\s*)?(?:on:\s*\[?.*\b)?(pull_request_target|workflow_run)\b").unwrap());
static GHA_HEAD_CHECKOUT_REF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(?:ref|repository):\s*['\x22]?\$\{\{\s*github\.(?:head_ref|event\.pull_request\.head\.(?:sha|ref|repo\.full_name)|event\.workflow_run\.head_(?:sha|branch))").unwrap()
});
static GHA_WRITE_ALL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^\s*permissions:\s*['"]?write-all\b"#).unwrap());

static COMPOSE_FILE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(^|/)(docker-)?compose(\.[\w.-]+)?\.ya?ml$").unwrap());
static COMPOSE_USER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r##"^\s*user:\s*['"]?([^'"\s#]+)"##).unwrap());
// Official images whose entrypoint drops from root to a dedicated user
// itself (gosu/su-exec), so no `user:` is needed — and setting one can break them.
static COMPOSE_SELF_DROPPING_IMAGE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^\s*image:\s*['"]?(?:docker\.io/)?(?:library/)?(?:postgres|mysql|mariadb|redis|valkey|mongo|rabbitmq|elasticsearch|opensearchproject/opensearch|memcached|cassandra|couchdb|zookeeper)(?:[:@]|['"]?\s*$)"#).unwrap()
});
static COMPOSE_PRIVILEGED_REGEXES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"^\s*privileged:\s*['"]?true\b"#).unwrap(),
        Regex::new(r"/var/run/docker\.sock").unwrap(),
        Regex::new(r#"^\s*(?:network_mode|pid|ipc|userns_mode):\s*['"]?host\b"#).unwrap(),
    ]
});
static YAML_LIST_KEY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*([\w-]+):\s*(\[.*\])?\s*(?:#.*)?$").unwrap());
static DANGEROUS_CAP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)['"]?\b(ALL|SYS_ADMIN|CAP_SYS_ADMIN)\b['"]?"#).unwrap());

// Importing a stdlib/lxml XML *parser* module. saxutils/handler are helpers
// defusedxml.sax itself still needs, so they're not flagged.
static PY_UNSAFE_XML_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(?:import\s+(?:xml\.etree(?:\.c?ElementTree)?|xml\.dom(?:\.(?:minidom|pulldom|expatbuilder))?|xml\.sax(?:\.expatreader)?|lxml(?:\.etree)?)\b|from\s+(?:xml\.etree(?:\.c?ElementTree)?|xml\.dom(?:\.(?:minidom|pulldom|expatbuilder))?|xml\.sax|lxml(?:\.etree)?)\s+import\b)").unwrap()
});
static PY_XML_SAFE_HELPER_IMPORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*from\s+xml\.sax\s+import\s+(?:saxutils|handler)(?:\s*,\s*(?:saxutils|handler))*\s*$").unwrap());
static PY_XML_PARSE_CALL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:parse|parseString|fromstring|fromstringlist|XML|XMLID|iterparse|XMLParser|XMLPullParser|make_parser)\s*\(").unwrap());
static LXML_SAFE_PARSER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"resolve_entities\s*=\s*False").unwrap());
static JS_XML_NOENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bnoent\s*:\s*true\b").unwrap());

static TLS_VERIFY_DISABLED_REGEXES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"\bverify\s*=\s*False\b").unwrap(),
        Regex::new(r"\bssl\._create_unverified_context\b").unwrap(),
        Regex::new(r"\bcheck_hostname\s*=\s*False\b").unwrap(),
        Regex::new(r"\bverify_mode\s*=\s*(?:ssl\.)?CERT_NONE\b|cert_reqs\s*=\s*(?:ssl\.)?CERT_NONE\b").unwrap(),
        Regex::new(r"\brejectUnauthorized\s*:\s*false\b").unwrap(),
        Regex::new(r#"NODE_TLS_REJECT_UNAUTHORIZED['"]?\]?\s*=\s*['"]?0"#).unwrap(),
        Regex::new(r"\bInsecureSkipVerify\s*:\s*true\b").unwrap(),
        // Ansible `uri`/`get_url`/... modules (Checkov CKV_ANSIBLE_1).
        Regex::new(r#"^\s*validate_certs:\s*['"]?(?:false|no|False|No)\b"#).unwrap(),
        // Shell: curl -k / --insecure, wget --no-check-certificate, pip --trusted-host.
        Regex::new(r"\bcurl\b[^\n|;&]*\s(?:-k|--insecure)\b|\bwget\b[^\n|;&]*--no-check-certificate|\bpip3?\b[^\n|;&]*--trusted-host\b").unwrap(),
    ]
});
static JWT_HINT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bjwt\b|jsonwebtoken|\bjose\b").unwrap());
static JWT_VERIFY_DISABLED_REGEXES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"['"]verify_signature['"]\s*:\s*False\b"#).unwrap(),
        Regex::new(r"\bjwt\.decode\([^)]*\bverify\s*=\s*False").unwrap(),
        Regex::new(r#"(?i)\balgorithms\s*[=:]\s*\[[^\]]*['"]none['"]"#).unwrap(),
        Regex::new(r"\bignoreExpiration\s*:\s*true\b").unwrap(),
    ]
});
static FLASK_DEBUG_RUN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.run\([^)]*\bdebug\s*=\s*True\b").unwrap());
static DJANGO_DEBUG_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^DEBUG\s*=\s*True\b").unwrap());
static DJANGO_SETTINGS_PATH_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?:^|/)settings(?:/[^/]+)?\.py$|(?:^|/)settings\.py$").unwrap());
static PERMISSIVE_CORS_REGEXES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"(?i)Access-Control-Allow-Origin['"]?\s*[,:=]\s*['"]\*['"]"#).unwrap(),
        Regex::new(r"\bCORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True\b").unwrap(),
        Regex::new(r#"\ballow_origins\s*=\s*\[\s*['"]\*['"]\s*\]"#).unwrap(),
        Regex::new(r#"\borigins?\s*[:=]\s*['"]\*['"]"#).unwrap(),
        Regex::new(r"\bcors\(\s*\)").unwrap(),
    ]
});
static GHA_WORKFLOW_PATH_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$").unwrap());

static DOCKERFILE_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(^|/)(dockerfile(\.[\w.-]+)?|[\w.-]+\.dockerfile)$").unwrap());
// Captures the image ref and, when present, the stage name from `AS <name>`
// (multi-stage builds reference an earlier stage by name in a later `FROM`,
// which isn't a real image and shouldn't be checked for a tag).
static DOCKER_FROM_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$").unwrap());
static DOCKER_USER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*USER\s+(\S+)\s*$").unwrap());
static DOCKER_PIPE_TO_SHELL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:/bin/|/usr/bin/(?:env\s+)?)?(?:ba|z|da)?sh\b").unwrap());
static DOCKER_ADD_REMOTE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*ADD\s+(?:--[\w-]+(?:=\S+)?\s+)*https?://").unwrap());
static DOCKER_ADD_CHECKSUM_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)--checksum=").unwrap());
static DOCKER_SECRET_ARG_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^\s*(?:ARG|ENV)\s+([A-Za-z0-9_]*(?:password|secret|api_key|apikey|token|private_key)[A-Za-z0-9_]*)\s*[= ]").unwrap());

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
    let mut hits = Vec::new();
    for cap in AI_INVOKE_REGEX.captures_iter(content) {
        let whole = cap.get(0).unwrap();
        let receiver = cap.get(1).map(|g| g.as_str()).unwrap_or("");
        let last_segment = receiver.rsplit('.').next().unwrap_or(receiver);
        if GENERIC_CLIENT_RECEIVER_RE.is_match(last_segment) {
            continue;
        }
        // Only this specific call's own (possibly multi-line) argument
        // list is checked for `recursion_limit` — a whole-file substring
        // search previously let an unrelated comment, or a *different*
        // `.invoke()` call elsewhere in the same file, silently suppress
        // every ungoverned call in that file rather than just the one
        // that actually sets it.
        let call_args = extract_balanced_paren_span(&content[whole.end()..]);
        if call_args.contains("recursion_limit") {
            continue;
        }
        let line = content[..whole.start()].matches('\n').count() + 1;
        let line_text = content[whole.start()..].lines().next().unwrap_or("");
        hits.push(CheckHit { line, snippet: line_text.trim().chars().take(160).collect(), kind: None });
    }
    hits
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
        for re in [&WEAK_CRYPTO_REGEXES[0], &WEAK_CRYPTO_REGEXES[2], &WEAK_CRYPTO_REGEXES[3], &WEAK_CRYPTO_REGEXES[4]] {
            if re.is_match(line) {
                hits.push(CheckHit { line: i + 1, snippet: line.trim().chars().take(160).collect(), kind: None });
            }
        }
    }
    hits
}

fn no_insecure_deserialization(content: &str) -> Vec<CheckHit> {
    let mut hits: Vec<CheckHit> = plain(scan_lines_all(content, &INSECURE_DESERIALIZATION_REGEXES));
    for m in YAML_LOAD_RE.find_iter(content) {
        // The `Loader=` argument commonly sits on its own line in a
        // formatted multi-line call:
        //   yaml.load(
        //       f,
        //       Loader=yaml.SafeLoader,
        //   )
        // so the safe-loader check needs the whole balanced call span, not
        // just the line `yaml.load(` itself matched on.
        let call_args = extract_balanced_paren_span(&content[m.end()..]);
        if !YAML_SAFE_LOADER_RE.is_match(call_args) {
            let line = content[..m.start()].matches('\n').count() + 1;
            let line_text = content[m.start()..].lines().next().unwrap_or("");
            hits.push(CheckHit { line, snippet: line_text.trim().chars().take(160).collect(), kind: None });
        }
    }
    hits
}

/// Given the text right after a call's opening `(` (already consumed),
/// returns the slice up to its matching closing `)` — tracking nested
/// parens so an argument that itself contains a call
/// (`yaml.load(f, Loader=get_loader())`) doesn't truncate the scan at the
/// first `)` it reaches.
fn extract_balanced_paren_span(rest: &str) -> &str {
    let bytes = rest.as_bytes();
    let mut depth = 1i32;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return &rest[..i];
                }
            }
            _ => {}
        }
    }
    rest
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

fn is_gha_workflow(rel_path: &str) -> bool {
    GHA_WORKFLOW_PATH_RE.is_match(&rel_path.replace('\\', "/"))
}

fn snippet_of(line: &str) -> String {
    line.trim().chars().take(160).collect()
}

/// Lines of `content` with any trailing `\r` stripped, numbered from 1.
fn numbered_lines(content: &str) -> impl Iterator<Item = (usize, &str)> {
    content.split('\n').enumerate().map(|(i, l)| (i + 1, l.strip_suffix('\r').unwrap_or(l)))
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn is_blank_or_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.is_empty() || t.starts_with('#')
}

/// One hit per line where any of `regexes` matches (no duplicates when
/// several patterns hit the same line).
fn scan_lines_any(content: &str, regexes: &[Regex]) -> Vec<CheckHit> {
    numbered_lines(content).filter(|(_, l)| regexes.iter().any(|re| re.is_match(l))).map(|(n, l)| CheckHit { line: n, snippet: snippet_of(l), kind: None }).collect()
}

fn skip_tests(rel_path: &str, check: impl FnOnce() -> Vec<CheckHit>) -> Vec<CheckHit> {
    if is_test_path(rel_path) {
        vec![]
    } else {
        check()
    }
}

fn is_test_path(rel_path: &str) -> bool {
    let normalized = rel_path.replace('\\', "/");
    TEST_FILE_REGEX.is_match(&normalized) || normalized.ends_with("_test.go")
}

/// Documentation files: they quote insecure snippets to explain them.
fn is_prose(rel_path: &str) -> bool {
    let lower = rel_path.to_lowercase();
    [".md", ".mdx", ".rst", ".txt", ".adoc", ".html"].iter().any(|e| lower.ends_with(e))
}

fn no_unpinned_gha_action(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_gha_workflow(rel_path) {
        return vec![];
    }
    let mut hits = Vec::new();
    for (n, line) in numbered_lines(content) {
        let Some(m) = GHA_USES_RE.captures(line) else { continue };
        let reference = &m[1];
        if reference.starts_with("./") {
            continue;
        }
        let pinned = match reference.strip_prefix("docker://") {
            Some(image) => image.contains("@sha256:"),
            None => reference.rsplit_once('@').is_some_and(|(_, r)| GHA_FULL_SHA_RE.is_match(r)),
        };
        if !pinned {
            hits.push(CheckHit { line: n, snippet: snippet_of(line), kind: None });
        }
    }
    hits
}

/// Flags untrusted `${{ }}` expressions inside a `run:`/`script:` value,
/// inline or in its `|`/`>` block (every following line indented deeper
/// than the key). An expression in `env:`/`with:` (other than `script:`)
/// is the recommended fix and isn't flagged.
fn gha_script_injection(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_gha_workflow(rel_path) {
        return vec![];
    }
    let mut hits = Vec::new();
    let mut block_indent: Option<usize> = None;
    for (n, line) in numbered_lines(content) {
        if let Some(key_indent) = block_indent {
            if is_blank_or_comment(line) || indent_of(line) > key_indent {
                if GHA_UNTRUSTED_EXPR_RE.is_match(line) {
                    hits.push(CheckHit { line: n, snippet: snippet_of(line), kind: None });
                }
                continue;
            }
            block_indent = None;
        }
        if let Some(caps) = GHA_SCRIPT_KEY_RE.captures(line) {
            let value = caps[2].trim();
            if value.is_empty() || value.starts_with('|') || value.starts_with('>') {
                block_indent = Some(caps[1].len());
            } else if GHA_UNTRUSTED_EXPR_RE.is_match(value) {
                hits.push(CheckHit { line: n, snippet: snippet_of(line), kind: None });
            }
        }
    }
    hits
}

fn gha_pwn_request(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_gha_workflow(rel_path) || !GHA_PR_TARGET_RE.is_match(content) {
        return vec![];
    }
    numbered_lines(content).filter(|(_, l)| GHA_HEAD_CHECKOUT_REF_RE.is_match(l)).map(|(n, l)| CheckHit { line: n, snippet: snippet_of(l), kind: None }).collect()
}

fn gha_write_all_permissions(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_gha_workflow(rel_path) {
        return vec![];
    }
    scan_lines_any(content, std::slice::from_ref(&GHA_WRITE_ALL_RE))
}

fn is_compose_file(rel_path: &str) -> bool {
    COMPOSE_FILE_RE.is_match(&rel_path.replace('\\', "/"))
}

/// `(service name, line of its key, body lines)` for every service under
/// the top-level `services:` key, found by indentation (no YAML parser —
/// line numbers matter more here than full YAML fidelity).
type ComposeService<'a> = (String, usize, Vec<(usize, &'a str)>);

fn compose_services(content: &str) -> Vec<ComposeService<'_>> {
    let mut services = Vec::new();
    let mut in_services = false;
    let mut service_indent: Option<usize> = None;
    for (n, line) in numbered_lines(content) {
        if is_blank_or_comment(line) {
            continue;
        }
        let indent = indent_of(line);
        if indent == 0 {
            in_services = line.split('#').next().unwrap_or("").trim() == "services:";
            service_indent = None;
            continue;
        }
        if !in_services {
            continue;
        }
        let si = *service_indent.get_or_insert(indent);
        if indent == si {
            let name = line.trim().trim_end_matches(':').trim_matches(|c| c == '"' || c == '\'').to_string();
            services.push((name, n, Vec::new()));
        } else if indent > si {
            if let Some((_, _, body)) = services.last_mut() {
                body.push((n, line));
            }
        }
    }
    services
}

fn compose_runs_as_root(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_compose_file(rel_path) {
        return vec![];
    }
    let mut hits = Vec::new();
    for (name, service_line, body) in compose_services(content) {
        if body.iter().any(|(_, l)| COMPOSE_SELF_DROPPING_IMAGE_RE.is_match(l)) {
            continue;
        }
        match body.iter().find_map(|(n, l)| COMPOSE_USER_RE.captures(l).map(|c| (*n, *l, c[1].to_string()))) {
            None => hits.push(CheckHit { line: service_line, snippet: format!("service '{name}' sets no user: — runs as the image default (root for most images)"), kind: Some(name) }),
            Some((n, l, user)) => {
                let uid = user.split(':').next().unwrap_or("");
                if uid == "root" || uid == "0" {
                    hits.push(CheckHit { line: n, snippet: snippet_of(l), kind: Some(name) });
                }
            }
        }
    }
    hits
}

fn compose_privileged_container(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_compose_file(rel_path) {
        return vec![];
    }
    let mut hits = scan_lines_any(content, &COMPOSE_PRIVILEGED_REGEXES);
    // cap_add entries: `cap_add: [ALL]` inline, or `- SYS_ADMIN` list items
    // under it. `cap_drop: [ALL]` is the recommended pattern, so the list
    // owner has to be tracked rather than flagging every `- ALL`.
    let mut list_key: Option<(usize, String)> = None;
    for (n, line) in numbered_lines(content) {
        if is_blank_or_comment(line) {
            continue;
        }
        let indent = indent_of(line);
        let trimmed = line.trim_start();
        if trimmed.starts_with('-') {
            if let Some((key_indent, key)) = &list_key {
                if indent >= *key_indent && key == "cap_add" && DANGEROUS_CAP_RE.is_match(trimmed) {
                    hits.push(CheckHit { line: n, snippet: snippet_of(line), kind: None });
                }
            }
            continue;
        }
        list_key = None;
        if let Some(caps) = YAML_LIST_KEY_RE.captures(line) {
            let key = caps[1].to_string();
            match caps.get(2) {
                Some(inline) if key == "cap_add" && DANGEROUS_CAP_RE.is_match(inline.as_str()) => hits.push(CheckHit { line: n, snippet: snippet_of(line), kind: None }),
                Some(_) => {}
                None => list_key = Some((indent, key)),
            }
        }
    }
    hits.sort_by_key(|h| h.line);
    hits.dedup_by_key(|h| h.line);
    hits
}

/// Python: reported at each unsafe parser *import*, and only when the file
/// actually calls a parse function — a module that only builds/serializes
/// XML with ElementTree isn't parsing untrusted input. JS: `noent: true`.
fn no_unsafe_xml_parsing(content: &str, rel_path: &str) -> Vec<CheckHit> {
    let is_python = rel_path.is_empty() || rel_path.to_lowercase().ends_with(".py");
    let mut hits = Vec::new();
    if is_python && PY_XML_PARSE_CALL_RE.is_match(content) {
        let lxml_hardened = LXML_SAFE_PARSER_RE.is_match(content);
        for (n, line) in numbered_lines(content) {
            if !PY_UNSAFE_XML_IMPORT_RE.is_match(line) || PY_XML_SAFE_HELPER_IMPORT_RE.is_match(line) {
                continue;
            }
            if lxml_hardened && line.contains("lxml") {
                continue;
            }
            hits.push(CheckHit { line: n, snippet: snippet_of(line), kind: None });
        }
    }
    hits.extend(scan_lines_any(content, std::slice::from_ref(&JS_XML_NOENT_RE)));
    hits
}

fn no_tls_verification_disabled(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if is_test_path(rel_path) || is_prose(rel_path) {
        return vec![];
    }
    // `jwt.decode(..., verify=False)` is the JWT guideline's, not a TLS setting.
    scan_lines_any(content, &TLS_VERIFY_DISABLED_REGEXES).into_iter().filter(|h| !h.snippet.contains("jwt.")).collect()
}

fn no_jwt_verification_disabled(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if is_test_path(rel_path) || !JWT_HINT_RE.is_match(content) {
        return vec![];
    }
    scan_lines_any(content, &JWT_VERIFY_DISABLED_REGEXES)
}

fn no_debug_mode_enabled(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if is_test_path(rel_path) {
        return vec![];
    }
    let is_settings = DJANGO_SETTINGS_PATH_RE.is_match(&rel_path.replace('\\', "/"));
    numbered_lines(content)
        .filter(|(_, l)| FLASK_DEBUG_RUN_RE.is_match(l) || (is_settings && DJANGO_DEBUG_RE.is_match(l)))
        .map(|(n, l)| CheckHit { line: n, snippet: snippet_of(l), kind: None })
        .collect()
}

fn no_permissive_cors(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if is_test_path(rel_path) {
        return vec![];
    }
    scan_lines_any(content, &PERMISSIVE_CORS_REGEXES)
}

fn docker_remote_script_execution(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_dockerfile(rel_path) {
        return vec![];
    }
    numbered_lines(content)
        .filter(|(_, l)| DOCKER_PIPE_TO_SHELL_RE.is_match(l) || (DOCKER_ADD_REMOTE_RE.is_match(l) && !DOCKER_ADD_CHECKSUM_RE.is_match(l)))
        .map(|(n, l)| CheckHit { line: n, snippet: snippet_of(l), kind: None })
        .collect()
}

/// Template files a project is explicitly instructed to commit as this
/// guideline's own remediation ("commit a .env.example with placeholder
/// keys only") — never real secret-bearing env files themselves, so
/// following the guideline's advice must never trip the guideline it's
/// advice for.
const ENV_TEMPLATE_SUFFIXES: [&str; 3] = [".env.example", ".env.sample", ".env.template"];

fn no_committed_env_files(rel_path: &str) -> Vec<CheckHit> {
    let base = Path::new(rel_path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if ENV_TEMPLATE_SUFFIXES.iter().any(|s| base == *s) {
        return vec![];
    }
    if base == ".env" || base.starts_with(".env.") {
        vec![CheckHit { line: 0, snippet: rel_path.to_string(), kind: None }]
    } else {
        vec![]
    }
}

fn is_dockerfile(rel_path: &str) -> bool {
    DOCKERFILE_NAME_RE.is_match(&rel_path.replace('\\', "/"))
}

/// Flags a `FROM` with no tag (implicit `:latest`) or an explicit `:latest`
/// tag. Splits the image ref on its *last* colon to find a tag, so a
/// `registry.example.com:5000/image` with no real tag still correctly reads
/// as unpinned (the split lands on the port, `contains('/')` rejects it,
/// same as "no tag" would) — a deliberate side effect of the simplification,
/// not a bug. A `name@sha256:<digest>` ref is treated as pinned (the digest
/// itself becomes the "tag" half), which is the strongest form of pinning.
fn docker_unpinned_base_image(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_dockerfile(rel_path) {
        return vec![];
    }
    let mut stage_names: HashSet<String> = HashSet::new();
    let mut hits = Vec::new();
    for (i, line) in content.split('\n').enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let Some(caps) = DOCKER_FROM_RE.captures(line) else { continue };
        let image_ref = caps.get(1).map(|g| g.as_str()).unwrap_or("");
        let is_prior_stage = stage_names.contains(&image_ref.to_lowercase());
        if let Some(stage) = caps.get(2) {
            stage_names.insert(stage.as_str().to_lowercase());
        }
        if is_prior_stage {
            continue; // `FROM builder AS test` — references an earlier stage, not a real image
        }
        let tag = image_ref.rsplit_once(':').map(|(_, t)| t).filter(|t| !t.contains('/'));
        let unpinned = match tag {
            None => true,
            Some(t) => t.eq_ignore_ascii_case("latest"),
        };
        if unpinned {
            hits.push(CheckHit { line: i + 1, snippet: line.trim().chars().take(160).collect(), kind: None });
        }
    }
    hits
}

/// File-level: flags a Dockerfile with no `USER` instruction at all, or
/// whose last `USER` instruction is `root`/`0` — mirrors `USER` semantics
/// (later instructions override earlier ones, including across stages).
/// Reports at line 0 when there's no `USER` line to point at, same
/// file-level-finding convention `no_committed_env_files` uses.
fn docker_runs_as_root(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_dockerfile(rel_path) {
        return vec![];
    }
    let mut last: Option<(usize, String)> = None;
    for (i, line) in content.split('\n').enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(caps) = DOCKER_USER_RE.captures(line) {
            last = Some((i + 1, caps[1].to_string()));
        }
    }
    match last {
        None => vec![CheckHit { line: 0, snippet: "no USER instruction — container runs as root by default".to_string(), kind: None }],
        Some((line, user)) if user == "root" || user == "0" => vec![CheckHit { line, snippet: format!("USER {user}"), kind: None }],
        Some(_) => vec![],
    }
}

fn docker_secret_build_arg(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_dockerfile(rel_path) {
        return vec![];
    }
    let mut hits = Vec::new();
    for (i, line) in content.split('\n').enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(caps) = DOCKER_SECRET_ARG_RE.captures(line) {
            hits.push(CheckHit { line: i + 1, snippet: line.trim().chars().take(160).collect(), kind: Some(caps[1].to_lowercase()) });
        }
    }
    hits
}

// ---- Checks added from the most frequent findings across real scans ----

static PRIVATE_KEY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----").unwrap());

static PEM_BODY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9+/]{40,}={0,2}").unwrap());

// A URL whose authority carries "user:password" before the host — group 1 is
// the password, group 2 the host.
static URL_CREDENTIAL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@'"`]+:([^\s@/'"`]+)@([^\s:/'"`?#]+)"#).unwrap());
const URL_PASSWORD_PLACEHOLDERS: &[&str] = &["password", "pass", "passwd", "pwd", "secret", "changeme", "change-me", "xxx", "xxxx", "****", "***", "token", "example", "user", "username", "test", "dummy", "placeholder", "your-password", "yourpassword", "mypassword"];
const LOOPBACK_HOSTS: &[&str] = &["localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal"];

static LOG_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:(?:logging|logger|log|_logger|_log|LOGGER|LOG)\.(?:debug|info|warning|warn|error|exception|critical|fatal|trace|log)|console\.(?:log|info|warn|error|debug|trace)|print|println|printf|fmt\.Print(?:ln|f)?|System\.out\.print(?:ln)?)\s*\(").unwrap()
});
static SENSITIVE_IDENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b[\w$]*?(?:password|passwd|secret|token|api_?key|apikey|credential|authorization|private_?key|access_?key)[\w$]*\b").unwrap());
// Identifiers that merely *mention* a sensitive word: LLM token counters,
// names/types/lengths/paths/expiry of a secret rather than its value.
static SENSITIVE_IDENT_EXCLUDE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)count|usage|limit|len|length|size|tokenizer|tokens_|_tokens|^tokens$|max_?tokens|num_?tokens|type|name|expir|ttl|url|path|file|field|header|endpoint|_id$|^id_|valid|missing|present|exists|has_|is_|_set$").unwrap());

static PY_PATH_SINK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:open|send_file|FileResponse|os\.path\.join|os\.remove|os\.unlink|shutil\.\w+|pathlib\.Path|Path)\(\s*[^)]*\brequest\.(?:args|form|values|files|json|GET|POST|query_params|path_params|data|get_json)").unwrap()
});
static JS_PATH_SINK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:fs(?:\.promises)?\.\w+|readFile(?:Sync)?|writeFile(?:Sync)?|createReadStream|createWriteStream|unlink(?:Sync)?|res\.sendFile|res\.download|path\.(?:join|resolve))\(\s*[^)]*\breq\.(?:params|query|body|files?)\b").unwrap()
});

static INSECURE_RANDOM_CALL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bMath\.random\(\)|\brandom\.(?:random|randint|randrange|choice|choices|getrandbits|sample)\(").unwrap());
static RANDOM_SENSITIVE_CONTEXT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)token|secret|password|passwd|nonce|salt|otp|session|csrf|reset|api_?key|verification_?code").unwrap());

static DYNAMIC_URLOPEN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\burlopen\(\s*[^'"\s)]"#).unwrap());

static SUBSTRING_URL_CHECK_REGEXES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"(?i)\b[\w$.]*(?:url|uri|host|hostname|origin|href|referr?er|domain|redirect)[\w$]*\s*\.\s*(?:includes|indexOf|contains)\(\s*['"`][\w-]+(?:\.[\w-]+)+[^'"`]*['"`]"#).unwrap(),
        Regex::new(r#"(?i)['"][\w.-]+\.[a-z]{2,}[^'"]*['"]\s+in\s+[\w.]*(?:url|uri|host|hostname|origin|href|referr?er|domain|redirect)\w*\b"#).unwrap(),
    ]
});

static HANDROLLED_SANITIZE_REGEXES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // `.replace('<', '&lt;')` with a *string* pattern replaces only the first match.
        Regex::new(r#"\.replace\(\s*['"`](?:<|>|&|"|'|\\'|\\")['"`]\s*,"#).unwrap(),
        Regex::new(r"(?i)\.replace(?:All)?\(\s*/[^/\n]*<\\?/?script").unwrap(),
    ]
});

static BROWSER_STORAGE_SECRET_REGEXES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"(?i)\b(?:localStorage|sessionStorage)\.setItem\(\s*['"`][^'"`]*(?:token|jwt|password|secret|session_?id|credential|api_?key)"#).unwrap(),
        Regex::new(r#"(?i)\b(?:localStorage|sessionStorage)(?:\.(?:\w*(?:token|jwt|password|secret|credential)\w*)|\[\s*['"`][^'"`]*(?:token|jwt|password|secret|credential)[^'"`]*['"`]\s*\])\s*="#).unwrap(),
    ]
});

static TEMPLATE_VAR_IN_HREF_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)\b(?:href|src|action|formaction)\s*=\s*["']?\s*(?:\{\{|\{%|<%=?|\$\{|#\{)"#).unwrap());

// Framework-generated URLs that can't carry a `javascript:` scheme: Hugo
// page/site fields and URL filters, Flask `url_for`, Django `{% url %}`/`{% static %}`.
static TEMPLATE_SAFE_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^-?\s*(?:\.(?:RelPermalink|Permalink|Page\.(?:RelPermalink|Permalink)|Site\.(?:BaseURL|Home)|Parent\.(?:RelPermalink|Permalink))\b|url_for\b|static\b|url\s|relref\b|ref\b|[^}]*\|\s*(?:relURL|absURL|relLangURL|absLangURL)\b)").unwrap()
});
static GHA_CHECKOUT_USES_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^\s*(?:-\s+)?uses:\s*['"]?actions/checkout@"#).unwrap());
static GHA_PERSIST_FALSE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^\s*persist-credentials:\s*['"]?false\b"#).unwrap());
static GHA_PERMISSIONS_KEY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*permissions:").unwrap());
static GHA_JOBS_KEY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^jobs:").unwrap());

static DOCKER_HEALTHCHECK_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?im)^\s*HEALTHCHECK\b").unwrap());
static DOCKER_SHELL_FORM_CMD_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*(CMD|ENTRYPOINT)\s+[^\[\s]").unwrap());
static DOCKER_RUN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*RUN\s").unwrap());
static DOCKER_PIPEFAIL_SHELL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*SHELL\s*\[.*pipefail").unwrap());
static PIPEFAIL_SET_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"set\s+-[a-z]*o\s+pipefail|set\s+-o\s+pipefail").unwrap());
// A single `|` that isn't part of `||` (and isn't inside `|&`).
static SHELL_PIPE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?:^|[^|])\|(?:[^|&]|$)").unwrap());
static DOCKER_INSTALL_SEGMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(apt-get\s+(?:-\S+\s+)*install|apt\s+install|apk\s+(?:-\S+\s+)*add|pip3?\s+install|python3?\s+-m\s+pip\s+install)\b([^;&|]*)").unwrap());

static OPENAPI_YAML_MARKER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?m)^(?:openapi:\s*['"]?3|swagger:\s*['"]?2)"#).unwrap());
static OPENAPI_JSON_MARKER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#""(?:openapi|swagger)"\s*:\s*"[23]"#).unwrap());
static OPENAPI_YAML_TOP_SECURITY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^security:").unwrap());
static OPENAPI_EMPTY_SECURITY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^security:\s*\[\s*\]|^\s{0,2}"security"\s*:\s*\[\s*\]"#).unwrap());
static OPENAPI_JSON_SECURITY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#""security"\s*:\s*\[\s*\{"#).unwrap());

static TF_RESOURCE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^\s*resource\s+"(\w+)""#).unwrap());
static TF_PUBLIC_LINE_REGEXES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"^\s*acl\s*=\s*"public-read(?:-write)?""#).unwrap(),
        Regex::new(r"^\s*publicly_accessible\s*=\s*true\b").unwrap(),
        Regex::new(r"^\s*(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b").unwrap(),
    ]
});
static TF_WORLD_CIDR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#""(?:0\.0\.0\.0/0|::/0)""#).unwrap());
static TF_INGRESS_BLOCK_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*ingress\s*\{").unwrap());
static TF_INGRESS_TYPE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^\s*type\s*=\s*"ingress""#).unwrap());
static TF_PORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*(from_port|to_port)\s*=\s*(\d+)").unwrap());
static TF_ENCRYPTION_OFF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^\s*(?:encrypted|storage_encrypted|enable_key_rotation|encryption_enabled|enabled_for_disk_encryption|at_rest_encryption_enabled|transit_encryption_enabled|kms_encryption_enabled|https_only|enable_https_traffic_only|https_traffic_only_enabled)\s*=\s*false\b|^\s*min(?:imum)?_tls_version\s*=\s*"(?:TLS1_[01]|1\.[01]|TLSv1(?:\.1)?)""#).unwrap()
});

static REQUIREMENTS_PATH_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(?:^|/)requirements[\w.-]*\.txt$").unwrap());

fn text_hits(content: &str, regex: &Regex) -> Vec<CheckHit> {
    numbered_lines(content).filter(|(_, l)| regex.is_match(l)).map(|(n, l)| CheckHit { line: n, snippet: snippet_of(l), kind: None }).collect()
}

/// Only a real key: the BEGIN marker followed by base64 key material (on
/// the next lines, after optional `Proc-Type:`-style headers, or inline after
/// an escaped `\n`). Placeholders and code assembling a PEM from a variable
/// are not keys.
fn no_committed_private_keys(content: &str) -> Vec<CheckHit> {
    let lines: Vec<(usize, &str)> = numbered_lines(content).collect();
    let mut hits = Vec::new();
    for (i, (n, line)) in lines.iter().enumerate() {
        let Some(m) = PRIVATE_KEY_RE.find(line) else { continue };
        let inline = PEM_BODY_RE.is_match(line[m.end()..].trim_start_matches("\\n"));
        let following = lines[i + 1..].iter().map(|(_, l)| l.trim().trim_matches(|c| c == '"' || c == '\'' || c == ',' || c == '+')).filter(|l| !l.is_empty() && !l.contains(':')).take(1).any(|l| PEM_BODY_RE.is_match(l));
        if inline || following {
            hits.push(CheckHit { line: *n, snippet: "private key block".to_string(), kind: None });
        }
    }
    hits
}

fn no_credentials_in_urls(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if is_test_path(rel_path) {
        return vec![];
    }
    let mut hits = Vec::new();
    for (n, line) in numbered_lines(content) {
        let flagged = URL_CREDENTIAL_RE.captures_iter(line).any(|c| {
            let password = c[1].to_lowercase();
            let host = c[2].to_lowercase();
            let placeholder = password.starts_with(['$', '{', '<', '%', '*']) || password.contains("${") || URL_PASSWORD_PLACEHOLDERS.contains(&password.as_str());
            !placeholder && !LOOPBACK_HOSTS.contains(&host.as_str())
        });
        if flagged {
            hits.push(CheckHit { line: n, snippet: snippet_of(&URL_CREDENTIAL_RE.replace_all(line, "<redacted-url>")), kind: None });
        }
    }
    hits
}

/// Returns the code of `args` with string-literal text removed but the
/// contents of `{...}`/`${...}` interpolations kept, so `"bad password"`
/// is ignored while `f"pw={password}"` / `` `t=${token}` `` still count.
fn strip_string_literals(args: &str) -> String {
    let mut out = String::new();
    let mut quote: Option<char> = None;
    let mut interp_depth = 0usize;
    let mut chars = args.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            None => {
                if c == '"' || c == '\'' || c == '`' {
                    quote = Some(c);
                } else {
                    out.push(c);
                }
            }
            Some(q) => {
                if interp_depth > 0 {
                    match c {
                        '{' => interp_depth += 1,
                        '}' => interp_depth -= 1,
                        _ => {}
                    }
                    out.push(if interp_depth == 0 { ' ' } else { c });
                } else if c == '\\' {
                    chars.next();
                } else if c == '{' {
                    interp_depth = 1;
                    out.push(' ');
                } else if c == q {
                    quote = None;
                    out.push(' ');
                }
            }
        }
    }
    out
}

fn no_sensitive_data_in_logs(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if is_test_path(rel_path) {
        return vec![];
    }
    let mut hits = Vec::new();
    for (n, line) in numbered_lines(content) {
        let Some(m) = LOG_CALL_RE.find(line) else { continue };
        let code = strip_string_literals(extract_balanced_paren_span(&line[m.end()..]));
        let leaked = SENSITIVE_IDENT_RE.find_iter(&code).find(|id| !SENSITIVE_IDENT_EXCLUDE_RE.is_match(id.as_str()));
        if let Some(id) = leaked {
            hits.push(CheckHit { line: n, snippet: snippet_of(line), kind: Some(id.as_str().to_string()) });
        }
    }
    hits
}

fn no_path_traversal_sinks(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if rel_path.is_empty() {
        return scan_lines_any(content, &[PY_PATH_SINK_RE.clone(), JS_PATH_SINK_RE.clone()]);
    }
    let regex = if rel_path.to_lowercase().ends_with(".py") { &*PY_PATH_SINK_RE } else { &*JS_PATH_SINK_RE };
    text_hits(content, regex)
}

fn no_insecure_randomness(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if is_test_path(rel_path) {
        return vec![];
    }
    numbered_lines(content)
        .filter(|(_, l)| INSECURE_RANDOM_CALL_RE.is_match(l) && RANDOM_SENSITIVE_CONTEXT_RE.is_match(l))
        .map(|(n, l)| CheckHit { line: n, snippet: snippet_of(l), kind: None })
        .collect()
}

fn no_dynamic_urllib_open(content: &str) -> Vec<CheckHit> {
    if !content.contains("urllib") {
        return vec![];
    }
    text_hits(content, &DYNAMIC_URLOPEN_RE)
}

fn no_template_var_in_href(content: &str) -> Vec<CheckHit> {
    numbered_lines(content)
        .filter(|(_, l)| TEMPLATE_VAR_IN_HREF_RE.find_iter(l).any(|m| !TEMPLATE_SAFE_URL_RE.is_match(&l[m.end()..])))
        .map(|(n, l)| CheckHit { line: n, snippet: snippet_of(l), kind: None })
        .collect()
}

/// Each `actions/checkout` step's block (until the next line at or above
/// the step's `-` indent) must contain `persist-credentials: false`.
fn gha_checkout_persist_credentials(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_gha_workflow(rel_path) {
        return vec![];
    }
    let lines: Vec<(usize, &str)> = numbered_lines(content).collect();
    let mut hits = Vec::new();
    for (idx, (n, line)) in lines.iter().enumerate() {
        if !GHA_CHECKOUT_USES_RE.is_match(line) {
            continue;
        }
        // The step's own `- ` line: this one, or the nearest one above with a smaller indent.
        let step_start = (0..=idx).rev().find(|&i| {
            let l = lines[i].1;
            l.trim_start().starts_with("- ") && (i == idx || indent_of(l) < indent_of(line))
        });
        let Some(step_start) = step_start else { continue };
        let dash_indent = indent_of(lines[step_start].1);
        let block_end = (step_start + 1..lines.len()).find(|&i| !is_blank_or_comment(lines[i].1) && indent_of(lines[i].1) <= dash_indent).unwrap_or(lines.len());
        if !lines[step_start..block_end].iter().any(|(_, l)| GHA_PERSIST_FALSE_RE.is_match(l)) {
            hits.push(CheckHit { line: *n, snippet: snippet_of(line), kind: None });
        }
    }
    hits
}

fn gha_permissions_not_declared(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_gha_workflow(rel_path) || !GHA_JOBS_KEY_RE.is_match(content) {
        return vec![];
    }
    if numbered_lines(content).any(|(_, l)| GHA_PERMISSIONS_KEY_RE.is_match(l)) {
        return vec![];
    }
    vec![CheckHit { line: 0, snippet: "no permissions: block — GITHUB_TOKEN gets the repo/org default scopes".to_string(), kind: None }]
}

fn docker_missing_healthcheck(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_dockerfile(rel_path) || DOCKER_HEALTHCHECK_RE.is_match(content) {
        return vec![];
    }
    vec![CheckHit { line: 0, snippet: "no HEALTHCHECK instruction".to_string(), kind: None }]
}

fn docker_non_numeric_user(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_dockerfile(rel_path) {
        return vec![];
    }
    let last = numbered_lines(content).filter_map(|(n, l)| DOCKER_USER_RE.captures(l).map(|c| (n, l, c[1].to_string()))).last();
    match last {
        Some((n, l, user)) => {
            let uid = user.split(':').next().unwrap_or("");
            // root is docker-runs-as-root's finding; a build-arg/env reference can't be judged.
            if uid == "root" || uid.starts_with('$') || uid.chars().all(|c| c.is_ascii_digit()) {
                vec![]
            } else {
                vec![CheckHit { line: n, snippet: snippet_of(l), kind: None }]
            }
        }
        None => vec![],
    }
}

/// Dockerfile instructions with `\`-continuations joined, each paired with
/// the line it starts on.
fn docker_logical_lines(content: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut current: Option<(usize, String)> = None;
    for (n, line) in numbered_lines(content) {
        let trimmed = line.trim_end();
        if current.is_none() && trimmed.trim_start().starts_with('#') {
            continue;
        }
        let (body, continues) = match trimmed.strip_suffix('\\') {
            Some(b) => (b, true),
            None => (trimmed, false),
        };
        match current.as_mut() {
            Some((_, text)) => {
                if !body.trim_start().starts_with('#') {
                    text.push(' ');
                    text.push_str(body.trim());
                }
            }
            None => current = Some((n, body.to_string())),
        }
        if !continues {
            if let Some(done) = current.take() {
                out.push(done);
            }
        }
    }
    out.extend(current);
    out
}

fn docker_unpinned_packages(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_dockerfile(rel_path) {
        return vec![];
    }
    let mut hits = Vec::new();
    for (n, instr) in docker_logical_lines(content) {
        if !DOCKER_RUN_RE.is_match(&instr) {
            continue;
        }
        let mut unpinned: Vec<String> = Vec::new();
        for caps in DOCKER_INSTALL_SEGMENT_RE.captures_iter(&instr) {
            let manager = &caps[1];
            let is_pip = manager.contains("pip");
            let mut skip_next = false;
            for token in caps[2].split_whitespace() {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                if token.starts_with('-') {
                    // Options that take a separate value: -r/-c files, index URLs.
                    skip_next = is_pip && matches!(token, "-r" | "--requirement" | "-c" | "--constraint" | "-i" | "--index-url" | "--extra-index-url" | "-f" | "--find-links" | "--target" | "-t");
                    continue;
                }
                if token.contains('$') || token.contains('/') || token.starts_with('.') || token.ends_with(".whl") || token.ends_with(".txt") {
                    continue;
                }
                let pinned = if is_pip { token.contains("==") || token.contains(" @ ") } else { token.contains('=') };
                if !pinned {
                    unpinned.push(token.trim_matches(|c| c == '"' || c == '\'').to_string());
                }
            }
        }
        if !unpinned.is_empty() {
            hits.push(CheckHit { line: n, snippet: format!("unpinned: {}", unpinned.join(", ")).chars().take(160).collect(), kind: None });
        }
    }
    hits
}

fn docker_exec_form_cmd(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_dockerfile(rel_path) {
        return vec![];
    }
    docker_logical_lines(content)
        .into_iter()
        .filter(|(_, instr)| DOCKER_SHELL_FORM_CMD_RE.is_match(instr))
        .map(|(n, instr)| CheckHit { line: n, snippet: instr.trim().chars().take(160).collect(), kind: None })
        .collect()
}

fn docker_pipefail(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !is_dockerfile(rel_path) {
        return vec![];
    }
    let mut pipefail_shell = false;
    let mut hits = Vec::new();
    for (n, instr) in docker_logical_lines(content) {
        if DOCKER_PIPEFAIL_SHELL_RE.is_match(&instr) {
            pipefail_shell = true;
            continue;
        }
        if instr.trim_start().to_uppercase().starts_with("FROM ") {
            pipefail_shell = false; // SHELL doesn't carry across stages
            continue;
        }
        if DOCKER_RUN_RE.is_match(&instr) && !pipefail_shell && !instr.trim_start()[3..].trim_start().starts_with('[') && SHELL_PIPE_RE.is_match(&strip_string_literals(&instr)) && !PIPEFAIL_SET_RE.is_match(&instr) {
            hits.push(CheckHit { line: n, snippet: instr.trim().chars().take(160).collect(), kind: None });
        }
    }
    hits
}

fn openapi_security_defined(content: &str, rel_path: &str) -> Vec<CheckHit> {
    let is_json = rel_path.to_lowercase().ends_with(".json");
    let is_spec = if is_json { OPENAPI_JSON_MARKER_RE.is_match(&content[..content.len().min(4096)]) } else { OPENAPI_YAML_MARKER_RE.is_match(content) };
    if !is_spec {
        return vec![];
    }
    let mut hits = text_hits(content, &OPENAPI_EMPTY_SECURITY_RE);
    let declared = if is_json { OPENAPI_JSON_SECURITY_RE.is_match(content) } else { OPENAPI_YAML_TOP_SECURITY_RE.is_match(content) };
    if !declared && hits.is_empty() {
        hits.push(CheckHit { line: 0, snippet: "no top-level security requirement".to_string(), kind: None });
    }
    hits
}

/// Flags public ACLs/`publicly_accessible`/disabled public-access-block
/// flags anywhere, and world-open CIDRs inside ingress rules (an `ingress {}`
/// block, `aws_security_group_rule` with `type = "ingress"`, or
/// `aws_vpc_security_group_ingress_rule`) unless the rule covers only 80/443.
type NumberedLines<'a> = Vec<(usize, &'a str)>;

fn iac_public_exposure(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !rel_path.is_empty() && !rel_path.to_lowercase().ends_with(".tf") {
        return vec![];
    }
    let lines: Vec<(usize, &str)> = numbered_lines(content).collect();
    let mut hits: Vec<CheckHit> = lines.iter().filter(|(_, l)| TF_PUBLIC_LINE_REGEXES.iter().any(|re| re.is_match(l))).map(|(n, l)| CheckHit { line: *n, snippet: snippet_of(l), kind: None }).collect();

    // Group lines into ingress rules: (lines of the rule).
    let mut rules: Vec<Vec<(usize, &str)>> = Vec::new();
    // (resource type, its lines, brace depth)
    let mut resource: Option<(String, NumberedLines<'_>, i32)> = None;
    let mut ingress: Option<(Vec<(usize, &str)>, i32)> = None;
    for &(n, line) in &lines {
        let opens = line.matches('{').count() as i32;
        let closes = line.matches('}').count() as i32;
        if resource.is_none() {
            if let Some(c) = TF_RESOURCE_RE.captures(line) {
                resource = Some((c[1].to_string(), Vec::new(), 0));
            }
        }
        if let Some((_, body, depth)) = resource.as_mut() {
            body.push((n, line));
            *depth += opens - closes;
        }
        if ingress.is_none() && TF_INGRESS_BLOCK_RE.is_match(line) {
            ingress = Some((Vec::new(), 0));
        }
        if let Some((body, depth)) = ingress.as_mut() {
            body.push((n, line));
            *depth += opens - closes;
            if *depth <= 0 {
                rules.push(std::mem::take(body));
                ingress = None;
            }
        }
        if let Some((kind, body, depth)) = resource.as_ref() {
            if *depth <= 0 {
                let is_rule = kind == "aws_vpc_security_group_ingress_rule" || (kind == "aws_security_group_rule" && body.iter().any(|(_, l)| TF_INGRESS_TYPE_RE.is_match(l)));
                if is_rule {
                    rules.push(body.clone());
                }
                resource = None;
            }
        }
    }
    for rule in rules {
        let ports: Vec<u32> = rule.iter().filter_map(|(_, l)| TF_PORT_RE.captures(l).and_then(|c| c[2].parse().ok())).collect();
        if !ports.is_empty() && ports.iter().all(|p| *p == 80 || *p == 443) {
            continue;
        }
        for (n, l) in &rule {
            if TF_WORLD_CIDR_RE.is_match(l) {
                hits.push(CheckHit { line: *n, snippet: snippet_of(l), kind: None });
            }
        }
    }
    hits.sort_by_key(|h| h.line);
    hits.dedup_by_key(|h| h.line);
    hits
}

fn iac_encryption_disabled(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !rel_path.is_empty() && !rel_path.to_lowercase().ends_with(".tf") {
        return vec![];
    }
    text_hits(content, &TF_ENCRYPTION_OFF_RE)
}

fn python_unpinned_requirements(content: &str, rel_path: &str) -> Vec<CheckHit> {
    if !REQUIREMENTS_PATH_RE.is_match(&rel_path.replace('\\', "/")) {
        return vec![];
    }
    let mut hits = Vec::new();
    for (n, line) in numbered_lines(content) {
        let spec = line.split(" #").next().unwrap_or("").split(';').next().unwrap_or("").trim();
        if spec.is_empty() || spec.starts_with('#') || spec.starts_with('-') || spec.contains("://") || spec.contains(" @ ") || spec.starts_with('.') || spec.starts_with('/') {
            continue;
        }
        if !spec.contains("==") {
            hits.push(CheckHit { line: n, snippet: snippet_of(line), kind: None });
        }
    }
    hits
}

// ---- project-level checks (need the whole tree, so only check_project runs them) ----

const LICENSE_FILE_STEMS: &[&str] = &["license", "licence", "copying", "unlicense"];
static MANIFEST_LICENSE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?m)"licen[cs]es?"\s*:|^\s*licen[cs]e(?:-file|_files?)?\s*[=:]|<licenses?>"#).unwrap());

fn project_license_declared(root: &Path) -> Vec<CheckHit> {
    let Ok(entries) = std::fs::read_dir(root) else { return vec![] };
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        let stem = name.split('.').next().unwrap_or("");
        if LICENSE_FILE_STEMS.iter().any(|s| stem == *s || stem.starts_with(&format!("{s}-")) || stem.starts_with(&format!("{s}_"))) {
            return vec![];
        }
        if matches!(name.as_str(), "package.json" | "cargo.toml" | "pyproject.toml" | "setup.cfg" | "pom.xml") {
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                if MANIFEST_LICENSE_RE.is_match(&text) {
                    return vec![];
                }
            }
        }
    }
    vec![CheckHit { line: 0, snippet: "no LICENSE file and no license field in the root manifest".to_string(), kind: None }]
}

const NPM_LOCKFILES: &[&str] = &["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"];

/// `(relative path, hit)` for every manifest under `root` whose lockfile is
/// missing from its own directory and from every ancestor up to `root`
/// (workspaces keep one lockfile at the top).
fn lockfile_committed(root: &Path, files: &[std::path::PathBuf]) -> Vec<(String, CheckHit)> {
    let has_in_ancestors = |dir: &Path, names: &[&str]| {
        let mut current = Some(dir);
        while let Some(d) = current {
            if names.iter().any(|n| d.join(n).is_file()) {
                return true;
            }
            if d == root {
                break;
            }
            current = d.parent();
        }
        false
    };
    let mut out = Vec::new();
    for file in files {
        let Some(name) = file.file_name().map(|n| n.to_string_lossy().into_owned()) else { continue };
        let Some(dir) = file.parent() else { continue };
        let missing = match name.as_str() {
            "package.json" => {
                let declares = std::fs::read_to_string(file).map(|t| t.contains("\"dependencies\"") || t.contains("\"devDependencies\"")).unwrap_or(false);
                declares.then(|| (!has_in_ancestors(dir, NPM_LOCKFILES)).then_some("no package-lock.json / yarn.lock / pnpm-lock.yaml / bun.lock")).flatten()
            }
            "pyproject.toml" => {
                let poetry = std::fs::read_to_string(file).map(|t| t.contains("[tool.poetry")).unwrap_or(false);
                (poetry && !has_in_ancestors(dir, &["poetry.lock"])).then_some("Poetry project without poetry.lock")
            }
            "Pipfile" => (!has_in_ancestors(dir, &["Pipfile.lock"])).then_some("Pipfile without Pipfile.lock"),
            _ => None,
        };
        if let Some(msg) = missing {
            let rel = file.strip_prefix(root).unwrap_or(file).to_string_lossy().into_owned();
            out.push((rel, CheckHit { line: 0, snippet: msg.to_string(), kind: None }));
        }
    }
    out
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
        "dockerUnpinnedBaseImage" => docker_unpinned_base_image(content, rel_path),
        "dockerRunsAsRoot" => docker_runs_as_root(content, rel_path),
        "dockerSecretBuildArg" => docker_secret_build_arg(content, rel_path),
        "dockerRemoteScriptExecution" => docker_remote_script_execution(content, rel_path),
        "ghaScriptInjection" => gha_script_injection(content, rel_path),
        "ghaPwnRequest" => gha_pwn_request(content, rel_path),
        "ghaWriteAllPermissions" => gha_write_all_permissions(content, rel_path),
        "composeRunsAsRoot" => compose_runs_as_root(content, rel_path),
        "composePrivilegedContainer" => compose_privileged_container(content, rel_path),
        "noUnsafeXmlParsing" => no_unsafe_xml_parsing(content, rel_path),
        "noTlsVerificationDisabled" => no_tls_verification_disabled(content, rel_path),
        "noJwtVerificationDisabled" => no_jwt_verification_disabled(content, rel_path),
        "noDebugModeEnabled" => no_debug_mode_enabled(content, rel_path),
        "noPermissiveCors" => no_permissive_cors(content, rel_path),
        "noCommittedPrivateKeys" => no_committed_private_keys(content),
        "noCredentialsInUrls" => no_credentials_in_urls(content, rel_path),
        "noSensitiveDataInLogs" => no_sensitive_data_in_logs(content, rel_path),
        "noPathTraversalSinks" => no_path_traversal_sinks(content, rel_path),
        "noInsecureRandomness" => no_insecure_randomness(content, rel_path),
        "noDynamicUrllibOpen" => no_dynamic_urllib_open(content),
        "noSubstringUrlValidation" => skip_tests(rel_path, || scan_lines_any(content, &SUBSTRING_URL_CHECK_REGEXES)),
        "noHandrolledHtmlSanitization" => skip_tests(rel_path, || scan_lines_any(content, &HANDROLLED_SANITIZE_REGEXES)),
        "noSensitiveDataInBrowserStorage" => skip_tests(rel_path, || scan_lines_any(content, &BROWSER_STORAGE_SECRET_REGEXES)),
        "noTemplateVarInHref" => no_template_var_in_href(content),
        "ghaCheckoutPersistCredentials" => gha_checkout_persist_credentials(content, rel_path),
        "ghaPermissionsNotDeclared" => gha_permissions_not_declared(content, rel_path),
        "dockerMissingHealthcheck" => docker_missing_healthcheck(content, rel_path),
        "dockerNonNumericUser" => docker_non_numeric_user(content, rel_path),
        "dockerUnpinnedPackages" => docker_unpinned_packages(content, rel_path),
        "dockerExecFormCmd" => docker_exec_form_cmd(content, rel_path),
        "dockerPipefail" => docker_pipefail(content, rel_path),
        "openapiSecurityDefined" => openapi_security_defined(content, rel_path),
        "iacPublicExposure" => iac_public_exposure(content, rel_path),
        "iacEncryptionDisabled" => iac_encryption_disabled(content, rel_path),
        "pythonUnpinnedRequirements" => python_unpinned_requirements(content, rel_path),
        // Project-level (projectLicenseDeclared, lockfileCommitted): need the
        // whole tree, so only check_project runs them.
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
    // An empty `rel_path` means the caller (an ad-hoc `POST /check`/MCP
    // `check_guidelines` call with no `path`/filename hint) never gave us
    // a file at all — distinct from `check_project`'s own file walk (below)
    // always passing a real, if extensionless, path. Treating the two the
    // same silently skipped every extension-scoped guideline (SQL
    // injection, XSS sinks, weak crypto, insecure deserialization, ...)
    // whenever a caller omitted `path`, giving false assurance that
    // clearly malicious content was compliant. Only a genuinely
    // extensionless real file (`Dockerfile`, `Makefile`) still gets
    // filtered as before.
    let ext = Path::new(rel_path).extension().map(|e| format!(".{}", e.to_string_lossy().to_lowercase()));
    let mut violations = Vec::new();

    for g in guidelines() {
        let Some(check_id) = g.check_id else { continue };
        if let Some(ext) = &ext {
            if !g.applies_to.contains(&"*") && !g.applies_to.contains(&ext.as_str()) {
                continue;
            }
        } else if rel_path.is_empty() {
            // No path given at all — don't filter by extension.
        } else if !g.applies_to.contains(&"*") {
            // A real, extensionless path — same filtering as before.
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

/// Bundled/minified third-party assets (`jquery.min.js`, source maps):
/// not code the project writes, and one "line" is the whole library.
fn is_minified_asset(rel_path: &str) -> bool {
    let lower = rel_path.to_lowercase();
    [".min.js", ".min.css", ".min.mjs", ".js.map", ".css.map"].iter().any(|s| lower.ends_with(s))
}

#[derive(Debug, Serialize)]
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

        if BINARY_EXTENSIONS.contains(ext.as_str()) || is_minified_asset(&rel_path) {
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

    let project_level = |check_id: &str| guidelines().iter().find(|g| g.check_id == Some(check_id)).expect("project-level guideline exists");
    let mut project_hits: Vec<(&'static crate::catalog::Guideline, String, CheckHit)> = Vec::new();
    for hit in project_license_declared(root) {
        project_hits.push((project_level("projectLicenseDeclared"), "LICENSE".to_string(), hit));
    }
    for (file, hit) in lockfile_committed(root, &files) {
        project_hits.push((project_level("lockfileCommitted"), file, hit));
    }
    for (g, file, hit) in project_hits {
        violations.push(Violation { guideline_id: g.id, category: g.category, severity: g.severity, title: g.title, file, line: hit.line, snippet: hit.snippet });
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
    fn ai_recursion_limit_still_flags_an_ungoverned_call_when_a_different_call_sets_recursion_limit() {
        // A whole-file substring search for "recursion_limit" previously
        // let this governed call suppress the finding for the completely
        // separate, actually-ungoverned `other_chain.invoke(x)` below it.
        let content = "import langchain\nchain.invoke(x, {'recursion_limit': 10})\nother_chain.invoke(x)\n";
        let hits = run_check("aiRecursionLimit", content, "app.py").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, 3);
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
    fn no_unpinned_gha_action_requires_full_sha_everywhere() {
        let wf = ".github/workflows/ci.yml";
        let sha_pinned = "    uses: owner/action@1234567890abcdef1234567890abcdef12345678 # v1.2.3\n";
        assert!(run_check("noUnpinnedGhaAction", sha_pinned, wf).unwrap().is_empty());
        // actions/* is no longer exempt, and full semver tags count as mutable.
        assert_eq!(run_check("noUnpinnedGhaAction", "      - uses: actions/checkout@v4\n", wf).unwrap().len(), 1);
        assert_eq!(run_check("noUnpinnedGhaAction", "      - uses: owner/action@v1.2.3\n", wf).unwrap().len(), 1);
        assert_eq!(run_check("noUnpinnedGhaAction", "    uses: org/repo/.github/workflows/build.yml@main\n", wf).unwrap().len(), 1);
        assert_eq!(run_check("noUnpinnedGhaAction", "      - uses: \"owner/action@abc1234\"\n", wf).unwrap().len(), 1);
        assert!(run_check("noUnpinnedGhaAction", "      - uses: ./.github/actions/local\n", wf).unwrap().is_empty());
        assert_eq!(run_check("noUnpinnedGhaAction", "      - uses: docker://alpine:3.19\n", wf).unwrap().len(), 1);
        assert!(run_check("noUnpinnedGhaAction", "      - uses: docker://alpine@sha256:abcdef\n", wf).unwrap().is_empty());
    }

    #[test]
    fn gha_script_injection_flags_untrusted_expr_in_run_blocks_only() {
        let wf = ".github/workflows/triage.yml";
        let content = "jobs:\n  t:\n    steps:\n      - run: |\n          echo \"${{ github.event.issue.title }}\"\n          echo ok\n      - name: safe\n        env:\n          TITLE: ${{ github.event.issue.title }}\n        run: echo \"$TITLE\"\n      - run: echo ${{ github.head_ref }}\n      - run: echo ${{ github.event.pull_request.number }}\n";
        let hits = run_check("ghaScriptInjection", content, wf).unwrap();
        assert_eq!(hits.iter().map(|h| h.line).collect::<Vec<_>>(), vec![5, 11]);
    }

    #[test]
    fn gha_script_injection_covers_github_script() {
        let content = "      - uses: actions/github-script@0000000000000000000000000000000000000000\n        with:\n          script: |\n            const b = `${{ github.event.comment.body }}`\n";
        assert_eq!(run_check("ghaScriptInjection", content, ".github/workflows/x.yml").unwrap().len(), 1);
    }

    #[test]
    fn gha_pwn_request_needs_pull_request_target_and_head_checkout() {
        let wf = ".github/workflows/pr.yml";
        let checkout = "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n";
        let target = format!("on:\n  pull_request_target:\njobs:\n  b:\n    steps:\n{checkout}");
        let hits = run_check("ghaPwnRequest", &target, wf).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, 8);
        let plain_pr = format!("on:\n  pull_request:\njobs:\n  b:\n    steps:\n{checkout}");
        assert!(run_check("ghaPwnRequest", &plain_pr, wf).unwrap().is_empty());
        let inline_on = format!("on: [push, pull_request_target]\njobs:\n{checkout}");
        assert_eq!(run_check("ghaPwnRequest", &inline_on, wf).unwrap().len(), 1);
    }

    #[test]
    fn gha_write_all_permissions_flags_write_all() {
        let wf = ".github/workflows/x.yml";
        assert_eq!(run_check("ghaWriteAllPermissions", "permissions: write-all\n", wf).unwrap().len(), 1);
        assert!(run_check("ghaWriteAllPermissions", "permissions:\n  contents: read\n", wf).unwrap().is_empty());
    }

    #[test]
    fn compose_runs_as_root_flags_missing_and_root_users() {
        let content = "version: '3'\nservices:\n  web:\n    image: nginx:1.27\n  api:\n    image: api:1\n    user: \"10001:10001\"\n  worker:\n    image: w:1\n    user: root\n  db:\n    image: pg:16\n    user: \"0:0\"\nvolumes:\n  data:\n";
        let hits = run_check("composeRunsAsRoot", content, "docker-compose.yml").unwrap();
        let names: Vec<_> = hits.iter().filter_map(|h| h.kind.clone()).collect();
        assert_eq!(names, vec!["web", "worker", "db"]);
        assert_eq!(hits[0].line, 3);
        assert_eq!(hits[1].line, 10);
        assert!(run_check("composeRunsAsRoot", content, "config.yml").unwrap().is_empty());
        assert_eq!(run_check("composeRunsAsRoot", content, "deploy/compose.prod.yaml").unwrap().len(), 3);
    }

    #[test]
    fn compose_privileged_container_flags_escapes_but_not_cap_drop_all() {
        let content = "services:\n  a:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n    network_mode: host\n    cap_drop:\n      - ALL\n    cap_add:\n      - NET_BIND_SERVICE\n      - SYS_ADMIN\n  b:\n    cap_add: [ALL]\n";
        let lines: Vec<_> = run_check("composePrivilegedContainer", content, "compose.yml").unwrap().iter().map(|h| h.line).collect();
        assert_eq!(lines, vec![3, 5, 6, 11, 13]);
    }

    #[test]
    fn no_unsafe_xml_parsing_flags_stdlib_parsers_not_defusedxml() {
        let unsafe_py = "import xml.etree.ElementTree as ET\nroot = ET.fromstring(data)\n";
        assert_eq!(run_check("noUnsafeXmlParsing", unsafe_py, "app.py").unwrap().len(), 1);
        let minidom = "from xml.dom import minidom\ndoc = minidom.parseString(body)\n";
        assert_eq!(run_check("noUnsafeXmlParsing", minidom, "app.py").unwrap().len(), 1);
        let safe = "import defusedxml.ElementTree as ET\nroot = ET.fromstring(data)\n";
        assert!(run_check("noUnsafeXmlParsing", safe, "app.py").unwrap().is_empty());
        // Building XML only — no parse call — isn't flagged.
        let build_only = "import xml.etree.ElementTree as ET\nel = ET.Element('a')\nET.tostring(el)\n";
        assert!(run_check("noUnsafeXmlParsing", build_only, "app.py").unwrap().is_empty());
        let helper = "from xml.sax import saxutils\nfrom defusedxml.sax import parse\nparse(f, h)\n";
        assert!(run_check("noUnsafeXmlParsing", helper, "app.py").unwrap().is_empty());
        let lxml_safe = "from lxml import etree\np = etree.XMLParser(resolve_entities=False, no_network=True)\netree.fromstring(d, p)\n";
        assert!(run_check("noUnsafeXmlParsing", lxml_safe, "app.py").unwrap().is_empty());
        assert_eq!(run_check("noUnsafeXmlParsing", "libxml.parseXml(s, { noent: true })\n", "app.js").unwrap().len(), 1);
    }

    #[test]
    fn no_tls_verification_disabled_flags_each_language_and_skips_tests() {
        assert_eq!(run_check("noTlsVerificationDisabled", "requests.get(url, verify=False)\n", "app.py").unwrap().len(), 1);
        assert_eq!(run_check("noTlsVerificationDisabled", "ctx = ssl._create_unverified_context()\n", "app.py").unwrap().len(), 1);
        assert_eq!(run_check("noTlsVerificationDisabled", "new https.Agent({ rejectUnauthorized: false })\n", "app.ts").unwrap().len(), 1);
        assert_eq!(run_check("noTlsVerificationDisabled", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'\n", "app.js").unwrap().len(), 1);
        assert_eq!(run_check("noTlsVerificationDisabled", "cfg := &tls.Config{InsecureSkipVerify: true}\n", "main.go").unwrap().len(), 1);
        assert!(run_check("noTlsVerificationDisabled", "cfg := &tls.Config{InsecureSkipVerify: true}\n", "main_test.go").unwrap().is_empty());
        assert!(run_check("noTlsVerificationDisabled", "requests.get(url, verify=False)\n", "tests/test_api.py").unwrap().is_empty());
        assert!(run_check("noTlsVerificationDisabled", "requests.get(url, verify='/etc/ca.pem')\n", "app.py").unwrap().is_empty());
    }

    #[test]
    fn no_jwt_verification_disabled_flags_unverified_decode_and_none_alg() {
        let py = "import jwt\na = jwt.decode(t, options={\"verify_signature\": False})\nb = jwt.decode(t, k, algorithms=[\"none\"])\nc = jwt.decode(t, k, algorithms=[\"RS256\"])\n";
        assert_eq!(run_check("noJwtVerificationDisabled", py, "auth.py").unwrap().iter().map(|h| h.line).collect::<Vec<_>>(), vec![2, 3]);
        let js = "const jwt = require('jsonwebtoken')\njwt.verify(t, k, { ignoreExpiration: true })\n";
        assert_eq!(run_check("noJwtVerificationDisabled", js, "auth.js").unwrap().len(), 1);
        // jwt.decode(verify=False) is reported as JWT, not as a TLS finding.
        assert!(run_check("noTlsVerificationDisabled", "x = jwt.decode(t, verify=False)\n", "auth.py").unwrap().is_empty());
    }

    #[test]
    fn no_debug_mode_enabled_flags_flask_run_and_django_settings() {
        assert_eq!(run_check("noDebugModeEnabled", "app.run(host='0.0.0.0', debug=True)\n", "app.py").unwrap().len(), 1);
        assert_eq!(run_check("noDebugModeEnabled", "DEBUG = True\n", "mysite/settings.py").unwrap().len(), 1);
        assert_eq!(run_check("noDebugModeEnabled", "DEBUG = True\n", "mysite/settings/prod.py").unwrap().len(), 1);
        assert!(run_check("noDebugModeEnabled", "DEBUG = True\n", "app/constants.py").unwrap().is_empty());
        assert!(run_check("noDebugModeEnabled", "app.run(debug=os.environ.get('D') == '1')\n", "app.py").unwrap().is_empty());
    }

    #[test]
    fn no_permissive_cors_flags_wildcards() {
        assert_eq!(run_check("noPermissiveCors", "app.use(cors())\n", "server.js").unwrap().len(), 1);
        assert_eq!(run_check("noPermissiveCors", "app.use(cors({ origin: '*' }))\n", "server.js").unwrap().len(), 1);
        assert_eq!(run_check("noPermissiveCors", "res.setHeader('Access-Control-Allow-Origin', '*')\n", "server.ts").unwrap().len(), 1);
        assert_eq!(run_check("noPermissiveCors", "app.add_middleware(CORSMiddleware, allow_origins=[\"*\"])\n", "main.py").unwrap().len(), 1);
        assert_eq!(run_check("noPermissiveCors", "CORS_ALLOW_ALL_ORIGINS = True\n", "settings.py").unwrap().len(), 1);
        assert!(run_check("noPermissiveCors", "app.use(cors({ origin: ['https://app.example.com'] }))\n", "server.js").unwrap().is_empty());
    }

    #[test]
    fn docker_remote_script_execution_flags_pipe_to_shell_and_unverified_add() {
        assert_eq!(run_check("dockerRemoteScriptExecution", "RUN curl -fsSL https://x.sh | bash\n", "Dockerfile").unwrap().len(), 1);
        assert_eq!(run_check("dockerRemoteScriptExecution", "    && wget -qO- https://x | sh \\\n", "Dockerfile").unwrap().len(), 1);
        assert_eq!(run_check("dockerRemoteScriptExecution", "ADD https://example.com/tool.tgz /opt/\n", "Dockerfile").unwrap().len(), 1);
        assert!(run_check("dockerRemoteScriptExecution", "ADD --checksum=sha256:abc https://example.com/t.tgz /opt/\n", "Dockerfile").unwrap().is_empty());
        assert!(run_check("dockerRemoteScriptExecution", "RUN curl -fsSLo /tmp/x.sh https://x.sh && echo 'abc  /tmp/x.sh' | sha256sum -c\n", "Dockerfile").unwrap().is_empty());
    }

    #[test]
    fn no_committed_env_files_flags_dotenv_variants() {
        assert_eq!(run_check("noCommittedEnvFiles", "", ".env").unwrap().len(), 1);
        assert_eq!(run_check("noCommittedEnvFiles", "", ".env.production").unwrap().len(), 1);
        assert!(run_check("noCommittedEnvFiles", "", "config.env.js").unwrap().is_empty());
    }

    /// BUG-138: `.env.example`/`.env.sample`/`.env.template` are this
    /// guideline's own documented remediation ("commit a .env.example
    /// with placeholder keys only") — flagging them as a violation
    /// penalized a project for correctly following the advice.
    #[test]
    fn no_committed_env_files_does_not_flag_template_files() {
        assert!(run_check("noCommittedEnvFiles", "", ".env.example").unwrap().is_empty());
        assert!(run_check("noCommittedEnvFiles", "", ".env.sample").unwrap().is_empty());
        assert!(run_check("noCommittedEnvFiles", "", ".env.template").unwrap().is_empty());
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
    fn docker_unpinned_base_image_flags_missing_and_latest_tag() {
        assert_eq!(run_check("dockerUnpinnedBaseImage", "FROM node\n", "Dockerfile").unwrap().len(), 1);
        assert_eq!(run_check("dockerUnpinnedBaseImage", "FROM node:latest\n", "Dockerfile").unwrap().len(), 1);
        assert!(run_check("dockerUnpinnedBaseImage", "FROM node:20.11.1\n", "Dockerfile").unwrap().is_empty());
        assert!(run_check("dockerUnpinnedBaseImage", "FROM node@sha256:abcdef1234\n", "Dockerfile").unwrap().is_empty());
    }

    #[test]
    fn docker_unpinned_base_image_ignores_multi_stage_references() {
        let content = "FROM node:20.11.1 AS builder\nFROM builder AS test\n";
        assert!(run_check("dockerUnpinnedBaseImage", content, "Dockerfile").unwrap().is_empty());
    }

    #[test]
    fn docker_unpinned_base_image_only_applies_to_dockerfiles() {
        assert!(run_check("dockerUnpinnedBaseImage", "FROM node\n", "notes.md").unwrap().is_empty());
        assert_eq!(run_check("dockerUnpinnedBaseImage", "FROM node\n", "docker/Dockerfile.prod").unwrap().len(), 1);
    }

    #[test]
    fn docker_runs_as_root_flags_missing_or_root_user() {
        assert_eq!(run_check("dockerRunsAsRoot", "FROM node:20\n", "Dockerfile").unwrap().len(), 1);
        assert_eq!(run_check("dockerRunsAsRoot", "FROM node:20\nUSER root\n", "Dockerfile").unwrap().len(), 1);
        assert!(run_check("dockerRunsAsRoot", "FROM node:20\nUSER appuser\n", "Dockerfile").unwrap().is_empty());
    }

    #[test]
    fn docker_secret_build_arg_flags_credential_looking_names() {
        let hits = run_check("dockerSecretBuildArg", "ARG API_KEY=xyz\n", "Dockerfile").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind.as_deref(), Some("api_key"));
        assert!(run_check("dockerSecretBuildArg", "ENV NODE_ENV=production\n", "Dockerfile").unwrap().is_empty());
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

    /// Fixture builders: assembled at runtime so secret scanners (Ignite's
    /// own pre-push gate included) don't flag the test source itself.
    fn pem_begin(kind: &str) -> String {
        format!("{dashes}BEGIN {kind}PRIVATE KEY{dashes}", dashes = "-".repeat(5))
    }

    fn cred_url(scheme: &str, user: &str, password: &str, host: &str) -> String {
        format!("{scheme}://{user}:{password}{at}{host}", at = '@')
    }

    fn lines_of(check: &str, content: &str, path: &str) -> Vec<usize> {
        run_check(check, content, path).unwrap().iter().map(|h| h.line).collect()
    }

    #[test]
    fn no_committed_private_keys_flags_pem_blocks() {
        let body = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun";
        let rsa = pem_begin("RSA ");
        assert_eq!(lines_of("noCommittedPrivateKeys", &format!("x\n{rsa}\n{body}\n"), "key.pem"), vec![2]);
        let encrypted = format!("{rsa}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,AB12\n\n{body}\n");
        assert_eq!(lines_of("noCommittedPrivateKeys", &encrypted, "id"), vec![1]);
        assert_eq!(lines_of("noCommittedPrivateKeys", &format!("k = \"{}\\n{body}\\n\"", pem_begin("OPENSSH ")), "a.py"), vec![1]);
        assert!(lines_of("noCommittedPrivateKeys", "-----BEGIN PUBLIC KEY-----\n", "k.pem").is_empty());
    }

    #[test]
    fn no_credentials_in_urls_ignores_placeholders_and_loopback() {
        let real = format!("DB = '{}:5432/app'\n", cred_url("postgres", "app", "S3cr3tPw", "db.prod.internal"));
        let hits = run_check("noCredentialsInUrls", &real, "settings.py").unwrap();
        assert_eq!(hits.len(), 1);
        assert!(!hits[0].snippet.contains("S3cr3tPw"), "snippet must not echo the credential");
        let env_ref = format!("url: {}:5432/app\n", cred_url("postgres", "app", "${DB_PASSWORD}", "db"));
        assert!(lines_of("noCredentialsInUrls", &env_ref, "compose.yml").is_empty());
        let placeholder = format!("{}/x\n", cred_url("postgres", "user", "password", "db.example.com"));
        assert!(lines_of("noCredentialsInUrls", &placeholder, "README.md").is_empty());
        let loopback = format!("{}:5432/dev\n", cred_url("postgres", "postgres", "postgres", "localhost"));
        assert!(lines_of("noCredentialsInUrls", &loopback, "x.env.example").is_empty());
    }

    #[test]
    fn no_sensitive_data_in_logs_flags_values_not_messages() {
        assert_eq!(lines_of("noSensitiveDataInLogs", "logger.info(f\"login {user} pw={password}\")\n", "a.py"), vec![1]);
        assert_eq!(lines_of("noSensitiveDataInLogs", "console.log('token', authToken)\n", "a.js"), vec![1]);
        assert_eq!(lines_of("noSensitiveDataInLogs", "console.log(`t=${req.headers.authorization}`)\n", "a.ts"), vec![1]);
        assert!(lines_of("noSensitiveDataInLogs", "logger.warning(\"invalid password for %s\", user)\n", "a.py").is_empty());
        assert!(lines_of("noSensitiveDataInLogs", "logger.info(\"used %d\", max_tokens)\n", "a.py").is_empty());
        assert!(lines_of("noSensitiveDataInLogs", "print(token_count)\n", "a.py").is_empty());
        assert!(lines_of("noSensitiveDataInLogs", "print(password)\n", "tests/test_a.py").is_empty());
    }

    #[test]
    fn no_path_traversal_sinks_flags_request_paths() {
        assert_eq!(lines_of("noPathTraversalSinks", "return send_file(request.args['f'])\n", "app.py"), vec![1]);
        assert_eq!(lines_of("noPathTraversalSinks", "p = os.path.join(BASE, request.args.get('name'))\n", "app.py"), vec![1]);
        assert_eq!(lines_of("noPathTraversalSinks", "res.sendFile(path.join(dir, req.params.file))\n", "app.js"), vec![1]);
        assert!(lines_of("noPathTraversalSinks", "return send_from_directory(BASE, request.args['f'])\n", "app.py").is_empty());
        assert!(lines_of("noPathTraversalSinks", "fs.readFileSync(path.join(__dirname, 'a.txt'))\n", "app.js").is_empty());
    }

    #[test]
    fn no_insecure_randomness_needs_sensitive_context() {
        assert_eq!(lines_of("noInsecureRandomness", "const token = Math.random().toString(36)\n", "a.js"), vec![1]);
        assert_eq!(lines_of("noInsecureRandomness", "reset_code = ''.join(random.choices(ALPHA, k=8))\n", "a.py"), vec![1]);
        assert!(lines_of("noInsecureRandomness", "const jitter = Math.random() * 100\n", "a.js").is_empty());
    }

    #[test]
    fn no_dynamic_urllib_open_flags_variables_only() {
        let c = "from urllib.request import urlopen\nurlopen(url)\nurlopen('https://api.example.com')\n";
        assert_eq!(lines_of("noDynamicUrllibOpen", c, "a.py"), vec![2]);
    }

    #[test]
    fn no_substring_url_validation_flags_includes_and_in() {
        assert_eq!(lines_of("noSubstringUrlValidation", "if (redirectUrl.includes('example.com')) go()\n", "a.js"), vec![1]);
        assert_eq!(lines_of("noSubstringUrlValidation", "if \"example.com\" in referer:\n", "a.py"), vec![1]);
        assert!(lines_of("noSubstringUrlValidation", "if (new URL(u).hostname === 'example.com') go()\n", "a.js").is_empty());
    }

    #[test]
    fn no_handrolled_html_sanitization_flags_string_replace_and_script_regex() {
        assert_eq!(lines_of("noHandrolledHtmlSanitization", "s = s.replace('<', '&lt;')\n", "a.js"), vec![1]);
        assert_eq!(lines_of("noHandrolledHtmlSanitization", "s = s.replace(/<script>/gi, '')\n", "a.ts"), vec![1]);
        assert!(lines_of("noHandrolledHtmlSanitization", "s = s.replace(/</g, '&lt;')\n", "a.js").is_empty());
    }

    #[test]
    fn no_sensitive_data_in_browser_storage_flags_tokens() {
        assert_eq!(lines_of("noSensitiveDataInBrowserStorage", "localStorage.setItem('accessToken', t)\n", "a.ts"), vec![1]);
        assert_eq!(lines_of("noSensitiveDataInBrowserStorage", "sessionStorage['jwt'] = t\n", "a.js"), vec![1]);
        assert!(lines_of("noSensitiveDataInBrowserStorage", "localStorage.setItem('theme', 'dark')\n", "a.ts").is_empty());
        assert!(lines_of("noSensitiveDataInBrowserStorage", "localStorage.setItem('jwt', 'x')\n", "src/__tests__/core.test.ts").is_empty());
    }

    #[test]
    fn no_template_var_in_href_flags_leading_expression() {
        assert_eq!(lines_of("noTemplateVarInHref", "<a href=\"{{ link }}\">x</a>\n", "t.html"), vec![1]);
        assert!(lines_of("noTemplateVarInHref", "<a href=\"/users/{{ id }}\">x</a>\n", "t.html").is_empty());
    }

    #[test]
    fn gha_checkout_persist_credentials_checks_each_step() {
        let wf = ".github/workflows/ci.yml";
        let c = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - name: second\n        uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n";
        assert_eq!(lines_of("ghaCheckoutPersistCredentials", c, wf), vec![4, 9]);
    }

    #[test]
    fn gha_permissions_not_declared_flags_missing_block() {
        let wf = ".github/workflows/ci.yml";
        assert_eq!(lines_of("ghaPermissionsNotDeclared", "on: push\njobs:\n  a:\n    runs-on: x\n", wf), vec![0]);
        assert!(lines_of("ghaPermissionsNotDeclared", "on: push\npermissions:\n  contents: read\njobs:\n  a: {}\n", wf).is_empty());
        assert!(lines_of("ghaPermissionsNotDeclared", "jobs:\n  a:\n    permissions:\n      contents: read\n", wf).is_empty());
    }

    #[test]
    fn docker_healthcheck_user_and_cmd_form() {
        assert_eq!(lines_of("dockerMissingHealthcheck", "FROM a:1\nCMD [\"x\"]\n", "Dockerfile"), vec![0]);
        assert!(lines_of("dockerMissingHealthcheck", "FROM a:1\nHEALTHCHECK NONE\n", "Dockerfile").is_empty());
        assert_eq!(lines_of("dockerNonNumericUser", "FROM a:1\nUSER appuser\n", "Dockerfile"), vec![2]);
        assert!(lines_of("dockerNonNumericUser", "FROM a:1\nUSER 10001:10001\n", "Dockerfile").is_empty());
        assert!(lines_of("dockerNonNumericUser", "FROM a:1\nUSER root\n", "Dockerfile").is_empty());
        assert_eq!(lines_of("dockerExecFormCmd", "CMD python app.py\nENTRYPOINT [\"/app\"]\n", "Dockerfile"), vec![1]);
    }

    #[test]
    fn docker_unpinned_packages_handles_continuations_and_requirements() {
        let c = "FROM debian:12\nRUN apt-get update && \\\n    apt-get install -y --no-install-recommends \\\n      curl=8.5.0-2 git && \\\n    rm -rf /var/lib/apt/lists/*\nRUN pip install --no-cache-dir -r requirements.txt\nRUN pip install requests==2.32.3 flask\nRUN apk add --no-cache tini=0.19.0-r3\n";
        let hits = run_check("dockerUnpinnedPackages", c, "Dockerfile").unwrap();
        assert_eq!(hits.iter().map(|h| h.line).collect::<Vec<_>>(), vec![2, 7]);
        assert!(hits[0].snippet.contains("git") && !hits[0].snippet.contains("curl"));
        assert!(hits[1].snippet.contains("flask") && !hits[1].snippet.contains("requests"));
    }

    #[test]
    fn docker_pipefail_respects_shell_and_set() {
        let c = "FROM a:1\nRUN curl -fsSL https://x/a.tgz | tar xz\nRUN set -o pipefail && curl x | tar xz\nRUN test -f a || echo no\nSHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"]\nRUN curl x | tar xz\nFROM b:1\nRUN cat a | grep b\n";
        assert_eq!(lines_of("dockerPipefail", c, "Dockerfile"), vec![2, 8]);
    }

    #[test]
    fn openapi_security_defined_flags_missing_or_empty() {
        assert_eq!(lines_of("openapiSecurityDefined", "openapi: 3.0.3\ninfo:\n  title: x\npaths: {}\n", "api.yaml"), vec![0]);
        assert!(lines_of("openapiSecurityDefined", "openapi: 3.0.3\nsecurity:\n  - bearer: []\npaths: {}\n", "api.yaml").is_empty());
        assert_eq!(lines_of("openapiSecurityDefined", "openapi: 3.1.0\nsecurity: []\n", "api.yml"), vec![2]);
        assert_eq!(lines_of("openapiSecurityDefined", "{\"openapi\": \"3.0.0\", \"paths\": {}}\n", "api.json"), vec![0]);
        assert!(lines_of("openapiSecurityDefined", "name: not-a-spec\n", "config.yaml").is_empty());
    }

    #[test]
    fn iac_public_exposure_flags_public_and_world_open_ingress() {
        let tf = r#"resource "aws_s3_bucket_acl" "a" {
  acl = "public-read"
}
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group_rule" "db" {
  type        = "ingress"
  from_port   = 5432
  to_port     = 5432
  cidr_blocks = ["0.0.0.0/0"]
}
resource "aws_db_instance" "d" {
  publicly_accessible = true
}
"#;
        assert_eq!(lines_of("iacPublicExposure", tf, "main.tf"), vec![2, 13, 23, 26]);
    }

    #[test]
    fn iac_encryption_disabled_flags_off_switches() {
        let tf = "resource \"aws_ebs_volume\" \"v\" {\n  encrypted = false\n}\nresource \"aws_kms_key\" \"k\" {\n  enable_key_rotation = true\n}\nmin_tls_version = \"TLS1_0\"\n";
        assert_eq!(lines_of("iacEncryptionDisabled", tf, "main.tf"), vec![2, 7]);
    }

    #[test]
    fn python_unpinned_requirements_flags_ranges() {
        let c = "# deps\nrequests==2.32.3\nflask>=3.0\nnumpy\n-r base.txt\ngit+https://github.com/x/y.git@abc#egg=y\npandas==2.2.2 ; python_version >= '3.9'\n";
        assert_eq!(lines_of("pythonUnpinnedRequirements", c, "requirements.txt"), vec![3, 4]);
        assert!(lines_of("pythonUnpinnedRequirements", "flask\n", "requirements.in").is_empty());
    }

    #[test]
    fn tls_check_covers_ansible_and_shell_but_not_docs() {
        assert_eq!(lines_of("noTlsVerificationDisabled", "- uri:\n    url: https://x\n    validate_certs: no\n", "site.yml"), vec![3]);
        assert_eq!(lines_of("noTlsVerificationDisabled", "RUN curl -k https://x/a.sh -o a.sh\n", "Dockerfile"), vec![1]);
        assert!(lines_of("noTlsVerificationDisabled", "Never use `verify=False`.\n", "README.md").is_empty());
    }

    #[test]
    fn project_level_checks_license_and_lockfile() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), "{\"dependencies\": {\"x\": \"1\"}}").unwrap();
        fs::create_dir_all(root.join("packages/a")).unwrap();
        fs::write(root.join("packages/a/package.json"), "{\"dependencies\": {\"y\": \"1\"}}").unwrap();
        let result = check_project(root).unwrap();
        assert!(result.violations.iter().any(|v| v.guideline_id == "project-license-declared"));
        assert_eq!(result.violations.iter().filter(|v| v.guideline_id == "lockfile-committed").count(), 2);

        // Root lockfile covers the workspace package too; a license field satisfies the license check.
        fs::write(root.join("package-lock.json"), "{}").unwrap();
        fs::write(root.join("package.json"), "{\"license\": \"UNLICENSED\", \"dependencies\": {\"x\": \"1\"}}").unwrap();
        let result = check_project(root).unwrap();
        assert!(!result.violations.iter().any(|v| v.guideline_id == "project-license-declared" || v.guideline_id == "lockfile-committed"));
    }

    #[test]
    fn false_positive_guards_from_real_scans() {
        // Hugo/Flask generated URLs aren't attacker-controlled.
        assert!(lines_of("noTemplateVarInHref", "<a href=\"{{ .RelPermalink }}\">x</a>\n", "t.html").is_empty());
        assert!(lines_of("noTemplateVarInHref", "<a href=\"{{ url_for('home') }}\">x</a>\n", "t.html").is_empty());
        // "reauth" isn't a credential.
        assert!(lines_of("noSensitiveDataInBrowserStorage", "sessionStorage.setItem('app_reauth_target', id)\n", "a.ts").is_empty());
        // PEM placeholders / assembly code aren't keys; a real block is.
        let begin = pem_begin("");
        assert!(lines_of("noCommittedPrivateKeys", &format!("placeholder=\"{begin}…\"\n"), "a.tsx").is_empty());
        assert!(lines_of("noCommittedPrivateKeys", &format!("pem = \"{begin}\\n\";\npem += keyBody;\n"), "a.groovy").is_empty());
        let real = format!("{begin}\n{}\n", "A".repeat(64));
        assert_eq!(lines_of("noCommittedPrivateKeys", &real, "k.pem"), vec![1]);
        // Non-host substrings aren't URL validation.
        assert!(lines_of("noSubstringUrlValidation", "const sep = returnUrl.includes('?') ? '&' : '?'\n", "a.ts").is_empty());
        // A `|` inside a quoted sed expression isn't a pipe.
        assert!(lines_of("dockerPipefail", "FROM a:1\nRUN sed -i 's|http://|https://|g' /etc/x\n", "Dockerfile").is_empty());
        // HEALTHCHECK's CMD is not the container CMD.
        assert!(lines_of("dockerExecFormCmd", "HEALTHCHECK --interval=30s \\\n  CMD curl -f http://localhost/ || exit 1\n", "Dockerfile").is_empty());
        // Official images that drop root themselves.
        let compose = "services:\n  db:\n    image: postgres:16\n  cache:\n    image: \"redis:7-alpine\"\n  app:\n    image: app:1\n";
        assert_eq!(lines_of("composeRunsAsRoot", compose, "docker-compose.yml"), vec![6]);
    }

    #[test]
    fn check_project_skips_minified_assets() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("lib.min.js"), "var token=Math.random();eval(x)\n").unwrap();
        fs::write(dir.path().join("LICENSE"), "MIT\n").unwrap();
        assert!(check_project(dir.path()).unwrap().violations.is_empty());
    }

    #[test]
    fn project_level_checks_are_skipped_by_check_content() {
        assert!(run_check("projectLicenseDeclared", "", "x").is_none());
        assert!(run_check("lockfileCommitted", "", "x").is_none());
    }
}
