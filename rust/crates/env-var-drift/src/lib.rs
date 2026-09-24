//! Built-in environment-variable drift check: diffs the variables a
//! project's code actually reads against the ones its committed env
//! template (`.env.example`/`.env.sample`/`.env.template`/...,
//! `ignite_fs_utils::is_env_template_file`) documents.
//!
//! Two advisory finding kinds, never blocking — a missing doc entry is a
//! configuration-hygiene gap, not a security issue:
//! - [`KIND_UNDOCUMENTED`]: a variable read in code (by a string-literal
//!   name) that no template lists, reported once per variable at its first
//!   read site.
//! - [`KIND_STALE`]: a template entry whose name is never mentioned in any
//!   code/config file at all, reported at the template line.
//!
//! "Documented" includes commented-out `# VAR=` entries, not only live
//! `VAR=` lines: templates routinely comment out optional variables to
//! show they exist without setting a value, and treating those as
//! undocumented is exactly the false positive this check has to avoid.
//!
//! Reads are regex-matched per language (Rust, JS/TS, Python, Go,
//! JVM, C#, Ruby, docker-compose `${VAR}` interpolation). Only a literal
//! name counts — `env::var(name)` with a computed name can't be resolved
//! statically and is skipped. Staleness is deliberately looser than that:
//! any whole-word mention of the name in a non-doc file (a Dockerfile
//! `ENV`/`ARG`, a workflow `${{ env.X }}`, a Prisma `env("X")`, a code
//! read through a wrapper this check doesn't know) keeps an entry from
//! being called stale, since flagging a genuinely-used variable is worse
//! than missing a truly dead one. OS/platform-provided variables (`HOME`,
//! `PATH`, `CARGO_*`, ...) are never reported as undocumented, and
//! variables SDKs consume implicitly without any code mentioning them
//! (`AWS_*`, `OTEL_*`, `DATABASE_URL`, ...) are never reported as stale.
//!
//! A project with no template at all gets `engine: "not_applicable"` and
//! no findings — there's nothing to drift from.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use ignite_fs_utils::{build_snippet, is_env_template_file, looks_binary, walk_files, Snippet, SnippetOptions};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const KIND_UNDOCUMENTED: &str = "env-var-undocumented";
pub const KIND_STALE: &str = "env-template-stale-entry";

/// Generated/minified bundles and big data files aren't where config reads
/// live, and reading them whole only costs time.
const MAX_FILE_BYTES: u64 = 2_000_000;

pub struct EnvVarDriftConfig {
    pub enabled: bool,
}

impl Default for EnvVarDriftConfig {
    fn default() -> Self {
        EnvVarDriftConfig { enabled: true }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EnvVarDriftFinding {
    pub file: String,
    pub line: usize,
    pub kind: &'static str,
    pub var: String,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
    pub code: Option<Snippet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnvVarDriftResult {
    pub findings: Vec<EnvVarDriftFinding>,
    /// `"disabled"`, `"not_applicable"` (no env template in the project),
    /// or `"built-in"`.
    pub engine: &'static str,
    /// Relative paths of every env template the documented set was read from.
    pub templates: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lang {
    Rust,
    Js,
    Python,
    Go,
    Jvm,
    CSharp,
    Ruby,
    Compose,
}

impl Lang {
    fn for_path(rel: &str) -> Option<Lang> {
        let base = rel.rsplit('/').next().unwrap_or(rel).to_lowercase();
        if (base.starts_with("docker-compose") || base.starts_with("compose")) && (base.ends_with(".yml") || base.ends_with(".yaml")) {
            return Some(Lang::Compose);
        }
        let ext = base.rsplit_once('.').map(|(_, e)| e)?;
        Some(match ext {
            "rs" => Lang::Rust,
            "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "mts" | "cts" | "vue" | "svelte" | "astro" => Lang::Js,
            "py" => Lang::Python,
            "go" => Lang::Go,
            "java" | "kt" | "kts" | "scala" | "groovy" => Lang::Jvm,
            "cs" => Lang::CSharp,
            "rb" => Lang::Ruby,
            _ => return None,
        })
    }

    fn comment_prefixes(self) -> &'static [&'static str] {
        match self {
            Lang::Python | Lang::Ruby | Lang::Compose => &["#"],
            _ => &["//", "/*", "*"],
        }
    }

    fn patterns(self) -> &'static [Regex] {
        match self {
            Lang::Rust => &RUST_READS,
            Lang::Js => &JS_READS,
            Lang::Python => &PYTHON_READS,
            Lang::Go => &GO_READS,
            Lang::Jvm => &JVM_READS,
            Lang::CSharp => &CSHARP_READS,
            Lang::Ruby => &RUBY_READS,
            Lang::Compose => &COMPOSE_READS,
        }
    }
}

fn compile(patterns: &[&str]) -> Vec<Regex> {
    patterns.iter().filter_map(|p| Regex::new(p).ok()).collect()
}

// Capture group 1 is always the variable name.
static RUST_READS: Lazy<Vec<Regex>> = Lazy::new(|| {
    compile(&[
        r#"\benv::var(?:_os)?\(\s*"([A-Za-z_][A-Za-z0-9_]*)""#,
        r#"\b(?:option_)?env!\(\s*"([A-Za-z_][A-Za-z0-9_]*)""#,
        // Project-local wrappers (`env_bool(..)`, `env_num::<u64>(..)`,
        // ...) — restricted to an UPPER_SNAKE literal so an unrelated
        // `env_*` helper taking an ordinary string doesn't register.
        r#"\benv_[a-z0-9_]+(?:::<[^>]*>)?\(\s*"([A-Z][A-Z0-9_]*)""#,
    ])
});
static JS_READS: Lazy<Vec<Regex>> = Lazy::new(|| {
    compile(&[
        r"\bprocess\.env\.([A-Za-z_][A-Za-z0-9_]*)",
        r#"\bprocess\.env\[\s*['"`]([A-Za-z_][A-Za-z0-9_]*)['"`]\s*\]"#,
        r"\bimport\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)",
        r#"\bDeno\.env\.get\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]"#,
    ])
});
static PYTHON_READS: Lazy<Vec<Regex>> = Lazy::new(|| {
    compile(&[
        r#"\benviron\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\]"#,
        r#"\benviron\.get\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]"#,
        r#"\bgetenv\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]"#,
    ])
});
static GO_READS: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[r#"\bos\.(?:Getenv|LookupEnv)\(\s*"([A-Za-z_][A-Za-z0-9_]*)""#]));
static JVM_READS: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[r#"\bSystem\.getenv\(\s*"([A-Za-z_][A-Za-z0-9_]*)""#]));
static CSHARP_READS: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[r#"\bEnvironment\.GetEnvironmentVariable\(\s*"([A-Za-z_][A-Za-z0-9_]*)""#]));
static RUBY_READS: Lazy<Vec<Regex>> =
    Lazy::new(|| compile(&[r#"\bENV\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\]"#, r#"\bENV\.fetch\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]"#]));
static COMPOSE_READS: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:[:?+\-][^}]*)?\}"]));

static TEMPLATE_ACTIVE_RE: Lazy<Option<Regex>> = Lazy::new(|| Regex::new(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=").ok());
/// Commented entries must be UPPER_SNAKE so prose like `# e.g. foo=bar`
/// isn't mistaken for a documented variable.
static TEMPLATE_COMMENTED_RE: Lazy<Option<Regex>> = Lazy::new(|| Regex::new(r"^\s*#+\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=").ok());

/// Set by the OS, shell, CI runner, or build tool — never something a
/// project's env template is expected to list.
const PLATFORM_VARS: &[&str] = &[
    "HOME", "PATH", "USER", "USERNAME", "USERPROFILE", "SHELL", "PWD", "OLDPWD", "TMPDIR", "TMP", "TEMP", "LANG", "LANGUAGE", "TERM", "HOSTNAME",
    "LOGNAME", "CI", "NODE_ENV", "TZ", "EDITOR", "VISUAL", "PAGER", "NO_COLOR", "FORCE_COLOR", "CLICOLOR", "COLUMNS", "LINES", "DISPLAY", "APPDATA",
    "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SSH_AUTH_SOCK", "RUST_BACKTRACE", "RUST_LOG",
    "OUT_DIR", "TARGET", "HOST", "PROFILE", "OPT_LEVEL", "NUM_JOBS", "MODE", "DEV", "PROD", "SSR", "BASE_URL", "VIRTUAL_ENV", "PYTHONPATH", "GOPATH",
    "GOROOT", "GOOS", "GOARCH", "JAVA_HOME", "KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT",
];
const PLATFORM_PREFIXES: &[&str] = &["XDG_", "LC_", "CARGO_", "GITHUB_", "RUNNER_", "ACTIONS_", "npm_", "DEP_"];

/// Read by an SDK/driver/runtime on its own, so a template entry for one
/// is legitimately never mentioned in the project's own code.
const IMPLICIT_VARS: &[&str] = &[
    "DATABASE_URL", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "REQUESTS_CA_BUNDLE", "SENTRY_DSN", "SENTRY_ENVIRONMENT", "JAVA_OPTS",
    "JAVA_TOOL_OPTIONS", "GOOGLE_APPLICATION_CREDENTIALS", "RUST_LOG", "RUST_BACKTRACE", "TZ", "LANG", "NODE_OPTIONS", "NODE_ENV",
];
const IMPLICIT_PREFIXES: &[&str] = &["AWS_", "AZURE_", "OTEL_", "DD_", "PG", "PYTHON", "SSL_CERT_", "NODE_EXTRA_", "NPM_CONFIG_", "DOTNET_", "ASPNETCORE_", "GITHUB_"];

fn is_platform_var(name: &str) -> bool {
    PLATFORM_VARS.contains(&name) || PLATFORM_PREFIXES.iter().any(|p| name.starts_with(p))
}

fn is_implicitly_consumed(name: &str) -> bool {
    IMPLICIT_VARS.contains(&name) || IMPLICIT_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Test code routinely reads throwaway variables (`IGNITE_TEST_*`, fake
/// credentials) that nobody should have to document.
fn is_test_path(rel: &str) -> bool {
    let lower = rel.to_lowercase();
    let mut segments: Vec<&str> = lower.split('/').collect();
    let base = segments.pop().unwrap_or("");
    if segments.iter().any(|s| matches!(*s, "test" | "tests" | "__tests__" | "spec" | "specs" | "fixtures" | "testdata" | "__mocks__")) {
        return true;
    }
    let stem = base.rsplit_once('.').map(|(s, _)| s).unwrap_or(base);
    stem.ends_with(".test") || stem.ends_with(".spec") || stem.ends_with("_test") || stem.ends_with("_spec") || stem.starts_with("test_") || stem == "conftest"
}

fn is_doc_file(rel: &str) -> bool {
    let lower = rel.to_lowercase();
    [".md", ".mdx", ".rst", ".txt", ".adoc"].iter().any(|e| lower.ends_with(e))
}

/// `true` when `rest` (the text right after a match) makes the match an
/// assignment (`os.environ["X"] = ...`, `process.env.X = ...`) rather
/// than a read. `==`/`===` comparisons are still reads.
fn is_assignment(rest: &str) -> bool {
    let rest = rest.trim_start();
    rest.starts_with('=') && !rest.starts_with("==")
}

struct TemplateEntry {
    file: String,
    line: usize,
    name: String,
}

struct ReadSite {
    file: String,
    line: usize,
    code: Option<Snippet>,
}

/// Every `(line, name)` a template documents, live or commented out.
pub fn parse_template(content: &str) -> Vec<(usize, String)> {
    let (Some(active), Some(commented)) = (TEMPLATE_ACTIVE_RE.as_ref(), TEMPLATE_COMMENTED_RE.as_ref()) else { return vec![] };
    content
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let caps = if line.trim_start().starts_with('#') { commented.captures(line) } else { active.captures(line) };
            caps.and_then(|c| c.get(1)).map(|m| (i + 1, m.as_str().to_string()))
        })
        .collect()
}

/// Every `(line, name)` of a literal-name env var read in `content`,
/// written in `lang`.
fn extract_reads(content: &str, lang: Lang) -> Vec<(usize, String)> {
    let mut reads = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    // Brace depth inside a `#[cfg(test)] mod x { ... }` being skipped. Test
    // modules can sit mid-file with real code after them, so only the
    // module's own body is skipped. Braces are counted naively (a brace in a
    // string literal can end the skip early, which only means scanning more).
    let mut test_mod_depth: Option<i64> = None;
    for (i, line) in lines.iter().enumerate() {
        if lang == Lang::Rust {
            if let Some(depth) = test_mod_depth.as_mut() {
                *depth += line.matches('{').count() as i64 - line.matches('}').count() as i64;
                if *depth <= 0 {
                    test_mod_depth = None;
                }
                continue;
            }
            if line.trim() == "#[cfg(test)]" && lines.get(i + 1).is_some_and(|next| next.trim_start().starts_with("mod ") && next.contains('{')) {
                test_mod_depth = Some(0);
                continue;
            }
        }
        let trimmed = line.trim_start();
        if lang.comment_prefixes().iter().any(|p| trimmed.starts_with(p)) {
            continue;
        }
        for re in lang.patterns() {
            for caps in re.captures_iter(line) {
                let (Some(whole), Some(name)) = (caps.get(0), caps.get(1)) else { continue };
                // `$${VAR}` is compose's escape for a literal `${VAR}`.
                if lang == Lang::Compose && line[..whole.start()].ends_with('$') {
                    continue;
                }
                if is_assignment(&line[whole.end()..]) {
                    continue;
                }
                reads.push((i + 1, name.as_str().to_string()));
            }
        }
    }
    reads
}

fn read_text(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_FILE_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    if looks_binary(&bytes) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

pub fn check_env_var_drift(root: &Path, config: &EnvVarDriftConfig) -> std::io::Result<EnvVarDriftResult> {
    if !config.enabled {
        return Ok(EnvVarDriftResult { findings: vec![], engine: "disabled", templates: vec![] });
    }

    let mut files: Vec<(String, std::path::PathBuf)> = walk_files(root)?
        .into_iter()
        .map(|p| (p.strip_prefix(root).unwrap_or(&p).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"), p))
        .collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let base_of = |rel: &str| rel.rsplit('/').next().unwrap_or(rel).to_string();
    let mut templates: Vec<String> = Vec::new();
    let mut entries: Vec<TemplateEntry> = Vec::new();
    for (rel, path) in &files {
        if !is_env_template_file(&base_of(rel)) {
            continue;
        }
        let Some(content) = read_text(path) else { continue };
        templates.push(rel.clone());
        entries.extend(parse_template(&content).into_iter().map(|(line, name)| TemplateEntry { file: rel.clone(), line, name }));
    }
    if templates.is_empty() {
        return Ok(EnvVarDriftResult { findings: vec![], engine: "not_applicable", templates });
    }
    let documented: BTreeSet<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    let mention_re = if documented.is_empty() {
        None
    } else {
        Regex::new(&format!(r"\b(?:{})\b", documented.iter().map(|n| regex::escape(n)).collect::<Vec<_>>().join("|"))).ok()
    };

    let mut undocumented: BTreeMap<String, Vec<ReadSite>> = BTreeMap::new();
    let mut mentioned: BTreeSet<String> = BTreeSet::new();
    for (rel, path) in &files {
        let base = base_of(rel);
        // Real `.env` files (and the templates themselves) are the
        // documentation side, never the "used by" side.
        if base.to_lowercase().starts_with(".env") || is_doc_file(rel) {
            continue;
        }
        let lang = Lang::for_path(rel);
        if lang.is_none() && mention_re.is_none() {
            continue;
        }
        let Some(content) = read_text(path) else { continue };

        if let Some(re) = &mention_re {
            mentioned.extend(re.find_iter(&content).map(|m| m.as_str().to_string()));
        }
        let Some(lang) = lang else { continue };
        if is_test_path(rel) {
            continue;
        }
        for (line, name) in extract_reads(&content, lang) {
            if documented.contains(name.as_str()) || is_platform_var(&name) {
                continue;
            }
            let sites = undocumented.entry(name).or_default();
            let code = if sites.is_empty() { build_snippet(&content, line, SnippetOptions::default()) } else { None };
            sites.push(ReadSite { file: rel.clone(), line, code });
        }
    }

    let template_list = templates.join(", ");
    let mut findings = Vec::new();
    for (name, mut sites) in undocumented {
        let first = sites.remove(0);
        let others = if sites.is_empty() { String::new() } else { format!(" ({} other read site(s))", sites.len()) };
        findings.push(EnvVarDriftFinding {
            file: first.file,
            line: first.line,
            kind: KIND_UNDOCUMENTED,
            message: format!("Environment variable `{name}` is read here but not documented in {template_list}{others} — add a `{name}=` (or commented `# {name}=`) entry."),
            var: name,
            tool: "env-var-drift",
            severity: "warning",
            code: first.code,
        });
    }
    for entry in &entries {
        if mentioned.contains(&entry.name) || is_implicitly_consumed(&entry.name) {
            continue;
        }
        let code = std::fs::read_to_string(root.join(&entry.file)).ok().and_then(|c| build_snippet(&c, entry.line, SnippetOptions::default()));
        findings.push(EnvVarDriftFinding {
            file: entry.file.clone(),
            line: entry.line,
            kind: KIND_STALE,
            message: format!("`{}` is documented in {} but nothing in the project references it — a stale entry, or read through a dynamic name this check can't see.", entry.name, entry.file),
            var: entry.name.clone(),
            tool: "env-var-drift",
            severity: "info",
            code,
        });
    }

    Ok(EnvVarDriftResult { findings, engine: "built-in", templates })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn run(files: &[(&str, &str)]) -> EnvVarDriftResult {
        let dir = tempdir().unwrap();
        for (rel, content) in files {
            let path = dir.path().join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        let result = check_env_var_drift(dir.path(), &EnvVarDriftConfig::default()).unwrap();
        ignite_fs_utils::invalidate_walk_cache(dir.path());
        result
    }

    fn vars(result: &EnvVarDriftResult, kind: &str) -> Vec<String> {
        result.findings.iter().filter(|f| f.kind == kind).map(|f| f.var.clone()).collect()
    }

    #[test]
    fn disabled_reports_nothing() {
        let dir = tempdir().unwrap();
        let result = check_env_var_drift(dir.path(), &EnvVarDriftConfig { enabled: false }).unwrap();
        assert_eq!(result.engine, "disabled");
        assert!(result.findings.is_empty());
    }

    #[test]
    fn no_template_is_not_applicable() {
        let result = run(&[("src/main.rs", "fn main() { std::env::var(\"API_TOKEN\").ok(); }\n")]);
        assert_eq!(result.engine, "not_applicable");
        assert!(result.findings.is_empty());
    }

    #[test]
    fn commented_template_entries_count_as_documented() {
        let result = run(&[
            (".env.example", "PORT=8080\n# DAILY_REPORT_WEBHOOK_URL=\n#DAILY_REPORT_TOKEN=abc\n# e.g. foo=bar is prose\n"),
            ("src/main.rs", "fn main() {\n    env_str(\"DAILY_REPORT_WEBHOOK_URL\");\n    std::env::var(\"DAILY_REPORT_TOKEN\").ok();\n    std::env::var(\"PORT\").ok();\n}\n"),
        ]);
        assert_eq!(result.engine, "built-in");
        assert!(result.findings.is_empty(), "{:?}", result.findings);
    }

    #[test]
    fn parse_template_handles_export_and_ignores_prose() {
        let parsed = parse_template("export A=1\n  B = 2\n# C=\n# see foo=bar\n#   \nD\n");
        assert_eq!(parsed, vec![(1, "A".to_string()), (2, "B".to_string()), (3, "C".to_string())]);
    }

    #[test]
    fn flags_undocumented_reads_across_languages_once_per_var() {
        let result = run(&[
            (".env.example", "KNOWN=1\n"),
            ("src/a.rs", "fn f() { let _ = std::env::var(\"RUST_ONE\"); let _ = env!(\"RUST_TWO\"); let _ = env_num::<u64>(\"RUST_THREE\"); let _ = std::env::var(\"KNOWN\"); }\n"),
            ("web/app.ts", "const a = process.env.JS_ONE;\nconst b = process.env['JS_TWO'];\nconst c = import.meta.env.VITE_THREE;\nprocess.env.JS_WRITTEN = 'x';\nif (process.env.JS_ONE === 'y') {}\n"),
            ("svc/app.py", "import os\nos.environ['PY_ONE']\nos.getenv(\"PY_TWO\")\nos.environ.get('PY_THREE')\nos.environ['PY_WRITTEN'] = '1'\n"),
            ("cmd/main.go", "v := os.Getenv(\"GO_ONE\")\n_, ok := os.LookupEnv(\"GO_TWO\")\n"),
            ("App.java", "String s = System.getenv(\"JAVA_ONE\");\n"),
            ("App.cs", "var s = Environment.GetEnvironmentVariable(\"CS_ONE\");\n"),
            ("app.rb", "ENV['RB_ONE']\nENV.fetch(\"RB_TWO\")\n"),
            ("docker-compose.yml", "services:\n  app:\n    image: \"x:${COMPOSE_TAG:-latest}\"\n    command: echo $${NOT_A_READ}\n"),
        ]);
        let mut got = vars(&result, KIND_UNDOCUMENTED);
        got.sort();
        let mut want = vec![
            "RUST_ONE", "RUST_TWO", "RUST_THREE", "JS_ONE", "JS_TWO", "VITE_THREE", "PY_ONE", "PY_TWO", "PY_THREE", "GO_ONE", "GO_TWO", "JAVA_ONE", "CS_ONE", "RB_ONE",
            "RB_TWO", "COMPOSE_TAG",
        ];
        want.sort();
        assert_eq!(got, want);
        let js_one = result.findings.iter().find(|f| f.var == "JS_ONE").unwrap();
        assert_eq!((js_one.file.as_str(), js_one.line), ("web/app.ts", 1));
        assert!(js_one.message.contains("1 other read site"));
        assert!(js_one.code.is_some());
        assert!(result.findings.iter().all(|f| f.severity == "warning" || f.kind == KIND_STALE));
    }

    #[test]
    fn skips_dynamic_names_platform_vars_comments_and_tests() {
        let result = run(&[
            (".env.example", "KNOWN=1\n"),
            (
                "src/lib.rs",
                "pub fn f(name: &str) {\n    let _ = std::env::var(name);\n    let _ = std::env::var(\"HOME\");\n    let _ = env!(\"CARGO_PKG_VERSION\");\n    // std::env::var(\"IN_A_COMMENT\")\n    let _ = std::env::var(\"KNOWN\");\n}\n\n#[cfg(test)]\nmod tests {\n    fn t() { std::env::var(\"TEST_ONLY\").ok(); }\n}\n\npub fn after() {\n    let _ = std::env::var(\"AFTER_TEST_MOD\");\n}\n",
            ),
            ("tests/it.rs", "fn t() { std::env::var(\"INTEGRATION_ONLY\").ok(); }\n"),
            ("web/app.test.ts", "process.env.JEST_ONLY;\n"),
        ]);
        assert_eq!(vars(&result, KIND_UNDOCUMENTED), vec!["AFTER_TEST_MOD"], "{:?}", result.findings);
    }

    #[test]
    fn flags_stale_template_entries_but_not_mentioned_or_implicit_ones() {
        let result = run(&[
            (".env.example", "USED_IN_CODE=1\nUSED_IN_DOCKERFILE=1\nUSED_IN_WORKFLOW=1\n# COMMENTED_STALE=\nSTALE_ONE=\nAWS_REGION=eu-west-1\nONLY_IN_README=\n"),
            ("src/main.rs", "fn main() { std::env::var(\"USED_IN_CODE\").ok(); }\n"),
            ("Dockerfile", "FROM alpine\nARG USED_IN_DOCKERFILE\n"),
            (".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - run: echo ${{ env.USED_IN_WORKFLOW }}\n"),
            ("README.md", "Set ONLY_IN_README to something.\n"),
            (".env", "STALE_ONE=real-value\n"),
        ]);
        let mut stale = vars(&result, KIND_STALE);
        stale.sort();
        assert_eq!(stale, vec!["COMMENTED_STALE", "ONLY_IN_README", "STALE_ONE"]);
        let entry = result.findings.iter().find(|f| f.var == "STALE_ONE").unwrap();
        assert_eq!((entry.file.as_str(), entry.line, entry.severity), (".env.example", 5, "info"));
        assert!(entry.code.is_some());
    }

    #[test]
    fn documented_set_is_the_union_of_every_template() {
        let result = run(&[
            ("services/api/.env.example", "API_KEY=\n"),
            ("services/web/.env.sample", "WEB_ORIGIN=\n"),
            ("services/api/main.py", "import os\nos.getenv('API_KEY')\nos.getenv('WEB_ORIGIN')\n"),
        ]);
        assert!(vars(&result, KIND_UNDOCUMENTED).is_empty());
        assert_eq!(result.templates.len(), 2);
    }
}
