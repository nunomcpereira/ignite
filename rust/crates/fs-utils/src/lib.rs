//! Pure filesystem/content helpers shared by Ignite's checks — file
//! discovery, binary detection, code-snippet extraction. Faithful Rust port
//! of `lib/fs-utils.js`, kept function-for-function so behavior (and any
//! future fix) stays easy to diff against the Node original.
//!
//! No async runtime dependency here on purpose: the Node version's
//! `async function*` walk exists to cooperate with Node's single-threaded
//! event loop, not because directory traversal is actually asynchronous
//! I/O-bound in a way that benefits from it. A plain synchronous walk (this
//! port) is the more direct translation of what the code is doing.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// .angular is Angular CLI/Vite's own build cache (ng-cli-cache or vite's
/// deps_ssr chunks) — bundled, minified copies of third-party dependencies
/// (date-fns, firebase, express, ...) re-vendored under the project root,
/// not source anyone wrote or would review. Measured on a real 6-workspace
/// Angular monorepo: three .angular/cache directories accounted for 592k of
/// 950k total scanned lines (62%) — the single largest fixable chunk of
/// Phase 4's wall time was every check (semgrep, secrets, CodeQL, ...)
/// dutifully scanning the same vendored dependency bundles three times over.
pub fn skip_dirs() -> &'static HashSet<&'static str> {
    static SKIP_DIRS: std::sync::OnceLock<HashSet<&'static str>> = std::sync::OnceLock::new();
    SKIP_DIRS.get_or_init(|| {
        [
            "node_modules",
            ".git",
            ".next",
            ".angular",
            "dist",
            "build",
            "__pycache__",
            ".venv",
            "venv",
            "vendor",
            ".idea",
            ".vscode",
        ]
        .into_iter()
        .collect()
    })
}

pub const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "tiff", "pdf", "zip", "gz", "tar", "bz2",
    "7z", "rar", "woff", "woff2", "ttf", "otf", "eot", "mp3", "mp4", "mov", "avi", "mkv", "wav",
    "ogg", "exe", "dll", "so", "dylib", "bin", "o", "a", "class", "pyc", "wasm", "jar", "db",
    "sqlite", "sqlite3",
];

pub const SECRET_SCAN_CODE_EXTS: &[&str] = &[
    "js", "jsx", "ts", "tsx", "mjs", "cjs", "py", "go", "rb", "php", "java", "kt", "cs", "c",
    "cpp", "h", "hpp", "swift", "rs", "scala",
];

/// NUL byte in the first 8 KB is the classic binary heuristic.
pub fn looks_binary(buffer: &[u8]) -> bool {
    let slice = &buffer[..buffer.len().min(8192)];
    slice.contains(&0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnippetLine {
    pub number: usize,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snippet {
    pub start_line: usize,
    pub lines: Vec<SnippetLine>,
    pub highlight_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub highlight_end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub highlight_start: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub highlight_end: Option<usize>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SnippetOptions {
    pub col_start: Option<usize>,
    pub col_end: Option<usize>,
    pub radius: Option<usize>,
    pub end_line: Option<usize>,
}

/// Captures a few lines of context around a finding so the review UI can
/// show a code preview with the offending span highlighted, instead of a
/// bare file:line reference.
pub fn build_snippet(content: &str, line_number: usize, opts: SnippetOptions) -> Option<Snippet> {
    if line_number < 1 {
        return None;
    }
    // A naive split(['\r','\n']) over-splits on \r\n (empty string between
    // them); split_lines mirrors JS's /\r?\n/ semantics exactly.
    let lines: Vec<&str> = split_lines(content);
    let idx = line_number - 1;
    if idx >= lines.len() {
        return None;
    }

    let radius = opts.radius.unwrap_or(3);
    let highlight_end_line = match opts.end_line {
        Some(e) if e > line_number => e,
        _ => line_number,
    };
    let end_idx = (lines.len() - 1).min(highlight_end_line - 1);

    let start = idx.saturating_sub(radius);
    let end = (lines.len() - 1).min(end_idx + radius);

    let mut code = Vec::with_capacity(end - start + 1);
    for (i, line) in lines.iter().enumerate().take(end + 1).skip(start) {
        code.push(SnippetLine {
            number: i + 1,
            text: (*line).to_string(),
        });
    }

    let (highlight_start, highlight_end) = match (opts.col_start, opts.col_end) {
        (Some(cs), Some(ce)) if ce > cs => (Some(cs), Some(ce)),
        _ => (None, None),
    };

    Some(Snippet {
        start_line: start + 1,
        lines: code,
        highlight_line: line_number,
        highlight_end_line: if highlight_end_line > line_number {
            Some(highlight_end_line)
        } else {
            None
        },
        highlight_start,
        highlight_end,
    })
}

fn split_lines(content: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut rest = content;
    loop {
        match rest.find('\n') {
            Some(pos) => {
                let line = &rest[..pos];
                let line = line.strip_suffix('\r').unwrap_or(line);
                lines.push(line);
                rest = &rest[pos + 1..];
            }
            None => {
                lines.push(rest);
                break;
            }
        }
    }
    lines
}

// --- .gitignore-syntax pattern matching --------------------------------

#[derive(Debug, Clone)]
pub struct IgnorePattern {
    regex: GlobRegex,
    negate: bool,
}

/// Minimal .gitignore matcher: last-matching pattern wins (negation with `!`
/// supported), `*`/`**`/`?` handled, `/`-anchored vs anywhere-in-tree
/// patterns distinguished. Good enough to recognize the common cases
/// (`.env`, `.env*`) without pulling in a full gitignore-semantics crate —
/// same scope as the Node original, ported logic-for-logic rather than
/// swapped for the `ignore` crate's fuller (and behaviorally different)
/// semantics.
pub fn gitignore_pattern_to_regex(raw_pattern: &str) -> IgnorePattern {
    let mut pattern = raw_pattern.trim().to_string();
    let mut negate = false;
    if let Some(stripped) = pattern.strip_prefix('!') {
        negate = true;
        pattern = stripped.to_string();
    }
    let anchored = pattern.starts_with('/');
    if anchored {
        pattern = pattern[1..].to_string();
    }
    if let Some(stripped) = pattern.strip_suffix('/') {
        pattern = stripped.to_string();
    }
    IgnorePattern {
        regex: GlobRegex::compile(&pattern, anchored),
        negate,
    }
}

pub fn is_gitignored(patterns: &[IgnorePattern], rel_path: &str) -> bool {
    let normalized = rel_path.replace(std::path::MAIN_SEPARATOR, "/");
    let mut ignored = false;
    for p in patterns {
        if p.regex.is_match(&normalized) {
            ignored = !p.negate;
        }
    }
    ignored
}

/// A tiny hand-rolled glob matcher covering exactly what
/// gitignorePatternToRegex needs (`*`, `**`, `?`, and an anchored vs.
/// anywhere-in-tree mode) — no regex crate dependency for something this
/// small.
#[derive(Debug, Clone)]
struct GlobRegex {
    tokens: Vec<GlobToken>,
    anchored: bool,
}

#[derive(Debug, Clone)]
enum GlobToken {
    Literal(char),
    Star,       // `*` - matches any run of non-'/' chars
    DoubleStar, // `**` - matches any run of chars including '/'
    AnyChar,    // `?` - matches exactly one non-'/' char... JS impl used [^/] for `?` too
}

impl GlobRegex {
    fn compile(pattern: &str, anchored: bool) -> Self {
        let mut tokens = Vec::new();
        let chars: Vec<char> = pattern.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '*' {
                if i + 1 < chars.len() && chars[i + 1] == '*' {
                    tokens.push(GlobToken::DoubleStar);
                    i += 2;
                } else {
                    tokens.push(GlobToken::Star);
                    i += 1;
                }
            } else if chars[i] == '?' {
                tokens.push(GlobToken::AnyChar);
                i += 1;
            } else {
                tokens.push(GlobToken::Literal(chars[i]));
                i += 1;
            }
        }
        GlobRegex { tokens, anchored }
    }

    /// Mirrors the JS regex `^pattern(/.*)?$` (anchored) or
    /// `(^|/)pattern(/.*)?$` (anywhere-in-tree).
    fn is_match(&self, haystack: &str) -> bool {
        if self.anchored {
            self.match_at(haystack, 0)
        } else {
            // Try matching the pattern starting at the beginning, or right
            // after any '/' in the haystack.
            if self.match_at(haystack, 0) {
                return true;
            }
            for (i, c) in haystack.char_indices() {
                if c == '/' && self.match_at(haystack, i + 1) {
                    return true;
                }
            }
            false
        }
    }

    fn match_at(&self, haystack: &str, start: usize) -> bool {
        let hay: Vec<char> = haystack[start..].chars().collect();
        self.match_tokens(&self.tokens, &hay, 0, 0)
    }

    /// Backtracking matcher for the small token set above, then requires
    /// the rest of the haystack (if any) to be exactly `(/.*)?` — i.e. the
    /// pattern must match a full path segment, optionally followed by a
    /// deeper path.
    fn match_tokens(&self, tokens: &[GlobToken], hay: &[char], ti: usize, hi: usize) -> bool {
        if ti == tokens.len() {
            return hi == hay.len() || hay[hi] == '/';
        }
        match &tokens[ti] {
            GlobToken::Literal(c) => {
                hi < hay.len() && hay[hi] == *c && self.match_tokens(tokens, hay, ti + 1, hi + 1)
            }
            GlobToken::AnyChar => {
                hi < hay.len() && hay[hi] != '/' && self.match_tokens(tokens, hay, ti + 1, hi + 1)
            }
            GlobToken::Star => {
                let mut j = hi;
                loop {
                    if self.match_tokens(tokens, hay, ti + 1, j) {
                        return true;
                    }
                    if j >= hay.len() || hay[j] == '/' {
                        return false;
                    }
                    j += 1;
                }
            }
            GlobToken::DoubleStar => {
                let mut j = hi;
                loop {
                    if self.match_tokens(tokens, hay, ti + 1, j) {
                        return true;
                    }
                    if j >= hay.len() {
                        return false;
                    }
                    j += 1;
                }
            }
        }
    }
}

fn load_ignore_file_patterns(root: &Path, filename: &str) -> Vec<IgnorePattern> {
    match fs::read_to_string(root.join(filename)) {
        Ok(content) => content
            .split(['\n'])
            .map(|l| l.trim_end_matches('\r'))
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            })
            .map(gitignore_pattern_to_regex)
            .collect(),
        Err(_) => Vec::new(), // no such file at the project root — nothing to exempt/exclude
    }
}

/// Shared by checkEnvFiles/checkSecrets in the Node original: a file this
/// pipeline will never commit/push (because the project's own .gitignore
/// excludes it) poses no leak risk through this pipeline.
pub fn load_gitignore_patterns(root: &Path) -> Vec<IgnorePattern> {
    load_ignore_file_patterns(root, ".gitignore")
}

/// checks/igniteignore.js's counterpart — a project-root .igniteignore
/// (same .gitignore syntax) that `walk_files` honors directly.
pub fn load_igniteignore_patterns(root: &Path) -> Vec<IgnorePattern> {
    load_ignore_file_patterns(root, ".igniteignore")
}

// --- Directory walk -----------------------------------------------------

/// .igniteignore is honored here, at the one choke point every check's file
/// discovery already goes through — a project-root .igniteignore is loaded
/// once per top-level `walk_files(root)` call and an ignored directory is
/// pruned before it's ever descended into, same as SKIP_DIRS.
fn walk_dir(root: &Path, dir: &Path, ignore_patterns: &[IgnorePattern], out: &mut Vec<PathBuf>) -> io::Result<()> {
    let entries = fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue; // never follow symlinks out of staging
        }
        let full = entry.path();
        if !ignore_patterns.is_empty() {
            let rel = full
                .strip_prefix(root)
                .unwrap_or(&full)
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            if is_gitignored(ignore_patterns, &rel) {
                continue;
            }
        }
        if file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if skip_dirs().contains(name.as_ref()) {
                continue;
            }
            walk_dir(root, &full, ignore_patterns, out)?;
        } else if file_type.is_file() {
            out.push(full);
        }
    }
    Ok(())
}

fn compute_file_list(root: &Path) -> io::Result<Vec<PathBuf>> {
    let ignore_patterns = load_igniteignore_patterns(root);
    let mut files = Vec::new();
    walk_dir(root, root, &ignore_patterns, &mut files)?;
    Ok(files)
}

/// `walk_files(root)` is called independently by ~10 of Phase 4's built-in
/// checks in the Node original, all running concurrently, each re-walking
/// the same directory tree from scratch. Same cache-per-root fix ported
/// here: the resolved file list is memoized per canonicalized root and
/// reused across calls within the process, invalidated explicitly via
/// `invalidate_walk_cache` once a staged root is torn down.
static WALK_CACHE: Mutex<Option<HashMap<PathBuf, Vec<PathBuf>>>> = Mutex::new(None);

pub fn walk_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    let key = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    {
        let cache = WALK_CACHE.lock().unwrap();
        if let Some(map) = cache.as_ref() {
            if let Some(files) = map.get(&key) {
                return Ok(files.clone());
            }
        }
    }
    let files = compute_file_list(root)?;
    let mut cache = WALK_CACHE.lock().unwrap();
    cache
        .get_or_insert_with(HashMap::new)
        .insert(key, files.clone());
    Ok(files)
}

pub fn invalidate_walk_cache(root: &Path) {
    let key = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    if let Some(map) = WALK_CACHE.lock().unwrap().as_mut() {
        map.remove(&key);
    }
}

// --- Misc -----------------------------------------------------------------

pub fn hash_buffer(buffer: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(buffer);
    format!("{:x}", hasher.finalize())
}

/// Resolves an external tool's reported file path into a path relative to
/// `root`, canonicalizing both sides first (same reasoning as the Node
/// original: some tools canonicalize symlinks in their own output, others
/// don't, so only realpath-ing one side produces a technically-valid but
/// useless multi-`../` relative path).
pub fn relative_to_root(root: &Path, target_path: &str) -> PathBuf {
    let resolved = root.join(target_path);
    let real_root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let real_target = fs::canonicalize(&resolved).unwrap_or(resolved);
    pathdiff(&real_target, &real_root)
}

/// Minimal `path.relative` equivalent (no external dependency): both inputs
/// are already-canonicalized absolute paths, so a simple common-prefix
/// strip suffices.
fn pathdiff(target: &Path, base: &Path) -> PathBuf {
    let target_components: Vec<_> = target.components().collect();
    let base_components: Vec<_> = base.components().collect();
    let mut common = 0;
    while common < target_components.len()
        && common < base_components.len()
        && target_components[common] == base_components[common]
    {
        common += 1;
    }
    let mut result = PathBuf::new();
    for _ in common..base_components.len() {
        result.push("..");
    }
    for comp in &target_components[common..] {
        result.push(comp.as_os_str());
    }
    result
}

const ENV_TEMPLATE_SUFFIXES: &[&str] = &[".example", ".sample", ".template", ".dist", ".defaults"];

/// .env.example/.sample/.template/.dist/.defaults are the documented-defaults
/// convention — by design they hold no real secrets and are meant to be
/// committed, so they're never flagged.
pub fn is_env_template_file(base: &str) -> bool {
    let lower = base.to_lowercase();
    lower.starts_with(".env") && ENV_TEMPLATE_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn looks_binary_detects_nul_byte() {
        assert!(looks_binary(b"hello\0world"));
        assert!(!looks_binary(b"hello world"));
    }

    #[test]
    fn is_env_template_file_matches_conventional_suffixes() {
        assert!(is_env_template_file(".env.example"));
        assert!(is_env_template_file(".env.sample"));
        assert!(!is_env_template_file(".env"));
        assert!(!is_env_template_file(".env.local"));
    }

    #[test]
    fn gitignore_glob_star_and_doublestar() {
        let p = gitignore_pattern_to_regex("*.env");
        assert!(is_gitignored(&[p], "config.env"));

        let p = gitignore_pattern_to_regex("dist/**");
        assert!(is_gitignored(&[p], "dist/a/b/c.js"));
    }

    #[test]
    fn gitignore_negation_last_match_wins() {
        let patterns = vec![
            gitignore_pattern_to_regex("*.log"),
            gitignore_pattern_to_regex("!important.log"),
        ];
        assert!(is_gitignored(&patterns, "debug.log"));
        assert!(!is_gitignored(&patterns, "important.log"));
    }

    #[test]
    fn walk_files_skips_skip_dirs_and_symlinks() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        fs::write(root.join("node_modules/pkg/x.js"), "x").unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/a.js"), "a").unwrap();

        let files = walk_files(root).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("src/a.js"));
        invalidate_walk_cache(root);
    }

    #[test]
    fn walk_files_honors_igniteignore() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join(".igniteignore"), "fixtures/\n").unwrap();
        fs::create_dir_all(root.join("fixtures")).unwrap();
        fs::write(root.join("fixtures/data.json"), "{}").unwrap();
        fs::write(root.join("real.js"), "x").unwrap();

        // .igniteignore itself isn't self-excluding (same as the Node
        // original — nothing special-cases it out of its own results), so
        // the walk still surfaces it alongside real.js; only fixtures/ is
        // pruned.
        let files = walk_files(root).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|f| f.ends_with("real.js")));
        assert!(files.iter().any(|f| f.ends_with(".igniteignore")));
        assert!(!files.iter().any(|f| f.to_string_lossy().contains("fixtures")));
        invalidate_walk_cache(root);
    }

    #[test]
    fn build_snippet_captures_radius_around_line() {
        let content = "1\n2\n3\n4\n5\n6\n7\n";
        let snip = build_snippet(content, 4, SnippetOptions::default()).unwrap();
        assert_eq!(snip.highlight_line, 4);
        assert_eq!(snip.start_line, 1); // 4 - radius(3) = 1
        assert_eq!(snip.lines.len(), 7); // lines 1..=7
    }

    #[test]
    fn hash_buffer_matches_known_sha256() {
        // sha256("") — a stable, well-known vector.
        assert_eq!(
            hash_buffer(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
