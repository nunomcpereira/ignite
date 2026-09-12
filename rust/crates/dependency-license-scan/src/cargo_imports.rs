//! Rust (cargo) import-level transitive reachability — the same signal
//! `ignite_module_graph` provides for npm and `python_imports` provides
//! for pypi, reimplemented here for Rust's own syntax. Rust differs from
//! all three: idiomatic Rust routinely calls a dependency through a
//! fully-qualified path with no `use` statement at all (`rand::random()`,
//! `serde_json::to_string(&v)`), so scanning only `use` declarations
//! (this crate's own convention, and JS/Python/Go's actual import
//! syntax) would miss the common case. Instead this looks for *any*
//! `crate_name::` path prefix anywhere in the source — which correctly
//! covers both `use` and fully-qualified calls in one pass, since a
//! `use foo::bar;` line already contains the same `foo::` substring a
//! bare `foo::bar()` call would.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;

/// Cargo package names can contain hyphens; Rust identifiers can't — a
/// dependency named `some-crate` in `Cargo.toml` is always referred to
/// as `some_crate` in code. Simple, unambiguous, and (unlike Python's
/// pip-name-vs-import-name split) has no real exceptions: cargo itself
/// enforces this mapping for every published crate.
pub fn expected_rust_module_name(cargo_package_name: &str) -> String {
    cargo_package_name.replace('-', "_")
}

static RUST_PATH_PREFIX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)::").unwrap());

/// Best-effort comment/string stripper — not a real Rust lexer (doesn't
/// handle raw strings `r#"..."#`, byte strings, or nested block comments),
/// but removes the common case of a commented-out `foo::bar(...)` call or
/// a `// see https://...::...` doc link falsely registering `foo` as used.
/// Leaves a same-length placeholder (spaces, with newlines preserved)
/// rather than deleting the span, so this never shifts any position a
/// caller might otherwise report against.
fn strip_comments_and_strings(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut chars = content.char_indices().peekable();
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut in_string = false;
    let mut escaped = false;
    while let Some((_, ch)) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                out.push('\n');
            } else {
                out.push(' ');
            }
            continue;
        }
        if in_block_comment {
            if ch == '*' && chars.peek().is_some_and(|(_, n)| *n == '/') {
                chars.next();
                in_block_comment = false;
                out.push_str("  ");
            } else {
                out.push(if ch == '\n' { '\n' } else { ' ' });
            }
            continue;
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            out.push(if ch == '\n' { '\n' } else { ' ' });
            continue;
        }
        match ch {
            '/' if chars.peek().is_some_and(|(_, n)| *n == '/') => {
                chars.next();
                in_line_comment = true;
                out.push_str("  ");
            }
            '/' if chars.peek().is_some_and(|(_, n)| *n == '*') => {
                chars.next();
                in_block_comment = true;
                out.push_str("  ");
            }
            '"' => {
                in_string = true;
                out.push(' ');
            }
            other => out.push(other),
        }
    }
    out
}

/// Every distinct identifier that appears immediately before `::`
/// anywhere in the project's `.rs` source. Deliberately broader than
/// "external crate names actually used" — the same `Foo::` shape also
/// matches local module paths (`crate::`, `self::`/`super::`), enum
/// variants (`MyEnum::Variant`), and associated functions
/// (`String::from(...)`, `Vec::new()`). That's an acceptable trade-off
/// here: a caller only ever checks membership for one specific,
/// already-known Cargo.toml dependency name, so the extra noise never
/// produces a false "not imported" — the only way this over-reports
/// "used" is a local identifier that happens to collide with a real
/// dependency's crate name (a local `mod serde { ... }` alongside an
/// actual `serde` dependency, say), and erring toward not flagging a
/// dependency is the safer failure direction for a human-facing
/// annotation-only signal.
pub fn collect_used_rust_crates(root: &Path) -> HashSet<String> {
    let mut used = HashSet::new();
    let Ok(files) = ignite_fs_utils::walk_files(root) else { return used };
    for file in files.into_iter().filter(|f| f.extension().is_some_and(|e| e == "rs")) {
        let Ok(content) = std::fs::read_to_string(&file) else { continue };
        let content = strip_comments_and_strings(&content);
        for cap in RUST_PATH_PREFIX_RE.captures_iter(&content) {
            used.insert(cap[1].to_string());
        }
    }
    used
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_rust_module_name_converts_hyphens_to_underscores() {
        assert_eq!(expected_rust_module_name("tokio-util"), "tokio_util");
        assert_eq!(expected_rust_module_name("serde"), "serde");
    }

    #[test]
    fn collect_used_rust_crates_finds_use_declarations() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.rs"), "use serde::Serialize;\nuse tokio_util::sync::CancellationToken;\n").unwrap();
        let used = collect_used_rust_crates(dir.path());
        assert!(used.contains("serde"));
        assert!(used.contains("tokio_util"));
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[test]
    fn collect_used_rust_crates_finds_fully_qualified_calls_with_no_use_statement() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.rs"), "fn main() {\n    let s = serde_json::to_string(&()).unwrap();\n    let n: u32 = rand::random();\n}\n").unwrap();
        let used = collect_used_rust_crates(dir.path());
        assert!(used.contains("serde_json"));
        assert!(used.contains("rand"));
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[test]
    fn collect_used_rust_crates_empty_for_a_project_with_no_rust_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("readme.txt"), "not rust").unwrap();
        assert!(collect_used_rust_crates(dir.path()).is_empty());
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }
}
