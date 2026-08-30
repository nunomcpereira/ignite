//! Built-in CSS/Tailwind dead-class scan. Faithful port of
//! `checks/css-dead-code.js`. Deliberately one-directional: only
//! declared-but-unused CSS classes are flagged, never "unused Tailwind
//! utilities" (those only exist if referenced in the first place).

use ignite_fs_utils::{build_snippet, looks_binary, walk_files, SnippetOptions};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;

static CSS_EXT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\.(css|scss|less)$").unwrap());
static MARKUP_EXT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\.(js|jsx|ts|tsx|mjs|cjs|html|vue|svelte)$").unwrap());
// The JS original uses a trailing lookahead `(?=[\s,.:#[{>+~)])` the
// `regex` crate can't express directly — matched here without it, then
// `next_char_ends_selector` re-checks the character right after the match
// manually, same effective condition.
static CLASS_SELECTOR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.(-?[A-Za-z_][A-Za-z0-9_-]*)").unwrap());
static CLASS_ATTR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\b(?:class|className)\s*=\s*(?:"([^"]*)"|'([^']*)'|\{`([^`]*)`\})"#).unwrap());
static SKIP_PREFIX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(is-|has-|js-)").unwrap());

fn next_char_ends_selector(rest: &str) -> bool {
    match rest.chars().next() {
        None => false, // JS's lookahead requires one of the chars to follow — end-of-string never matches
        Some(c) => c.is_whitespace() || ",.:#[{>+~)".contains(c),
    }
}

/// Order matches the JS `Set`'s insertion order (first-seen, left to
/// right through the content) rather than an arbitrary hash order — kept
/// as a `Vec` with a dedup check instead of a bare `HashSet` so finding
/// order stays byte-identical to the Node original, not just membership-
/// identical.
pub fn extract_declared_classes(css_content: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut names = Vec::new();
    for m in CLASS_SELECTOR_RE.find_iter(css_content) {
        if next_char_ends_selector(&css_content[m.end()..]) {
            let caps = CLASS_SELECTOR_RE.captures(m.as_str()).unwrap();
            let name = caps[1].to_string();
            if seen.insert(name.clone()) {
                names.push(name);
            }
        }
    }
    names
}

pub fn extract_used_classes(markup_content: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    for cap in CLASS_ATTR_RE.captures_iter(markup_content) {
        let raw = cap.get(1).or_else(|| cap.get(2)).or_else(|| cap.get(3)).map(|m| m.as_str()).unwrap_or("");
        for cls in raw.split_whitespace() {
            names.insert(cls.to_string());
        }
    }
    names
}

#[derive(Debug, Clone, Serialize)]
pub struct CssDeadCodeFinding {
    pub file: String,
    pub line: usize,
    pub kind: &'static str,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<ignite_fs_utils::Snippet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScannedCounts {
    pub css_files: usize,
    pub markup_files: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CssDeadCodeResult {
    pub findings: Vec<CssDeadCodeFinding>,
    pub engine: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned: Option<ScannedCounts>,
}

pub struct CssDeadCodeConfig {
    pub enabled: bool,
}

pub fn check_css_dead_code(root: &Path, config: &CssDeadCodeConfig) -> std::io::Result<CssDeadCodeResult> {
    if !config.enabled {
        return Ok(CssDeadCodeResult { findings: vec![], engine: "disabled", scanned: None });
    }

    let files = walk_files(root)?;
    let mut css_files: Vec<(std::path::PathBuf, String)> = Vec::new();
    let mut used_classes: HashSet<String> = HashSet::new();
    let mut css_file_count = 0usize;
    let mut markup_file_count = 0usize;

    for file in &files {
        let path_str = file.to_string_lossy();
        let is_css = CSS_EXT_RE.is_match(&path_str);
        let is_markup = MARKUP_EXT_RE.is_match(&path_str);
        if !is_css && !is_markup {
            continue;
        }
        let Ok(buffer) = std::fs::read(file) else { continue };
        if looks_binary(&buffer) {
            continue;
        }
        let content = String::from_utf8_lossy(&buffer).into_owned();
        if is_css {
            css_files.push((file.clone(), content.clone()));
            css_file_count += 1;
        }
        if is_markup {
            for c in extract_used_classes(&content) {
                used_classes.insert(c);
            }
            markup_file_count += 1;
        }
    }

    if css_file_count == 0 {
        return Ok(CssDeadCodeResult {
            findings: vec![],
            engine: "built-in",
            scanned: Some(ScannedCounts { css_files: 0, markup_files: markup_file_count }),
        });
    }

    let mut findings = Vec::new();
    for (file, content) in &css_files {
        let declared = extract_declared_classes(content);
        let rel = rel_str(root, file);
        for cls in &declared {
            if used_classes.contains(cls) {
                continue;
            }
            if SKIP_PREFIX_RE.is_match(cls) {
                continue;
            }
            let needle = format!(".{cls}");
            let line_idx = content.split('\n').position(|l| l.contains(&needle));
            let line = line_idx.map(|i| i + 1).unwrap_or(1);
            findings.push(CssDeadCodeFinding {
                file: rel.clone(),
                line,
                kind: "unused-css-class",
                tool: "ignite-built-in",
                severity: "warning",
                message: format!(
                    "CSS class \".{cls}\" is declared in {rel} but never referenced in a class/className attribute across {markup_file_count} scanned markup file(s)."
                ),
                code: build_snippet(content, line, SnippetOptions::default()),
            });
        }
    }

    Ok(CssDeadCodeResult {
        findings,
        engine: "built-in",
        scanned: Some(ScannedCounts { css_files: css_file_count, markup_files: markup_file_count }),
    })
}

fn rel_str(root: &Path, file: &Path) -> String {
    file.strip_prefix(root).unwrap_or(file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn extract_declared_classes_handles_various_selector_shapes() {
        let css = ".button { color: red; } .card, .card-header:hover { } .-neg-margin[data-x] {}";
        let names = extract_declared_classes(css);
        assert!(names.iter().any(|n| n == "button"));
        assert!(names.iter().any(|n| n == "card"));
        assert!(names.iter().any(|n| n == "card-header"));
        assert!(names.iter().any(|n| n == "-neg-margin"));
    }

    #[test]
    fn extract_used_classes_from_all_three_class_attr_shapes() {
        let markup = r#"<div class="foo bar"></div><Comp className='baz'></Comp><X className={`dyn-${x} qux`} />"#;
        let used = extract_used_classes(markup);
        for name in ["foo", "bar", "baz", "qux"] {
            assert!(used.contains(name), "missing {name}");
        }
    }

    #[test]
    fn flags_declared_class_never_used_in_markup() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("styles.css"), ".used { } .orphan { }\n").unwrap();
        fs::write(root.join("app.jsx"), "<div className=\"used\" />\n").unwrap();

        let result = check_css_dead_code(root, &CssDeadCodeConfig { enabled: true }).unwrap();
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].message.contains("orphan"));
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn skips_is_has_js_prefixed_classes_even_if_unused() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("styles.css"), ".is-active { } .has-error { } .js-toggle { }\n").unwrap();
        fs::write(root.join("app.jsx"), "<div />\n").unwrap();

        let result = check_css_dead_code(root, &CssDeadCodeConfig { enabled: true }).unwrap();
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn no_css_files_short_circuits_with_empty_findings() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("app.jsx"), "<div className=\"foo\" />\n").unwrap();
        let result = check_css_dead_code(root, &CssDeadCodeConfig { enabled: true }).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.scanned.unwrap().css_files, 0);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        let result = check_css_dead_code(dir.path(), &CssDeadCodeConfig { enabled: false }).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.engine, "disabled");
    }
}
