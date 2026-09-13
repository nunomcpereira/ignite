//! Built-in CSS/Tailwind dead-class scan. Faithful port of
//! `checks/css-dead-code.js`. Deliberately one-directional: only
//! declared-but-unused CSS classes are flagged, never "unused Tailwind
//! utilities" (those only exist if referenced in the first place).
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

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
// `class="..."`/`className='...'` plain string forms, plus the JSX
// `className={`...`}` template-literal form the JS original already
// covered — extended here with `className={'...'}`/`className={"..."}`
// (a string literal *inside* the `{}` expression, not a template
// literal — equally common in real JSX and previously unmatched
// entirely, so any class only ever referenced that way was invisible to
// `extract_used_classes` and got misreported as dead).
static CLASS_ATTR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(?:class|className)\s*=\s*(?:"([^"]*)"|'([^']*)'|\{`([^`]*)`\}|\{"([^"]*)"\}|\{'([^']*)'\})"#).unwrap()
});
// Svelte's `class:name` / `class:name={expr}` directive shorthand — the
// class named right in the attribute is applied whenever `expr` (or the
// implied same-named variable) is truthy, so it counts as "used" on its
// own regardless of what's inside `{}`. Previously unmatched, so every
// class only ever referenced this way was flagged as dead code.
static SVELTE_CLASS_DIRECTIVE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bclass:([A-Za-z_-][\w-]*)").unwrap());
// Vue's `:class="..."`/`v-bind:class="..."` binding — same string-literal
// shape as `class=`, just a different attribute name. A dynamic
// object/array expression (`:class="{ active: isActive }"`) still has its
// class names as bare quoted strings inside, which the shared
// `extract_quoted_words` helper below picks up regardless.
static VUE_CLASS_BIND_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?:v-bind:class|:class)\s*=\s*"([^"]*)""#).unwrap());
// `clsx(...)`/`classnames(...)`/`cn(...)` utility calls and
// `classList.add/remove/toggle(...)` — extracts every quoted-string
// argument's contents (each may itself be space-separated classes) rather
// than trying to fully parse the call's actual JS argument expression.
// Only matches the call's opening `(` — the argument list itself is
// extracted separately via balanced-parenthesis scanning
// (`extract_balanced_call_args` below), since `[^)]*` truncates at the
// first `)`, which a nested call/expression inside the arguments
// (`clsx(isMobile(req), "btn-primary")`) reaches long before the real
// closing paren.
static CLASS_UTILITY_CALL_START_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:clsx|classnames|cn|classList\.(?:add|remove|toggle))\(").unwrap());
static QUOTED_STRING_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#""([^"]*)"|'([^']*)'|`([^`]*)`"#).unwrap());
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
        let raw = cap.get(1).or_else(|| cap.get(2)).or_else(|| cap.get(3)).or_else(|| cap.get(4)).or_else(|| cap.get(5)).map(|m| m.as_str()).unwrap_or("");
        for cls in raw.split_whitespace() {
            names.insert(cls.to_string());
        }
    }
    for cap in SVELTE_CLASS_DIRECTIVE_RE.captures_iter(markup_content) {
        names.insert(cap[1].to_string());
    }
    for cap in VUE_CLASS_BIND_RE.captures_iter(markup_content) {
        for cls in cap[1].split_whitespace() {
            names.insert(cls.to_string());
        }
    }
    for m in CLASS_UTILITY_CALL_START_RE.find_iter(markup_content) {
        let args = extract_balanced_call_args(&markup_content[m.end()..]);
        for qcap in QUOTED_STRING_RE.captures_iter(args) {
            let raw = qcap.get(1).or_else(|| qcap.get(2)).or_else(|| qcap.get(3)).map(|m| m.as_str()).unwrap_or("");
            for cls in raw.split_whitespace() {
                names.insert(cls.to_string());
            }
        }
    }
    names
}

/// Given the text right after a call's opening `(` (already consumed),
/// returns the slice up to its matching closing `)` — tracking nested
/// parens and skipping over `)` characters inside a quoted string, so a
/// nested call or an expression argument (`clsx(isMobile(req), "btn")`)
/// doesn't truncate the argument list at the first `)` encountered.
fn extract_balanced_call_args(rest: &str) -> &str {
    let mut depth = 1i32;
    let mut in_quote: Option<char> = None;
    let mut escape_next = false;
    for (i, c) in rest.char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        if let Some(q) = in_quote {
            if c == '\\' {
                escape_next = true;
                continue;
            }
            if c == q {
                in_quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' | '`' => in_quote = Some(c),
            '(' => depth += 1,
            ')' => {
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
            // Plain `.contains` would match `.btn` inside a `.btn-primary`
            // line and misattribute the finding to the wrong selector's
            // line — require the class name to actually end there (same
            // "not immediately followed by an identifier char" check
            // `next_char_ends_selector` already applies during extraction).
            let needle = format!(".{cls}");
            let line_idx = content.split('\n').position(|l| l.match_indices(&needle).any(|(i, _)| next_char_ends_selector(&l[i + needle.len()..])));
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
