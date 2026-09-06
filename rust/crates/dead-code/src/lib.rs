//! Built-in dead-code / unused-export / unused-dependency / circular-import
//! scan for JS/TS projects. Faithful port of `checks/dead-code.js`. Always
//! advisory — a heuristic, regex-based reachability graph, never a hard
//! gate.
//!
//! The JS original's optional TypeScript-AST confirmation pass (upgrading
//! `unused-export` candidates via the *scanned project's own* `typescript`
//! npm package, when present in its `node_modules`) is not ported: it's an
//! npm-ecosystem-specific enhancement — reaching for a real TS compiler
//! from Rust to parse someone else's JS/TS project isn't a "faithful port"
//! so much as a different feature, and pulling in `swc`/`oxc` or similar to
//! approximate it is a real scope decision, not a mechanical translation.
//! This port always reports `engine: "built-in"` (never
//! `"built-in+typescript-ast"`) and skips that narrowing step — so on a
//! project where the regex export-name match landed inside a comment/
//! string/nested scope, this can report a few more `unused-export` false
//! positives than the Node version does when TypeScript happens to be
//! available. Advisory-only, so the cost of that gap is a human glancing
//! at one extra candidate, not a wrong block.

use ignite_fs_utils::{build_snippet, SnippetOptions};
use ignite_module_graph::{build_module_graph, find_cycles, ModuleGraph, JS_TS_EXT};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

static TEST_FILE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(\.test\.|\.spec\.|[/\\]__tests__[/\\]|[/\\]__mocks__[/\\])").unwrap());
static CONFIG_FILE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\.config\.(js|cjs|mjs|ts)$|^(jest|vitest|webpack|rollup|vite|babel|eslint|tailwind|postcss|next|playwright)\.config\.").unwrap()
});
static ENTRY_BASENAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^(index|main|server|app|cli)\.(js|jsx|ts|tsx|mjs|cjs)$").unwrap());
static NAMED_IMPORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\bimport\s*\{([^}]*)\}\s*from\s*['"][^'"]+['"]"#).unwrap());
static CJS_DESTRUCTURE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(").unwrap());
static NAME_AS_ALIAS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([\w$]+)(?:\s+as\s+([\w$]+))?$").unwrap());
static DEP_ESCAPE_SPECIAL: Lazy<Regex> = Lazy::new(|| Regex::new(r#"[.*+?^${}()|\[\]\\]"#).unwrap());

#[derive(Debug, Clone, Serialize)]
pub struct DeadCodeFinding {
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<ignite_fs_utils::Snippet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeadCodeResult {
    pub findings: Vec<DeadCodeFinding>,
    pub engine: &'static str,
    pub scanned: usize,
    pub reached: usize,
    pub entries: usize,
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Collects every relative-path-shaped value from package.json's
/// main/module/types/typings/bin/exports fields and resolves each to a
/// real file in `file_set`.
fn collect_pkg_entry_points(pkg: &serde_json::Value, pkg_dir: &Path, file_set: &HashSet<PathBuf>) -> HashSet<PathBuf> {
    let mut rels: Vec<String> = Vec::new();
    let mut push = |v: &serde_json::Value| {
        if let Some(s) = v.as_str() {
            rels.push(s.to_string());
        }
    };
    for key in ["main", "module", "types", "typings"] {
        if let Some(v) = pkg.get(key) {
            push(v);
        }
    }
    if let Some(bin) = pkg.get("bin") {
        if let Some(s) = bin.as_str() {
            push(&serde_json::Value::String(s.to_string()));
        } else if let Some(obj) = bin.as_object() {
            for v in obj.values() {
                push(v);
            }
        }
    }
    fn walk_exports(node: &serde_json::Value, rels: &mut Vec<String>) {
        if let Some(s) = node.as_str() {
            rels.push(s.to_string());
        } else if let Some(obj) = node.as_object() {
            for v in obj.values() {
                walk_exports(v, rels);
            }
        }
    }
    if let Some(exports) = pkg.get("exports") {
        walk_exports(exports, &mut rels);
    }

    let mut resolved = HashSet::new();
    for rel in rels {
        let base = pkg_dir.join(&rel);
        let base = normalize_path(&base);
        let mut candidates = vec![base.clone()];
        let stem = strip_last_ext(&base);
        for ext in JS_TS_EXT {
            candidates.push(append_ext(&stem, ext));
        }
        candidates.push(append_ext(&base, ".js"));
        for cand in candidates {
            if file_set.contains(&cand) {
                resolved.insert(cand);
            }
        }
    }
    resolved
}

fn normalize_path(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn append_ext(base: &Path, ext: &str) -> PathBuf {
    let mut s = base.as_os_str().to_os_string();
    s.push(ext);
    PathBuf::from(s)
}

/// `base.replace(/\.[^./]+$/, '')` — strips a trailing `.ext` segment
/// (one with no further `.`/`/` in it), same narrow scope as the JS regex.
fn strip_last_ext(base: &Path) -> PathBuf {
    let s = base.to_string_lossy();
    static TRAILING_EXT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.[^./]+$").unwrap());
    PathBuf::from(TRAILING_EXT_RE.replace(&s, "").into_owned())
}

pub struct DeadCodeConfig {
    pub enabled: bool,
}

pub fn check_dead_code(root: &Path, config: &DeadCodeConfig) -> std::io::Result<DeadCodeResult> {
    if !config.enabled {
        return Ok(DeadCodeResult { findings: vec![], engine: "disabled", scanned: 0, reached: 0, entries: 0 });
    }

    let ModuleGraph { files, graph } = build_module_graph(root)?;
    if files.is_empty() {
        return Ok(DeadCodeResult { findings: vec![], engine: "built-in", scanned: 0, reached: 0, entries: 0 });
    }
    let file_set: HashSet<PathBuf> = files.iter().cloned().collect();

    // --- entry points -----------------------------------------------
    let mut entries: HashSet<PathBuf> = HashSet::new();
    for f in &files {
        let base = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let full = f.to_string_lossy();
        if TEST_FILE_RE.is_match(&full) || CONFIG_FILE_RE.is_match(&base) || ENTRY_BASENAME_RE.is_match(&base) {
            entries.insert(f.clone());
        }
    }
    let pkg_json_path = root.join("package.json");
    let pkg = read_json(&pkg_json_path);
    if let Some(pkg) = &pkg {
        for e in collect_pkg_entry_points(pkg, root, &file_set) {
            entries.insert(e);
        }
    }

    // --- reachability (BFS from entries) -----------------------------
    let mut reached: HashSet<PathBuf> = entries.clone();
    let mut queue: Vec<PathBuf> = entries.iter().cloned().collect();
    let mut qi = 0;
    while qi < queue.len() {
        let cur = queue[qi].clone();
        qi += 1;
        let Some(node) = graph.get(&cur) else { continue };
        for imp in &node.imports {
            if reached.insert(imp.clone()) {
                queue.push(imp.clone());
            }
        }
    }

    let mut findings = Vec::new();

    // --- circular dependencies ---------------------------------------
    for cycle_files in find_cycles(&graph) {
        let rel = rel_str(root, &cycle_files[0]);
        let mut chain_parts: Vec<String> = cycle_files.iter().map(|f| rel_str(root, f)).collect();
        chain_parts.push(rel_str(root, &cycle_files[0]));
        let chain = chain_parts.join(" -> ");
        let content = graph.get(&cycle_files[0]).map(|n| n.content.as_str()).unwrap_or("");
        findings.push(DeadCodeFinding {
            file: rel,
            line: 1,
            kind: "circular-dependency".to_string(),
            tool: "ignite-built-in",
            severity: "warning",
            message: format!("Import cycle detected: {chain}"),
            code: build_snippet(content, 1, SnippetOptions::default()),
        });
    }

    // --- unused files --------------------------------------------------
    for f in &files {
        if reached.contains(f) {
            continue;
        }
        let rel = rel_str(root, f);
        let content = graph.get(f).map(|n| n.content.as_str()).unwrap_or("");
        findings.push(DeadCodeFinding {
            file: rel.clone(),
            line: 1,
            kind: "unused-file".to_string(),
            tool: "ignite-built-in",
            severity: "warning",
            message: format!(
                "{rel} is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion."
            ),
            code: build_snippet(content, 1, SnippetOptions::default()),
        });
    }

    // --- unused exports (within reached files only) --------------------
    let mut referenced_names: HashSet<String> = HashSet::new();
    for node in graph.values() {
        for cap in NAMED_IMPORT_RE.captures_iter(&node.content) {
            for part in cap[1].split(',') {
                let piece = part.trim();
                if piece.is_empty() {
                    continue;
                }
                if let Some(m) = NAME_AS_ALIAS_RE.captures(piece) {
                    referenced_names.insert(m[1].to_string());
                }
            }
        }
        for cap in CJS_DESTRUCTURE_RE.captures_iter(&node.content) {
            for part in cap[1].split(',') {
                let piece = part.trim().split(':').next().unwrap().trim();
                if !piece.is_empty() && piece.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$') {
                    referenced_names.insert(piece.to_string());
                }
            }
        }
    }

    struct Candidate<'a> {
        file: &'a PathBuf,
        name: String,
    }
    let mut unused_export_candidates: Vec<Candidate> = Vec::new();
    for f in &files {
        if !reached.contains(f) {
            continue; // already flagged as a whole unused file
        }
        let Some(node) = graph.get(f) else { continue };
        for name in &node.exports.names {
            if referenced_names.contains(name) {
                continue;
            }
            unused_export_candidates.push(Candidate { file: f, name: name.clone() });
        }
    }

    // No TypeScript-AST confirmation pass in this port (see module doc) —
    // engine always stays "built-in".
    let engine = "built-in";

    let export_word_re = Regex::new("export").unwrap();
    for cand in &unused_export_candidates {
        let rel = rel_str(root, cand.file);
        let node = graph.get(cand.file).unwrap();
        let name_re = Regex::new(&format!(r"\b{}\b", regex::escape(&cand.name))).unwrap();
        let line_idx = node
            .content
            .split('\n')
            .position(|l| name_re.is_match(l) && export_word_re.is_match(l));
        let line = line_idx.map(|i| i + 1).unwrap_or(1);
        findings.push(DeadCodeFinding {
            file: rel.clone(),
            line,
            kind: "unused-export".to_string(),
            tool: "ignite-built-in",
            severity: "warning",
            message: format!(
                "Export \"{}\" in {rel} is never imported by name anywhere else in the project — a candidate for removal.",
                cand.name
            ),
            code: build_snippet(&node.content, line, SnippetOptions::default()),
        });
    }

    // --- unused dependencies --------------------------------------------
    if let Some(pkg) = &pkg {
        let deps = pkg.get("dependencies").and_then(|v| v.as_object());
        let dev_deps = pkg.get("devDependencies").and_then(|v| v.as_object());
        if deps.is_some() || dev_deps.is_some() {
            let mut all_deps: Vec<String> = Vec::new();
            if let Some(d) = deps {
                all_deps.extend(d.keys().cloned());
            }
            if let Some(d) = dev_deps {
                for k in d.keys() {
                    if !all_deps.contains(k) {
                        all_deps.push(k.clone());
                    }
                }
            }
            let whole_source: String = graph.values().map(|n| n.content.as_str()).collect::<Vec<_>>().join("\n");
            let scripts_json = pkg.get("scripts").cloned().unwrap_or(serde_json::json!({})).to_string();

            for dep in &all_deps {
                let escaped = DEP_ESCAPE_SPECIAL.replace_all(dep, r"\$0");
                let used_re = Regex::new(&format!(r#"(?:from|require\()\s*['"]{escaped}(?:/[^'"]*)?['"]"#)).unwrap();
                if used_re.is_match(&whole_source) {
                    continue;
                }
                if scripts_json.contains(dep.as_str()) {
                    continue;
                }
                findings.push(DeadCodeFinding {
                    file: "package.json".to_string(),
                    line: 1,
                    kind: "unused-dependency".to_string(),
                    tool: "ignite-built-in",
                    severity: "warning",
                    message: format!(
                        "Dependency \"{dep}\" is declared in package.json but never imported/required from any scanned source file and isn't referenced by an npm script."
                    ),
                    code: None,
                });
            }
        }
    }

    Ok(DeadCodeResult { findings, engine, scanned: files.len(), reached: reached.len(), entries: entries.len() })
}

fn rel_str(root: &Path, file: &Path) -> String {
    file.strip_prefix(root).unwrap_or(file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn enabled() -> DeadCodeConfig {
        DeadCodeConfig { enabled: true }
    }

    #[test]
    fn flags_a_file_never_imported_from_any_entry_point() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"main": "index.js"}"#).unwrap();
        fs::write(root.join("index.js"), "require('./used');\n").unwrap();
        fs::write(root.join("used.js"), "module.exports = 1;\n").unwrap();
        fs::write(root.join("orphan.js"), "module.exports = 2;\n").unwrap();

        let result = check_dead_code(root, &enabled()).unwrap();
        let unused_files: Vec<_> = result.findings.iter().filter(|f| f.kind == "unused-file").collect();
        assert_eq!(unused_files.len(), 1);
        assert_eq!(unused_files[0].file, "orphan.js");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn flags_an_export_never_imported_by_name() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"main": "index.js"}"#).unwrap();
        fs::write(
            root.join("index.js"),
            "import { helperA } from './lib';\nconsole.log(helperA());\n",
        )
        .unwrap();
        fs::write(
            root.join("lib.js"),
            "export function helperA() { return 1; }\nexport function helperB() { return 2; }\n",
        )
        .unwrap();

        let result = check_dead_code(root, &enabled()).unwrap();
        let unused_exports: Vec<_> = result.findings.iter().filter(|f| f.kind == "unused-export").collect();
        assert_eq!(unused_exports.len(), 1);
        assert!(unused_exports[0].message.contains("helperB"));
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn flags_a_dependency_never_imported_or_scripted() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(
            root.join("package.json"),
            r#"{"main": "index.js", "dependencies": {"lodash": "^4.0.0", "express": "^4.0.0"}, "scripts": {"start": "express-server"}}"#,
        )
        .unwrap();
        fs::write(root.join("index.js"), "const _ = require('lodash');\n").unwrap();

        let result = check_dead_code(root, &enabled()).unwrap();
        let unused_deps: Vec<_> = result.findings.iter().filter(|f| f.kind == "unused-dependency").collect();
        // lodash is require()'d, express is mentioned in a script (even
        // though never imported) - neither should be flagged... wait,
        // express-server contains "express" as a substring, matching the
        // JS original's own scripts.includes(dep) check exactly.
        assert!(unused_deps.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn flags_a_dependency_truly_unused_by_source_or_scripts() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(
            root.join("package.json"),
            r#"{"main": "index.js", "dependencies": {"unused-pkg": "^1.0.0"}}"#,
        )
        .unwrap();
        fs::write(root.join("index.js"), "console.log('hi');\n").unwrap();

        let result = check_dead_code(root, &enabled()).unwrap();
        let unused_deps: Vec<_> = result.findings.iter().filter(|f| f.kind == "unused-dependency").collect();
        assert_eq!(unused_deps.len(), 1);
        assert!(unused_deps[0].message.contains("unused-pkg"));
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn detects_circular_dependency_between_two_files() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"main": "a.js"}"#).unwrap();
        fs::write(root.join("a.js"), "require('./b');\n").unwrap();
        fs::write(root.join("b.js"), "require('./a');\n").unwrap();

        let result = check_dead_code(root, &enabled()).unwrap();
        let cycles: Vec<_> = result.findings.iter().filter(|f| f.kind == "circular-dependency").collect();
        assert_eq!(cycles.len(), 1);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        let result = check_dead_code(dir.path(), &DeadCodeConfig { enabled: false }).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.engine, "disabled");
    }
}
