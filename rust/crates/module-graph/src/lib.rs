//! Lightweight JS/TS module graph: parses import/require/export statements
//! with regexes (no bundled parser dependency) and resolves relative
//! specifiers to real files on disk. Faithful port of
//! `lib/module-graph.js`. Shared by the dead-code and boundaries checks so
//! both walk the exact same graph.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub const JS_TS_EXT: &[&str] = &[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"];
const RESOLVABLE_EXTS: &[&str] = &[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".json"];

// `$` added to the clause character class for framework-specific
// identifiers (Svelte's `$state`, `$props`, ...) that are otherwise a
// completely ordinary named import; `/` and `\*` (a literal `*` inside a
// `/* ... */` block comment, not the namespace-import `*` this class
// already allows unescaped) let an inline comment inside the import
// clause pass through instead of breaking the match entirely. `(?s)`
// lets `\s` (used here, not `.`) span real newlines in a multiline
// import clause the same way it already needed to for a single-line one.
static IMPORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?s)\bimport\s+(?:[\w*{},\s$/]+\s+from\s+)?['"]([^'"]+)['"]"#).unwrap());
// `\*\s+as\s+\w+` covers an ES2020 namespace re-export
// (`export * as utils from './utils'`); the optional leading `type\s+`
// covers a TypeScript type-only re-export (`export type { A } from ...`,
// `export type * from ...`) — both previously fell through this regex
// entirely, leaving the target module out of the dependency graph and
// falsely reported as an `unused-file` deletion candidate.
static EXPORT_FROM_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\bexport\s+(?:type\s+)?(?:\*(?:\s+as\s+\w+)?|\{[^}]*\})\s+from\s+['"]([^'"]+)['"]"#).unwrap());
static DYNAMIC_IMPORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\bimport\(\s*['"]([^'"]+)['"]\s*\)"#).unwrap());
static REQUIRE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\brequire\(\s*['"]([^'"]+)['"]\s*\)"#).unwrap());

static EXPORT_DECL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bexport\s+(?:async\s+)?(?:function\*?|class|const|let|var)\s+([A-Za-z_$][\w$]*)").unwrap());
// The JS original is `\bexport\s*\{([^}]*)\}(?!\s*from)` — the `regex`
// crate has no lookaround support, so the "not followed by `from`"
// condition is checked manually against the text right after each match
// (see `extract_exports` below) instead of being part of the pattern.
// TypeScript type-only exports (`export type { Foo, Bar }`) put `type`
// between `export` and `{` — previously unmatched, so a type export was
// treated as unexported and falsely flagged as dead code.
static EXPORT_LIST_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bexport\s*(?:type\s+)?\{([^}]*)\}").unwrap());
static EXPORT_LIST_FOLLOWED_BY_FROM_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*from").unwrap());
static EXPORT_DEFAULT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bexport\s+default\b").unwrap());
static CJS_EXPORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:module\.exports\.|exports\.)([A-Za-z_$][\w$]*)\s*=").unwrap());
static CJS_EXPORT_OBJECT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bmodule\.exports\s*=\s*\{([^}]*)\}").unwrap());
static NAME_AS_ALIAS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([\w$]+)(?:\s+as\s+([\w$]+))?$").unwrap());

// A leading `/` is not a relative specifier in real JS/TS module
// resolution — Node/bundlers treat only `.`/`..`-prefixed specifiers as
// relative-to-the-importing-file; a bare `/foo` is either an absolute
// filesystem path or a bundler-specific root alias, neither of which this
// crate's simple relative-specifier resolver has any business treating as
// "resolve `spec` against `from_file`'s directory". `resolve_specifier`
// only ever returns a match already present in the project's own
// `file_set`, so this was never a real path-escape risk — but excluding
// `/` here means an absolute specifier is now correctly treated as a bare
// (external) specifier instead of being run through resolution at all.
pub fn is_relative_specifier(spec: &str) -> bool {
    spec.starts_with('.')
}

fn resolve_specifier(from_file: &Path, spec: &str, file_set: &HashSet<PathBuf>) -> Option<PathBuf> {
    if !is_relative_specifier(spec) {
        return None; // bare package specifier — not project-local
    }
    let base = from_file.parent().unwrap_or(Path::new("")).join(spec);
    let base = normalize_path(&base);

    if file_set.contains(&base) {
        return Some(base);
    }
    for ext in RESOLVABLE_EXTS {
        let candidate = append_ext(&base, ext);
        if file_set.contains(&candidate) {
            return Some(candidate);
        }
    }
    for ext in RESOLVABLE_EXTS {
        let candidate = base.join(format!("index{ext}"));
        if file_set.contains(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn append_ext(base: &Path, ext: &str) -> PathBuf {
    let mut s = base.as_os_str().to_os_string();
    s.push(ext);
    PathBuf::from(s)
}

/// `path.resolve` collapses `.`/`..` segments without touching the
/// filesystem — `Path::join` alone doesn't do this, so a manual lexical
/// normalization stands in.
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

pub fn extract_specifiers(content: &str) -> Vec<String> {
    let mut specs = Vec::new();
    for re in [&*IMPORT_RE, &*EXPORT_FROM_RE, &*DYNAMIC_IMPORT_RE, &*REQUIRE_RE] {
        for cap in re.captures_iter(content) {
            specs.push(cap[1].to_string());
        }
    }
    specs
}

#[derive(Debug, Clone, Default)]
pub struct ExportInfo {
    pub names: Vec<String>,
    pub has_default: bool,
}

pub fn extract_exports(content: &str) -> ExportInfo {
    let mut names_set: Vec<String> = Vec::new();
    let mut names_seen = HashSet::new();
    let mut push_name = |n: String| {
        if names_seen.insert(n.clone()) {
            names_set.push(n);
        }
    };

    let mut has_default = EXPORT_DEFAULT_RE.is_match(content);

    for cap in EXPORT_DECL_RE.captures_iter(content) {
        push_name(cap[1].to_string());
    }

    for m in EXPORT_LIST_RE.find_iter(content) {
        let after = &content[m.end()..];
        if EXPORT_LIST_FOLLOWED_BY_FROM_RE.is_match(after) {
            continue; // `export { a } from '...'` — a re-export, not a local declaration
        }
        let caps = EXPORT_LIST_RE.captures(m.as_str()).unwrap();
        for part in caps[1].split(',') {
            let piece = part.trim();
            if piece.is_empty() {
                continue;
            }
            let Some(as_match) = NAME_AS_ALIAS_RE.captures(piece) else { continue };
            if &as_match[1] == "default" {
                has_default = true;
                continue;
            }
            push_name(as_match.get(2).map_or(&as_match[1], |m| m.as_str()).to_string());
        }
    }

    for cap in CJS_EXPORT_RE.captures_iter(content) {
        push_name(cap[1].to_string());
    }

    if let Some(obj_match) = CJS_EXPORT_OBJECT_RE.captures(content) {
        for part in obj_match[1].split(',') {
            let piece = part.trim();
            if piece.is_empty() {
                continue;
            }
            // `{ key: value }` -> exported name is the key (what a consumer
            // destructures as), not the local value identifier.
            let key = piece.split(':').next().unwrap().trim();
            // JS: `.replace(/^\.\.\.$/, '')` — anchored both ends, so this
            // only clears a key that IS exactly "...", never strips a
            // "..." prefix off something like "...spread" (that stays
            // "...spread" and fails the identifier check below, same as
            // the JS original — a spread has no single destructurable key
            // name to report as an export).
            let key = if key == "..." { "" } else { key };
            if !key.is_empty() && key.chars().enumerate().all(|(i, c)| {
                if i == 0 { c.is_ascii_alphabetic() || c == '_' || c == '$' } else { c.is_ascii_alphanumeric() || c == '_' || c == '$' }
            }) {
                push_name(key.to_string());
            }
        }
    }

    ExportInfo { names: names_set, has_default }
}

#[derive(Debug, Clone)]
pub struct ModuleNode {
    pub content: String,
    pub imports: Vec<PathBuf>,
    pub bare_imports: Vec<String>,
    pub exports: ExportInfo,
}

pub struct ModuleGraph {
    pub files: Vec<PathBuf>,
    pub graph: HashMap<PathBuf, ModuleNode>,
}

/// Builds a module graph over every JS/TS-family file under root.
pub fn build_module_graph(root: &Path) -> std::io::Result<ModuleGraph> {
    let all_files = ignite_fs_utils::walk_files(root)?;
    let files: Vec<PathBuf> = all_files
        .into_iter()
        .filter(|f| f.extension().map(|e| JS_TS_EXT.contains(&format!(".{}", e.to_string_lossy()).as_str())).unwrap_or(false))
        .collect();
    let file_set: HashSet<PathBuf> = files.iter().cloned().collect();
    let mut graph = HashMap::new();

    for file in &files {
        let Ok(buffer) = std::fs::read(file) else { continue };
        if ignite_fs_utils::looks_binary(&buffer) {
            continue;
        }
        let content = String::from_utf8_lossy(&buffer).into_owned();
        let specs = extract_specifiers(&content);
        let mut imports = Vec::new();
        let mut bare_imports = Vec::new();
        for spec in specs {
            if is_relative_specifier(&spec) {
                if let Some(resolved) = resolve_specifier(file, &spec, &file_set) {
                    imports.push(resolved);
                }
            } else {
                bare_imports.push(spec);
            }
        }
        let exports = extract_exports(&content);
        graph.insert(file.clone(), ModuleNode { content, imports, bare_imports, exports });
    }

    Ok(ModuleGraph { files, graph })
}

/// Normalizes a bare import specifier to the npm root package name a
/// `package.json`/lockfile would actually list — a scoped package's own
/// subpath import (`@org/pkg/dist/thing`) still names the `@org/pkg`
/// package, and an unscoped subpath import (`lodash/get`) still names
/// `lodash`. `None` only for a specifier with a shape too degenerate to
/// name any package at all (empty string, or a bare `@` with no name
/// after it) — not expected from a real import statement, but this
/// stays a clean `None` rather than panicking on it.
pub fn root_package_name(specifier: &str) -> Option<&str> {
    if specifier.starts_with('@') {
        let mut parts = specifier.splitn(3, '/');
        let scope = parts.next()?;
        let name = parts.next()?;
        if name.is_empty() {
            return None;
        }
        Some(&specifier[..scope.len() + 1 + name.len()])
    } else {
        let name = specifier.split('/').next()?;
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }
}

/// Every distinct npm package actually imported/required anywhere in the
/// project's JS/TS source — the reachability signal
/// `dependency-license-scan`'s vulnerability findings use to note when a
/// flagged dependency isn't imported by any project file at all (present
/// only via another dependency's own transitive requirement, or listed
/// in the manifest but genuinely unused).
pub fn collect_imported_packages(graph: &ModuleGraph) -> HashSet<String> {
    graph.graph.values().flat_map(|node| node.bare_imports.iter()).filter_map(|spec| root_package_name(spec)).map(str::to_string).collect()
}

/// Finds import cycles (standard three-color DFS). Returns one array of
/// absolute file paths per distinct cycle, each starting at its
/// lexicographically-smallest member (rotation-invariant canonical form)
/// so the same cycle reached via two different entry files is reported
/// once.
pub fn find_cycles(graph: &HashMap<PathBuf, ModuleNode>) -> Vec<Vec<PathBuf>> {
    #[derive(PartialEq, Clone, Copy)]
    enum Color {
        White,
        Gray,
        Black,
    }

    let mut color: HashMap<&PathBuf, Color> = graph.keys().map(|f| (f, Color::White)).collect();
    let mut stack: Vec<&PathBuf> = Vec::new();
    let mut stack_index: HashMap<&PathBuf, usize> = HashMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut cycles: Vec<Vec<PathBuf>> = Vec::new();

    fn canonicalize(cycle_files: &[PathBuf]) -> Vec<PathBuf> {
        let mut min_idx = 0;
        for (i, f) in cycle_files.iter().enumerate().skip(1) {
            if f < &cycle_files[min_idx] {
                min_idx = i;
            }
        }
        let mut out = cycle_files[min_idx..].to_vec();
        out.extend_from_slice(&cycle_files[..min_idx]);
        out
    }

    // Recursion via an explicit worklist would be more idiomatic Rust, but
    // this graph is small enough in practice (a project's own JS/TS file
    // count) that a direct recursive port (matching the JS original's own
    // recursive dfs) keeps this easy to diff against it.
    fn dfs<'a>(
        file: &'a PathBuf,
        graph: &'a HashMap<PathBuf, ModuleNode>,
        color: &mut HashMap<&'a PathBuf, Color>,
        stack: &mut Vec<&'a PathBuf>,
        stack_index: &mut HashMap<&'a PathBuf, usize>,
        seen: &mut HashSet<String>,
        cycles: &mut Vec<Vec<PathBuf>>,
    ) {
        color.insert(file, Color::Gray);
        stack_index.insert(file, stack.len());
        stack.push(file);

        if let Some(node) = graph.get(file) {
            for imp in &node.imports {
                let Some(imp_key) = graph.get_key_value(imp).map(|(k, _)| k) else { continue };
                match color.get(imp_key).copied().unwrap_or(Color::White) {
                    Color::White => dfs(imp_key, graph, color, stack, stack_index, seen, cycles),
                    Color::Gray => {
                        let start = stack_index[imp_key];
                        let cycle_files: Vec<PathBuf> = stack[start..].iter().map(|f| (*f).clone()).collect();
                        let canon = canonicalize(&cycle_files);
                        let key = canon
                            .iter()
                            .map(|p| p.to_string_lossy().into_owned())
                            .collect::<Vec<_>>()
                            .join("\n");
                        if seen.insert(key) {
                            cycles.push(canon);
                        }
                    }
                    Color::Black => {}
                }
            }
        }

        stack.pop();
        stack_index.remove(file);
        color.insert(file, Color::Black);
    }

    let all_files: Vec<&PathBuf> = graph.keys().collect();
    for file in all_files {
        if color.get(file).copied() == Some(Color::White) {
            dfs(file, graph, &mut color, &mut stack, &mut stack_index, &mut seen, &mut cycles);
        }
    }

    cycles
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn extract_specifiers_finds_import_export_from_dynamic_and_require() {
        let content = r#"
            import a from './a';
            import { b, c as d } from './bc';
            export * from './re-export';
            export { e } from './e';
            const f = await import('./dynamic');
            const g = require('./cjs');
            import 'bare-package';
        "#;
        let specs = extract_specifiers(content);
        assert!(specs.contains(&"./a".to_string()));
        assert!(specs.contains(&"./bc".to_string()));
        assert!(specs.contains(&"./re-export".to_string()));
        assert!(specs.contains(&"./e".to_string()));
        assert!(specs.contains(&"./dynamic".to_string()));
        assert!(specs.contains(&"./cjs".to_string()));
        assert!(specs.contains(&"bare-package".to_string()));
    }

    #[test]
    fn extract_exports_covers_es_and_cjs_shapes() {
        let content = r#"
            export function foo() {}
            export class Bar {}
            export const baz = 1;
            export { qux, quux as renamed };
            export default function () {}
            module.exports.legacy = 1;
            exports.legacyToo = 2;
        "#;
        let info = extract_exports(content);
        assert!(info.has_default);
        for name in ["foo", "Bar", "baz", "qux", "renamed", "legacy", "legacyToo"] {
            assert!(info.names.contains(&name.to_string()), "missing {name}");
        }
    }

    #[test]
    fn extract_exports_export_list_followed_by_from_is_not_a_local_declaration() {
        // `export { a } from './x'` is a re-export, not something this file
        // itself declares — must not appear in extract_exports' names.
        let content = "export { a } from './x';\nexport { b };\n";
        let info = extract_exports(content);
        assert!(!info.names.contains(&"a".to_string()));
        assert!(info.names.contains(&"b".to_string()));
    }

    #[test]
    fn extract_exports_cjs_export_object_shorthand_and_aliased() {
        let content = "module.exports = { foo, bar: renamedBar, ...spread };";
        let info = extract_exports(content);
        assert!(info.names.contains(&"foo".to_string()));
        assert!(info.names.contains(&"bar".to_string()));
        assert!(!info.names.contains(&"spread".to_string()), "...spread has no destructurable key name");
    }

    #[test]
    fn build_module_graph_resolves_relative_imports_to_real_files() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.js"), "import { b } from './b';\nexport const a = 1;\n").unwrap();
        fs::write(root.join("b.js"), "export const b = 2;\n").unwrap();
        let mg = build_module_graph(root).unwrap();
        assert_eq!(mg.files.len(), 2);
        let a_path = root.join("a.js");
        let b_path = root.join("b.js");
        let a_node = mg.graph.get(&a_path).unwrap();
        assert_eq!(a_node.imports, vec![b_path]);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn find_cycles_detects_a_two_file_import_cycle() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.js"), "import './b';\n").unwrap();
        fs::write(root.join("b.js"), "import './a';\n").unwrap();
        let mg = build_module_graph(root).unwrap();
        let cycles = find_cycles(&mg.graph);
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 2);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn find_cycles_dedupes_the_same_cycle_reached_from_either_participant() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.js"), "import './b';\n").unwrap();
        fs::write(root.join("b.js"), "import './c';\n").unwrap();
        fs::write(root.join("c.js"), "import './a';\n").unwrap();
        let mg = build_module_graph(root).unwrap();
        let cycles = find_cycles(&mg.graph);
        assert_eq!(cycles.len(), 1, "a->b->c->a is one cycle regardless of DFS entry point");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn find_cycles_returns_empty_for_an_acyclic_graph() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.js"), "import './b';\n").unwrap();
        fs::write(root.join("b.js"), "export const b = 1;\n").unwrap();
        let mg = build_module_graph(root).unwrap();
        assert!(find_cycles(&mg.graph).is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn root_package_name_handles_unscoped_and_scoped_subpaths() {
        assert_eq!(root_package_name("lodash"), Some("lodash"));
        assert_eq!(root_package_name("lodash/get"), Some("lodash"));
        assert_eq!(root_package_name("@org/pkg"), Some("@org/pkg"));
        assert_eq!(root_package_name("@org/pkg/dist/thing"), Some("@org/pkg"));
    }

    #[test]
    fn root_package_name_none_for_degenerate_specifiers() {
        assert_eq!(root_package_name(""), None);
        assert_eq!(root_package_name("@org/"), None);
        assert_eq!(root_package_name("@org"), None);
    }

    #[test]
    fn collect_imported_packages_gathers_bare_imports_across_every_file() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.js"), "import _ from 'lodash';\nimport './local';\n").unwrap();
        fs::write(root.join("local.js"), "const axios = require('axios/dist/node');\nexport const x = 1;\n").unwrap();
        let mg = build_module_graph(root).unwrap();
        let imported = collect_imported_packages(&mg);
        assert!(imported.contains("lodash"));
        assert!(imported.contains("axios"));
        assert_eq!(imported.len(), 2, "a relative import ('./local') must not count as a package: {imported:?}");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn collect_imported_packages_empty_when_nothing_imports_a_bare_package() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.js"), "export const x = 1;\n").unwrap();
        let mg = build_module_graph(root).unwrap();
        assert!(collect_imported_packages(&mg).is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}
