//! Lightweight JS/TS module graph: parses import/require/export statements
//! via a real ECMAScript/TypeScript AST (`oxc_parser`) rather than regexes,
//! and resolves relative specifiers to real files on disk. Shared by the
//! dead-code and boundaries checks so both walk the exact same graph.
//!
//! A regex-based scanner (this crate's original implementation) fights a
//! context-free grammar it fundamentally can't represent — multiline
//! import clauses, TypeScript inline type exports
//! (`export { type Foo }`), ES2020 namespace re-exports, and CommonJS
//! object-shorthand `module.exports = { a, b }` each needed their own
//! regex escape hatch, and there was always another shape (a comment
//! containing `import`, a string literal containing `require(`) a purely
//! textual scanner could misparse. Parsing for real once per file and
//! walking the resulting AST handles all of these correctly by
//! construction instead of accumulating regex special cases.
//!
//! Parsing always uses [`SourceType::tsx`] regardless of the file's real
//! extension — TypeScript (and JSX) syntax is a superset of plain
//! JS/CJS, so this one permissive mode parses every extension this crate
//! supports (`.js`/`.jsx`/`.ts`/`.tsx`/`.mjs`/`.cjs`/`.mts`/`.cts`)
//! without needing to thread a real extension through `extract_specifiers`/
//! `extract_exports`'s public, content-only signatures.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{walk_js::*, VisitJs};
use oxc_parser::Parser;
use oxc_span::SourceType;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub const JS_TS_EXT: &[&str] = &[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"];
const RESOLVABLE_EXTS: &[&str] = &[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".json"];

/// Extracts the plain string content of a `ModuleExportName` — the
/// `foo`/`"foo"` on either side of an `export { local as exported }` /
/// `import { imported as local }` specifier, regardless of whether it's a
/// bare identifier or (an ES2022 addition) a string literal.
fn module_export_name_text<'a>(name: &ModuleExportName<'a>) -> &'a str {
    match name {
        ModuleExportName::IdentifierName(n) => n.name.as_str(),
        ModuleExportName::IdentifierReference(n) => n.name.as_str(),
        ModuleExportName::StringLiteral(s) => s.value.as_str(),
    }
}

/// `module.exports` as an assignment target (the object half of
/// `module.exports.foo = ...` / `module.exports = {...}`) — an
/// `Expression::StaticMemberExpression` whose own object is the bare
/// identifier `module` and whose property is `exports`.
fn is_module_dot_exports(expr: &Expression) -> bool {
    let Expression::StaticMemberExpression(sme) = expr else { return false };
    sme.property.name.as_str() == "exports" && matches!(&sme.object, Expression::Identifier(id) if id.name.as_str() == "module")
}

/// The exported name from a CJS `module.exports.X = ...` / `exports.X = ...`
/// assignment target, or `None` if `target` isn't shaped like either.
fn cjs_named_export_target<'a>(target: &'a AssignmentTarget<'a>) -> Option<&'a str> {
    let AssignmentTarget::StaticMemberExpression(sme) = target else { return None };
    let prop = sme.property.name.as_str();
    let is_bare_exports = matches!(&sme.object, Expression::Identifier(id) if id.name.as_str() == "exports");
    if is_bare_exports || is_module_dot_exports(&sme.object) {
        Some(prop)
    } else {
        None
    }
}

/// Whether `target` is exactly `module.exports` (the whole-object-replace
/// shape, `module.exports = {...}`), as opposed to `module.exports.X`/
/// `exports.X` (a single named export assignment).
fn is_module_exports_whole_object_target(target: &AssignmentTarget) -> bool {
    let AssignmentTarget::StaticMemberExpression(sme) = target else { return false };
    sme.property.name.as_str() == "exports" && matches!(&sme.object, Expression::Identifier(id) if id.name.as_str() == "module")
}

#[derive(Default)]
struct ModuleVisitor {
    specifiers: Vec<String>,
    names_set: Vec<String>,
    names_seen: HashSet<String>,
    has_default: bool,
}

impl ModuleVisitor {
    fn push_name(&mut self, n: &str) {
        if self.names_seen.insert(n.to_string()) {
            self.names_set.push(n.to_string());
        }
    }

    /// Declared binding name(s) from a top-level `export <decl>` —
    /// `function`/`class` contribute their own name (if any; an anonymous
    /// default-exported function/class carries no separate named export),
    /// `const`/`let`/`var` contribute each declarator's simple identifier.
    /// A destructuring declarator (`export const { a, b } = x`) is skipped,
    /// same as the regex-based implementation this replaces — real AST
    /// support for that is possible but out of scope for a first cut here.
    fn collect_declaration_names(&mut self, decl: &Declaration) {
        match decl {
            Declaration::FunctionDeclaration(f) => {
                if let Some(id) = &f.id {
                    self.push_name(id.name.as_str());
                }
            }
            Declaration::ClassDeclaration(c) => {
                if let Some(id) = &c.id {
                    self.push_name(id.name.as_str());
                }
            }
            Declaration::VariableDeclaration(v) => {
                for d in &v.declarations {
                    if let BindingPattern::BindingIdentifier(bi) = &d.id {
                        self.push_name(bi.name.as_str());
                    }
                }
            }
            _ => {}
        }
    }
}

impl<'a> VisitJs<'a> for ModuleVisitor {
    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        self.specifiers.push(it.source.value.as_str().to_string());
    }

    fn visit_export_from_declaration(&mut self, it: &ExportFromDeclaration<'a>) {
        // `export { a, b } from './x'` / `export type { A } from './x'` —
        // a re-export forwards names from elsewhere rather than declaring
        // them here, so (matching the prior regex-based behavior) this
        // only ever contributes the specifier path, never a local name.
        self.specifiers.push(it.source.value.as_str().to_string());
    }

    fn visit_export_all_declaration(&mut self, it: &ExportAllDeclaration<'a>) {
        // `export * from './x'` / `export * as ns from './x'`.
        self.specifiers.push(it.source.value.as_str().to_string());
    }

    fn visit_import_expression(&mut self, it: &ImportExpression<'a>) {
        if let Expression::StringLiteral(s) = &it.source {
            self.specifiers.push(s.value.as_str().to_string());
        }
        walk_import_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Expression::Identifier(callee) = &it.callee {
            if callee.name.as_str() == "require" {
                if let Some(Argument::StringLiteral(s)) = it.arguments.first() {
                    self.specifiers.push(s.value.as_str().to_string());
                }
            }
        }
        walk_call_expression(self, it);
    }

    fn visit_export_declaration(&mut self, it: &ExportDeclaration<'a>) {
        self.collect_declaration_names(&it.declaration);
        walk_export_declaration(self, it);
    }

    fn visit_export_named_declaration(&mut self, it: &ExportNamedDeclaration<'a>) {
        // `export { a, b as c };` — a purely local named-export list (no
        // `from`). The exported (possibly aliased) name is what a consumer
        // actually imports, matching what the prior regex-based
        // implementation pushed for `x as y` clauses.
        for spec in &it.specifiers {
            let local = module_export_name_text(&spec.local);
            if local == "default" {
                // `export { default as Foo }` re-exports the module's own
                // default under a new name — treated purely as "this file
                // has a default export" (matching prior behavior), not as
                // declaring a separately-named local export.
                self.has_default = true;
                continue;
            }
            self.push_name(module_export_name_text(&spec.exported));
        }
    }

    fn visit_export_default_declaration(&mut self, it: &ExportDefaultDeclaration<'a>) {
        self.has_default = true;
        walk_export_default_declaration(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if it.operator == AssignmentOperator::Assign {
            if is_module_exports_whole_object_target(&it.left) {
                // `module.exports = { foo, bar: renamedBar, ...spread }` —
                // each plain (non-computed, non-spread) key is an exported
                // name; a spread has no single destructurable key to
                // report (matching the prior regex-based behavior).
                if let Expression::ObjectExpression(obj) = &it.right {
                    for prop in &obj.properties {
                        if let ObjectPropertyKind::ObjectProperty(p) = prop {
                            if let PropertyKey::StaticIdentifier(key) = &p.key {
                                self.push_name(key.name.as_str());
                            }
                        }
                    }
                }
            } else if let Some(name) = cjs_named_export_target(&it.left) {
                // `module.exports.foo = ...` / `exports.foo = ...`.
                self.push_name(name);
            }
        }
        walk_assignment_expression(self, it);
    }
}

/// Parses `content` once (always as permissive TSX — see the module doc)
/// and returns both the module specifiers it references and the names it
/// exports — the one real-AST replacement for what used to be two
/// independent regex passes (`extract_specifiers`/`extract_exports`).
/// Malformed source that the parser can't recover from at all yields
/// empty results rather than panicking or propagating a parse error —
/// this crate's checks have always treated "found nothing" as a safe,
/// silent degradation for a file this scanner can't make sense of.
fn analyze(content: &str) -> (Vec<String>, ExportInfo) {
    let allocator = Allocator::default();
    let source_type = SourceType::tsx();
    let ret = Parser::new(&allocator, content, source_type).parse();
    if ret.fatal_error {
        return (Vec::new(), ExportInfo::default());
    }
    let mut visitor = ModuleVisitor::default();
    visitor.visit_program(&ret.program);
    (visitor.specifiers, ExportInfo { names: visitor.names_set, has_default: visitor.has_default })
}

pub fn extract_specifiers(content: &str) -> Vec<String> {
    analyze(content).0
}

#[derive(Debug, Clone, Default)]
pub struct ExportInfo {
    pub names: Vec<String>,
    pub has_default: bool,
}

pub fn extract_exports(content: &str) -> ExportInfo {
    analyze(content).1
}

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
    fn extract_exports_covers_typescript_inline_type_exports() {
        let content = "export { type User, type Config as AppConfig, apiClient };\n";
        let info = extract_exports(content);
        assert!(info.names.contains(&"User".to_string()));
        assert!(info.names.contains(&"AppConfig".to_string()));
        assert!(info.names.contains(&"apiClient".to_string()));
    }

    #[test]
    fn extract_specifiers_handles_a_real_multiline_import_clause() {
        let content = "import {\n    a,\n    b,\n    c,\n} from './multiline';\n";
        let specs = extract_specifiers(content);
        assert!(specs.contains(&"./multiline".to_string()));
    }

    #[test]
    fn extract_specifiers_covers_namespace_re_export() {
        let content = "export * as utils from './utils';\n";
        let specs = extract_specifiers(content);
        assert!(specs.contains(&"./utils".to_string()));
    }

    #[test]
    fn extract_exports_ignores_names_inside_comments_and_strings() {
        // A regex-based scanner could be fooled by text that merely looks
        // like an export inside a comment or string literal; a real parser
        // never is.
        let content = "// export const fake = 1;\nconst s = \"export const alsoFake = 2;\";\nexport const real = 3;\n";
        let info = extract_exports(content);
        assert!(info.names.contains(&"real".to_string()));
        assert!(!info.names.contains(&"fake".to_string()));
        assert!(!info.names.contains(&"alsoFake".to_string()));
    }

    #[test]
    fn extract_exports_finds_multiple_variable_declarators_in_one_statement() {
        // A single regex capture group could only ever pull out one name
        // per `export const ...` match — a real AST walk naturally
        // enumerates every declarator.
        let content = "export const a = 1, b = 2, c = 3;\n";
        let info = extract_exports(content);
        for name in ["a", "b", "c"] {
            assert!(info.names.contains(&name.to_string()), "missing {name}");
        }
    }

    #[test]
    fn extract_specifiers_finds_require_nested_inside_an_export_declaration() {
        let content = "export const db = require('./db');\n";
        let specs = extract_specifiers(content);
        assert!(specs.contains(&"./db".to_string()));
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
