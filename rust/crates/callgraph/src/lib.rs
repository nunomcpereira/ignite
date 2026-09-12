//! Studio's "Call Graph" feature: caller -> callee edges across a project,
//! so a component's real usage is visible as a graph instead of only
//! per-file findings. Two engines feed one shared [`CallGraph`] shape:
//!
//!   - **CodeQL** (javascript, python, java, go): [`CODEQL_CALL_GRAPH_QUERIES`]
//!     below, run through `ignite_codeql_cross_file::run_custom_codeql_query`
//!     against the project's already-built CodeQL database — the same one
//!     Studio's "Run CodeQL" button builds. Real static-analysis call
//!     resolution, not a text scan. Each query was hand-validated against a
//!     real `codeql` CLI + a throwaway single-language database before being
//!     checked in here (`codeql database create` + `codeql query run` +
//!     `codeql bqrs decode`), so the exact predicate names/shapes are
//!     confirmed against CodeQL 2.26.3's actual standard libraries, not
//!     guessed from documentation.
//!   - **Rust**: CodeQL has no official Rust support (see CLAUDE.md's
//!     "Transitive dependency reachability" section, which hit the same
//!     wall for dependency-vulnerability reachability). [`build_rust_call_graph`]
//!     falls back to a lightweight regex-based scan — function/method
//!     definitions matched by name against call sites project-wide.
//!     Deliberately the same "no type resolution, name-based matching"
//!     posture (and the same honest caveats) as `dependency-license-scan`'s
//!     `cargo_imports.rs`: an approximate visualization aid, not an
//!     authoritative call graph. A method call `x.foo()` can match every
//!     `fn foo` in the project when there are several — capped at 6
//!     candidates per call site (see `MAX_AMBIGUOUS_TARGETS`) past which the
//!     call is dropped rather than fanned out into noise.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use ignite_codeql_cross_file::{run_custom_codeql_query, QueryResult};
use ignite_tool_runner::ToolRunner;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CallGraphNode {
    pub id: String,
    pub name: String,
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CallGraphEdge {
    pub caller: String,
    pub callee: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CallGraph {
    pub nodes: Vec<CallGraphNode>,
    pub edges: Vec<CallGraphEdge>,
    /// True when the graph hit `MAX_NODES`/`MAX_EDGES` and was cut off —
    /// a real repo's full function-level graph can run into the tens of
    /// thousands of edges, which stops being a legible picture long before
    /// it stops being technically renderable.
    pub truncated: bool,
}

const MAX_NODES: usize = 1500;
const MAX_EDGES: usize = 4000;
const MAX_AMBIGUOUS_TARGETS: usize = 6;

fn node_id(file: &str, name: &str, line: usize) -> String {
    format!("{file}:{line}:{name}")
}

/* ------------------------------------------------------------------ */
/* CodeQL engine                                                        */
/* ------------------------------------------------------------------ */

/// Every column is a plain `String`/`Integer` CodeQL value (never a `File`
/// or `Location` entity directly) so `run_custom_codeql_query`'s row parser
/// returns clean primitive cells — selecting an entity type there instead
/// would wrap the cell as `{label, url}` and only the *first* such column
/// survives that parser's single-location extraction, which would silently
/// drop either the caller's or the callee's position.
const JS_QUERY: &str = r#"
import javascript

from Function caller, DataFlow::InvokeNode call, Function callee
where call.asExpr().getEnclosingFunction() = caller
  and callee = call.getACallee()
select caller.getName(), caller.getFile().getRelativePath(), caller.getLocation().getStartLine(),
       callee.getName(), callee.getFile().getRelativePath(), callee.getLocation().getStartLine()
"#;

/// Python's dynamic typing means CodeQL can't generally resolve `x.foo()`
/// method calls without full points-to analysis — this only resolves
/// direct-name calls (`foo()`), the same "no method-call resolution"
/// limitation documented for the Python import-level reachability check in
/// `dependency-license-scan/src/python_imports.rs`.
const PY_QUERY: &str = r#"
import python

from Function caller, Call call, Function callee
where call.getScope() = caller
  and callee.getName() = call.getFunc().(Name).getId()
select caller.getName(), caller.getLocation().getFile().getRelativePath(), caller.getLocation().getStartLine(),
       callee.getName(), callee.getLocation().getFile().getRelativePath(), callee.getLocation().getStartLine()
"#;

const JAVA_QUERY: &str = r#"
import java

from Method caller, MethodCall call, Method callee
where call.getEnclosingCallable() = caller
  and callee = call.getMethod()
select caller.getName(), caller.getCompilationUnit().getRelativePath(), caller.getLocation().getStartLine(),
       callee.getName(), callee.getCompilationUnit().getRelativePath(), callee.getLocation().getStartLine()
"#;

/// `CallExpr.getEnclosingFunction()` returns a `FuncDef` (the AST node),
/// while `CallExpr.getTarget()` returns a `Function` (the declared symbol)
/// — two genuinely distinct classes in the Go extractor's library, not a
/// subtype pair, so they can't be compared directly. `FuncDecl.getFunction()`
/// is the bridge from the AST node back to its declared symbol.
const GO_QUERY: &str = r#"
import go

from Function caller, CallExpr call, Function callee
where call.getEnclosingFunction().(FuncDecl).getFunction() = caller
  and callee = call.getTarget()
select caller.getName(), caller.getLocation().getFile().getRelativePath(), caller.getLocation().getStartLine(),
       callee.getName(), callee.getLocation().getFile().getRelativePath(), callee.getLocation().getStartLine()
"#;

static CODEQL_CALL_GRAPH_QUERIES: Lazy<HashMap<&'static str, &'static str>> =
    Lazy::new(|| HashMap::from([("javascript", JS_QUERY), ("python", PY_QUERY), ("java", JAVA_QUERY), ("go", GO_QUERY)]));

pub fn codeql_call_graph_query(language: &str) -> Option<&'static str> {
    CODEQL_CALL_GRAPH_QUERIES.get(language).copied()
}

pub fn codeql_call_graph_languages() -> Vec<&'static str> {
    let mut langs: Vec<&'static str> = CODEQL_CALL_GRAPH_QUERIES.keys().copied().collect();
    langs.sort_unstable();
    langs
}

/// Builds a [`CallGraph`] from a 6-column `(callerName, callerFile,
/// callerLine, calleeName, calleeFile, calleeLine)` query result — the
/// shape every query above selects. `caller`/`calleeLine` are each
/// function's *definition* line (not the call site), which is what makes
/// the same function referenced from two different call sites collapse
/// into one node instead of duplicating it.
pub fn call_graph_from_query_result(result: &QueryResult) -> CallGraph {
    let mut nodes: Vec<CallGraphNode> = Vec::new();
    let mut node_ids: HashSet<String> = HashSet::new();
    let mut edges: Vec<CallGraphEdge> = Vec::new();
    let mut edge_keys: HashSet<(String, String)> = HashSet::new();
    let mut truncated = false;

    for row in &result.rows {
        if row.cells.len() < 6 {
            continue;
        }
        if nodes.len() >= MAX_NODES || edges.len() >= MAX_EDGES {
            truncated = true;
            break;
        }
        let caller_name = row.cells[0].clone();
        let caller_file = row.cells[1].clone();
        let caller_line: usize = row.cells[2].parse().unwrap_or(0);
        let callee_name = row.cells[3].clone();
        let callee_file = row.cells[4].clone();
        let callee_line: usize = row.cells[5].parse().unwrap_or(0);

        let caller_id = node_id(&caller_file, &caller_name, caller_line);
        let callee_id = node_id(&callee_file, &callee_name, callee_line);

        if node_ids.insert(caller_id.clone()) {
            nodes.push(CallGraphNode { id: caller_id.clone(), name: caller_name, file: caller_file, line: caller_line });
        }
        if node_ids.insert(callee_id.clone()) {
            nodes.push(CallGraphNode { id: callee_id.clone(), name: callee_name, file: callee_file, line: callee_line });
        }
        if edge_keys.insert((caller_id.clone(), callee_id.clone())) {
            edges.push(CallGraphEdge { caller: caller_id, callee: callee_id });
        }
    }

    CallGraph { nodes, edges, truncated }
}

/// Runs the call-graph query for `language` against `db_dir` (an
/// already-built CodeQL database, same convention as
/// `run_custom_codeql_query`'s other callers) and shapes the result.
pub async fn build_codeql_call_graph(
    root: &Path,
    db_dir: &Path,
    language: &str,
    runner: &ToolRunner,
    timeout_ms: u64,
    log: impl FnMut(&str),
) -> Result<CallGraph, ignite_codeql_cross_file::CodeqlError> {
    let query = codeql_call_graph_query(language).ok_or_else(|| ignite_codeql_cross_file::CodeqlError::Message(format!("No call-graph query available for language \"{language}\".")))?;
    let result = run_custom_codeql_query(root, db_dir, language, query, runner, timeout_ms, log).await?;
    Ok(call_graph_from_query_result(&result))
}

/* ------------------------------------------------------------------ */
/* Rust fallback — regex-based, no CodeQL support for this language     */
/* ------------------------------------------------------------------ */

static RUST_FN_DEF_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[(<]").unwrap());

/// Any `identifier(` — a word boundary already excludes it from matching
/// mid-identifier, and holds regardless of whether the identifier is
/// preceded by `.` (method call), `::` (path call) or nothing (bare call),
/// so one pattern covers all three call shapes.
static RUST_CALL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap());

struct RustFnSpan {
    name: String,
    line: usize,
    /// Byte offset of the match start (including any `pub`/`async` prefix)
    /// — used to exclude a nested fn's own signature text (not just its
    /// body) when scanning the enclosing function for call sites, so `fn
    /// inner(` doesn't get misread as a call to `inner`.
    def_start: usize,
    body_start: usize,
    body_end: usize,
}

fn balanced_close(bytes: &[u8], open_pos: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0i32;
    let mut i = open_pos;
    while i < bytes.len() {
        if bytes[i] == open {
            depth += 1;
        } else if bytes[i] == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn parse_rust_fn_spans(content: &str) -> Vec<RustFnSpan> {
    let bytes = content.as_bytes();
    let mut spans = Vec::new();
    for cap in RUST_FN_DEF_RE.captures_iter(content) {
        let whole = cap.get(0).unwrap();
        let name = cap[1].to_string();
        let mut pos = whole.end() - 1; // the '(' or '<' the match ended on
        if bytes.get(pos) == Some(&b'<') {
            let mut depth = 1i32;
            pos += 1;
            while pos < bytes.len() && depth > 0 {
                match bytes[pos] {
                    b'<' => depth += 1,
                    b'>' => depth -= 1,
                    _ => {}
                }
                pos += 1;
            }
            match content[pos..].find('(') {
                Some(off) => pos += off,
                None => continue,
            }
        }
        let Some(close_paren) = balanced_close(bytes, pos, b'(', b')') else { continue };
        let after_params = close_paren + 1;
        // First `{` or `;` after the param list — a `;` means a trait
        // method declaration with no body, which has nothing to scan and
        // isn't a real call-graph node.
        let Some(rel_offset) = content[after_params..].find(['{', ';']) else { continue };
        let sig_tail = after_params + rel_offset;
        if bytes[sig_tail] == b';' {
            continue;
        }
        let Some(body_end) = balanced_close(bytes, sig_tail, b'{', b'}') else { continue };
        let line = content[..whole.start()].matches('\n').count() + 1;
        spans.push(RustFnSpan { name, line, def_start: whole.start(), body_start: sig_tail, body_end });
    }
    spans
}

struct RustFileSpans {
    rel: String,
    content: String,
    spans: Vec<RustFnSpan>,
}

/// Approximate Rust call graph: no type resolution, so a call `x.foo()`
/// resolves to every `fn foo` definition in the project (capped at
/// [`MAX_AMBIGUOUS_TARGETS`], past which it's dropped as too ambiguous to
/// be a useful edge). See the module doc for the full rationale.
pub fn build_rust_call_graph(root: &Path) -> std::io::Result<CallGraph> {
    let mut files_data: Vec<RustFileSpans> = Vec::new();
    let mut name_to_nodes: HashMap<String, Vec<String>> = HashMap::new();
    let mut nodes: Vec<CallGraphNode> = Vec::new();
    let mut node_ids: HashSet<String> = HashSet::new();

    for file in ignite_fs_utils::walk_files(root)?.into_iter().filter(|f| f.extension().is_some_and(|e| e == "rs")) {
        let Ok(content) = std::fs::read_to_string(&file) else { continue };
        let rel = ignite_fs_utils::relative_to_root(root, &file.to_string_lossy()).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        let spans = parse_rust_fn_spans(&content);
        for span in &spans {
            let id = node_id(&rel, &span.name, span.line);
            if node_ids.insert(id.clone()) {
                nodes.push(CallGraphNode { id: id.clone(), name: span.name.clone(), file: rel.clone(), line: span.line });
            }
            name_to_nodes.entry(span.name.clone()).or_default().push(id);
        }
        files_data.push(RustFileSpans { rel, content, spans });
    }

    let mut truncated = nodes.len() > MAX_NODES;
    nodes.truncate(MAX_NODES);
    let kept_ids: HashSet<String> = nodes.iter().map(|n| n.id.clone()).collect();

    let mut edges: Vec<CallGraphEdge> = Vec::new();
    let mut edge_keys: HashSet<(String, String)> = HashSet::new();

    'outer: for fd in &files_data {
        for (i, span) in fd.spans.iter().enumerate() {
            let caller_id = node_id(&fd.rel, &span.name, span.line);
            if !kept_ids.contains(&caller_id) {
                continue;
            }
            let nested: Vec<(usize, usize)> = fd
                .spans
                .iter()
                .enumerate()
                .filter(|(j, s)| *j != i && s.def_start > span.body_start && s.body_end < span.body_end)
                .map(|(_, s)| (s.def_start, s.body_end))
                .collect();
            let body = &fd.content[span.body_start..span.body_end];
            for cap in RUST_CALL_RE.captures_iter(body) {
                let name_match = cap.get(1).unwrap();
                let abs_pos = span.body_start + name_match.start();
                if nested.iter().any(|(s, e)| abs_pos >= *s && abs_pos < *e) {
                    continue;
                }
                let Some(targets) = name_to_nodes.get(name_match.as_str()) else { continue };
                if targets.len() > MAX_AMBIGUOUS_TARGETS {
                    continue;
                }
                for callee_id in targets {
                    if !kept_ids.contains(callee_id) {
                        continue;
                    }
                    if edges.len() >= MAX_EDGES {
                        truncated = true;
                        break 'outer;
                    }
                    if edge_keys.insert((caller_id.clone(), callee_id.clone())) {
                        edges.push(CallGraphEdge { caller: caller_id.clone(), callee: callee_id.clone() });
                    }
                }
            }
        }
    }

    Ok(CallGraph { nodes, edges, truncated })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ignite_codeql_cross_file::QueryResultRow;
    use tempfile::tempdir;

    fn row(cells: &[&str]) -> QueryResultRow {
        QueryResultRow { cells: cells.iter().map(|s| s.to_string()).collect(), location: None }
    }

    #[test]
    fn call_graph_from_query_result_dedupes_nodes_and_edges() {
        let result = QueryResult {
            columns: vec![],
            rows: vec![
                row(&["main", "app.js", "5", "helper", "app.js", "1"]),
                row(&["main", "app.js", "5", "process", "app.js", "10"]),
                // Same edge again (e.g. two call sites in `main`) must not duplicate.
                row(&["main", "app.js", "5", "helper", "app.js", "1"]),
            ],
        };
        let graph = call_graph_from_query_result(&result);
        assert_eq!(graph.nodes.len(), 3);
        assert_eq!(graph.edges.len(), 2);
        assert!(!graph.truncated);
    }

    #[test]
    fn call_graph_from_query_result_ignores_short_rows() {
        let result = QueryResult { columns: vec![], rows: vec![row(&["only", "three", "cells"])] };
        let graph = call_graph_from_query_result(&result);
        assert!(graph.nodes.is_empty());
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn codeql_call_graph_query_covers_all_four_languages() {
        for lang in ["javascript", "python", "java", "go"] {
            assert!(codeql_call_graph_query(lang).is_some(), "missing query for {lang}");
        }
        assert!(codeql_call_graph_query("rust").is_none());
    }

    #[test]
    fn build_rust_call_graph_finds_direct_calls() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("main.rs"),
            "fn helper(x: i32) -> i32 {\n    x + 1\n}\n\nfn main() {\n    let y = helper(2);\n    process(y);\n}\n\nfn process(v: i32) -> i32 {\n    v * 2\n}\n",
        )
        .unwrap();
        let graph = build_rust_call_graph(dir.path()).unwrap();
        assert_eq!(graph.nodes.len(), 3);
        let main_id = graph.nodes.iter().find(|n| n.name == "main").unwrap().id.clone();
        let helper_id = graph.nodes.iter().find(|n| n.name == "helper").unwrap().id.clone();
        let process_id = graph.nodes.iter().find(|n| n.name == "process").unwrap().id.clone();
        assert!(graph.edges.contains(&CallGraphEdge { caller: main_id.clone(), callee: helper_id }));
        assert!(graph.edges.contains(&CallGraphEdge { caller: main_id, callee: process_id }));
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[test]
    fn build_rust_call_graph_resolves_method_calls_by_name() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("lib.rs"),
            "struct Foo;\nimpl Foo {\n    fn bar(&self) -> i32 { 1 }\n}\n\nfn caller(f: &Foo) -> i32 {\n    f.bar()\n}\n",
        )
        .unwrap();
        let graph = build_rust_call_graph(dir.path()).unwrap();
        let caller_id = graph.nodes.iter().find(|n| n.name == "caller").unwrap().id.clone();
        let bar_id = graph.nodes.iter().find(|n| n.name == "bar").unwrap().id.clone();
        assert!(graph.edges.contains(&CallGraphEdge { caller: caller_id, callee: bar_id }));
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[test]
    fn build_rust_call_graph_does_not_attribute_nested_fn_calls_to_outer() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("lib.rs"),
            "fn outer() {\n    fn inner() {\n        leaf();\n    }\n    inner();\n}\n\nfn leaf() {}\n",
        )
        .unwrap();
        let graph = build_rust_call_graph(dir.path()).unwrap();
        let outer_id = graph.nodes.iter().find(|n| n.name == "outer").unwrap().id.clone();
        let inner_id = graph.nodes.iter().find(|n| n.name == "inner").unwrap().id.clone();
        let leaf_id = graph.nodes.iter().find(|n| n.name == "leaf").unwrap().id.clone();
        assert!(graph.edges.contains(&CallGraphEdge { caller: outer_id.clone(), callee: inner_id.clone() }));
        assert!(graph.edges.contains(&CallGraphEdge { caller: inner_id, callee: leaf_id }));
        assert!(!graph.edges.iter().any(|e| e.caller == outer_id && e.callee.contains("leaf")));
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[test]
    fn build_rust_call_graph_drops_calls_past_the_ambiguity_cap() {
        let dir = tempdir().unwrap();
        let mut src = String::from("fn caller() {\n    dup();\n}\n\n");
        for i in 0..8 {
            src.push_str(&format!("mod m{i} {{\n    pub fn dup() {{}}\n}}\n"));
        }
        std::fs::write(dir.path().join("lib.rs"), src).unwrap();
        let graph = build_rust_call_graph(dir.path()).unwrap();
        let caller_id = graph.nodes.iter().find(|n| n.name == "caller").unwrap().id.clone();
        assert!(!graph.edges.iter().any(|e| e.caller == caller_id));
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }
}
