//! Faithful port of `lib/auto-fix.js` — turns a subset of dead-code and
//! AI-governance findings into a fix plan and (optionally) applies it.
//! `unused-file` -> delete; `unused-dependency` -> remove the
//! `package.json` entry; `unused-export` -> narrow an `export { }` list
//! when present, else `manual`; an ungoverned `.invoke()`/`.stream()` call
//! -> insert an explicit recursion-limit argument when the call is a
//! simple single-line/single-argument call, else `manual`.
//!
//! Always dry-run by default (`apply_auto_fix_plan`'s `dry_run: true`) —
//! actually touching disk requires an explicit `dry_run: false`.

use once_cell::sync::Lazy;
use regex::Regex;
use std::path::{Path, PathBuf};

static DEP_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#""([^"]+)""#).unwrap());
static EXPORT_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"Export "([^"]+)""#).unwrap());
static AI_INVOKE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b([A-Za-z_$][\w.]*)\.(invoke|stream|ainvoke|astream)\(").unwrap());
// JS's version uses a negative lookahead `(?!\s*from)` the `regex` crate
// can't express; matched manually below instead by checking the trailing
// context of each `export { ... }` match.
static EXPORT_LIST_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bexport\s*\{([^}]*)\}").unwrap());
static TRAILING_FROM_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*from").unwrap());
static AS_ALIAS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+as\s+\w+$").unwrap());

// LangGraph's own documented default recursion_limit — making it explicit
// changes nothing about runtime behavior, it only turns an implicit
// framework default into something a human/reviewer can actually see and
// tune, which is what the governance guideline is really asking for.
const DEFAULT_RECURSION_LIMIT: u32 = 25;

pub struct FindingInput {
    pub kind: String,
    pub file: String,
    pub line: Option<usize>,
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
pub enum FixAction {
    DeleteFile { file: String, detail: String },
    RemoveDependency { file: String, dependency: String, detail: String },
    NarrowExportListOrManual { file: String, line: Option<usize>, name: Option<String>, detail: String },
    AddRecursionLimitOrManual { file: String, line: Option<usize>, detail: String },
}

pub struct AutoFixPlan {
    pub actions: Vec<FixAction>,
}

pub fn compute_auto_fix_plan(findings: &[FindingInput]) -> AutoFixPlan {
    let mut actions = Vec::new();
    for f in findings {
        match f.kind.as_str() {
            "unused-file" => actions.push(FixAction::DeleteFile { file: f.file.clone(), detail: format!("Delete {} — unreferenced from any detected entry point.", f.file) }),
            "unused-dependency" => {
                if let Some(dep) = f.message.as_deref().and_then(|m| DEP_NAME_RE.captures(m)).map(|c| c[1].to_string()) {
                    actions.push(FixAction::RemoveDependency { file: "package.json".to_string(), dependency: dep.clone(), detail: format!("Remove \"{dep}\" from package.json dependencies/devDependencies.") });
                }
            }
            "unused-export" => {
                let name = f.message.as_deref().and_then(|m| EXPORT_NAME_RE.captures(m)).map(|c| c[1].to_string());
                let line = f.line.unwrap_or(0);
                let detail = format!(
                    "Export \"{}\" in {}:{} is unused — narrowed out of an `export {{ }}` list if present, otherwise flagged for manual review (deleting the declaration itself needs a human).",
                    name.as_deref().unwrap_or(""),
                    f.file,
                    line
                );
                actions.push(FixAction::NarrowExportListOrManual { file: f.file.clone(), line: f.line, name, detail });
            }
            "ungoverned-ai-invocation" => {
                let line = f.line.unwrap_or(0);
                let detail = format!(
                    "{}:{} — `.invoke()`/`.stream()` call with no recursion_limit; inserted an explicit limit if the call is a simple single-line/single-argument call, otherwise flagged for manual review (an existing second argument needs a human to merge into, not overwrite).",
                    f.file, line
                );
                actions.push(FixAction::AddRecursionLimitOrManual { file: f.file.clone(), line: f.line, detail });
            }
            _ => {}
        }
    }
    AutoFixPlan { actions }
}

// Finds the AI_INVOKE_RE call's own argument list on `line`, tracking
// paren/bracket/brace depth and string state so a comma inside a nested
// object/array/string isn't mistaken for a second top-level argument.
// Returns None (never auto-fixable) when the call's closing paren isn't
// on this same line, or a top-level comma is found (a second argument
// already exists).
fn find_single_arg_call_close(line: &str, open_paren_idx: usize) -> Option<usize> {
    let chars: Vec<char> = line.chars().collect();
    let mut depth = 1i32;
    let mut quote: Option<char> = None;
    let mut i = open_paren_idx + 1;
    while i < chars.len() {
        let ch = chars[i];
        if let Some(q) = quote {
            if ch == '\\' {
                i += 2;
                continue;
            }
            if ch == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match ch {
            '"' | '\'' | '`' => quote = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            ',' if depth == 1 => return None,
            _ => {}
        }
        i += 1;
    }
    None
}

pub struct FixResult {
    pub action: FixAction,
    pub applied: bool,
    pub manual: bool,
    pub error: Option<String>,
}

fn char_byte_idx(s: &str, char_idx: usize) -> usize {
    s.char_indices().nth(char_idx).map(|(b, _)| b).unwrap_or(s.len())
}

fn apply_governance_fix(root: &Path, file: &str, line_no: Option<usize>) -> std::io::Result<(bool, bool)> {
    let abs = root.join(file);
    let content = std::fs::read_to_string(&abs)?;
    let uses_crlf = content.contains("\r\n");
    let mut lines: Vec<String> = content.split(['\n']).map(|l| l.trim_end_matches('\r').to_string()).collect();
    let Some(line_no) = line_no else { return Ok((false, true)) };
    let line_idx = line_no.wrapping_sub(1);
    let Some(line) = lines.get(line_idx).cloned() else { return Ok((false, true)) };

    let Some(m) = AI_INVOKE_RE.find(&line) else { return Ok((false, true)) };
    let open_paren_char_idx = line[..m.end()].chars().count() - 1;
    let close_paren_char_idx = match find_single_arg_call_close(&line, open_paren_char_idx) {
        Some(idx) => idx,
        None => return Ok((false, true)),
    };
    let close_byte_idx = char_byte_idx(&line, close_paren_char_idx);

    let is_python = Path::new(file).extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("py")).unwrap_or(false);
    let insertion = if is_python { format!(", config={{\"recursion_limit\": {DEFAULT_RECURSION_LIMIT}}}") } else { format!(", {{ recursionLimit: {DEFAULT_RECURSION_LIMIT} }}") };
    let new_line = format!("{}{}{}", &line[..close_byte_idx], insertion, &line[close_byte_idx..]);
    lines[line_idx] = new_line;
    let eol = if uses_crlf { "\r\n" } else { "\n" };
    std::fs::write(&abs, lines.join(eol))?;
    Ok((true, false))
}

fn apply_delete_file(root: &Path, file: &str) -> std::io::Result<()> {
    std::fs::remove_file(root.join(file))
}

fn apply_remove_dependency(root: &Path, dependency: &str) -> std::io::Result<bool> {
    let pkg_path = root.join("package.json");
    let content = std::fs::read_to_string(&pkg_path)?;
    let mut pkg: serde_json::Value = serde_json::from_str(&content)?;
    let mut removed = false;
    for field in ["dependencies", "devDependencies"] {
        if let Some(obj) = pkg.get_mut(field).and_then(|v| v.as_object_mut()) {
            if obj.remove(dependency).is_some() {
                removed = true;
            }
        }
    }
    if removed {
        std::fs::write(&pkg_path, format!("{}\n", serde_json::to_string_pretty(&pkg)?))?;
    }
    Ok(removed)
}

fn apply_narrow_export(root: &Path, file: &str, name: Option<&str>) -> std::io::Result<bool> {
    let abs = root.join(file);
    let content = std::fs::read_to_string(&abs)?;
    let Some(name) = name else { return Ok(false) };
    let Some(m) = EXPORT_LIST_RE.captures(&content) else { return Ok(false) };
    let full_match = m.get(0).unwrap();
    let trailing = &content[full_match.end()..];
    if TRAILING_FROM_RE.is_match(trailing) {
        return Ok(false); // re-export ("export { x } from ...") — not this case
    }
    let list = &m[1];
    let names: Vec<&str> = list.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    let kept: Vec<&str> = names.iter().copied().filter(|n| AS_ALIAS_RE.replace(n, "").trim() != name).collect();
    if kept.len() == names.len() {
        return Ok(false); // name wasn't in an export list — needs a human
    }
    let replacement = if kept.is_empty() { String::new() } else { format!("export {{ {} }}", kept.join(", ")) };
    let new_content = format!("{}{}{}", &content[..full_match.start()], replacement, &content[full_match.end()..]);
    std::fs::write(&abs, new_content)?;
    Ok(true)
}

pub fn apply_auto_fix_plan(plan: AutoFixPlan, root: &Path, dry_run: bool) -> (bool, Vec<FixResult>) {
    if dry_run {
        let results = plan.actions.into_iter().map(|action| FixResult { action, applied: false, manual: false, error: None }).collect();
        return (true, results);
    }

    let root: PathBuf = root.to_path_buf();
    let mut results = Vec::new();
    for action in plan.actions {
        let outcome = match &action {
            FixAction::DeleteFile { file, .. } => apply_delete_file(&root, file).map(|_| (true, false)),
            FixAction::RemoveDependency { dependency, .. } => apply_remove_dependency(&root, dependency).map(|removed| (removed, false)),
            FixAction::NarrowExportListOrManual { file, name, .. } => apply_narrow_export(&root, file, name.as_deref()).map(|applied| (applied, !applied)),
            FixAction::AddRecursionLimitOrManual { file, line, .. } => apply_governance_fix(&root, file, *line),
        };
        results.push(match outcome {
            Ok((applied, manual)) => FixResult { action, applied, manual, error: None },
            Err(e) => FixResult { action, applied: false, manual: false, error: Some(e.to_string()) },
        });
    }
    (false, results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::tempdir;

    fn finding(kind: &str, file: &str, line: Option<usize>, message: Option<&str>) -> FindingInput {
        FindingInput { kind: kind.to_string(), file: file.to_string(), line, message: message.map(|m| m.to_string()) }
    }

    fn make_temp_project(files: HashMap<&str, &str>) -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        for (name, content) in files {
            let path = dir.path().join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(path, content).unwrap();
        }
        dir
    }

    #[test]
    fn maps_dead_code_finding_kinds_to_fix_actions() {
        let findings = vec![
            finding("unused-file", "orphan.js", None, None),
            finding("unused-dependency", "package.json", None, Some("Dependency \"lodash\" is declared...")),
            finding("unused-export", "lib.js", Some(3), Some("Export \"helperB\" in lib.js is never imported...")),
        ];
        let plan = compute_auto_fix_plan(&findings);
        assert_eq!(plan.actions.len(), 3);
        assert!(matches!(plan.actions[0], FixAction::DeleteFile { .. }));
        match &plan.actions[1] {
            FixAction::RemoveDependency { dependency, .. } => assert_eq!(dependency, "lodash"),
            _ => panic!("expected RemoveDependency"),
        }
        match &plan.actions[2] {
            FixAction::NarrowExportListOrManual { name, .. } => assert_eq!(name.as_deref(), Some("helperB")),
            _ => panic!("expected NarrowExportListOrManual"),
        }
    }

    #[test]
    fn dry_run_does_not_touch_disk() {
        let dir = make_temp_project(HashMap::from([("orphan.js", "module.exports = 1;\n")]));
        let plan = compute_auto_fix_plan(&[finding("unused-file", "orphan.js", None, None)]);
        let (dry_run, results) = apply_auto_fix_plan(plan, dir.path(), true);
        assert!(dry_run);
        assert!(!results[0].applied);
        assert!(dir.path().join("orphan.js").exists());
    }

    #[test]
    fn apply_deletes_unused_file() {
        let dir = make_temp_project(HashMap::from([("orphan.js", "module.exports = 1;\n")]));
        let plan = compute_auto_fix_plan(&[finding("unused-file", "orphan.js", None, None)]);
        let (_, results) = apply_auto_fix_plan(plan, dir.path(), false);
        assert!(results[0].applied);
        assert!(!dir.path().join("orphan.js").exists());
    }

    #[test]
    fn apply_removes_unused_dependency_from_package_json() {
        let dir = make_temp_project(HashMap::from([("package.json", r#"{"name":"x","dependencies":{"lodash":"^4.0.0","express":"^4.0.0"}}"#)]));
        let plan = compute_auto_fix_plan(&[finding("unused-dependency", "package.json", None, Some("Dependency \"lodash\" is declared in package.json..."))]);
        let (_, results) = apply_auto_fix_plan(plan, dir.path(), false);
        assert!(results[0].applied);
        let pkg: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.path().join("package.json")).unwrap()).unwrap();
        assert!(pkg["dependencies"].get("lodash").is_none());
        assert_eq!(pkg["dependencies"]["express"], "^4.0.0");
    }

    #[test]
    fn apply_narrows_export_list_keeping_declaration() {
        let dir = make_temp_project(HashMap::from([("lib.js", "function helperA() { return 1; }\nfunction helperB() { return 2; }\nexport { helperA, helperB };\n")]));
        let plan = compute_auto_fix_plan(&[finding("unused-export", "lib.js", Some(3), Some("Export \"helperB\" in lib.js is never imported..."))]);
        let (_, results) = apply_auto_fix_plan(plan, dir.path(), false);
        assert!(results[0].applied);
        let content = std::fs::read_to_string(dir.path().join("lib.js")).unwrap();
        assert!(content.contains("export { helperA }"));
        assert!(content.contains("function helperB"));
    }

    #[test]
    fn unused_export_not_in_export_list_is_manual() {
        let dir = make_temp_project(HashMap::from([("lib.js", "export function helperA() { return 1; }\n")]));
        let plan = compute_auto_fix_plan(&[finding("unused-export", "lib.js", Some(1), Some("Export \"helperA\" in lib.js is never imported..."))]);
        let (_, results) = apply_auto_fix_plan(plan, dir.path(), false);
        assert!(!results[0].applied);
        assert!(results[0].manual);
    }

    #[test]
    fn maps_ungoverned_ai_invocation_to_fix_action() {
        let findings = vec![finding("ungoverned-ai-invocation", "agent.ts", Some(3), None)];
        let plan = compute_auto_fix_plan(&findings);
        assert_eq!(plan.actions.len(), 1);
        match &plan.actions[0] {
            FixAction::AddRecursionLimitOrManual { file, line, .. } => {
                assert_eq!(file, "agent.ts");
                assert_eq!(*line, Some(3));
            }
            _ => panic!("expected AddRecursionLimitOrManual"),
        }
    }

    #[test]
    fn inserts_recursion_limit_into_simple_js_invoke_call() {
        let dir = make_temp_project(HashMap::from([("agent.ts", "export async function run(graph: any, input: any) {\n  const result = await graph.invoke(input);\n  return result;\n}\n")]));
        let plan = compute_auto_fix_plan(&[finding("ungoverned-ai-invocation", "agent.ts", Some(2), None)]);
        let (_, results) = apply_auto_fix_plan(plan, dir.path(), false);
        assert!(results[0].applied);
        let content = std::fs::read_to_string(dir.path().join("agent.ts")).unwrap();
        assert!(content.contains("graph.invoke(input, { recursionLimit: 25 })"));
    }

    #[test]
    fn inserts_recursion_limit_config_dict_into_python_invoke_call() {
        let dir = make_temp_project(HashMap::from([("agent.py", "def run(graph, input):\n    result = graph.invoke(input)\n    return result\n")]));
        let plan = compute_auto_fix_plan(&[finding("ungoverned-ai-invocation", "agent.py", Some(2), None)]);
        let (_, results) = apply_auto_fix_plan(plan, dir.path(), false);
        assert!(results[0].applied);
        let content = std::fs::read_to_string(dir.path().join("agent.py")).unwrap();
        assert!(content.contains("graph.invoke(input, config={\"recursion_limit\": 25})"));
    }

    #[test]
    fn invoke_call_with_existing_second_arg_is_manual() {
        let dir = make_temp_project(HashMap::from([("agent.ts", "const result = await graph.invoke(input, { someOtherOption: true });\n")]));
        let plan = compute_auto_fix_plan(&[finding("ungoverned-ai-invocation", "agent.ts", Some(1), None)]);
        let (_, results) = apply_auto_fix_plan(plan, dir.path(), false);
        assert!(!results[0].applied);
        assert!(results[0].manual);
        let content = std::fs::read_to_string(dir.path().join("agent.ts")).unwrap();
        assert!(content.contains("someOtherOption: true"));
    }

    #[test]
    fn invoke_call_spanning_multiple_lines_is_manual() {
        let dir = make_temp_project(HashMap::from([("agent.ts", "const result = await graph.invoke(\n  input\n);\n")]));
        let plan = compute_auto_fix_plan(&[finding("ungoverned-ai-invocation", "agent.ts", Some(1), None)]);
        let (_, results) = apply_auto_fix_plan(plan, dir.path(), false);
        assert!(!results[0].applied);
        assert!(results[0].manual);
    }
}
