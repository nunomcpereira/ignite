//! Go function-level transitive reachability: for advisories whose OSV
//! record includes exact affected-symbol data — confirmed empirically
//! against the live osv.dev API while building this: entries sourced
//! from Go's own vulndb populate `affected[].ecosystem_specific.imports[]`
//! (`{path, symbols}`), no other ecosystem's advisories do (checked an
//! npm/GHSA advisory the same way) — checks whether the project's own Go
//! source actually *calls* one of the named vulnerable functions, not
//! just whether it imports the package. Real call-level reachability,
//! not the import-level heuristic `ignite_module_graph` provides for
//! npm, but only available where the advisory data itself supports it.

use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// One `affected[].ecosystem_specific.imports[]` entry from a Go vulndb
/// OSV record: the import path a set of vulnerable functions belongs to,
/// and their exact names.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AffectedImport {
    pub path: String,
    pub symbols: Vec<String>,
}

/// Pulls every Go-ecosystem `affected[].ecosystem_specific.imports[]`
/// entry out of a raw OSV record (`DepsDevClient::fetch_osv_record`) —
/// empty for any advisory that doesn't carry this (every ecosystem
/// besides Go's vulndb, as of writing), or for a `None` fetch result the
/// caller passes through as `&Value::Null`.
pub fn extract_go_affected_imports(osv_record: &serde_json::Value) -> Vec<AffectedImport> {
    let mut out = Vec::new();
    let Some(affected) = osv_record.get("affected").and_then(|v| v.as_array()) else { return out };
    for entry in affected {
        if entry.get("package").and_then(|p| p.get("ecosystem")).and_then(|v| v.as_str()) != Some("Go") {
            continue;
        }
        let Some(imports) = entry.get("ecosystem_specific").and_then(|e| e.get("imports")).and_then(|v| v.as_array()) else { continue };
        for imp in imports {
            let Some(path) = imp.get("path").and_then(|v| v.as_str()) else { continue };
            let symbols: Vec<String> = imp.get("symbols").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default();
            if !symbols.is_empty() {
                out.push(AffectedImport { path: path.to_string(), symbols });
            }
        }
    }
    out
}

static GO_IMPORT_SINGLE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?m)^\s*import\s+(?:([\w.]+)\s+)?"([^"]+)"\s*$"#).unwrap());
static GO_IMPORT_BLOCK_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)\bimport\s*\(([^)]*)\)").unwrap());
static GO_IMPORT_BLOCK_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?m)^\s*(?:([\w.]+)\s+)?"([^"]+)"\s*$"#).unwrap());

#[derive(Debug, Clone, PartialEq, Eq)]
enum GoImportAlias {
    /// The name a call site would qualify the symbol with — either an
    /// explicit alias (`import foo "bar/baz"` -> `foo`) or, when none is
    /// given, Go's own default of the import path's last segment.
    Named(String),
    /// `import _ "path"` — side-effect only; a blank import can never
    /// directly call a named symbol (only indirectly, via that package's
    /// own `init()`, which this regex-level scanner has no way to trace).
    Blank,
    /// `import . "path"` — every exported symbol becomes usable
    /// unqualified in this file.
    Dot,
}

/// Every import in one Go file's source, as `(alias, import path)`.
/// Regex-based (no real Go parser), same convention as this codebase's
/// other lightweight source scanners (`ignite-module-graph`'s JS/TS
/// import extraction, `ignite-secrets`' pattern matching) — good enough
/// for a best-effort reachability signal, not a substitute for a real
/// compiler frontend.
fn parse_go_imports(content: &str) -> Vec<(GoImportAlias, String)> {
    fn classify(alias: Option<&str>, path: &str) -> GoImportAlias {
        match alias {
            Some("_") => GoImportAlias::Blank,
            Some(".") => GoImportAlias::Dot,
            Some(a) => GoImportAlias::Named(a.to_string()),
            None => GoImportAlias::Named(path.rsplit('/').next().unwrap_or(path).to_string()),
        }
    }

    let mut out = Vec::new();
    for cap in GO_IMPORT_SINGLE_RE.captures_iter(content) {
        let path = cap[2].to_string();
        out.push((classify(cap.get(1).map(|m| m.as_str()), &path), path));
    }
    for block in GO_IMPORT_BLOCK_RE.captures_iter(content) {
        for cap in GO_IMPORT_BLOCK_LINE_RE.captures_iter(&block[1]) {
            let path = cap[2].to_string();
            out.push((classify(cap.get(1).map(|m| m.as_str()), &path), path));
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GoReachability {
    /// No symbol-level advisory data to check against — no verdict
    /// possible, no annotation should be added.
    Unknown,
    /// The affected import path isn't imported anywhere in the project,
    /// or is imported but none of the named vulnerable symbols is ever
    /// called.
    NotCalled,
    /// At least one named vulnerable symbol is actually called somewhere
    /// in the project's own Go source.
    Called,
}

/// Checks every `.go` file under `root` for a call to any symbol in
/// `affected` — matched against the exact import path each symbol
/// belongs to (alias/blank/dot imports all handled), not a bare name
/// match anywhere in the file, so a same-named local function or an
/// unrelated package's identically-named export never counts as a false
/// "called" match.
pub fn check_go_reachability(root: &Path, affected: &[AffectedImport]) -> GoReachability {
    if affected.is_empty() {
        return GoReachability::Unknown;
    }
    let Ok(files) = ignite_fs_utils::walk_files(root) else { return GoReachability::Unknown };
    let go_files = files.into_iter().filter(|f| f.extension().is_some_and(|e| e == "go"));

    for file in go_files {
        let Ok(content) = std::fs::read_to_string(&file) else { continue };
        let imports = parse_go_imports(&content);
        for target in affected {
            let Some((alias, _)) = imports.iter().find(|(_, path)| path == &target.path) else { continue };
            for symbol in &target.symbols {
                let pattern = match alias {
                    GoImportAlias::Blank => continue,
                    GoImportAlias::Dot => format!(r"\b{}\s*\(", regex::escape(symbol)),
                    GoImportAlias::Named(local) => format!(r"\b{}\.{}\s*\(", regex::escape(local), regex::escape(symbol)),
                };
                if Regex::new(&pattern).map(|re| re.is_match(&content)).unwrap_or(false) {
                    return GoReachability::Called;
                }
            }
        }
    }
    GoReachability::NotCalled
}

#[cfg(test)]
mod tests {
    use super::*;

    fn go_2021_0113_style_record() -> serde_json::Value {
        serde_json::json!({
            "affected": [{
                "package": { "name": "golang.org/x/text", "ecosystem": "Go" },
                "ecosystem_specific": { "imports": [{ "path": "golang.org/x/text/language", "symbols": ["MatchStrings", "MustParse", "Parse", "ParseAcceptLanguage"] }] },
            }],
        })
    }

    #[test]
    fn extract_go_affected_imports_pulls_path_and_symbols() {
        let imports = extract_go_affected_imports(&go_2021_0113_style_record());
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].path, "golang.org/x/text/language");
        assert!(imports[0].symbols.contains(&"Parse".to_string()));
    }

    #[test]
    fn extract_go_affected_imports_empty_for_non_go_ecosystem() {
        let record = serde_json::json!({
            "affected": [{ "package": { "name": "body-parser", "ecosystem": "npm" }, "ecosystem_specific": { "imports": [{ "path": "body-parser", "symbols": ["parse"] }] } }],
        });
        assert!(extract_go_affected_imports(&record).is_empty());
    }

    #[test]
    fn extract_go_affected_imports_empty_when_no_imports_field() {
        let record = serde_json::json!({ "affected": [{ "package": { "name": "x", "ecosystem": "Go" } }] });
        assert!(extract_go_affected_imports(&record).is_empty());
    }

    #[test]
    fn parse_go_imports_handles_single_aliased_blank_and_dot_imports() {
        let content = "package main\n\nimport \"fmt\"\nimport myalias \"golang.org/x/text/language\"\nimport _ \"database/sql/driver\"\nimport . \"strings\"\n";
        let imports = parse_go_imports(content);
        assert!(imports.contains(&(GoImportAlias::Named("fmt".to_string()), "fmt".to_string())));
        assert!(imports.contains(&(GoImportAlias::Named("myalias".to_string()), "golang.org/x/text/language".to_string())));
        assert!(imports.contains(&(GoImportAlias::Blank, "database/sql/driver".to_string())));
        assert!(imports.contains(&(GoImportAlias::Dot, "strings".to_string())));
    }

    #[test]
    fn parse_go_imports_handles_grouped_import_block() {
        let content = "package main\n\nimport (\n\t\"fmt\"\n\tlang \"golang.org/x/text/language\"\n)\n";
        let imports = parse_go_imports(content);
        assert!(imports.contains(&(GoImportAlias::Named("fmt".to_string()), "fmt".to_string())));
        assert!(imports.contains(&(GoImportAlias::Named("lang".to_string()), "golang.org/x/text/language".to_string())));
    }

    #[test]
    fn parse_go_imports_defaults_alias_to_last_path_segment() {
        let content = "import \"golang.org/x/text/language\"\n";
        let imports = parse_go_imports(content);
        assert_eq!(imports[0].0, GoImportAlias::Named("language".to_string()));
    }

    #[test]
    fn check_go_reachability_unknown_without_affected_symbols() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(check_go_reachability(dir.path(), &[]), GoReachability::Unknown);
    }

    #[test]
    fn check_go_reachability_not_called_when_package_never_imported() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.go"), "package main\n\nfunc main() {}\n").unwrap();
        let affected = vec![AffectedImport { path: "golang.org/x/text/language".to_string(), symbols: vec!["Parse".to_string()] }];
        assert_eq!(check_go_reachability(dir.path(), &affected), GoReachability::NotCalled);
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[test]
    fn check_go_reachability_not_called_when_imported_but_symbol_never_invoked() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.go"), "package main\n\nimport \"golang.org/x/text/language\"\n\nvar _ language.Tag\n").unwrap();
        let affected = vec![AffectedImport { path: "golang.org/x/text/language".to_string(), symbols: vec!["Parse".to_string()] }];
        assert_eq!(check_go_reachability(dir.path(), &affected), GoReachability::NotCalled);
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[test]
    fn check_go_reachability_called_when_symbol_invoked_via_default_alias() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.go"), "package main\n\nimport \"golang.org/x/text/language\"\n\nfunc main() { language.Parse(\"en\") }\n").unwrap();
        let affected = vec![AffectedImport { path: "golang.org/x/text/language".to_string(), symbols: vec!["Parse".to_string()] }];
        assert_eq!(check_go_reachability(dir.path(), &affected), GoReachability::Called);
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[test]
    fn check_go_reachability_called_via_explicit_alias() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.go"), "package main\n\nimport lang \"golang.org/x/text/language\"\n\nfunc main() { lang.Parse(\"en\") }\n").unwrap();
        let affected = vec![AffectedImport { path: "golang.org/x/text/language".to_string(), symbols: vec!["Parse".to_string()] }];
        assert_eq!(check_go_reachability(dir.path(), &affected), GoReachability::Called);
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[test]
    fn check_go_reachability_called_via_dot_import() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.go"), "package main\n\nimport . \"golang.org/x/text/language\"\n\nfunc main() { Parse(\"en\") }\n").unwrap();
        let affected = vec![AffectedImport { path: "golang.org/x/text/language".to_string(), symbols: vec!["Parse".to_string()] }];
        assert_eq!(check_go_reachability(dir.path(), &affected), GoReachability::Called);
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[test]
    fn check_go_reachability_blank_import_never_counts_as_called() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.go"), "package main\n\nimport _ \"golang.org/x/text/language\"\n").unwrap();
        let affected = vec![AffectedImport { path: "golang.org/x/text/language".to_string(), symbols: vec!["Parse".to_string()] }];
        assert_eq!(check_go_reachability(dir.path(), &affected), GoReachability::NotCalled);
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[test]
    fn check_go_reachability_does_not_false_match_a_same_named_symbol_from_a_different_package() {
        // `parser.Parse(...)` calls a *different* package's `Parse` — must
        // not be mistaken for `golang.org/x/text/language`'s `Parse`.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.go"), "package main\n\nimport \"golang.org/x/text/language\"\nimport parser \"some/other/parser\"\n\nfunc main() {\n\tparser.Parse(\"x\")\n\tvar _ = language.Tag{}\n}\n").unwrap();
        let affected = vec![AffectedImport { path: "golang.org/x/text/language".to_string(), symbols: vec!["Parse".to_string()] }];
        assert_eq!(check_go_reachability(dir.path(), &affected), GoReachability::NotCalled);
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }
}
