//! Faithful port of `lib/runtime-coverage.js`'s `normalizeCoverageReport` —
//! normalizes an ingested runtime coverage report (Istanbul's
//! `coverage-final.json`, or a simple `{ path: hitCount }` map) into the
//! shape `db-store`'s `ingest_runtime_coverage` stores. The Ignite-side
//! counterpart to a project's own CI uploading whatever coverage report
//! its test suite already produces.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use ignite_db_store::RuntimeCoverageInput;
use serde_json::Value;
use std::collections::HashMap;

pub fn is_istanbul_report(data: &Value) -> bool {
    let Some(obj) = data.as_object() else { return false };
    let Some((_, entry)) = obj.iter().next() else { return false };
    let Some(entry_obj) = entry.as_object() else { return false };
    entry_obj.contains_key("statementMap") || entry_obj.contains_key("s")
}

/// Lexically resolves `.`/`..` path components (no filesystem access,
/// no symlink resolution — just segment-level collapsing) so a coverage
/// path reported with a `../` component (e.g. a monorepo test runner
/// reporting paths relative to its own package rather than the project
/// root) still matches the plain, `..`-free relative path Ignite's own
/// issue findings use for the same file.
fn collapse_dot_components(path: &str) -> String {
    // Preserve a leading `/` for a genuinely absolute path (e.g. the
    // outside-the-project-root fallback that keeps the raw absolute key
    // unchanged) — splitting on `/` alone would otherwise treat the empty
    // segment before a leading slash the same as a bare `.` and silently
    // drop it, turning an absolute path into a relative-looking one.
    let is_absolute = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            _ => out.push(seg),
        }
    }
    let joined = out.join("/");
    if is_absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

fn normalize_istanbul(data: &Value, project_root: Option<&str>) -> HashMap<String, RuntimeCoverageInput> {
    let mut out = HashMap::new();
    let Some(obj) = data.as_object() else { return out };
    for (abs_or_rel, file_cov) in obj {
        // `starts_with(root)` alone matches a sibling directory sharing
        // `root` as a string prefix (`/app` matching `/app-backend/...`),
        // slicing off `-backend/...` instead of leaving the path
        // untouched — checking for a following separator (or an exact
        // match) confirms `root` is actually a directory-boundary
        // ancestor before stripping it.
        let rel_path = match project_root {
            Some(root) if abs_or_rel == root => String::new(),
            Some(root) if abs_or_rel.starts_with(root) && abs_or_rel[root.len()..].starts_with(['/', '\\']) => abs_or_rel[root.len()..].trim_start_matches(['/', '\\']).replace('\\', "/"),
            _ => abs_or_rel.replace('\\', "/"),
        };
        let rel_path = collapse_dot_components(&rel_path);
        let hits: Vec<i64> = file_cov.get("s").and_then(|s| s.as_object()).map(|s| s.values().map(|v| v.as_i64().unwrap_or(0)).collect()).unwrap_or_default();
        let hit_count: i64 = hits.iter().sum();
        let covered = hits.iter().filter(|&&n| n > 0).count();
        let covered_pct = if !hits.is_empty() { Some((covered as f64 / hits.len() as f64 * 1000.0).round() / 10.0) } else { None };
        out.insert(rel_path, RuntimeCoverageInput { hit_count, covered_pct });
    }
    out
}

fn normalize_simple_map(data: &Value) -> HashMap<String, RuntimeCoverageInput> {
    let mut out = HashMap::new();
    let Some(obj) = data.as_object() else { return out };
    for (rel_path, value) in obj {
        let hit_count = value.as_i64().unwrap_or(0);
        out.insert(rel_path.clone(), RuntimeCoverageInput { hit_count, covered_pct: Some(if hit_count > 0 { 100.0 } else { 0.0 }) });
    }
    out
}

pub enum CoverageFormat {
    Istanbul,
    Simple,
}

pub struct NormalizedCoverage {
    pub normalized: HashMap<String, RuntimeCoverageInput>,
    pub format: CoverageFormat,
}

pub fn normalize_coverage_report(raw_report: &Value, project_root: Option<&str>) -> NormalizedCoverage {
    if is_istanbul_report(raw_report) {
        NormalizedCoverage { normalized: normalize_istanbul(raw_report, project_root), format: CoverageFormat::Istanbul }
    } else {
        NormalizedCoverage { normalized: normalize_simple_map(raw_report), format: CoverageFormat::Simple }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_istanbul_shape() {
        assert!(is_istanbul_report(&json!({"/root/a.js": {"statementMap": {}, "s": {}}})));
        assert!(!is_istanbul_report(&json!({"a.js": 5})));
        assert!(!is_istanbul_report(&json!({})));
        assert!(!is_istanbul_report(&Value::Null));
    }

    #[test]
    fn simple_map_format() {
        let result = normalize_coverage_report(&json!({"src/a.js": 5, "src/b.js": 0}), None);
        assert!(matches!(result.format, CoverageFormat::Simple));
        let a = &result.normalized["src/a.js"];
        assert_eq!(a.hit_count, 5);
        assert_eq!(a.covered_pct, Some(100.0));
        let b = &result.normalized["src/b.js"];
        assert_eq!(b.hit_count, 0);
        assert_eq!(b.covered_pct, Some(0.0));
    }

    #[test]
    fn istanbul_format_computes_hit_count_and_covered_pct() {
        let report = json!({
            "/project/src/a.js": {
                "statementMap": {"0": {}, "1": {}, "2": {}},
                "s": {"0": 3, "1": 0, "2": 2},
            }
        });
        let result = normalize_coverage_report(&report, Some("/project"));
        assert!(matches!(result.format, CoverageFormat::Istanbul));
        let entry = &result.normalized["src/a.js"];
        assert_eq!(entry.hit_count, 5);
        assert_eq!(entry.covered_pct, Some((2.0_f64 / 3.0 * 1000.0).round() / 10.0));
    }

    #[test]
    fn istanbul_absolute_path_outside_project_root_falls_back_to_raw_key() {
        let report = json!({"/elsewhere/a.js": {"s": {"0": 1}}});
        let result = normalize_coverage_report(&report, Some("/project"));
        assert!(result.normalized.contains_key("/elsewhere/a.js"));
    }
}
