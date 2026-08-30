//! Faithful port of `lib/runtime-coverage.js`'s `normalizeCoverageReport` —
//! normalizes an ingested runtime coverage report (Istanbul's
//! `coverage-final.json`, or a simple `{ path: hitCount }` map) into the
//! shape `db-store`'s `ingest_runtime_coverage` stores. The Ignite-side
//! counterpart to a project's own CI uploading whatever coverage report
//! its test suite already produces.

use ignite_db_store::RuntimeCoverageInput;
use serde_json::Value;
use std::collections::HashMap;

pub fn is_istanbul_report(data: &Value) -> bool {
    let Some(obj) = data.as_object() else { return false };
    let Some((_, entry)) = obj.iter().next() else { return false };
    let Some(entry_obj) = entry.as_object() else { return false };
    entry_obj.contains_key("statementMap") || entry_obj.contains_key("s")
}

fn normalize_istanbul(data: &Value, project_root: Option<&str>) -> HashMap<String, RuntimeCoverageInput> {
    let mut out = HashMap::new();
    let Some(obj) = data.as_object() else { return out };
    for (abs_or_rel, file_cov) in obj {
        let rel_path = match project_root {
            Some(root) if abs_or_rel.starts_with(root) => abs_or_rel[root.len()..].trim_start_matches(['/', '\\']).to_string(),
            _ => abs_or_rel.clone(),
        };
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
