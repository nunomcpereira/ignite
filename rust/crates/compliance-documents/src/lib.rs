//! EU AI Act doc-presence scan. Faithful port of
//! `checks/compliance-documents.js`. Filename/path pattern match only —
//! never produces issues, never blocks a run, advisory context for a human.

use ignite_fs_utils::{relative_to_root, walk_files};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

pub const DOCUMENT_CATEGORIES: &[&str] = &[
    "risk-management-system",  // Art. 9
    "technical-documentation", // Art. 11 / Annex IV
    "fria",                    // Art. 27 — fundamental rights impact assessment
    "training-data-summary",   // Art. 53 — GPAI providers
    "post-market-monitoring",  // Art. 72
];

static PATTERNS: Lazy<BTreeMap<&'static str, Regex>> = Lazy::new(|| {
    [
        ("risk-management-system", r"(?i)risk[-_ ]?management([-_ ]?system)?|\brms\b"),
        ("technical-documentation", r"(?i)annex[-_ ]?iv|technical[-_ ]?documentation|tech[-_ ]?docs?"),
        ("fria", r"(?i)\bfria\b|fundamental[-_ ]?rights[-_ ]?impact"),
        ("training-data-summary", r"(?i)training[-_ ]?data[-_ ]?summary|dataset[-_ ]?summary|model[-_ ]?card"),
        ("post-market-monitoring", r"(?i)post[-_ ]?market[-_ ]?monitoring|\bpmms\b"),
    ]
    .into_iter()
    .map(|(k, p)| (k, Regex::new(p).unwrap()))
    .collect()
});

#[derive(Debug, Clone, Serialize)]
pub struct DocumentMatch {
    pub file: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DocumentCategoryReport {
    pub status: &'static str, // "DETECTED" | "MISSING"
    pub matches: Vec<DocumentMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComplianceDocumentsResult {
    pub engine: &'static str,
    pub documents: BTreeMap<&'static str, DocumentCategoryReport>,
}

fn empty_documents_report() -> BTreeMap<&'static str, DocumentCategoryReport> {
    DOCUMENT_CATEGORIES.iter().map(|&cat| (cat, DocumentCategoryReport { status: "MISSING", matches: vec![] })).collect()
}

pub fn check_compliance_documents(root: &Path, enabled: bool) -> std::io::Result<ComplianceDocumentsResult> {
    let mut documents = empty_documents_report();
    if !enabled {
        return Ok(ComplianceDocumentsResult { engine: "disabled", documents });
    }

    for file in walk_files(root)? {
        let base = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let rel = relative_to_root(root, &file.to_string_lossy()).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        for &category in DOCUMENT_CATEGORIES {
            let pattern = &PATTERNS[category];
            if pattern.is_match(&base) || pattern.is_match(&rel) {
                documents.get_mut(category).unwrap().matches.push(DocumentMatch { file: rel.clone() });
            }
        }
    }

    for report in documents.values_mut() {
        report.status = if !report.matches.is_empty() { "DETECTED" } else { "MISSING" };
    }

    Ok(ComplianceDocumentsResult { engine: "built-in", documents })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn detects_a_risk_management_system_document_by_filename() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("RISK-MANAGEMENT-SYSTEM.md"), "content").unwrap();

        let result = check_compliance_documents(root, true).unwrap();
        assert_eq!(result.documents["risk-management-system"].status, "DETECTED");
        assert_eq!(result.documents["fria"].status, "MISSING");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn matches_by_path_not_just_basename() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("docs/annex-iv")).unwrap();
        fs::write(root.join("docs/annex-iv/spec.pdf"), "content").unwrap();

        let result = check_compliance_documents(root, true).unwrap();
        assert_eq!(result.documents["technical-documentation"].status, "DETECTED");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn all_categories_missing_when_nothing_matches() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("README.md"), "hello").unwrap();

        let result = check_compliance_documents(root, true).unwrap();
        for cat in DOCUMENT_CATEGORIES {
            assert_eq!(result.documents[cat].status, "MISSING", "{cat}");
        }
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn disabled_returns_all_missing_without_scanning() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("RISK-MANAGEMENT-SYSTEM.md"), "content").unwrap();

        let result = check_compliance_documents(root, false).unwrap();
        assert_eq!(result.engine, "disabled");
        assert_eq!(result.documents["risk-management-system"].status, "MISSING");
    }
}
