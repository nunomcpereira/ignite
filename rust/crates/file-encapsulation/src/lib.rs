//! Built-in "low encapsulation" check. Faithful port of
//! `checks/file-encapsulation.js`. Flags any single source file over
//! max_lines lines - a cheap, language-agnostic proxy for "too many
//! responsibilities in one file". Always advisory.

use ignite_fs_utils::{build_snippet, looks_binary, walk_files, Snippet, SnippetOptions, SECRET_SCAN_CODE_EXTS};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct FileEncapsulationFinding {
    pub file: String,
    pub line: usize,
    pub kind: &'static str,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Snippet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileEncapsulationResult {
    pub findings: Vec<FileEncapsulationFinding>,
    pub engine: &'static str,
}

pub struct FileEncapsulationConfig {
    pub enabled: bool,
    pub max_lines: usize,
}

pub fn check_file_encapsulation(root: &Path, config: &FileEncapsulationConfig) -> std::io::Result<FileEncapsulationResult> {
    if !config.enabled {
        return Ok(FileEncapsulationResult { findings: vec![], engine: "disabled" });
    }

    let files = walk_files(root)?;
    let mut findings = Vec::new();

    for file in &files {
        let ext = file.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        if !SECRET_SCAN_CODE_EXTS.contains(&ext.as_str()) {
            continue;
        }
        let Ok(buffer) = std::fs::read(file) else { continue };
        if looks_binary(&buffer) {
            continue;
        }
        let content = String::from_utf8_lossy(&buffer).into_owned();
        let line_count = content.split('\n').count();
        if line_count <= config.max_lines {
            continue;
        }

        let rel = file.strip_prefix(root).unwrap_or(file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        findings.push(FileEncapsulationFinding {
            file: rel.clone(),
            line: 1,
            kind: "file-too-large",
            tool: "ignite-built-in",
            severity: "warning",
            message: format!(
                "{rel} is {line_count} lines — over the {}-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.",
                config.max_lines
            ),
            code: build_snippet(&content, 1, SnippetOptions::default()),
        });
    }

    Ok(FileEncapsulationResult { findings, engine: "built-in" })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn flags_a_file_over_the_line_threshold() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let content = "x\n".repeat(1500);
        fs::write(root.join("big.js"), &content).unwrap();
        fs::write(root.join("small.js"), "x\n").unwrap();

        let result = check_file_encapsulation(root, &FileEncapsulationConfig { enabled: true, max_lines: 1000 }).unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].file, "big.js");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn ignores_non_code_extensions() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let content = "x\n".repeat(1500);
        fs::write(root.join("data.json"), &content).unwrap();

        let result = check_file_encapsulation(root, &FileEncapsulationConfig { enabled: true, max_lines: 1000 }).unwrap();
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        let result = check_file_encapsulation(dir.path(), &FileEncapsulationConfig { enabled: false, max_lines: 1000 }).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.engine, "disabled");
    }
}
