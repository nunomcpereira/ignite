//! Built-in "low encapsulation" check. Faithful port of
//! `checks/file-encapsulation.js`. Flags any single source file over
//! max_lines lines - a cheap, language-agnostic proxy for "too many
//! responsibilities in one file". Always advisory.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

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

#[derive(Debug, Clone)]
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
        let Some((head, line_count)) = count_lines(file) else { continue };
        if line_count <= config.max_lines {
            continue;
        }
        let content = String::from_utf8_lossy(&head);

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

/// Bytes kept from the start of a file for the binary sniff and the
/// line-1 snippet; the rest is only counted, never held in memory.
const HEAD_BYTES: usize = 64 * 1024;

/// Streams `file` in fixed-size chunks and returns its first
/// [`HEAD_BYTES`] plus its line count (`split('\n').count()` semantics),
/// or `None` for an unreadable or binary file. Constant memory, so a
/// multi-GB generated file can't exhaust the process the way reading it
/// whole used to.
fn count_lines(file: &Path) -> Option<(Vec<u8>, usize)> {
    use std::io::Read;
    let mut reader = std::fs::File::open(file).ok()?;
    let mut head = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut newlines = 0usize;
    let mut sniffed = false;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        };
        let chunk = &buf[..n];
        if head.len() < HEAD_BYTES {
            head.extend_from_slice(&chunk[..n.min(HEAD_BYTES - head.len())]);
        }
        if !sniffed && head.len() >= 8192 {
            if looks_binary(&head) {
                return None;
            }
            sniffed = true;
        }
        newlines += chunk.iter().filter(|&&b| b == b'\n').count();
    }
    if !sniffed && looks_binary(&head) {
        return None;
    }
    Some((head, newlines + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn count_lines_matches_split_semantics_across_chunks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.js");
        // Spans several 64 KiB read chunks, no trailing newline.
        let content = format!("{}last", "line of code\n".repeat(20_000));
        fs::write(&path, &content).unwrap();
        let (head, count) = count_lines(&path).unwrap();
        assert_eq!(count, content.split('\n').count());
        assert_eq!(head.len(), HEAD_BYTES);
    }

    #[test]
    fn count_lines_skips_binary_files_past_the_first_chunk_boundary() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.js");
        let mut bytes = b"x\n".repeat(2000);
        bytes[100] = 0;
        fs::write(&path, &bytes).unwrap();
        assert!(count_lines(&path).is_none());
    }

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
