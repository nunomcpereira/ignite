//! Code-duplication scan via jscpd. Faithful port of
//! `checks/code-duplication.js`. jscpd does its own multi-language file
//! discovery over `root` in one pass; each clone becomes one finding
//! anchored at its first occurrence, referencing the second in the
//! message. No built-in fallback — duplicate-block detection needs the
//! real tool.

use ignite_fs_utils::{build_snippet, relative_to_root, Snippet, SnippetOptions};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::path::Path;

static MEANINGFUL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Za-z0-9_]").unwrap());

pub struct CodeDuplicationConfig {
    pub enabled: bool,
    pub min_lines: u32,
    pub min_tokens: u32,
    pub ignore_patterns: Vec<String>,
}

impl Default for CodeDuplicationConfig {
    fn default() -> Self {
        CodeDuplicationConfig { enabled: false, min_lines: 5, min_tokens: 50, ignore_patterns: vec![] }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DuplicateRef {
    pub file: String,
    pub line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeDuplicationFinding {
    pub file: String,
    pub line: usize,
    pub kind: &'static str,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Snippet>,
    pub duplicate_ref: DuplicateRef,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeDuplicationResult {
    pub findings: Vec<CodeDuplicationFinding>,
    pub engine: &'static str,
}

pub async fn jscpd_tooling(runner: &ToolRunner) -> bool {
    runner
        .run_tool("jscpd", &["--version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default())
        .await
        .is_ok()
}

fn relative(root: &Path, name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    relative_to_root(root, name).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/")
}

fn parse_jscpd_report(root: &Path, data: &serde_json::Value, min_lines: u32) -> Vec<CodeDuplicationFinding> {
    let duplicates = data.get("duplicates").and_then(|d| d.as_array()).cloned().unwrap_or_default();
    let mut findings = Vec::new();
    for dup in &duplicates {
        let dup_lines = dup.get("lines").and_then(|l| l.as_u64()).unwrap_or(0) as u32;
        if dup_lines < min_lines {
            continue;
        }
        let first = dup.get("firstFile");
        let first_name = first.and_then(|f| f.get("name")).and_then(|n| n.as_str()).unwrap_or("");
        let rel_file = relative(root, first_name);
        let line = first
            .and_then(|f| f.get("startLoc"))
            .and_then(|s| s.get("line"))
            .and_then(|l| l.as_u64())
            .unwrap_or(0)
            .max(1) as usize;
        let end_line = first
            .and_then(|f| f.get("endLoc"))
            .and_then(|s| s.get("line"))
            .and_then(|l| l.as_u64())
            .map(|l| l as usize)
            .unwrap_or(line);

        let second = dup.get("secondFile");
        let second_name = second.and_then(|f| f.get("name")).and_then(|n| n.as_str());
        let other_file = second_name.map(|n| relative(root, n)).unwrap_or_else(|| "?".to_string());
        let other_line = second
            .and_then(|f| f.get("startLoc"))
            .and_then(|s| s.get("line"))
            .and_then(|l| l.as_u64())
            .unwrap_or(0)
            .max(1) as usize;
        let other_end_line = second
            .and_then(|f| f.get("endLoc"))
            .and_then(|s| s.get("line"))
            .and_then(|l| l.as_u64())
            .map(|l| l as usize)
            .unwrap_or(other_line);
        let other_range = if other_end_line > other_line { format!("{}-{}", other_line, other_end_line) } else { other_line.to_string() };

        let content = std::fs::read_to_string(root.join(&rel_file)).ok();
        if let Some(c) = &content {
            let lines: Vec<&str> = c.split('\n').collect();
            let start_idx = line.saturating_sub(1);
            let end_idx = end_line.min(lines.len());
            let span = if start_idx < end_idx { &lines[start_idx..end_idx] } else { &[] as &[&str] };
            let meaningful = span.iter().any(|l| MEANINGFUL_RE.is_match(l));
            if !meaningful {
                continue;
            }
        }

        findings.push(CodeDuplicationFinding {
            file: rel_file,
            line,
            kind: "duplicate-code",
            tool: "jscpd",
            severity: "warning",
            message: format!("{}-line duplicate block, also found in {}:{}.", dup_lines, other_file, other_range),
            code: content.as_deref().and_then(|c| build_snippet(c, line, SnippetOptions { end_line: Some(end_line), ..Default::default() })),
            duplicate_ref: DuplicateRef { file: other_file, line: other_line, end_line: other_end_line },
        });
    }
    findings
}

pub async fn check_code_duplication(root: &Path, runner: &ToolRunner, config: &CodeDuplicationConfig) -> CodeDuplicationResult {
    let tooling_ok = config.enabled && jscpd_tooling(runner).await;
    if !tooling_ok {
        return CodeDuplicationResult { findings: vec![], engine: "disabled" };
    }

    let out_dir = std::env::temp_dir().join(format!("ignite-jscpd-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)));

    let mut args = vec![
        root.to_string_lossy().into_owned(),
        "--reporters".to_string(),
        "json".to_string(),
        "--output".to_string(),
        out_dir.to_string_lossy().into_owned(),
        "--silent".to_string(),
        "--min-lines".to_string(),
        config.min_lines.to_string(),
        "--min-tokens".to_string(),
        config.min_tokens.to_string(),
    ];
    if !config.ignore_patterns.is_empty() {
        args.push("--ignore".to_string());
        args.push(config.ignore_patterns.join(","));
    }

    let run_result = runner.run_tool("jscpd", &args, &root.to_string_lossy(), RunToolOptions { allowed_exit_codes: vec![0, 1], ..Default::default() }).await;

    let result = match run_result {
        Ok(_) => {
            let report_path = out_dir.join("jscpd-report.json");
            match tokio::fs::read_to_string(&report_path).await {
                Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
                    Ok(data) => CodeDuplicationResult { findings: parse_jscpd_report(root, &data, config.min_lines), engine: "jscpd" },
                    Err(_) => CodeDuplicationResult { findings: vec![], engine: "jscpd" },
                },
                Err(_) => CodeDuplicationResult { findings: vec![], engine: "jscpd" },
            }
        }
        Err(_) => CodeDuplicationResult { findings: vec![], engine: "disabled" },
    };

    let _ = tokio::fs::remove_dir_all(&out_dir).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    fn runner_with_jscpd() -> ToolRunner {
        let mut binaries = HashMap::new();
        binaries.insert("jscpd", "jscpd".to_string());
        ToolRunner::new(binaries)
    }

    #[cfg(unix)]
    #[test]
    fn relative_resolves_a_tool_reported_path_through_a_symlinked_root() {
        // Same class of bug fixed in pii-dataflow: a naive component-diff
        // never finds a common prefix between an uncanonicalized `root` and
        // a tool-reported path that canonicalizes symlinks (e.g. macOS
        // /tmp -> /private/tmp), so the resulting "relative" path is a
        // useless multi-`../` string that doesn't resolve back to the file.
        let real_dir = tempdir().unwrap();
        let real_root = fs::canonicalize(real_dir.path()).unwrap();
        fs::create_dir_all(real_root.join("src")).unwrap();
        fs::write(real_root.join("src/a.js"), "line1\nline2\n").unwrap();

        let symlink_root = real_dir.path().parent().unwrap().join("symlinked-root-alias-jscpd");
        std::os::unix::fs::symlink(&real_root, &symlink_root).unwrap();

        let reported = real_root.join("src/a.js");
        let rel = relative(&symlink_root, reported.to_str().unwrap());
        assert_eq!(rel, "src/a.js");

        let content = fs::read_to_string(symlink_root.join(&rel)).unwrap();
        assert_eq!(content, "line1\nline2\n");

        let _ = fs::remove_file(&symlink_root);
    }

    fn sample_report() -> serde_json::Value {
        serde_json::json!({
            "duplicates": [{
                "lines": 10,
                "firstFile": {"name": "a.js", "startLoc": {"line": 2}, "endLoc": {"line": 11}},
                "secondFile": {"name": "b.js", "startLoc": {"line": 5}, "endLoc": {"line": 14}},
            }]
        })
    }

    #[test]
    fn parses_report_into_finding_with_duplicate_ref() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let mut content = String::new();
        for i in 1..=15 {
            content.push_str(&format!("const x{} = {};\n", i, i));
        }
        fs::write(root.join("a.js"), &content).unwrap();
        fs::write(root.join("b.js"), &content).unwrap();

        let findings = parse_jscpd_report(root, &sample_report(), 5);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "a.js");
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].duplicate_ref.file, "b.js");
        assert_eq!(findings[0].duplicate_ref.line, 5);
        assert_eq!(findings[0].duplicate_ref.end_line, 14);
        assert!(findings[0].message.contains("10-line duplicate block"));
        assert!(findings[0].message.contains("b.js:5-14"));
    }

    #[test]
    fn skips_below_min_lines_guard() {
        let dir = tempdir().unwrap();
        let findings = parse_jscpd_report(dir.path(), &sample_report(), 20);
        assert!(findings.is_empty());
    }

    #[test]
    fn skips_punctuation_only_duplicate_span() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        // Lines 2..=11 are all closing punctuation, no identifier chars.
        let content = "x\n}\n}\n}\n}\n}\n}\n}\n}\n}\n}\n".to_string();
        fs::write(root.join("a.js"), &content).unwrap();

        let findings = parse_jscpd_report(root, &sample_report(), 5);
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        let config = CodeDuplicationConfig { enabled: false, ..Default::default() };
        let result = check_code_duplication(dir.path(), &ToolRunner::new(HashMap::new()), &config).await;
        assert_eq!(result.engine, "disabled");
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn real_jscpd_binary_end_to_end() {
        let mut check = std::process::Command::new("jscpd");
        check.arg("--version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: jscpd not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        let block = "function doWork(x) {\n  const a = x + 1;\n  const b = a * 2;\n  const c = b - 3;\n  console.log(a, b, c);\n  return c;\n}\n";
        fs::write(root.join("one.js"), format!("{}\n// filler\n", block)).unwrap();
        fs::write(root.join("two.js"), format!("{}\n// filler\n", block)).unwrap();

        let config = CodeDuplicationConfig { enabled: true, min_lines: 5, min_tokens: 10, ignore_patterns: vec![] };
        let result = check_code_duplication(root, &runner_with_jscpd(), &config).await;
        assert_eq!(result.engine, "jscpd");
        assert!(!result.findings.is_empty(), "expected jscpd to flag the duplicated block between one.js and two.js");
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}
