//! Per-language LOC metrics via gocloc. Faithful port of
//! `checks/loc-metrics.js`. Purely descriptive — never produces issues.

use ignite_fs_utils::{relative_to_root, skip_dirs_regex};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct FileLocEntry {
    pub file: String,
    pub language: String,
    pub code: i64,
    pub comment: i64,
    pub blank: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LanguageAggregate {
    pub name: String,
    pub files: i64,
    pub code: i64,
    pub comment: i64,
    pub blank: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LocMetrics {
    pub languages: Vec<LanguageAggregate>,
    pub total: serde_json::Value,
    pub files: Vec<FileLocEntry>,
}

pub struct LocMetricsResult {
    pub engine: &'static str,
    pub metrics: Option<LocMetrics>,
}

pub async fn gocloc_tooling(runner: &ToolRunner) -> bool {
    runner.run_tool("gocloc", &["--version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default()).await.is_ok()
}

/// Precise per-language LOC counts via gocloc, which does its own multi-
/// language file discovery over `root` in one pass.
pub async fn generate_loc_metrics(root: &Path, runner: &ToolRunner, enabled: bool) -> LocMetricsResult {
    if !enabled || !gocloc_tooling(runner).await {
        return LocMetricsResult { engine: "disabled", metrics: None };
    }

    let output = match runner
        .run_tool(
            "gocloc",
            &[
                "--by-file".to_string(),
                "--output-type".to_string(),
                "json".to_string(),
                "--fullpath".to_string(),
                "--not-match-d".to_string(),
                skip_dirs_regex(),
                root.to_string_lossy().into_owned(),
            ],
            &root.to_string_lossy(),
            RunToolOptions::default(),
        )
        .await
    {
        Ok(o) => o,
        Err(_) => return LocMetricsResult { engine: "disabled", metrics: None },
    };

    let raw: serde_json::Value = if output.stdout.trim().is_empty() {
        return LocMetricsResult { engine: "gocloc", metrics: None };
    } else {
        match serde_json::from_str(&output.stdout) {
            Ok(v) => v,
            Err(_) => return LocMetricsResult { engine: "disabled", metrics: None },
        }
    };

    let raw_files = raw.get("files").and_then(|f| f.as_array()).cloned().unwrap_or_default();
    let mut files = Vec::new();
    for f in &raw_files {
        let name = f.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let rel = relative_to_root(root, name).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        files.push(FileLocEntry {
            file: rel,
            language: f.get("language").and_then(|l| l.as_str()).unwrap_or("").to_string(),
            code: f.get("code").and_then(|c| c.as_i64()).unwrap_or(0),
            comment: f.get("comment").and_then(|c| c.as_i64()).unwrap_or(0),
            blank: f.get("blank").and_then(|c| c.as_i64()).unwrap_or(0),
        });
    }

    let mut by_language: BTreeMap<String, LanguageAggregate> = BTreeMap::new();
    for f in &files {
        let agg = by_language.entry(f.language.clone()).or_insert_with(|| LanguageAggregate { name: f.language.clone(), files: 0, code: 0, comment: 0, blank: 0 });
        agg.files += 1;
        agg.code += f.code;
        agg.comment += f.comment;
        agg.blank += f.blank;
    }

    let metrics = LocMetrics { languages: by_language.into_values().collect(), total: raw.get("total").cloned().unwrap_or(serde_json::Value::Null), files };
    LocMetricsResult { engine: "gocloc", metrics: Some(metrics) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    fn runner_with_gocloc() -> ToolRunner {
        let mut binaries = HashMap::new();
        binaries.insert("gocloc", "gocloc".to_string());
        ToolRunner::new(binaries)
    }

    #[tokio::test]
    async fn disabled_returns_no_metrics() {
        let dir = tempdir().unwrap();
        let result = generate_loc_metrics(dir.path(), &ToolRunner::new(HashMap::new()), false).await;
        assert_eq!(result.engine, "disabled");
        assert!(result.metrics.is_none());
    }

    #[tokio::test]
    async fn real_gocloc_binary_end_to_end() {
        let mut check = std::process::Command::new("gocloc");
        check.arg("--version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: gocloc not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("app.js"), "// a comment\nfunction f() {\n  return 1;\n}\n\n").unwrap();
        fs::write(root.join("main.py"), "# a comment\ndef f():\n    return 1\n").unwrap();

        let result = generate_loc_metrics(root, &runner_with_gocloc(), true).await;
        assert_eq!(result.engine, "gocloc");
        let metrics = result.metrics.unwrap();
        assert_eq!(metrics.files.len(), 2);
        assert!(metrics.languages.iter().any(|l| l.name == "JavaScript"));
        assert!(metrics.languages.iter().any(|l| l.name == "Python"));
    }
}
