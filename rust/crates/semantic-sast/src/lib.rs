//! Semantic pattern-matching SAST via Semgrep OSS. Faithful port of
//! `checks/semantic-sast.js`, including the reverted (documented, not
//! silently dropped) experiment of running each `--config` pack as its
//! own concurrent process — measured slower in the JS original (343s vs
//! 264s on a 950k-LOC monorepo), so this port also uses one process with
//! multiple `--config` flags.

use ignite_fs_utils::{build_snippet, relative_to_root, skip_dirs, Snippet, SnippetOptions};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

/// Same rationale as BEARER_FORCE_WARNING_TITLES in pii-dataflow.js (not
/// yet ported): these rule messages are known noisy/low-confidence
/// findings that can be reported as ERROR by rule metadata despite not
/// materially changing real risk.
static SEMGREP_FORCE_WARNING_TITLES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)unsanitized dynamic input in file path").unwrap(),
        Regex::new(r"(?i)observable timing discrepancy").unwrap(),
        Regex::new(r"(?i)timing discrepancy").unwrap(),
    ]
});
static CWE_PREFIX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^CWE-\d+").unwrap());

/// `p/security-audit`'s use-defusedxml rule fires on any
/// `xml.etree.ElementTree` import, regardless of whether the file actually
/// parses untrusted XML with it — real usage found via `ignite scan` on a
/// sibling project: a file imported native ET only for
/// `register_namespace`/`tostring` (serialization) and an exception type,
/// while all parsing went through `defusedxml.ElementTree.fromstring`
/// under a different local name. Semgrep has no cross-import-alias taint
/// tracking for this rule, so we downgrade it here, conditioned on the
/// file content actually showing the safe shape (defusedxml imported, no
/// native-ET parse call) — unlike SEMGREP_FORCE_WARNING_TITLES above, this
/// is content-aware, not a blanket downgrade of the rule.
static USE_DEFUSEDXML_FINDING_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)recommends using `?defusedxml`?").unwrap());
static DEFUSEDXML_IMPORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^\s*(?:from|import)\s+defusedxml\b").unwrap());
static NATIVE_XML_PARSE_CALL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:ET|xml\.etree\.ElementTree)\s*\.\s*(?:fromstring|parse|XMLParser)\s*\(").unwrap());

fn is_defusedxml_already_used_safely(content: &str) -> bool {
    DEFUSEDXML_IMPORT_RE.is_match(content) && !NATIVE_XML_PARSE_CALL_RE.is_match(content)
}

pub async fn build_semgrep_env() -> std::io::Result<HashMap<String, String>> {
    let semgrep_home = std::env::temp_dir().join("ignite-semgrep-home");
    let semgrep_cache = semgrep_home.join("cache");
    let _ = tokio::fs::create_dir_all(&semgrep_home).await;
    let _ = tokio::fs::create_dir_all(&semgrep_cache).await;
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), semgrep_home.to_string_lossy().into_owned());
    env.insert("XDG_CONFIG_HOME".to_string(), semgrep_home.to_string_lossy().into_owned());
    env.insert("XDG_CACHE_HOME".to_string(), semgrep_cache.to_string_lossy().into_owned());
    env.insert("SEMGREP_SEND_METRICS".to_string(), "off".to_string());
    Ok(env)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SemgrepToolingProbe {
    pub ok: bool,
    pub version: Option<String>,
    pub reason: Option<String>,
}

pub async fn semgrep_tooling(runner: &ToolRunner) -> SemgrepToolingProbe {
    let env = build_semgrep_env().await.unwrap_or_default();
    match runner.run_tool("semgrep", &["--version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions { env, ..Default::default() }).await {
        Ok(out) => SemgrepToolingProbe { ok: true, version: Some(out.stdout.trim().to_string()).filter(|s| !s.is_empty()), reason: None },
        Err(_) => SemgrepToolingProbe {
            ok: false,
            version: None,
            reason: Some("`semgrep` is not installed (brew install semgrep / pip install semgrep) — semantic SAST and posture findings are simply omitted.".to_string()),
        },
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SemanticSastFinding {
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Snippet>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SemanticSastResult {
    pub findings: Vec<SemanticSastFinding>,
    pub engine: &'static str,
}

pub struct SemanticSastConfig {
    pub enabled: bool,
    pub semgrep_config: String,
    pub timeout_ms: u64,
}

impl Default for SemanticSastConfig {
    fn default() -> Self {
        SemanticSastConfig { enabled: true, semgrep_config: "p/security-audit".to_string(), timeout_ms: 10 * 60_000 }
    }
}

pub async fn check_semantic_sast(root: &Path, runner: &ToolRunner, config: &SemanticSastConfig) -> SemanticSastResult {
    let tooling = if config.enabled {
        semgrep_tooling(runner).await
    } else {
        SemgrepToolingProbe { ok: false, version: None, reason: Some("semgrep is disabled (security.semgrep.enabled=false).".to_string()) }
    };
    if !tooling.ok {
        return SemanticSastResult { findings: vec![], engine: "disabled" };
    }

    let config_packs: Vec<String> = config.semgrep_config.split(',').map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect();
    let env = build_semgrep_env().await.unwrap_or_default();

    let mut args = vec!["scan".to_string()];
    for pack in &config_packs {
        args.push("--config".to_string());
        args.push(pack.clone());
    }
    // Same directory exclusions as Ignite's own walkFiles (SKIP_DIRS) —
    // semgrep does its own file discovery, so without these it happily
    // pattern-matches vendored/generated bundles.
    for dir in skip_dirs() {
        args.push("--exclude".to_string());
        args.push(dir.to_string());
    }
    args.extend(["--json".to_string(), "--quiet".to_string(), "--metrics".to_string(), "off".to_string(), root.to_string_lossy().into_owned()]);

    let output = match runner
        .run_tool("semgrep", &args, &root.to_string_lossy(), RunToolOptions { allowed_exit_codes: vec![0, 1], env, timeout_ms: Some(config.timeout_ms) })
        .await
    {
        Ok(o) => o,
        Err(_) => return SemanticSastResult { findings: vec![], engine: "failed" },
    };

    let data: serde_json::Value = if output.stdout.trim().is_empty() {
        serde_json::json!({"results": []})
    } else {
        match serde_json::from_str(&output.stdout) {
            Ok(v) => v,
            Err(_) => return SemanticSastResult { findings: vec![], engine: "failed" },
        }
    };
    let results = data.get("results").and_then(|r| r.as_array()).cloned().unwrap_or_default();

    let mut findings = Vec::new();
    for r in results {
        let raw_path = r.get("path").and_then(|p| p.as_str()).unwrap_or("");
        let rel_file = relative_to_root(root, raw_path).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        let line = r.get("start").and_then(|s| s.get("line")).and_then(|l| l.as_i64()).unwrap_or(1).max(1) as usize;
        let content = std::fs::read_to_string(root.join(&rel_file)).ok();
        let semgrep_severity = r.get("extra").and_then(|e| e.get("severity")).and_then(|s| s.as_str()).unwrap_or("WARNING").to_uppercase();
        let message = r.get("extra").and_then(|e| e.get("message")).and_then(|m| m.as_str()).unwrap_or("Semgrep finding").to_string();
        let forced_warning = SEMGREP_FORCE_WARNING_TITLES.iter().any(|re| re.is_match(&message))
            || (USE_DEFUSEDXML_FINDING_RE.is_match(&message)
                && content.as_deref().map(is_defusedxml_already_used_safely).unwrap_or(false));
        let cwe_list = r
            .get("extra")
            .and_then(|e| e.get("metadata"))
            .and_then(|m| m.get("cwe"))
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();
        let owasp_list = r
            .get("extra")
            .and_then(|e| e.get("metadata"))
            .and_then(|m| m.get("owasp"))
            .and_then(|o| o.as_array())
            .cloned()
            .unwrap_or_default();
        let cwe_first = cwe_list.first().and_then(|v| v.as_str()).unwrap_or("");
        let cwe = CWE_PREFIX_RE.find(cwe_first).map(|m| m.as_str().to_string());
        let owasp = owasp_list.first().and_then(|v| v.as_str()).map(String::from);
        let check_id = r.get("check_id").and_then(|c| c.as_str()).unwrap_or("semgrep-finding").to_lowercase();
        let severity: &'static str = if forced_warning {
            "warning"
        } else {
            match semgrep_severity.as_str() {
                "ERROR" => "error",
                _ => "warning",
            }
        };
        findings.push(SemanticSastFinding {
            file: rel_file,
            line,
            kind: check_id,
            tool: "semgrep",
            severity,
            message,
            code: content.as_deref().and_then(|c| build_snippet(c, line, SnippetOptions::default())),
            cwe,
            owasp,
        });
    }

    SemanticSastResult { findings, engine: "semgrep" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;
    use std::fs;
    use tempfile::tempdir;

    fn runner() -> ToolRunner {
        let mut binaries = StdHashMap::new();
        binaries.insert("semgrep", "semgrep".to_string());
        ToolRunner::new(binaries)
    }

    #[test]
    fn use_defusedxml_fp_downgrade_only_fires_when_native_et_never_parses() {
        // Real shape from ioc's backend/app/api/v1/branding.py: native ET
        // used only for register_namespace/tostring (serialization), all
        // parsing through defusedxml under a local alias.
        let safe = "import xml.etree.ElementTree as ET\nfrom defusedxml.ElementTree import fromstring as _safe_fromstring\nET.register_namespace(\"\", \"ns\")\nroot = _safe_fromstring(data)\nET.tostring(root)\n";
        assert!(is_defusedxml_already_used_safely(safe));

        // Genuine risk: defusedxml imported but native ET.fromstring still
        // reachable — must NOT downgrade.
        let still_risky = "import xml.etree.ElementTree as ET\nimport defusedxml\nroot = ET.fromstring(data)\n";
        assert!(!is_defusedxml_already_used_safely(still_risky));

        // No defusedxml at all — must NOT downgrade.
        let no_defusedxml = "import xml.etree.ElementTree as ET\nroot = ET.fromstring(data)\n";
        assert!(!is_defusedxml_already_used_safely(no_defusedxml));
    }

    #[tokio::test]
    async fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        let config = SemanticSastConfig { enabled: false, ..Default::default() };
        let result = check_semantic_sast(dir.path(), &runner(), &config).await;
        assert!(result.findings.is_empty());
        assert_eq!(result.engine, "disabled");
    }

    #[tokio::test]
    async fn real_semgrep_binary_end_to_end_against_a_custom_local_rule() {
        // Skips gracefully (rather than failing the suite) when semgrep
        // isn't installed on PATH, same convention the JS test suite uses
        // for every soft-dependency tool.
        let mut check = std::process::Command::new("semgrep");
        check.arg("--version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: semgrep not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(
            root.join("app.js"),
            "const exec = require(\"child_process\").exec;\nfunction run(userInput) {\n  exec(\"ls \" + userInput);\n}\nmodule.exports = run;\n",
        )
        .unwrap();
        fs::write(
            root.join("rule.yml"),
            "rules:\n  - id: test-command-injection\n    languages: [javascript]\n    severity: ERROR\n    message: Possible command injection via unsanitized input to exec()\n    patterns:\n      - pattern: exec($CMD)\n",
        )
        .unwrap();

        let config = SemanticSastConfig { enabled: true, semgrep_config: root.join("rule.yml").to_string_lossy().into_owned(), timeout_ms: 60_000 };
        let result = check_semantic_sast(root, &runner(), &config).await;
        assert_eq!(result.engine, "semgrep");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].file, "app.js");
        assert_eq!(result.findings[0].line, 3);
        assert_eq!(result.findings[0].severity, "error");
        assert_eq!(result.findings[0].tool, "semgrep");
    }
}
