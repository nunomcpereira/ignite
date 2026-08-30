//! Runs the onboarded project's own unit test suite, sandboxed inside a
//! throwaway Docker container per detected language (never on the host).
//! Faithful port of `checks/unit-test-runner.js`.

use once_cell::sync::Lazy;
use regex::Regex;
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use std::path::Path;

const DEFAULT_TEST_NODE_MAJOR: u32 = 22; // oldest LTS with node:sqlite and other modern built-ins

static NO_TEST_SPECIFIED_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bno test specified\b").unwrap());
static ENGINE_MAJOR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\d+)").unwrap());

fn read_package_json(root: &Path) -> Option<serde_json::Value> {
    let content = std::fs::read_to_string(root.join("package.json")).ok()?;
    serde_json::from_str(&content).ok()
}

fn detect_npm_test_script(pkg: &serde_json::Value) -> Option<String> {
    let test_script = pkg.get("scripts")?.get("test")?.as_str()?;
    if test_script.is_empty() || NO_TEST_SPECIFIED_RE.is_match(test_script) {
        return None;
    }
    Some(test_script.to_string())
}

/// Respects an `engines.node` minimum if the project declares one newer
/// than the default, so the container running the test suite has whatever
/// modern built-ins (e.g. `node:sqlite`) the project's own code expects.
fn resolve_test_node_image(pkg: &serde_json::Value) -> String {
    let declared_major = pkg.get("engines").and_then(|e| e.get("node")).and_then(|v| v.as_str()).and_then(|s| ENGINE_MAJOR_RE.find(s)).and_then(|m| m.as_str().parse::<u32>().ok());
    let major = declared_major.map(|d| d.max(DEFAULT_TEST_NODE_MAJOR)).unwrap_or(DEFAULT_TEST_NODE_MAJOR);
    format!("node:{major}-alpine")
}

fn file_exists(root: &Path, name: &str) -> bool {
    root.join(name).is_file()
}

struct DetectedRunner {
    language: &'static str,
    detail: String,
    image: String,
    command: String,
}

/// Each detector inspects the staged project root for that language's own
/// marker file(s) and, if present, returns the Docker image + shell
/// command used to install deps and run its native test suite. A project
/// can match more than one (e.g. a Node frontend next to a Go backend) —
/// all matches run, in this fixed order, and any one failing fails the
/// phase.
fn detect_runners(root: &Path) -> Vec<DetectedRunner> {
    let mut matches = Vec::new();

    if let Some(pkg) = read_package_json(root) {
        if let Some(test_script) = detect_npm_test_script(&pkg) {
            matches.push(DetectedRunner {
                language: "Node.js",
                detail: format!("npm test script: \"{test_script}\""),
                image: resolve_test_node_image(&pkg),
                // node:*-alpine ships no `git` — some suites shell out to a
                // real git binary, which fails with a bare "spawn git
                // ENOENT" inside the sandbox despite passing fine on the
                // host. --no-cache avoids leaving an apk index behind in
                // the throwaway container.
                command: "apk add --no-cache git >/dev/null 2>&1 || true; npm ci --no-audit --no-fund || npm install --no-audit --no-fund && npm test".to_string(),
            });
        }
    }

    if file_exists(root, "go.mod") {
        matches.push(DetectedRunner { language: "Go", detail: "`go.mod` found".to_string(), image: "golang:1.23-alpine".to_string(), command: "go test ./...".to_string() });
    }

    if file_exists(root, "Cargo.toml") {
        matches.push(DetectedRunner { language: "Rust", detail: "`Cargo.toml` found".to_string(), image: "rust:1-slim".to_string(), command: "cargo test --locked || cargo test".to_string() });
    }

    if file_exists(root, "pyproject.toml") || file_exists(root, "setup.py") || file_exists(root, "requirements.txt") {
        matches.push(DetectedRunner {
            language: "Python",
            detail: "Python project file found (pyproject.toml/setup.py/requirements.txt)".to_string(),
            image: "python:3.12-slim".to_string(),
            command: [
                "pip install --quiet --no-input --disable-pip-version-check pytest",
                "(test -f requirements.txt && pip install --quiet --no-input --disable-pip-version-check -r requirements.txt || true)",
                "(test -f pyproject.toml -o -f setup.py && pip install --quiet --no-input --disable-pip-version-check -e . || true)",
                "pytest",
            ]
            .join(" && "),
        });
    }

    if file_exists(root, "pom.xml") {
        matches.push(DetectedRunner { language: "Java (Maven)", detail: "`pom.xml` found".to_string(), image: "maven:3-eclipse-temurin-21".to_string(), command: "mvn --batch-mode --no-transfer-progress test".to_string() });
    }

    if file_exists(root, "build.gradle") || file_exists(root, "build.gradle.kts") {
        let has_wrapper = file_exists(root, "gradlew");
        matches.push(DetectedRunner {
            language: "Java (Gradle)",
            detail: if has_wrapper { "`build.gradle(.kts)` + gradlew wrapper found".to_string() } else { "`build.gradle(.kts)` found".to_string() },
            image: "gradle:8-jdk21".to_string(),
            command: if has_wrapper { "chmod +x ./gradlew && ./gradlew test --no-daemon".to_string() } else { "gradle test --no-daemon".to_string() },
        });
    }

    matches
}

pub struct UnitTestResult {
    pub ran: bool,
    pub languages: Vec<&'static str>,
}

#[derive(Debug, thiserror::Error)]
pub enum UnitTestError {
    #[error("Cannot run project unit tests: Docker daemon is not running (start Docker Desktop).")]
    DockerUnavailable,
    #[error("{0} unit tests failed: {1}")]
    TestsFailed(&'static str, String),
}

pub async fn run_project_unit_tests(root: &Path, runner: &ToolRunner, mut log: impl FnMut(&str) + Send) -> Result<UnitTestResult, UnitTestError> {
    let matches = detect_runners(root);

    if matches.is_empty() {
        log("No recognized test project (package.json/go.mod/Cargo.toml/pyproject.toml/setup.py/requirements.txt/pom.xml/build.gradle) — skipping unit test run.");
        return Ok(UnitTestResult { ran: false, languages: vec![] });
    }

    if runner.run_tool("docker", &["info".to_string(), "--format".to_string(), "{{.ServerVersion}}".to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions::default()).await.is_err() {
        return Err(UnitTestError::DockerUnavailable);
    }

    let root_str = root.to_string_lossy().into_owned();
    let mut languages = Vec::new();
    for m in &matches {
        log(&format!("Detected {} project ({}). Running its test suite in an isolated {} container (no host access, no network beyond dependency install)...", m.language, m.detail, m.image));
        let args = vec!["run".to_string(), "--rm".to_string(), "-v".to_string(), format!("{root_str}:/repo"), "-w".to_string(), "/repo".to_string(), m.image.clone(), "sh".to_string(), "-c".to_string(), m.command.clone()];
        let env = std::collections::HashMap::new();
        runner.run_tool_streaming("docker", &args, &std::env::temp_dir().to_string_lossy(), |line| log(&line.chars().take(400).collect::<String>()), &env, 10 * 60_000).await.map_err(|e| UnitTestError::TestsFailed(m.language, e.to_string()))?;
        log(&format!("✓ {} unit tests passed.", m.language));
        languages.push(m.language);
    }

    Ok(UnitTestResult { ran: true, languages })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::tempdir;

    #[tokio::test]
    async fn no_recognized_project_skips_without_touching_docker() {
        let dir = tempdir().unwrap();
        let runner = ToolRunner::new(HashMap::new());
        let mut logs = Vec::new();
        let result = run_project_unit_tests(dir.path(), &runner, |l| logs.push(l.to_string())).await.unwrap();
        assert!(!result.ran);
        assert!(logs.iter().any(|l| l.contains("skipping unit test run")));
    }

    #[test]
    fn detect_npm_test_script_ignores_default_placeholder() {
        let pkg: serde_json::Value = serde_json::json!({"scripts": {"test": "echo \"Error: no test specified\" && exit 1"}});
        assert!(detect_npm_test_script(&pkg).is_none());
    }

    #[test]
    fn detect_npm_test_script_returns_real_script() {
        let pkg: serde_json::Value = serde_json::json!({"scripts": {"test": "jest"}});
        assert_eq!(detect_npm_test_script(&pkg), Some("jest".to_string()));
    }

    #[test]
    fn resolve_test_node_image_uses_default_when_no_engines_field() {
        let pkg: serde_json::Value = serde_json::json!({});
        assert_eq!(resolve_test_node_image(&pkg), "node:22-alpine");
    }

    #[test]
    fn resolve_test_node_image_respects_newer_engines_node() {
        let pkg: serde_json::Value = serde_json::json!({"engines": {"node": ">=24.0.0"}});
        assert_eq!(resolve_test_node_image(&pkg), "node:24-alpine");
    }

    #[test]
    fn resolve_test_node_image_never_downgrades_below_default() {
        let pkg: serde_json::Value = serde_json::json!({"engines": {"node": ">=18.0.0"}});
        assert_eq!(resolve_test_node_image(&pkg), "node:22-alpine");
    }

    #[test]
    fn detect_runners_finds_node_project() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"scripts": {"test": "jest"}}"#).unwrap();
        let matches = detect_runners(dir.path());
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].language, "Node.js");
    }

    #[test]
    fn detect_runners_finds_go_project() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("go.mod"), "module example.com/foo\n").unwrap();
        let matches = detect_runners(dir.path());
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].language, "Go");
    }

    #[test]
    fn detect_runners_finds_multiple_languages_in_one_project() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"scripts": {"test": "jest"}}"#).unwrap();
        std::fs::write(dir.path().join("go.mod"), "module example.com/foo\n").unwrap();
        let matches = detect_runners(dir.path());
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn detect_runners_gradle_prefers_wrapper_command_when_present() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("build.gradle"), "").unwrap();
        std::fs::write(dir.path().join("gradlew"), "").unwrap();
        let matches = detect_runners(dir.path());
        assert_eq!(matches.len(), 1);
        assert!(matches[0].command.contains("./gradlew"));
    }

    #[test]
    fn detect_runners_finds_nothing_for_empty_project() {
        let dir = tempdir().unwrap();
        assert!(detect_runners(dir.path()).is_empty());
    }
}
