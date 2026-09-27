//! Opt-in release checks and explicit, package-manager-owned tool upgrades.
//! No shell commands, client-supplied package names, or automatic installations.
use crate::state::AppState;
use axum::{
    extract::{FromRequestParts, Path, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use ignite_tool_runner::RunToolOptions;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc, time::Duration};

struct Tool {
    key: &'static str,
    source: &'static str,
    package: &'static str,
    version_arg: &'static str,
    /// Dockerfile `ARG` pinning this tool's release in the published image.
    /// `None` = unpinned there (pipx/npm/gem/install-script): a `--no-cache`
    /// rebuild picks up the latest release.
    docker_arg: Option<&'static str>,
}
const TOOLS: &[Tool] = &[
    Tool {
        key: "ort",
        source: "github",
        package: "oss-review-toolkit/ort",
        version_arg: "--version",
        docker_arg: Some("ORT_VERSION"),
    },
    Tool {
        key: "licensee",
        source: "gem",
        package: "licensee",
        version_arg: "version",
        docker_arg: None,
    },
    Tool {
        key: "gitleaks",
        source: "github",
        package: "gitleaks/gitleaks",
        version_arg: "version",
        docker_arg: Some("GITLEAKS_VERSION"),
    },
    Tool {
        key: "trivy",
        source: "github",
        package: "aquasecurity/trivy",
        version_arg: "--version",
        docker_arg: Some("TRIVY_VERSION"),
    },
    Tool {
        key: "checkov",
        source: "pypi",
        package: "checkov",
        version_arg: "--version",
        docker_arg: None,
    },
    Tool {
        key: "hadolint",
        source: "github",
        package: "hadolint/hadolint",
        version_arg: "--version",
        docker_arg: Some("HADOLINT_VERSION"),
    },
    Tool {
        key: "syft",
        source: "github",
        package: "anchore/syft",
        version_arg: "version",
        docker_arg: Some("SYFT_VERSION"),
    },
    Tool {
        key: "cosign",
        source: "github",
        package: "sigstore/cosign",
        version_arg: "version",
        docker_arg: Some("COSIGN_VERSION"),
    },
    Tool {
        key: "semgrep",
        source: "pypi",
        package: "semgrep",
        version_arg: "--version",
        docker_arg: None,
    },
    Tool {
        key: "bearer",
        source: "github",
        package: "Bearer/bearer",
        version_arg: "version",
        docker_arg: None,
    },
    Tool {
        key: "jscpd",
        source: "npm",
        package: "jscpd",
        version_arg: "--version",
        docker_arg: None,
    },
    Tool {
        key: "gocloc",
        source: "github",
        package: "hhatto/gocloc",
        version_arg: "--version",
        docker_arg: Some("GOCLOC_VERSION"),
    },
    Tool {
        key: "spectral",
        source: "npm",
        package: "@stoplight/spectral-cli",
        version_arg: "--version",
        docker_arg: None,
    },
    Tool {
        key: "guarddog",
        source: "pypi",
        package: "guarddog",
        version_arg: "--version",
        docker_arg: None,
    },
    Tool {
        key: "codeql",
        source: "github",
        package: "github/codeql-cli-binaries",
        version_arg: "version",
        docker_arg: Some("CODEQL_VERSION"),
    },
    Tool {
        key: "picklescan",
        source: "pypi",
        package: "picklescan",
        version_arg: "--version",
        docker_arg: None,
    },
    Tool {
        key: "oasdiff",
        source: "github",
        package: "oasdiff/oasdiff",
        version_arg: "--version",
        docker_arg: Some("OASDIFF_VERSION"),
    },
    Tool {
        key: "zizmor",
        source: "pypi",
        package: "zizmor",
        version_arg: "--version",
        docker_arg: None,
    },
];
static SNAPSHOT: Lazy<Mutex<Value>> = Lazy::new(|| Mutex::new(json!({"checking": false, "checkedAt": null, "tools": {}})));
// Checks and mutations are single-flight across all callers and tools.
static OPERATION: Lazy<Arc<tokio::sync::Mutex<()>>> = Lazy::new(|| Arc::new(tokio::sync::Mutex::new(())));
type ApiError = (StatusCode, Json<Value>);
fn error(status: StatusCode, message: &str) -> ApiError {
    (status, Json(json!({"error": message})))
}

/// Release checks are a service-level startup task. When the operator has
/// enabled them, users can view the result and request a check without a
/// signed-in session; installing a tool remains session-authenticated.
struct ToolUpdateCheckAccess;
#[async_trait::async_trait]
impl FromRequestParts<Arc<AppState>> for ToolUpdateCheckAccess {
    type Rejection = Response;
    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let signed_in = crate::auth::resolve_user(&parts.headers, &state.db).is_some();
        let startup_check_enabled = startup_enabled(std::env::var("TOOLS_CHECK_UPDATES_ON_STARTUP").ok().as_deref());
        let simulation_allowed = state.config.security.allow_unauthenticated_validate_all || state.config.security.allow_unauthenticated_interactive_dry_run;
        if signed_in || startup_check_enabled || simulation_allowed {
            Ok(Self)
        } else {
            Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Authentication required. Enable TOOLS_CHECK_UPDATES_ON_STARTUP to allow tool checks without a session."})),
            )
                .into_response())
        }
    }
}

// A container's filesystem is recreated from its image on `docker compose
// down`/`up`, so an in-place package-manager upgrade would silently vanish.
// There the image is the unit of update: checks still run, upgrades don't.
static IN_CONTAINER: Lazy<bool> = Lazy::new(|| {
    detect_container(
        std::env::var("IGNITE_IN_CONTAINER").ok().as_deref(),
        ["/.dockerenv", "/run/.containerenv"].iter().any(|p| std::path::Path::new(p).exists()),
    )
});
pub fn detect_container(env: Option<&str>, marker_exists: bool) -> bool {
    match env.map(str::trim) {
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true") => true,
        Some(v) if v == "0" || v.eq_ignore_ascii_case("false") => false,
        _ => marker_exists,
    }
}
const CONTAINER_UPDATE_MESSAGE: &str = "Ignite is running in a container: updates installed inside it are lost when the container is recreated. Rebuild the image instead.";
fn rebuild_hint(t: &Tool, latest: &str) -> Value {
    json!({
        "buildArg": t.docker_arg.map(|arg| format!("{arg}={latest}")),
        "command": match t.docker_arg {
            Some(arg) => format!("docker compose build --pull --build-arg {arg}={latest} && docker compose up -d"),
            None => "docker compose build --pull --no-cache && docker compose up -d".into(),
        },
    })
}

pub fn startup_enabled(value: Option<&str>) -> bool {
    value.is_some_and(|v| v.eq_ignore_ascii_case("true"))
}
pub fn spawn_startup_check(state: Arc<AppState>) {
    if startup_enabled(std::env::var("TOOLS_CHECK_UPDATES_ON_STARTUP").ok().as_deref()) {
        start_check(state);
    }
}
fn start_check(state: Arc<AppState>) -> bool {
    let Ok(guard) = OPERATION.clone().try_lock_owned() else { return false };
    SNAPSHOT.lock()["checking"] = json!(true);
    tokio::spawn(async move {
        let _guard = guard;
        use futures::StreamExt;
        let pending: Vec<_> = TOOLS
            .iter()
            .map(|tool: &'static Tool| {
                let state = state.clone();
                async move { (tool.key, check_tool(&state, tool).await) }
            })
            .collect();
        let results = futures::stream::iter(pending).buffer_unordered(4);
        tokio::pin!(results);
        while let Some((key, value)) = results.next().await {
            SNAPSHOT.lock()["tools"][key] = value;
        }
        let mut snapshot = SNAPSHOT.lock();
        snapshot["checking"] = json!(false);
        snapshot["checkedAt"] = json!(chrono::Utc::now().to_rfc3339());
    });
    true
}

// Only stable numeric release versions can trigger an upgrade. Unknown/dev/
// prerelease strings are displayed as unknown rather than guessed as older.
fn version(text: &str) -> Option<(u64, u64, u64)> {
    static RE: Lazy<regex::Regex> = Lazy::new(|| regex::Regex::new(r"(?i)\bv?(\d+)\.(\d+)\.(\d+)([-.][a-z0-9]+)?").expect("constant version regex"));
    let c = RE.captures(text)?;
    if c.get(4).is_some() {
        return None;
    }
    Some((c[1].parse().ok()?, c[2].parse().ok()?, c[3].parse().ok()?))
}
fn version_string(v: (u64, u64, u64)) -> String {
    format!("{}.{}.{}", v.0, v.1, v.2)
}
fn release_url(t: &Tool) -> String {
    match t.source {
        "github" => format!("https://github.com/{}/releases/latest", t.package),
        "npm" => format!("https://www.npmjs.com/package/{}", t.package),
        "pypi" => format!("https://pypi.org/project/{}/", t.package),
        _ => format!("https://rubygems.org/gems/{}", t.package),
    }
}
async fn latest(t: &Tool) -> Result<String, String> {
    let (url, pointer) = match t.source {
        "github" => (format!("https://api.github.com/repos/{}/releases/latest", t.package), "/tag_name"),
        "npm" => (format!("https://registry.npmjs.org/{}/latest", t.package), "/version"),
        "pypi" => (format!("https://pypi.org/pypi/{}/json", t.package), "/info/version"),
        _ => (format!("https://rubygems.org/api/v1/gems/{}.json", t.package), "/version"),
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("Ignite-tool-updates")
        .build()
        .map_err(|e| e.to_string())?;
    let response = client.get(url).send().await.map_err(|e| e.to_string())?.error_for_status().map_err(|e| e.to_string())?;
    let data: Value = response.json().await.map_err(|e| e.to_string())?;
    data.pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "Release service did not return a version".into())
}
async fn installed(state: &AppState, t: &Tool) -> Result<String, String> {
    if t.key == "picklescan" {
        // picklescan has no --version flag. Read package metadata using the
        // interpreter next to the resolved entrypoint (including pipx venvs).
        let binary = executable(state.runner.binary_for(t.key).unwrap_or(t.key)).ok_or("Tool is unavailable")?;
        let python = binary.parent().ok_or("Cannot locate tool interpreter")?.join("python");
        let output = command(
            python.to_str().ok_or("Invalid interpreter path")?,
            &["-c".into(), "import importlib.metadata; print(importlib.metadata.version('picklescan'))".into()],
            15,
        )
        .await?;
        return version(&output).map(version_string).ok_or_else(|| "Installed version could not be determined".into());
    }
    let output = state
        .runner
        .run_tool(
            t.key,
            &[t.version_arg.into()],
            std::env::temp_dir().to_str().unwrap_or("/tmp"),
            RunToolOptions {
                timeout_ms: Some(60_000),
                ..Default::default()
            },
        )
        .await
        .map_err(|_| "Tool is unavailable or its version command failed".to_string())?;
    version(&format!("{}\n{}", output.stdout, output.stderr))
        .map(version_string)
        .ok_or_else(|| "Installed version could not be determined".into())
}
fn executable(name: &str) -> Option<PathBuf> {
    if name.contains(std::path::MAIN_SEPARATOR) {
        return std::fs::canonicalize(name).ok();
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|p| p.join(name))
        .find_map(|p| if p.is_file() { std::fs::canonicalize(p).ok() } else { None })
}

#[derive(Debug, Clone, PartialEq)]
struct Upgrade {
    program: &'static str,
    args: Vec<String>,
}
// Package managers are invoked directly with allowlisted arguments. A custom
// binary never gets replaced just because a package of the same name exists.
async fn upgrade_plan(state: &AppState, t: &Tool) -> Option<Upgrade> {
    let binary = executable(state.runner.binary_for(t.key).unwrap_or(t.key))?;
    if executable("brew").is_some() {
        let cellar = command("brew", &["--cellar".into()], 15).await.unwrap_or_default();
        if let Some(rel) = (!cellar.is_empty()).then(|| binary.strip_prefix(cellar.trim()).ok()).flatten() {
            let formula = rel.components().next()?.as_os_str().to_str()?;
            let expected = if t.key == "ort" { "oss-review-toolkit" } else { t.key };
            if formula == expected {
                return Some(Upgrade {
                    program: "brew",
                    args: vec!["upgrade".into(), formula.into()],
                });
            }
        }
    }
    if t.source == "npm" && executable("npm").is_some() {
        let root = command("npm", &["root".into(), "--global".into()], 15).await.ok()?;
        let package_root = std::fs::canonicalize(PathBuf::from(root.trim()).join(t.package)).ok()?;
        if binary.starts_with(package_root) {
            return Some(Upgrade {
                program: "npm",
                args: vec!["install".into(), "--global".into(), format!("{}@latest", t.package)],
            });
        }
    }
    if t.source == "pypi" && executable("pipx").is_some() {
        let home = command("pipx", &["environment".into(), "--value".into(), "PIPX_HOME".into()], 15).await.ok()?;
        let venv = std::fs::canonicalize(PathBuf::from(home.trim()).join("venvs").join(t.package)).ok()?;
        if binary.starts_with(venv) {
            return Some(Upgrade {
                program: "pipx",
                args: vec!["upgrade".into(), t.package.into()],
            });
        }
    }
    None
}
async fn command(program: &str, args: &[String], seconds: u64) -> Result<String, String> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .current_dir(std::env::temp_dir())
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .env("CI", "1")
        .env("HOMEBREW_NO_INSTALL_CLEANUP", "1");
    let output = tokio::time::timeout(Duration::from_secs(seconds), cmd.output())
        .await
        .map_err(|_| "Command timed out; inspect the package manager before retrying".to_string())?
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!("{} failed: {}", program, String::from_utf8_lossy(&output.stderr).chars().take(1500).collect::<String>()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
async fn check_tool(state: &AppState, t: &Tool) -> Value {
    let mut result = json!({"releaseUrl": release_url(t), "updateAvailable": false, "canUpdate": false});
    let current = match installed(state, t).await {
        Ok(v) => v,
        Err(e) => {
            result["error"] = json!(e);
            return result;
        }
    };
    result["installedVersion"] = json!(current);
    match latest(t).await {
        Ok(v) => {
            result["latestVersion"] = json!(v);
            result["updateAvailable"] = json!(matches!((version(&current), version(&v)), (Some(a), Some(b)) if b > a));
            if *IN_CONTAINER {
                result["rebuild"] = rebuild_hint(t, &v);
            } else if let Some(plan) = upgrade_plan(state, t).await {
                result["canUpdate"] = json!(true);
                result["manager"] = json!(plan.program);
            }
        }
        Err(e) => result["error"] = json!(e),
    }
    result
}
async fn status(_access: ToolUpdateCheckAccess) -> Json<Value> {
    let mut snapshot = SNAPSHOT.lock().clone();
    snapshot["container"] = json!(*IN_CONTAINER);
    Json(snapshot)
}
async fn check(State(state): State<Arc<AppState>>, _access: ToolUpdateCheckAccess, Json(_): Json<Value>) -> Result<StatusCode, ApiError> {
    if start_check(state) {
        Ok(StatusCode::ACCEPTED)
    } else {
        Err(error(StatusCode::CONFLICT, "A tool check or update is already running"))
    }
}
async fn update(State(state): State<Arc<AppState>>, Path(key): Path<String>, Json(_): Json<Value>) -> Result<StatusCode, ApiError> {
    let tool = TOOLS.iter().find(|t| t.key == key).ok_or_else(|| error(StatusCode::NOT_FOUND, "Unknown tool"))?;
    if *IN_CONTAINER {
        return Err(error(StatusCode::CONFLICT, CONTAINER_UPDATE_MESSAGE));
    }
    let guard = OPERATION
        .clone()
        .try_lock_owned()
        .map_err(|_| error(StatusCode::CONFLICT, "A tool check or update is already running"))?;
    if !state.running_runs.lock().is_empty() {
        return Err(error(StatusCode::CONFLICT, "Wait for active pipeline runs to finish before updating tools"));
    }
    let cached = SNAPSHOT.lock()["tools"][tool.key].clone();
    if cached["updateAvailable"] != true {
        return Err(error(StatusCode::CONFLICT, "Check for updates before updating this tool"));
    }
    if cached["canUpdate"] != true {
        return Err(error(StatusCode::CONFLICT, "This installation must be updated using its release instructions"));
    }
    SNAPSHOT.lock()["tools"][tool.key]["updating"] = json!(true);
    tokio::spawn(async move {
        let _guard = guard;
        // Resolve ownership again in the worker: even package-manager probes
        // must not delay the HTTP response, and cached ownership can be stale.
        let outcome = match upgrade_plan(&state, tool).await {
            Some(plan) => command(plan.program, &plan.args, 600).await,
            None => Err("This installation is no longer owned by a supported package manager; use its release instructions".into()),
        };
        let mut result = check_tool(&state, tool).await;
        if outcome.is_ok() && result["updateAvailable"] == true {
            result["error"] = json!("The package manager finished, but the upstream release is still newer. Check package availability or version pins.");
        }
        result["updating"] = json!(false);
        if let Err(e) = &outcome {
            result["error"] = json!(e);
        }
        let summary = format!("Tool update {}: {}", if outcome.is_ok() { "finished" } else { "failed" }, tool.key);
        let _ = state
            .db
            .record_audit_event("tool.update", if outcome.is_ok() { "info" } else { "warning" }, &summary, None, None, None, None);
        SNAPSHOT.lock()["tools"][tool.key] = result;
        super::tools_status::invalidate_cache();
    });
    Ok(StatusCode::ACCEPTED)
}
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/tools/updates", get(status))
        .route("/api/tools/updates/check", post(check))
        .route("/api/tools/:tool/update", post(update))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_check_is_explicitly_enabled() {
        assert!(!startup_enabled(None));
        assert!(!startup_enabled(Some("false")));
        assert!(startup_enabled(Some("true")));
    }
    #[test]
    fn container_detection_prefers_explicit_env_over_marker_files() {
        assert!(detect_container(None, true));
        assert!(!detect_container(None, false));
        assert!(detect_container(Some("1"), false));
        assert!(detect_container(Some("TRUE"), false));
        assert!(!detect_container(Some("0"), true));
        assert!(!detect_container(Some("false"), true));
        assert!(detect_container(Some("garbage"), true));
    }

    #[test]
    fn rebuild_hint_uses_dockerfile_pin_or_no_cache_rebuild() {
        let trivy = TOOLS.iter().find(|t| t.key == "trivy").unwrap();
        let hint = rebuild_hint(trivy, "v0.75.0");
        assert_eq!(hint["buildArg"], "TRIVY_VERSION=v0.75.0");
        assert_eq!(hint["command"], "docker compose build --pull --build-arg TRIVY_VERSION=v0.75.0 && docker compose up -d");
        let semgrep = TOOLS.iter().find(|t| t.key == "semgrep").unwrap();
        let hint = rebuild_hint(semgrep, "1.100.0");
        assert!(hint["buildArg"].is_null());
        assert_eq!(hint["command"], "docker compose build --pull --no-cache && docker compose up -d");
    }

    #[test]
    fn docker_args_match_the_dockerfile() {
        // Read at runtime: the image's own build stage may not copy the Dockerfile in.
        let Ok(dockerfile) = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../Dockerfile")) else {
            eprintln!("skipping: Dockerfile not present");
            return;
        };
        for arg in TOOLS.iter().filter_map(|t| t.docker_arg) {
            assert!(dockerfile.contains(&format!("ARG {arg}=")), "Dockerfile has no ARG {arg}");
        }
    }

    #[test]
    fn compares_numeric_versions_and_rejects_prereleases() {
        assert!(version("v1.10.0") > version("tool version 1.9.9"));
        assert_eq!(version("GitVersion: v2.4.1"), Some((2, 4, 1)));
        assert_eq!(version("1.2.3-rc1"), None);
        assert_eq!(version("development"), None);
    }
    #[test]
    fn catalog_is_unique_and_covers_ui_tools_except_shared_trivy_alias() {
        let keys: std::collections::HashSet<_> = TOOLS.iter().map(|t| t.key).collect();
        assert_eq!(keys.len(), 18);
        assert_eq!(keys.len(), TOOLS.len());
        assert!(TOOLS.iter().all(|t| release_url(t).starts_with("https://")));
    }
    #[tokio::test]
    async fn routes_require_auth_and_background_jobs_report_failures() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&dir.path().join("test.db")).unwrap();
        let mut test_config = ignite_config::Config::default();
        test_config.security.allow_unauthenticated_validate_all = true;
        let mut state = crate::state::test_state(db, test_config);
        // The background worker must never install real packages in this test.
        state.runner = ignite_tool_runner::ToolRunner::new(std::collections::HashMap::from([("jscpd", dir.path().join("missing-jscpd").to_string_lossy().into_owned())]));
        let app = router().with_state(Arc::new(state));
        let request = |uri: &str| Request::builder().method("POST").uri(uri).header("content-type", "application/json").body(Body::from("{}")).unwrap();
        // Host tool updates are intentionally available without a user
        // session; only allowlisted tools and detected package managers can
        // run, and the worker refuses updates during active scans.
        let status_request = Request::builder().uri("/api/tools/updates").body(Body::empty()).unwrap();
        assert_eq!(app.clone().oneshot(status_request).await.unwrap().status(), StatusCode::OK);
        assert_eq!(app.clone().oneshot(request("/api/tools/not-a-tool/update")).await.unwrap().status(), StatusCode::NOT_FOUND);
        let guard = OPERATION.clone().lock_owned().await;
        assert_eq!(app.clone().oneshot(request("/api/tools/jscpd/update")).await.unwrap().status(), StatusCode::CONFLICT);
        SNAPSHOT.lock()["tools"]["jscpd"] = json!({"updateAvailable": true, "canUpdate": true});
        drop(guard);
        let response = app.oneshot(request("/api/tools/jscpd/update")).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        // The request has completed; the spawned job independently records
        // the stale ownership failure, which a reopened page can retrieve.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if SNAPSHOT.lock()["tools"]["jscpd"]["updating"] == false {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(SNAPSHOT.lock()["tools"]["jscpd"]["error"].as_str().unwrap().contains("no longer owned"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn package_manager_commands_do_not_interpret_shell_input_and_report_failures() {
        let output = command("/usr/bin/printf", &["%s".into(), "$(echo should-not-execute); untouched".into()], 2).await.unwrap();
        assert_eq!(output, "$(echo should-not-execute); untouched");
        assert!(command("/usr/bin/false", &[], 2).await.is_err());
        assert!(command("/bin/sleep", &["2".into()], 0).await.unwrap_err().contains("timed out"));
    }
}
