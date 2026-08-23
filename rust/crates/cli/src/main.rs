//! `ignite scan [path]` — faithful port of `bin/ignite.js`. CLI wrapper
//! around `POST /api/pipeline/validate-all`, for agents/CI that want a
//! plain command + exit code instead of driving the HTTP API themselves.
//! Always dry-run by design (validate-all never ships/pushes).
//!
//! Usage: ignite scan [path] [--changed-files a.js,b.py] [--json] [--base-url URL] [--fast]
//! Exit codes: 0 = passed, 1 = blocking issues / validation failure,
//! 2 = couldn't reach the Ignite server or bad usage.

use serde_json::Value;

struct Args {
    command: Option<String>,
    project_path: Option<String>,
    changed_files: Option<Vec<String>>,
    json: bool,
    base_url: Option<String>,
    fast: bool,
}

fn parse_args(argv: &[String]) -> Args {
    let mut args = Args { command: None, project_path: None, changed_files: None, json: false, base_url: None, fast: false };
    let mut rest = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--json" => args.json = true,
            "--fast" => args.fast = true,
            "--changed-files" => {
                i += 1;
                let list = argv.get(i).cloned().unwrap_or_default();
                args.changed_files = Some(list.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect());
            }
            "--base-url" => {
                i += 1;
                args.base_url = argv.get(i).cloned();
            }
            other => rest.push(other.to_string()),
        }
        i += 1;
    }
    args.command = rest.first().cloned();
    args.project_path = rest.get(1).cloned();
    args
}

fn print_human_summary(result: &Value) {
    let issues = result.get("issues").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let error_count = issues.iter().filter(|i| i.get("severity").and_then(|v| v.as_str()) == Some("error") && i.get("status").and_then(|v| v.as_str()) != Some("overridden")).count();
    let warning_count = issues.iter().filter(|i| i.get("severity").and_then(|v| v.as_str()) == Some("warning")).count();
    let ok = result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let failed_phase = result.get("failedPhase").and_then(|v| v.as_i64());

    println!();
    print!("Ignite scan: {}", if ok { "PASSED" } else { "FAILED" });
    if let Some(phase) = failed_phase {
        print!(" (phase {phase})");
    }
    println!();
    if !ok {
        if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
            println!("  {err}");
        }
    }
    let filtered_note = if result.get("filteredByChangedFiles").and_then(|v| v.as_bool()).unwrap_or(false) {
        format!(" (of {} total — filtered to changed files)", result.get("totalIssueCount").and_then(|v| v.as_i64()).unwrap_or(0))
    } else {
        String::new()
    };
    println!("  {error_count} blocking issue(s), {warning_count} warning(s){filtered_note}");

    for issue in issues.iter().take(50) {
        let file = issue.get("file").and_then(|v| v.as_str());
        let line = issue.get("line").and_then(|v| v.as_i64());
        let loc = match file {
            Some(f) => format!("{f}{}", line.map(|l| format!(":{l}")).unwrap_or_default()),
            None => "(project-wide)".to_string(),
        };
        let tag = if issue.get("status").and_then(|v| v.as_str()) == Some("overridden") { "overridden".to_string() } else { issue.get("severity").and_then(|v| v.as_str()).unwrap_or("?").to_string() };
        let summary = issue.get("summary").and_then(|v| v.as_str()).unwrap_or("");
        println!("  [{tag}] {loc} — {summary}");
    }
    if issues.len() > 50 {
        println!("  ... and {} more", issues.len() - 50);
    }
}

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(&argv);

    if args.command.as_deref() != Some("scan") {
        eprintln!("Usage: ignite scan [path] [--changed-files a.js,b.py] [--json] [--base-url URL] [--fast]");
        std::process::exit(2);
    }

    let base_url = args.base_url.or_else(|| std::env::var("IGNITE_BASE_URL").ok()).unwrap_or_else(|| "http://localhost:51337".to_string());
    let base_url = base_url.trim_end_matches('/').to_string();
    let project_path = std::fs::canonicalize(args.project_path.clone().unwrap_or_else(|| ".".to_string())).unwrap_or_else(|_| std::path::PathBuf::from(args.project_path.unwrap_or_else(|| ".".to_string())));

    let mut body = serde_json::json!({ "projectPath": project_path.to_string_lossy() });
    let obj = body.as_object_mut().unwrap();
    if let Some(changed) = &args.changed_files {
        obj.insert("changedFiles".to_string(), serde_json::json!(changed));
    }
    if args.fast {
        obj.insert("fast".to_string(), serde_json::json!(true));
    }

    let client = reqwest::Client::new();
    let mut req = client.post(format!("{base_url}/api/pipeline/validate-all")).header("Content-Type", "application/json").header("X-Ignite-Client", "cli").json(&body);
    if let Ok(key) = std::env::var("IGNITE_API_KEY") {
        req = req.header("Authorization", format!("Bearer {key}"));
    }

    let response = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Could not reach Ignite server at {base_url}: {e}. Is it running (\"npm start\")?");
            std::process::exit(2);
        }
    };

    let status = response.status();
    let result: Option<Value> = response.json().await.ok();
    let Some(result) = result else {
        eprintln!("Ignite server returned a non-JSON response (HTTP {status}).");
        std::process::exit(2);
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else {
        print_human_summary(&result);
    }

    let ok = result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    std::process::exit(if ok { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_extracts_command_and_path() {
        let args = parse_args(&["scan".to_string(), "/some/path".to_string()]);
        assert_eq!(args.command.as_deref(), Some("scan"));
        assert_eq!(args.project_path.as_deref(), Some("/some/path"));
    }

    #[test]
    fn parse_args_parses_changed_files_list() {
        let args = parse_args(&["scan".to_string(), "--changed-files".to_string(), "a.js, b.py,".to_string()]);
        assert_eq!(args.changed_files, Some(vec!["a.js".to_string(), "b.py".to_string()]));
    }

    #[test]
    fn parse_args_parses_flags() {
        let args = parse_args(&["scan".to_string(), "--json".to_string(), "--fast".to_string(), "--base-url".to_string(), "http://example.com".to_string()]);
        assert!(args.json);
        assert!(args.fast);
        assert_eq!(args.base_url.as_deref(), Some("http://example.com"));
    }

    #[test]
    fn parse_args_defaults_project_path_to_none_when_omitted() {
        let args = parse_args(&["scan".to_string()]);
        assert!(args.project_path.is_none());
    }
}
