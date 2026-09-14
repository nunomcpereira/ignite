//! `ignite check [path]` — the "port `hooks/pre-push` into something with
//! tests" subcommand. Owns everything about `.ignite/acknowledgments.md`
//! (parsing, resubmitting as overrides, regenerating after a run) and the
//! `POST /api/pipeline/validate-all` call itself; the pure logic lives in
//! `acknowledgments.rs`, this module is just the I/O around it.
//!
//! Deliberately does NOT own the delta-check (skip a push whose tree is
//! byte-identical to the last fully-validated one) or the `git commit
//! --amend` step that folds a regenerated review file into the push —
//! both stay in `hooks/pre-push` itself, since they're genuinely
//! git/push-specific and simple enough that bash was never the risk there
//! (the risk was always the jq parsing/regeneration, which is what moved
//! here). The hook calls this, inspects the exit code, and does the
//! amend dance itself:
//! - exit 0: checks passed, review file didn't need touching
//! - exit 1: checks failed (blocking findings remain) or a non-overridable
//!   failure (fix the source and re-run)
//! - exit 2: couldn't reach the server / bad usage
//! - exit 3: checks passed, but the review file was regenerated
//!   (line-drift carry-forward, or a stale sha reference) - the hook
//!   should `git add` it, `commit --amend`, and block this push so the
//!   amended commit gets sent instead

use crate::acknowledgments::{self, Finding};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct CheckArgs {
    pub project_path: PathBuf,
    pub base_url: String,
    pub review_file: PathBuf,
    pub run_local_ci: bool,
    pub warning_decision: String,
    pub fast: bool,
    pub json: bool,
}

fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git").arg("-C").arg(repo).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// `owner`/`repo` out of a git remote URL — same regex `hooks/pre-push`
/// used via `sed -E 's#.*[:/]([^/]+)/([^/.]+)(\.git)?$#...#'`, ported
/// directly rather than reimplemented, so both SSH (`git@host:owner/repo.git`)
/// and HTTPS (`https://host/owner/repo.git`) remotes parse identically.
fn parse_org_repo(remote_url: &str) -> (String, String) {
    static RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| regex::Regex::new(r"[:/]([^/]+)/([^/]+?)(?:\.git)?$").unwrap());
    match RE.captures(remote_url) {
        Some(c) => (c[1].to_string(), c[2].to_string()),
        None => (String::new(), String::new()),
    }
}

fn findings_from_json(issues: &[Value]) -> Vec<Finding> {
    issues
        .iter()
        .map(|i| Finding {
            id: i.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            category: i.get("category").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            file: i.get("file").and_then(|v| v.as_str()).map(str::to_string),
            line: i.get("line").and_then(|v| v.as_i64()),
            severity: i.get("severity").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            summary: i.get("summary").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            status: i.get("status").and_then(|v| v.as_str()).map(str::to_string),
            snippet: i.get("snippet").cloned(),
        })
        .collect()
}

fn write_findings_snapshot(project_path: &Path, response: &Value, current_sha: &str) -> std::io::Result<PathBuf> {
    let now = chrono::Utc::now();
    let ts = now.format("%Y-%m-%dT%H-%M-%SZ").to_string();
    let now_iso = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let snapshot_dir = project_path.join(".ignite/scans").join(&ts);
    std::fs::create_dir_all(&snapshot_dir)?;
    let snapshot_file = snapshot_dir.join("findings.md");

    let issues = response.get("issues").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut out = format!("# Ignite scan findings — {now_iso}\n\nScanned against commit: {current_sha}\n\n");
    if issues.is_empty() {
        out.push_str("No findings.\n");
    } else {
        for (idx, issue) in issues.iter().enumerate() {
            let severity = issue.get("severity").and_then(|v| v.as_str()).unwrap_or("").to_uppercase();
            let category = issue.get("category").and_then(|v| v.as_str()).unwrap_or("");
            let summary = issue.get("summary").and_then(|v| v.as_str()).unwrap_or("");
            let id = issue.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let file = issue.get("file").and_then(|v| v.as_str());
            let line = issue.get("line").and_then(|v| v.as_i64());
            let score = issue.get("score").and_then(|v| v.as_i64()).map(|n| n.to_string()).unwrap_or_else(|| "null".to_string());
            let status = issue.get("status").and_then(|v| v.as_str());
            let loc = match file {
                Some(f) => match line {
                    Some(l) => format!("{f}:{l}"),
                    None => f.to_string(),
                },
                None => "(no file)".to_string(),
            };
            out.push_str(&format!("## {}. [{severity}] {category} - {summary}\n\n- ID: `{id}`\n- Location: {loc}\n- Score: {score}\n", idx + 1));
            if let Some(status) = status {
                out.push_str(&format!("- Status: {status}\n"));
            }
            out.push('\n');
        }
    }
    std::fs::write(&snapshot_file, out)?;
    Ok(snapshot_file)
}

/// Writes `content` to `path` with exactly one trailing newline appended,
/// matching `hooks/pre-push`'s own `printf '%s\n' ... > "$REVIEW_FILE"` -
/// which is why `run` compares against
/// `existing_text.trim_end_matches('\n')` rather than the raw
/// just-read-off-disk text.
fn write_review_file(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{content}\n"))
}

fn print_failed_phases(response: &Value) {
    let Some(phases) = response.get("phases").and_then(|v| v.as_array()) else { return };
    for phase in phases {
        if phase.get("state").and_then(|v| v.as_str()) != Some("failed") {
            continue;
        }
        let num = phase.get("phase").and_then(|v| v.as_i64()).unwrap_or(0);
        let title = phase.get("title").and_then(|v| v.as_str()).unwrap_or("");
        eprintln!("  Phase {num} - {title}");
        let logs = phase.get("logs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let tail: Vec<&Value> = logs.iter().rev().take(10).collect();
        for line in tail.into_iter().rev() {
            if let Some(s) = line.as_str() {
                eprintln!("    {s}");
            }
        }
    }
}

/// Exit code this subcommand should terminate the process with — see
/// this module's own doc comment for what each one means to the caller.
pub async fn run(args: CheckArgs) -> i32 {
    let repo_path = &args.project_path;

    // Normalize CRLF to LF before anything else parses this text — on a
    // CRLF checkout (Windows, or a repo with `core.autocrlf` on),
    // per-line regex captures (`ID_RE` et al. in `acknowledgments.rs`)
    // would otherwise retain a trailing `\r` in every captured field
    // (issue ids, justifications, ...), and the content comparison below
    // would never converge since generated content is always `\n`-only —
    // trapping every commit in an endless amend loop.
    let existing_text = std::fs::read_to_string(&args.review_file).unwrap_or_default().replace("\r\n", "\n");
    let existing_entries = acknowledgments::parse_blocks(&existing_text);
    let overrides = acknowledgments::build_overrides(&existing_entries);

    println!("→ Running Ignite checks against {} ...", repo_path.display());
    if !overrides.is_empty() {
        println!("  (resubmitting {} justification(s) from {})", overrides.len(), args.review_file.display());
    }

    let remote_url = git(repo_path, &["config", "--get", "remote.origin.url"]).unwrap_or_default();
    let (org, repo) = parse_org_repo(&remote_url);
    let actor_email = git(repo_path, &["config", "--get", "user.email"]).unwrap_or_default();
    let actor_name = git(repo_path, &["config", "--get", "user.name"]).unwrap_or_default();
    let current_sha = git(repo_path, &["rev-parse", "HEAD"]).unwrap_or_default();

    let mut body = serde_json::json!({
        "projectPath": repo_path.to_string_lossy(),
        "org": org,
        "repo": repo,
        "gxp": false,
        "runLocalCi": args.run_local_ci,
        "warningDecision": args.warning_decision,
        "overrides": overrides,
        "fast": args.fast,
    });
    if !actor_email.is_empty() {
        body["actor"] = serde_json::json!({ "email": actor_email, "name": if actor_name.is_empty() { actor_email.clone() } else { actor_name.clone() } });
    }

    let client = reqwest::Client::new();
    let mut req = client.post(format!("{}/api/pipeline/validate-all", args.base_url)).header("Content-Type", "application/json").header("X-Ignite-Client", "cli-check").json(&body);
    if let Ok(key) = std::env::var("IGNITE_API_KEY") {
        req = req.header("Authorization", format!("Bearer {key}"));
    }
    let response = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("✗ Ignite isn't reachable at {}: {e}", args.base_url);
            return 2;
        }
    };
    let status = response.status();
    let response: Value = match response.json().await {
        Ok(v) => v,
        Err(_) => {
            eprintln!("✗ Ignite returned a non-JSON response (HTTP {status}).");
            return 2;
        }
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    match write_findings_snapshot(repo_path, &response, &current_sha) {
        Ok(path) => println!("  Findings snapshot: {}", path.display()),
        Err(e) => eprintln!("  (warning: could not write findings snapshot: {e})"),
    }

    let ok = response.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    // `issues` can be JSON `null` (a phase before 4 failed, so the
    // override-eligible issue list was never built) as well as absent or
    // an array - only an actual array means "here are the issues to
    // reconcile the review file against."
    let issues_value = response.get("issues").and_then(|v| v.as_array()).cloned();
    let issues_count = issues_value.as_ref().map(|v| v.len()).unwrap_or(0);

    if !ok {
        eprintln!("✗ Ignite checks failed - push blocked.");
        print_failed_phases(&response);
        if issues_count == 0 {
            eprintln!();
            eprintln!("This failure isn't something a justification can override - fix it in the source and push again.");
            return 1;
        }
    }

    let findings = findings_from_json(issues_value.as_deref().unwrap_or(&[]));
    let unresolved_count = findings.iter().filter(|f| f.status.as_deref() != Some("overridden")).count();

    let new_content = if issues_count > 0 || !existing_text.trim().is_empty() { acknowledgments::build_new_review_content(&existing_text, &findings) } else { None };

    // `build_new_review_content` never has a trailing newline of its own
    // (same as bash's `$(...)` stripping them from both sides of this
    // comparison); `existing_text` is read straight off disk and almost
    // always ends in one, since that's how `write_review_file` leaves it
    // below. Compare against the trimmed form, or a file that's already
    // byte-identical in substance gets treated as "stale" on every single
    // run purely because of that one trailing newline, amending every push
    // for no reason.
    let existing_trimmed = existing_text.trim_end_matches('\n');

    if ok {
        println!("✓ Ignite checks passed.");
        if let Some(content) = &new_content {
            if content != existing_trimmed {
                if write_review_file(&args.review_file, content).is_err() {
                    eprintln!("  (warning: could not write {})", args.review_file.display());
                    return 0;
                }
                eprintln!("  {} was stale (old commit sha and/or a drifted line number) - refreshed.", args.review_file.display());
                return 3;
            }
        }
        return 0;
    }

    if let Some(content) = &new_content {
        let _ = write_review_file(&args.review_file, content);
    }
    eprintln!();
    eprintln!("✗ {unresolved_count} blocking finding(s) need a justification or a source fix.");
    eprintln!("  Edit {}, fill in \"Acknowledge:\" for whichever you want to", args.review_file.display());
    eprintln!("  override, then push again - or fix them in the source instead.");
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_org_repo_handles_ssh_and_https_remotes() {
        assert_eq!(parse_org_repo("git@github.com:nunomcpereira/ignite.git"), ("nunomcpereira".to_string(), "ignite".to_string()));
        assert_eq!(parse_org_repo("https://github.com/nunomcpereira/ignite.git"), ("nunomcpereira".to_string(), "ignite".to_string()));
        assert_eq!(parse_org_repo("https://github.com/nunomcpereira/ignite"), ("nunomcpereira".to_string(), "ignite".to_string()));
    }

    #[test]
    fn parse_org_repo_empty_for_an_unparseable_remote() {
        assert_eq!(parse_org_repo(""), (String::new(), String::new()));
    }

    #[test]
    fn findings_from_json_reads_camelcase_fields_and_optional_status() {
        let issues = serde_json::json!([
            { "id": "secret::a.rs::1", "category": "secret", "severity": "error", "summary": "s", "file": "a.rs", "line": 1 },
            { "id": "secret::b.rs::2", "category": "secret", "severity": "error", "summary": "s2", "file": "b.rs", "line": 2, "status": "overridden" }
        ]);
        let findings = findings_from_json(issues.as_array().unwrap());
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].status, None);
        assert_eq!(findings[1].status.as_deref(), Some("overridden"));
    }
}
