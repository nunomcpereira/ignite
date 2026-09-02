//! `enforce-gate-branch-protection <org/repo> [<org/repo>...] [--apply]` —
//! the GHAS-bypass-hardening branch-protection tool: Ignite's compliance
//! gate only fires if someone actually routes code through the pipeline
//! (push/PR), unlike GitHub Advanced Security which is enforced at the
//! platform level regardless of push path. This closes that gap by
//! requiring the `ignite/gate` status check (the same context
//! `routes/github_pr_status.rs`/`github_pr_status.rs` posts to) on the
//! repo's default branch and disallowing direct pushes that bypass a PR.
//!
//! **Dry-run by default.** Without `--apply` this only ever performs
//! read-only lookups (the repo's default branch) and prints the exact
//! `gh api` invocation — argv array plus JSON body — it *would* make,
//! never calling the mutating endpoint. Pass `--apply` to actually call
//! GitHub. This binary is not wired into any pipeline/cron path — it's a
//! deliberate, standalone tool for an operator to run by hand.
//!
//! Every `gh` invocation goes through `ignite_tool_runner::ToolRunner`
//! with an argument array (no shell), matching this repo's standing
//! hardening invariant. The protection payload is nested JSON that `gh
//! api`'s flat `-f`/`-F` field flags can't express, so — same pattern as
//! `ignite_github_api::gh_comment_on_pr`'s `--body-file` — it's written to
//! a temp file and passed via `--input <file>` rather than inlined as an
//! argument.

use ignite_github_api::parse_org_repo;
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Debug)]
pub struct ParsedArgs {
    pub repos: Vec<(String, String)>,
    pub apply: bool,
}

pub fn parse_args(raw: &[String]) -> Result<ParsedArgs, String> {
    let mut repos = Vec::new();
    let mut apply = false;
    let mut saw_dry_run_flag = false;

    for arg in raw {
        match arg.as_str() {
            "--apply" => apply = true,
            "--dry-run" => saw_dry_run_flag = true,
            "--dry-run=false" => {
                saw_dry_run_flag = true;
                apply = true;
            }
            "--dry-run=true" => saw_dry_run_flag = true,
            other if other.starts_with("--") => return Err(format!("Unknown flag: {other}")),
            other => repos.push(parse_org_repo(other)?),
        }
    }
    let _ = saw_dry_run_flag; // --dry-run is the (redundant) default; only --apply flips it off.

    if repos.is_empty() {
        return Err("Usage: enforce-gate-branch-protection <org/repo> [<org/repo>...] [--apply]".to_string());
    }
    Ok(ParsedArgs { repos, apply })
}

/// The branch-protection payload this tool enforces: require the
/// `ignite/gate` status check (strict — must be up to date with the base
/// branch), and require a pull request (with admins included, so it can't
/// be bypassed by a repo admin pushing directly) before merging.
pub fn protection_payload() -> Value {
    json!({
        "required_status_checks": {
            "strict": true,
            "contexts": ["ignite/gate"]
        },
        "enforce_admins": true,
        "required_pull_request_reviews": {
            "required_approving_review_count": 1,
            "dismiss_stale_reviews": true
        },
        "restrictions": null,
        "required_linear_history": false,
        "allow_force_pushes": false,
        "allow_deletions": false
    })
}

pub struct PlannedCall {
    pub full_name: String,
    pub default_branch: String,
    pub argv: Vec<String>,
    pub body: Value,
}

async fn plan_for_repo(runner: &ToolRunner, org: &str, repo: &str) -> Result<PlannedCall, String> {
    let full_name = format!("{org}/{repo}");
    let api = ignite_github_api::GithubApi::new(runner);
    let default_branch = api.default_branch(&full_name, &ignite_github_api::resolve_server_github_token()).await.map_err(|e| format!("Failed to look up {full_name}: {e}"))?;
    let body = protection_payload();
    let argv = vec!["gh".to_string(), "api".to_string(), "-X".to_string(), "PUT".to_string(), format!("repos/{full_name}/branches/{default_branch}/protection"), "--input".to_string(), "<tmpfile: see JSON body below>".to_string()];
    Ok(PlannedCall { full_name, default_branch, argv, body })
}

fn print_plan(plan: &PlannedCall) {
    println!("== {} (default branch: {}) ==", plan.full_name, plan.default_branch);
    println!("  {}", plan.argv.join(" "));
    println!("  body:");
    println!("{}", serde_json::to_string_pretty(&plan.body).unwrap_or_default().lines().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n"));
}

async fn apply_plan(runner: &ToolRunner, plan: &PlannedCall) -> Result<(), String> {
    let tmp = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    std::fs::write(tmp.path(), serde_json::to_vec(&plan.body).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let args = vec!["api".to_string(), "-X".to_string(), "PUT".to_string(), format!("repos/{}/branches/{}/protection", plan.full_name, plan.default_branch), "--input".to_string(), tmp.path().to_string_lossy().to_string()];
    let env: HashMap<String, String> = std::env::var("GH_TOKEN").or_else(|_| std::env::var("GITHUB_TOKEN")).map(|t| HashMap::from([("GH_TOKEN".to_string(), t)])).unwrap_or_default();
    runner.run_tool("gh", &args, &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() }).await.map_err(|e| format!("Failed to apply protection to {}: {e}", plan.full_name))?;
    Ok(())
}

fn default_runner() -> ToolRunner {
    ToolRunner::new(HashMap::new())
}

#[tokio::main]
async fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&raw) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };

    if !parsed.apply {
        println!("DRY RUN (pass --apply to actually call GitHub) — no changes will be made.\n");
    }

    let runner = default_runner();
    let mut had_error = false;

    for (org, repo) in &parsed.repos {
        match plan_for_repo(&runner, org, repo).await {
            Ok(plan) => {
                print_plan(&plan);
                if parsed.apply {
                    match apply_plan(&runner, &plan).await {
                        Ok(()) => println!("  applied.\n"),
                        Err(e) => {
                            eprintln!("  FAILED: {e}\n");
                            had_error = true;
                        }
                    }
                } else {
                    println!();
                }
            }
            Err(e) => {
                eprintln!("{org}/{repo}: {e}");
                had_error = true;
            }
        }
    }

    if had_error {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_defaults_to_dry_run() {
        let parsed = parse_args(&["acme/widgets".to_string()]).unwrap();
        assert!(!parsed.apply);
        assert_eq!(parsed.repos, vec![("acme".to_string(), "widgets".to_string())]);
    }

    #[test]
    fn parse_args_apply_flag_turns_off_dry_run() {
        let parsed = parse_args(&["acme/widgets".to_string(), "--apply".to_string()]).unwrap();
        assert!(parsed.apply);
    }

    #[test]
    fn parse_args_accepts_multiple_repos() {
        let parsed = parse_args(&["acme/widgets".to_string(), "acme/gadgets".to_string()]).unwrap();
        assert_eq!(parsed.repos.len(), 2);
    }

    #[test]
    fn parse_args_rejects_no_repos() {
        assert!(parse_args(&[]).is_err());
        assert!(parse_args(&["--apply".to_string()]).is_err());
    }

    #[test]
    fn parse_args_rejects_invalid_org_repo_spec() {
        let err = parse_args(&["not-a-spec".to_string()]).unwrap_err();
        assert!(err.contains("org/repo"));
    }

    #[test]
    fn parse_args_rejects_invalid_owner_name() {
        let err = parse_args(&["-bad/repo".to_string()]).unwrap_err();
        assert!(err.contains("Invalid GitHub owner/org"));
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        assert!(parse_args(&["acme/widgets".to_string(), "--yolo".to_string()]).is_err());
    }

    #[test]
    fn protection_payload_requires_ignite_gate_and_blocks_admin_bypass() {
        let body = protection_payload();
        assert_eq!(body["required_status_checks"]["contexts"][0], "ignite/gate");
        assert_eq!(body["required_status_checks"]["strict"], true);
        assert_eq!(body["enforce_admins"], true);
        assert_eq!(body["restrictions"], Value::Null);
    }

    fn make_fake_gh(dir: &std::path::Path) {
        let script_path = dir.join("gh");
        let script = r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "gh version 2.0.0 fake"; exit 0; fi
if [ "$1" = "api" ] && [ "$2" = "repos/acme/widgets" ]; then
  echo '{"default_branch":"main"}'
  exit 0
fi
echo "unexpected args: $@" >&2
exit 1
"#;
        std::fs::write(&script_path, script).unwrap();
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();
    }

    #[tokio::test]
    async fn plan_for_repo_resolves_default_branch_via_fake_gh_and_never_mutates() {
        let dir = tempfile::tempdir().unwrap();
        make_fake_gh(dir.path());
        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{}", dir.path().display(), old_path));

        let runner = default_runner();
        let plan = plan_for_repo(&runner, "acme", "widgets").await.unwrap();
        assert_eq!(plan.default_branch, "main");
        assert_eq!(plan.full_name, "acme/widgets");
        assert!(plan.argv.contains(&"PUT".to_string()));
        assert_eq!(plan.body["required_status_checks"]["contexts"][0], "ignite/gate");

        std::env::set_var("PATH", old_path);
    }
}
