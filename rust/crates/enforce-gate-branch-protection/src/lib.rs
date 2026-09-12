//! `enforce-gate-branch-protection <org/repo> [<org/repo>...] [--apply]` —
//! the GHAS-bypass-hardening branch-protection tool: Ignite's compliance
//! gate only fires if someone actually routes code through the pipeline
//! (push/PR), unlike GitHub Advanced Security which is enforced at the
//! platform level regardless of push path. This closes that gap by
//! requiring the `ignite/gate` status check (the same context
//! `routes/github_pr_status.rs`/`github_pr_status.rs` posts to) on the
//! repo's default branch and disallowing direct pushes that bypass a PR.
//!
//! `enforce-gate-branch-protection --org <org-name> [--org <org-name>...] [--apply]`
//! — the org-wide counterpart: GitHub's own Organization Rulesets apply
//! to every current *and future* repo in the org automatically, closing
//! the gap the per-repo form above leaves (a newly-created repo has no
//! protection until someone remembers to run this against it by name).
//! `--org` and `<org/repo>` targets can be freely mixed in one
//! invocation; at least one of either is required.
//!
//! **Dry-run by default.** Without `--apply` this only ever performs
//! read-only lookups (the repo's default branch, or an org's existing
//! rulesets) and prints the exact `gh api` invocation — argv array plus
//! JSON body — it *would* make, never calling the mutating endpoint.
//! Pass `--apply` to actually call GitHub. This binary is not wired into
//! any pipeline/cron path — it's a deliberate, standalone tool for an
//! operator to run by hand.
//!
//! `enforce-gate-branch-protection --org <org-name>... --check-drift [--apply]`
//! — org-ruleset drift detection, the natural follow-on to the org-wide
//! form above: applying a ruleset once only guarantees it's correct
//! *at that moment*. Someone with org-admin rights can still loosen it
//! by hand afterwards (drop the required `ignite/gate` check, add a
//! bypass actor, delete the ruleset outright) directly in GitHub's own
//! UI, and nothing about the one-shot flow would ever notice. This mode
//! fetches each `--org` target's *current* ruleset and diffs it against
//! the policy (`detect_ruleset_drift`), reporting every divergence; it
//! never mutates anything on its own — pair it with `--apply` to also
//! reconcile (re-`PUT` the correct ruleset) whatever's drifted, or leave
//! `--apply` off to only report. Exits `2` if any org has drift (even
//! when `--apply` just fixed it — a cron/CI caller watching this exit
//! code wants to know drift *happened*), `1` on a lookup/apply error, `0`
//! when every target already matches policy. Not wired into any
//! scheduled path itself — run it from cron/a scheduled GitHub Actions
//! workflow the same way `docs-site/docs/ci-integration.md` documents
//! for `scheduled-rescan`.
//!
//! Every `gh` invocation goes through `ignite_tool_runner::ToolRunner`
//! with an argument array (no shell), matching this repo's standing
//! hardening invariant. The protection/ruleset payload is nested JSON
//! that `gh api`'s flat `-f`/`-F` field flags can't express, so — same
//! pattern as `ignite_github_api::gh_comment_on_pr`'s `--body-file` —
//! the per-repo path writes it to a temp file and passes it via
//! `--input <file>`; the org-ruleset path reuses
//! `ignite_github_api::GithubApi::gh_api_write`, which already detects a
//! non-scalar field and routes through the raw REST fallback instead of
//! mangling it through `-f`.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use ignite_github_api::{is_valid_github_owner, parse_org_repo, GithubApi};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use serde_json::{json, Value};
use std::collections::HashMap;

/// Replaces this crate's previous ad-hoc `Result<_, String>` — every
/// existing caller (`main.rs`'s `eprintln!("{e}")` sites,
/// `repository_events_webhook.rs`'s `tracing::warn!("...{e}")`) only ever
/// displays the error, never matches on its text, so `Display` rendering
/// identical to the old strings is what matters, not the variant shape.
/// `From<String>`/`From<&str>` let every existing `Err(format!(...))` /
/// `Err("literal".to_string())` / `ok_or("literal")?` site keep compiling
/// unchanged — this crate's own errors are always just a rendered
/// message, and `ignite_github_api::parse_org_repo`'s `Result<_, String>`
/// (out of scope to convert here — that crate has much wider fan-out)
/// still flows through `?` the same way.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct EnforceGateError(String);

impl From<String> for EnforceGateError {
    fn from(s: String) -> Self {
        EnforceGateError(s)
    }
}
impl From<&str> for EnforceGateError {
    fn from(s: &str) -> Self {
        EnforceGateError(s.to_string())
    }
}

#[derive(Debug)]
pub struct ParsedArgs {
    pub repos: Vec<(String, String)>,
    pub orgs: Vec<String>,
    pub apply: bool,
    /// Org-ruleset drift-detection mode (`--check-drift`) — the
    /// continuous-enforcement counterpart to the normal one-shot
    /// create-or-update flow: instead of unconditionally overwriting each
    /// `--org` target's ruleset, fetches its *current* state, diffs it
    /// against the policy (`detect_ruleset_drift`), and reports every
    /// divergence without mutating anything unless `--apply` is also
    /// given. Suited to a cron/CI job that alerts (via this process's
    /// exit code — see `main`) when someone loosens a ruleset by hand in
    /// GitHub's own UI, closing the gap a purely one-shot CLI leaves
    /// between runs. Requires at least one `--org` target — an org
    /// ruleset is the only thing this mode checks (per-repo classic
    /// branch protection has no equivalent drift check).
    pub check_drift: bool,
}

pub fn parse_args(raw: &[String]) -> Result<ParsedArgs, EnforceGateError> {
    let mut repos = Vec::new();
    let mut orgs = Vec::new();
    let mut apply = false;
    let mut check_drift = false;
    let mut saw_dry_run_flag = false;
    let mut i = 0;

    while i < raw.len() {
        match raw[i].as_str() {
            "--apply" => apply = true,
            "--check-drift" => check_drift = true,
            "--dry-run" => saw_dry_run_flag = true,
            "--dry-run=false" => {
                saw_dry_run_flag = true;
                apply = true;
            }
            "--dry-run=true" => saw_dry_run_flag = true,
            "--org" => {
                i += 1;
                let org = raw.get(i).ok_or("--org requires a value")?;
                if !is_valid_github_owner(org) {
                    return Err(format!("Invalid GitHub owner/org: \"{org}\"").into());
                }
                orgs.push(org.clone());
            }
            other if other.starts_with("--") => return Err(format!("Unknown flag: {other}").into()),
            other => repos.push(parse_org_repo(other)?),
        }
        i += 1;
    }
    let _ = saw_dry_run_flag; // --dry-run is the (redundant) default; only --apply flips it off.

    if repos.is_empty() && orgs.is_empty() {
        return Err("Usage: enforce-gate-branch-protection <org/repo> [<org/repo>...] [--org <org-name>...] [--apply] [--check-drift]".into());
    }
    if check_drift && orgs.is_empty() {
        return Err("--check-drift requires at least one --org target.".into());
    }
    Ok(ParsedArgs { repos, orgs, apply, check_drift })
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

pub async fn plan_for_repo(runner: &ToolRunner, org: &str, repo: &str) -> Result<PlannedCall, EnforceGateError> {
    let full_name = format!("{org}/{repo}");
    let api = ignite_github_api::GithubApi::new(runner);
    let default_branch = api.default_branch(&full_name, &ignite_github_api::resolve_server_github_token()).await.map_err(|e| format!("Failed to look up {full_name}: {e}"))?;
    let body = protection_payload();
    let argv = vec!["gh".to_string(), "api".to_string(), "-X".to_string(), "PUT".to_string(), format!("repos/{full_name}/branches/{default_branch}/protection"), "--input".to_string(), "<tmpfile: see JSON body below>".to_string()];
    Ok(PlannedCall { full_name, default_branch, argv, body })
}

pub fn print_plan(plan: &PlannedCall) {
    println!("== {} (default branch: {}) ==", plan.full_name, plan.default_branch);
    println!("  {}", plan.argv.join(" "));
    println!("  body:");
    println!("{}", serde_json::to_string_pretty(&plan.body).unwrap_or_default().lines().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n"));
}

pub async fn apply_plan(runner: &ToolRunner, plan: &PlannedCall) -> Result<(), EnforceGateError> {
    let tmp = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    std::fs::write(tmp.path(), serde_json::to_vec(&plan.body).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let args = vec!["api".to_string(), "-X".to_string(), "PUT".to_string(), format!("repos/{}/branches/{}/protection", plan.full_name, plan.default_branch), "--input".to_string(), tmp.path().to_string_lossy().to_string()];
    let token = std::env::var("GH_TOKEN").or_else(|_| std::env::var("GITHUB_TOKEN")).map_err(|_| {
        EnforceGateError::from("No GH_TOKEN or GITHUB_TOKEN set in environment — refusing to call the GitHub API unauthenticated".to_string())
    })?;
    let env: HashMap<String, String> = HashMap::from([("GH_TOKEN".to_string(), token)]);
    runner.run_tool("gh", &args, &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() }).await.map_err(|e| format!("Failed to apply protection to {}: {e}", plan.full_name))?;
    Ok(())
}

/// Ruleset name this tool owns — used both as the ruleset's own `name`
/// field and as the idempotency key (`find_existing_org_ruleset_id`
/// looks for a ruleset already carrying this exact name before deciding
/// whether to create or update).
const ORG_RULESET_NAME: &str = "ignite-gate";

/// The org-wide GitHub Repository Ruleset this tool enforces — same
/// intent as `protection_payload` above (require `ignite/gate`, block
/// force-pushes/deletion, require a reviewed PR), expressed in GitHub's
/// newer Rulesets schema so it applies to every repo in the org — including
/// ones created after this runs — rather than needing to be re-run
/// per-repo. `bypass_actors: []` is the ruleset equivalent of
/// `enforce_admins: true`: nobody, including org owners, bypasses it.
pub fn org_ruleset_payload() -> Value {
    json!({
        "name": ORG_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "conditions": {
            "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] },
            "repository_name": { "include": ["~ALL"], "exclude": [] }
        },
        "rules": [
            { "type": "deletion" },
            { "type": "non_fast_forward" },
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews_on_push": true,
                    "require_code_owner_review": false,
                    "require_last_push_approval": false,
                    "required_review_thread_resolution": false
                }
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [{ "context": "ignite/gate", "integration_id": null }],
                    "strict_required_status_checks_policy": true
                }
            }
        ],
        "bypass_actors": []
    })
}

/// The `id` of `org`'s existing ruleset named `ORG_RULESET_NAME`, if any
/// — read-only, safe in dry-run. `Some` means `plan_for_org` should
/// `PUT` (update in place) rather than `POST` (create a duplicate).
pub async fn find_existing_org_ruleset_id(api: &GithubApi<'_>, org: &str, token: &str) -> Result<Option<u64>, EnforceGateError> {
    let rulesets = api.gh_api_get(&format!("orgs/{org}/rulesets"), token).await.map_err(|e| format!("Failed to list rulesets for org {org}: {e}"))?;
    Ok(rulesets
        .and_then(|v| v.as_array().cloned())
        .and_then(|list| list.into_iter().find(|r| r.get("name").and_then(|n| n.as_str()) == Some(ORG_RULESET_NAME)))
        .and_then(|r| r.get("id").and_then(|v| v.as_u64())))
}

/// Compares an org's *actual* GitHub ruleset (as returned by `GET
/// orgs/{org}/rulesets/{id}`) against the policy this tool enforces
/// (`org_ruleset_payload`), reporting every meaningful divergence in
/// plain English. Read-only/pure — the "detection" half of drift
/// detection/reconciliation: `--check-drift` calls this without ever
/// mutating anything, so an operator (or a cron job watching this
/// process's exit code) can tell *that* someone loosened the ruleset
/// directly in GitHub's own UI, without needing to already suspect it.
/// Deliberately checks the specific fields the policy actually cares
/// about (enforcement, bypass actors, and each of the four required rule
/// types/parameters) rather than a byte-for-byte diff against
/// `org_ruleset_payload()` — GitHub's API echoes back extra
/// server-assigned fields (`id`, `created_at`, per-rule ids, etc.) on
/// every rule that would make an exact-equality check report drift on
/// every single call, even a freshly-created, fully-compliant ruleset.
pub fn detect_ruleset_drift(existing: &Value, desired: &Value) -> Vec<String> {
    let mut drift = Vec::new();

    let existing_enforcement = existing.get("enforcement").and_then(|v| v.as_str()).unwrap_or("");
    let desired_enforcement = desired.get("enforcement").and_then(|v| v.as_str()).unwrap_or("");
    if existing_enforcement != desired_enforcement {
        drift.push(format!("enforcement is {existing_enforcement:?}, expected {desired_enforcement:?}"));
    }

    let existing_bypass_count = existing.get("bypass_actors").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
    if existing_bypass_count > 0 {
        drift.push(format!("bypass_actors is non-empty ({existing_bypass_count} actor(s)) — the policy requires nobody bypass this ruleset"));
    }

    let existing_rules = existing.get("rules").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let has_rule_type = |t: &str| existing_rules.iter().any(|r| r.get("type").and_then(|v| v.as_str()) == Some(t));

    if !has_rule_type("deletion") {
        drift.push("missing rule \"deletion\" — branch deletion is no longer blocked".to_string());
    }
    if !has_rule_type("non_fast_forward") {
        drift.push("missing rule \"non_fast_forward\" — force-pushes are no longer blocked".to_string());
    }
    if !has_rule_type("pull_request") {
        drift.push("missing rule \"pull_request\" — a reviewed PR is no longer required before merging".to_string());
    }

    let status_check_rule = existing_rules.iter().find(|r| r.get("type").and_then(|v| v.as_str()) == Some("required_status_checks"));
    match status_check_rule {
        None => drift.push("missing rule \"required_status_checks\" — \"ignite/gate\" is no longer required".to_string()),
        Some(rule) => {
            let contexts: Vec<&str> = rule
                .get("parameters")
                .and_then(|p| p.get("required_status_checks"))
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|c| c.get("context").and_then(|v| v.as_str())).collect())
                .unwrap_or_default();
            if !contexts.contains(&"ignite/gate") {
                drift.push("\"required_status_checks\" rule no longer includes \"ignite/gate\" as a required context".to_string());
            }
        }
    }

    drift
}

pub struct OrgPlannedCall {
    pub org: String,
    pub existing_ruleset_id: Option<u64>,
    pub method: &'static str,
    pub api_path: String,
    pub body: Value,
    /// Divergences found between the org's current ruleset and the
    /// policy — empty when a compliant ruleset already exists, or a
    /// single "no ruleset exists yet" entry when there's nothing to diff
    /// against. Always populated (even outside `--check-drift` mode), so
    /// the normal create-or-update flow's own output also surfaces
    /// exactly what it's about to fix.
    pub drift: Vec<String>,
}

pub async fn plan_for_org(runner: &ToolRunner, org: &str) -> Result<OrgPlannedCall, EnforceGateError> {
    let api = GithubApi::new(runner);
    let token = ignite_github_api::resolve_server_github_token();
    let existing_ruleset_id = find_existing_org_ruleset_id(&api, org, &token).await?;
    let body = org_ruleset_payload();
    let (method, api_path) = match existing_ruleset_id {
        Some(id) => ("PUT", format!("orgs/{org}/rulesets/{id}")),
        None => ("POST", format!("orgs/{org}/rulesets")),
    };
    let drift = match existing_ruleset_id {
        Some(id) => {
            let existing = api.gh_api_get(&format!("orgs/{org}/rulesets/{id}"), &token).await.map_err(|e| format!("Failed to fetch existing ruleset for org {org}: {e}"))?.unwrap_or(Value::Null);
            detect_ruleset_drift(&existing, &body)
        }
        None => vec!["no \"ignite-gate\" ruleset exists yet for this org".to_string()],
    };
    Ok(OrgPlannedCall { org: org.to_string(), existing_ruleset_id, method, api_path, body, drift })
}

pub fn print_org_plan(plan: &OrgPlannedCall) {
    println!("== org:{} ({}) ==", plan.org, if plan.existing_ruleset_id.is_some() { "update existing ruleset" } else { "create new ruleset" });
    if plan.drift.is_empty() {
        println!("  ruleset already matches policy — no drift detected.");
    } else {
        println!("  drift detected:");
        for d in &plan.drift {
            println!("    - {d}");
        }
    }
    println!("  gh api -X {} {}", plan.method, plan.api_path);
    println!("  body:");
    println!("{}", serde_json::to_string_pretty(&plan.body).unwrap_or_default().lines().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n"));
}

pub async fn apply_org_plan(runner: &ToolRunner, plan: &OrgPlannedCall) -> Result<(), EnforceGateError> {
    let api = GithubApi::new(runner);
    let token = ignite_github_api::resolve_server_github_token();
    let fields: HashMap<String, Value> = match &plan.body {
        Value::Object(map) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        _ => HashMap::new(),
    };
    api.gh_api_write(plan.method, &plan.api_path, &fields, &token).await.map_err(|e| format!("Failed to apply org ruleset for {}: {e}", plan.org))?;
    Ok(())
}

pub fn default_runner() -> ToolRunner {
    ToolRunner::new(HashMap::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serializes tests that mutate the process-global PATH env var — same
    // guard ignite-github-api's own PATH-mutating tests use.
    static PATH_LOCK: Mutex<()> = Mutex::new(());

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
    fn parse_args_accepts_org_flag_alone_or_mixed_with_repos() {
        let parsed = parse_args(&["--org".to_string(), "acme".to_string()]).unwrap();
        assert_eq!(parsed.orgs, vec!["acme".to_string()]);
        assert!(parsed.repos.is_empty());

        let mixed = parse_args(&["acme/widgets".to_string(), "--org".to_string(), "other-org".to_string()]).unwrap();
        assert_eq!(mixed.repos, vec![("acme".to_string(), "widgets".to_string())]);
        assert_eq!(mixed.orgs, vec!["other-org".to_string()]);
    }

    #[test]
    fn parse_args_rejects_org_flag_without_a_value() {
        assert!(parse_args(&["--org".to_string()]).is_err());
    }

    #[test]
    fn parse_args_rejects_invalid_org_name_after_org_flag() {
        let err = parse_args(&["--org".to_string(), "-bad".to_string()]).unwrap_err();
        assert!(err.to_string().contains("Invalid GitHub owner/org"));
    }

    #[test]
    fn org_ruleset_payload_requires_ignite_gate_targets_all_repos_and_blocks_bypass() {
        let body = org_ruleset_payload();
        assert_eq!(body["name"], ORG_RULESET_NAME);
        assert_eq!(body["enforcement"], "active");
        assert_eq!(body["conditions"]["repository_name"]["include"][0], "~ALL");
        assert_eq!(body["conditions"]["ref_name"]["include"][0], "~DEFAULT_BRANCH");
        assert!(body["bypass_actors"].as_array().unwrap().is_empty());
        let rule_types: Vec<&str> = body["rules"].as_array().unwrap().iter().filter_map(|r| r["type"].as_str()).collect();
        assert!(rule_types.contains(&"required_status_checks"));
        assert!(rule_types.contains(&"deletion"));
        assert!(rule_types.contains(&"non_fast_forward"));
        let status_checks = &body["rules"][3]["parameters"]["required_status_checks"];
        assert_eq!(status_checks[0]["context"], "ignite/gate");
    }

    #[test]
    fn parse_args_rejects_invalid_org_repo_spec() {
        let err = parse_args(&["not-a-spec".to_string()]).unwrap_err();
        assert!(err.to_string().contains("org/repo"));
    }

    #[test]
    fn parse_args_rejects_invalid_owner_name() {
        let err = parse_args(&["-bad/repo".to_string()]).unwrap_err();
        assert!(err.to_string().contains("Invalid GitHub owner/org"));
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
    #[allow(clippy::await_holding_lock)]
    async fn plan_for_repo_resolves_default_branch_via_fake_gh_and_never_mutates() {
        let _guard = PATH_LOCK.lock().unwrap();
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

    /// `ruleset_detail_json` backs `GET orgs/acme/rulesets/<id>` — only
    /// reached when `existing_rulesets_json` carries a matching id, so
    /// tests where no ruleset exists yet can pass an unused placeholder.
    fn make_fake_gh_org_rulesets(dir: &std::path::Path, existing_rulesets_json: &str, ruleset_detail_json: &str) {
        let script_path = dir.join("gh");
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "gh version 2.0.0 fake"; exit 0; fi
if [ "$1" = "api" ] && [ "$2" = "orgs/acme/rulesets" ] && [ -z "$3" ]; then
  echo '{existing_rulesets_json}'
  exit 0
fi
case "$2" in
  orgs/acme/rulesets/*)
    echo '{ruleset_detail_json}'
    exit 0
    ;;
esac
echo "unexpected args: $@" >&2
exit 1
"#
        );
        std::fs::write(&script_path, script).unwrap();
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn plan_for_org_creates_a_new_ruleset_when_none_exists_yet() {
        let _guard = PATH_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        make_fake_gh_org_rulesets(dir.path(), "[]", "{}");
        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{}", dir.path().display(), old_path));

        let runner = default_runner();
        let plan = plan_for_org(&runner, "acme").await.unwrap();
        assert_eq!(plan.existing_ruleset_id, None);
        assert_eq!(plan.method, "POST");
        assert_eq!(plan.api_path, "orgs/acme/rulesets");
        assert_eq!(plan.drift, vec!["no \"ignite-gate\" ruleset exists yet for this org".to_string()]);

        std::env::set_var("PATH", old_path);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn plan_for_org_updates_the_existing_ruleset_in_place() {
        let _guard = PATH_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let compliant_detail = serde_json::to_string(&org_ruleset_payload()).unwrap();
        make_fake_gh_org_rulesets(dir.path(), r#"[{"id": 42, "name": "ignite-gate"}]"#, &compliant_detail);
        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{}", dir.path().display(), old_path));

        let runner = default_runner();
        let plan = plan_for_org(&runner, "acme").await.unwrap();
        assert_eq!(plan.existing_ruleset_id, Some(42));
        assert_eq!(plan.method, "PUT");
        assert_eq!(plan.api_path, "orgs/acme/rulesets/42");
        assert!(plan.drift.is_empty(), "a ruleset identical to the desired policy should report no drift: {:?}", plan.drift);

        std::env::set_var("PATH", old_path);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn plan_for_org_ignores_a_same_named_ruleset_belonging_to_a_different_id_shape() {
        let _guard = PATH_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        make_fake_gh_org_rulesets(dir.path(), r#"[{"id": 7, "name": "some-other-ruleset"}]"#, "{}");
        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{}", dir.path().display(), old_path));

        let runner = default_runner();
        let plan = plan_for_org(&runner, "acme").await.unwrap();
        assert_eq!(plan.existing_ruleset_id, None, "must not match a ruleset with a different name");
        assert_eq!(plan.method, "POST");

        std::env::set_var("PATH", old_path);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn plan_for_org_detects_drift_when_a_human_loosened_the_ruleset_in_github() {
        let _guard = PATH_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // A human removed the pull_request rule and added a bypass actor
        // directly in GitHub's UI after this tool last applied policy.
        let loosened_detail = r#"{
            "id": 42, "name": "ignite-gate", "enforcement": "active",
            "bypass_actors": [{"actor_id": 1, "actor_type": "Team"}],
            "rules": [
                { "type": "deletion" },
                { "type": "non_fast_forward" },
                { "type": "required_status_checks", "parameters": { "required_status_checks": [{ "context": "ignite/gate" }] } }
            ]
        }"#;
        make_fake_gh_org_rulesets(dir.path(), r#"[{"id": 42, "name": "ignite-gate"}]"#, loosened_detail);
        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{}", dir.path().display(), old_path));

        let runner = default_runner();
        let plan = plan_for_org(&runner, "acme").await.unwrap();

        std::env::set_var("PATH", old_path);

        assert!(plan.drift.iter().any(|d| d.contains("bypass_actors")), "{:?}", plan.drift);
        assert!(plan.drift.iter().any(|d| d.contains("pull_request")), "{:?}", plan.drift);
    }

    #[test]
    fn detect_ruleset_drift_reports_nothing_for_a_fully_compliant_ruleset() {
        let desired = org_ruleset_payload();
        // Simulates what GitHub's API actually echoes back: the same
        // logical policy plus extra server-assigned fields no diff should
        // care about.
        let mut existing = desired.clone();
        existing["id"] = json!(42);
        existing["created_at"] = json!("2026-01-01T00:00:00Z");
        assert!(detect_ruleset_drift(&existing, &desired).is_empty());
    }

    #[test]
    fn detect_ruleset_drift_flags_disabled_enforcement() {
        let desired = org_ruleset_payload();
        let mut existing = desired.clone();
        existing["enforcement"] = json!("disabled");
        let drift = detect_ruleset_drift(&existing, &desired);
        assert!(drift.iter().any(|d| d.contains("enforcement")), "{drift:?}");
    }

    #[test]
    fn detect_ruleset_drift_flags_nonempty_bypass_actors() {
        let desired = org_ruleset_payload();
        let mut existing = desired.clone();
        existing["bypass_actors"] = json!([{ "actor_id": 1, "actor_type": "Team" }]);
        let drift = detect_ruleset_drift(&existing, &desired);
        assert!(drift.iter().any(|d| d.contains("bypass_actors")), "{drift:?}");
    }

    #[test]
    fn detect_ruleset_drift_flags_missing_rule_types() {
        let desired = org_ruleset_payload();
        let mut existing = desired.clone();
        existing["rules"] = json!([{ "type": "deletion" }]);
        let drift = detect_ruleset_drift(&existing, &desired);
        assert!(drift.iter().any(|d| d.contains("non_fast_forward")), "{drift:?}");
        assert!(drift.iter().any(|d| d.contains("pull_request")), "{drift:?}");
        assert!(drift.iter().any(|d| d.contains("required_status_checks")), "{drift:?}");
    }

    #[test]
    fn detect_ruleset_drift_flags_status_check_missing_ignite_gate_context() {
        let desired = org_ruleset_payload();
        let mut existing = desired.clone();
        existing["rules"] = json!([
            { "type": "deletion" },
            { "type": "non_fast_forward" },
            { "type": "pull_request", "parameters": { "required_approving_review_count": 1 } },
            { "type": "required_status_checks", "parameters": { "required_status_checks": [{ "context": "some-other-check" }] } }
        ]);
        let drift = detect_ruleset_drift(&existing, &desired);
        assert!(drift.iter().any(|d| d.contains("ignite/gate")), "{drift:?}");
    }

    #[test]
    fn parse_args_check_drift_requires_an_org_target() {
        let err = parse_args(&["--check-drift".to_string(), "acme/widgets".to_string()]).unwrap_err();
        assert!(err.to_string().contains("--check-drift requires"));
    }

    #[test]
    fn parse_args_check_drift_accepted_with_an_org_target() {
        let parsed = parse_args(&["--org".to_string(), "acme".to_string(), "--check-drift".to_string()]).unwrap();
        assert!(parsed.check_drift);
        assert_eq!(parsed.orgs, vec!["acme".to_string()]);
    }

    #[test]
    fn parse_args_check_drift_defaults_to_false() {
        let parsed = parse_args(&["acme/widgets".to_string()]).unwrap();
        assert!(!parsed.check_drift);
    }
}
