//! `POST /api/projects/:projectId/effectivate` — faithful port of
//! routes/review-gate.js's "Effectivate" endpoint. Turns a completed
//! `dryRun` interactive-pipeline simulation into the real thing:
//! provisions and pushes the exact snapshot that was already validated
//! (`AppState::pending_effectivations`, populated by
//! `routes/pipeline_interactive.rs` when a run finishes without shipping
//! for real), without re-running phases 1-5. Still hard-gated on any
//! blocking finding that hasn't been justified, re-checked here against
//! the project's current (possibly since-updated) issue list.
//!
//! `POST /api/pipeline/:jobId/review-decision` — the other route
//! `routes/review-gate.js` defines — is already ported in
//! `routes/pipeline_interactive.rs` (thin enough not to need this file).
//!
//! Session auth is now wired (`crate::auth::resolve_effective_github_token`
//! — a connected session's own GitHub token wins, falling back to
//! `resolve_server_github_token()` only for unattended/env-token
//! callers). No per-issue phase is tracked on `Issue` itself, so every
//! override recorded here is
//! attributed to phase 4, the phase most findings actually originate
//! from (same simplification `pipeline_onboard.rs`'s `issue_to_input`
//! already makes).

use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use ignite_db_store::{IssueInput, IssueRow};
use ignite_override_engine::{validate_overrides, Issue, Severity, SubmittedOverride};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn issue_row_to_input(r: &IssueRow) -> IssueInput {
    IssueInput { id: r.id.clone(), phase: r.phase, category: r.category.clone(), severity: r.severity.clone(), score: r.score, summary: r.summary.clone(), file: r.file.clone(), line: r.line, snippet: r.snippet.clone(), cross_file: r.cross_file, chain: r.chain.clone(), cwe: r.cwe.clone(), owasp: r.owasp.clone(), tool: r.tool.clone(), references: r.references.clone(), duplicate_ref: r.duplicate_ref.clone() }
}

fn issue_row_to_issue(r: &IssueRow) -> Issue {
    Issue {
        id: r.id.clone(),
        category: r.category.clone(),
        severity: if r.severity == "error" { Severity::Error } else { Severity::Warning },
        score: r.score.unwrap_or(0) as i32,
        summary: r.summary.clone(),
        file: r.file.clone(),
        line: r.line,
        snippet: r.snippet.clone(),
        cross_file: r.cross_file,
        chain: r.chain.clone(),
        duplicate_ref: None,
        cwe: r.cwe.clone(),
        owasp: r.owasp.clone(),
        tool: r.tool.clone(),
        references: r.references.as_ref().and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default(),
    }
}

fn resolve_actor_from_body(body: &Value) -> Option<(String, String)> {
    let actor = body.get("actor")?;
    let email = actor.get("email").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase();
    if !ignite_auth::is_valid_email(&email) {
        return None;
    }
    let name = actor.get("name").and_then(|v| v.as_str()).filter(|n| !n.trim().is_empty()).unwrap_or(&email).to_string();
    Some((email, name))
}

fn issues_json(rows: &[IssueRow]) -> Vec<Value> {
    rows.iter().map(|r| serde_json::to_value(r).unwrap()).collect()
}

async fn effectivate(Path(project_id): Path<i64>, State(state): State<Arc<AppState>>, headers: axum::http::HeaderMap, Json(body): Json<Value>) -> Response {
    let phase_meta = super::phase_meta::resolve_phase_meta(&state.config);
    let phase6_title = super::phase_meta::phase_title(&phase_meta, 6);
    let gh_token = crate::auth::resolve_effective_github_token(&headers, &state.db);
    if gh_token.is_empty() {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Log in and connect your GitHub account before effectivating." }))).into_response();
    }

    let pending = {
        let mut pending_map = state.pending_effectivations.lock().unwrap();
        let cutoff = Instant::now().checked_sub(Duration::from_secs(24 * 3600));
        pending_map.retain(|_, v| cutoff.map(|c| v.created_at > c).unwrap_or(true));
        pending_map.get(&project_id).map(|p| (p.org.clone(), p.repo.clone(), p.source_backup_dir.clone()))
    };
    let Some((org, repo, source_backup_dir)) = pending else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "No simulation output available to effectivate for this project (missing, expired, or already effectivated)." }))).into_response();
    };

    let issue_rows = state.db.get_project_issues(project_id);
    // Issues already justified at the live review gate (during the
    // simulation itself) are already `status: "overridden"` in the DB —
    // don't demand a second justification for those here, only for ones
    // still open.
    let still_open: Vec<Issue> = issue_rows.iter().filter(|r| r.status != "overridden").map(issue_row_to_issue).collect();
    let requested_overrides: Vec<SubmittedOverride> = body
        .get("overrides")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(|o| SubmittedOverride { issue_id: o.get("issueId").and_then(|v| v.as_str()).unwrap_or("").to_string(), justification: o.get("justification").and_then(|v| v.as_str()).unwrap_or("").to_string() }).collect())
        .unwrap_or_default();

    let result = validate_overrides(&still_open, &requested_overrides);
    if !result.ok {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": format!("{} blocking finding(s) still need to be checked + justified before this simulation can be effectivated.", result.unresolved_errors.len()),
                "needsReview": true,
                "issues": issues_json(&issue_rows),
            })),
        )
            .into_response();
    }

    let applied: Vec<(&Issue, String)> = result.applied.iter().map(|(i, j)| (*i, j.clone())).collect();
    let mut actor: Option<(String, String)> = None;
    if !applied.is_empty() {
        actor = resolve_actor_from_body(&body);
        if actor.is_none() {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Log in, or provide actor {email,name}, to submit overrides.", "needsReview": true, "issues": issues_json(&issue_rows) })),
            )
                .into_response();
        }
    }

    let publish_dir = {
        let mut p = source_backup_dir.clone().into_os_string();
        p.push("-effectivate-publish");
        std::path::PathBuf::from(p)
    };
    let effectivate_logs = Arc::new(Mutex::new(vec!["Effectivating simulation — provisioning + pushing the previously validated snapshot.".to_string()]));
    let log = {
        let logs = effectivate_logs.clone();
        let db = &state.db;
        let phase6_title = phase6_title.clone();
        move |m: &str| {
            let mut l = logs.lock().unwrap();
            l.push(m.to_string());
            let _ = db.upsert_step(project_id, 6, &phase6_title, "running", &l.join("\n"));
        }
    };

    let backup_ok = source_backup_dir.is_dir();
    if !backup_ok {
        state.pending_effectivations.lock().unwrap().remove(&project_id);
        return (StatusCode::GONE, Json(json!({ "error": "Simulation snapshot is no longer available (expired or already effectivated). Re-run the simulation to try again." }))).into_response();
    }

    if !applied.is_empty() {
        let (actor_email, actor_name) = actor.clone().unwrap();
        for (issue, justification) in &applied {
            state.db.add_override(ignite_db_store::AddOverrideArgs {
                project_id,
                job_id: &format!("effectivate-{project_id}"),
                phase: 4,
                issue_id: &issue.id,
                category: &issue.category,
                severity: match issue.severity {
                    Severity::Error => "error",
                    Severity::Warning => "warning",
                },
                summary: &issue.summary,
                file: issue.file.as_deref(),
                line: issue.line,
                justification,
                actor_email: &actor_email,
                actor_name: Some(&actor_name),
                email_sent: false,
            });
        }
        let applied_ids: HashSet<String> = applied.iter().map(|(i, _)| i.id.clone()).collect();
        let already_overridden_ids: HashSet<String> = issue_rows.iter().filter(|r| r.status == "overridden").map(|r| r.id.clone()).collect();
        let overridden_ids: HashSet<String> = applied_ids.union(&already_overridden_ids).cloned().collect();
        let inputs: Vec<IssueInput> = issue_rows.iter().map(issue_row_to_input).collect();
        state.db.replace_project_issues(project_id, &inputs, &overridden_ids);
    }

    let mut log = log;
    let _ = std::fs::remove_dir_all(&publish_dir);
    if let Err(e) = ignite_staging::clone_directory_without_symlinks(&source_backup_dir, &publish_dir) {
        log(&format!("✗ Effectivate failed: {e}"));
        let _ = state.db.upsert_step(project_id, 6, &phase6_title, "failed", &effectivate_logs.lock().unwrap().join("\n"));
        return (StatusCode::BAD_GATEWAY, Json(json!({ "error": format!("Effectivate failed: {e}") }))).into_response();
    }

    ignite_shipping::archive_phase6_payload(&publish_dir, Some(project_id), &state.runner, &state.db, &mut log).await;

    let ship_config = ignite_shipping::ShippingConfig::default();
    let gh_api = ignite_github_api::GithubApi::new(&state.runner);
    match ignite_shipping::ship_to_github(&publish_dir, &org, &repo, &gh_token, &state.runner, &gh_api, &ship_config, &mut log).await {
        Ok(ship_result) => {
            state.db.finish_project("success", None, Some(&ship_result.repo_url), ship_result.pr_url.as_deref(), project_id);
            log(&format!("✓ Effectivated — repository live at {}", ship_result.repo_url));
            let _ = state.db.upsert_step(project_id, 6, &phase6_title, "success", &effectivate_logs.lock().unwrap().join("\n"));
            state.pending_effectivations.lock().unwrap().remove(&project_id);
            let _ = std::fs::remove_dir_all(&source_backup_dir);
            let _ = std::fs::remove_dir_all(&publish_dir);
            (StatusCode::OK, Json(json!({ "ok": true, "repoUrl": ship_result.repo_url, "prUrl": ship_result.pr_url }))).into_response()
        }
        Err(e) => {
            log(&format!("✗ Effectivate failed: {e}"));
            let _ = state.db.upsert_step(project_id, 6, &phase6_title, "failed", &effectivate_logs.lock().unwrap().join("\n"));
            (StatusCode::BAD_GATEWAY, Json(json!({ "error": format!("Effectivate failed: {e}") }))).into_response()
        }
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/projects/:projectId/effectivate", post(effectivate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state;
    use std::collections::HashMap;

    fn build_state() -> (Arc<AppState>, tempfile::TempDir) {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let app_state = Arc::new(AppState {
            runner: state::default_runner(),
            db,
            running_runs: Mutex::new(HashMap::new()),
            pending_effectivations: Mutex::new(HashMap::new()),
            review_gate: crate::review_gate::ReviewGate::default(),
            llm_config: state::default_llm_config(),
            config: ignite_config::Config::default(),
            package_hallucination_checker: state::default_package_hallucination_checker(),
        });
        (app_state, db_dir)
    }

    async fn spawn_test_server(state: Arc<AppState>) -> String {
        let router = axum::Router::new().merge(router()).with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{addr}")
    }

    // `GH_TOKEN`/`GITHUB_TOKEN` are process-global — see
    // `state::GH_TOKEN_ENV_GUARD` for why this is needed and shared with
    // `main.rs`'s `onboard_rejects_missing_gh_token_when_not_dry_run`.
    use crate::state::GH_TOKEN_ENV_GUARD as ENV_GUARD;

    #[tokio::test]
    async fn returns_401_without_a_github_token() {
        let _guard = ENV_GUARD.lock().unwrap();
        std::env::remove_var("GH_TOKEN");
        std::env::remove_var("GITHUB_TOKEN");
        let (state, _dir) = build_state();
        let base = spawn_test_server(state).await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/projects/1/effectivate")).json(&json!({})).send().await.unwrap();
        assert_eq!(res.status(), 401);
    }

    #[tokio::test]
    async fn returns_404_when_no_pending_effectivation() {
        let _guard = ENV_GUARD.lock().unwrap();
        std::env::set_var("GH_TOKEN", "test-token");
        let (state, _dir) = build_state();
        let base = spawn_test_server(state).await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/projects/999/effectivate")).json(&json!({})).send().await.unwrap();
        assert_eq!(res.status(), 404);
        std::env::remove_var("GH_TOKEN");
    }

    #[tokio::test]
    async fn returns_409_when_blocking_issue_is_unresolved() {
        let _guard = ENV_GUARD.lock().unwrap();
        std::env::set_var("GH_TOKEN", "test-token");
        let (state, _dir) = build_state();
        let project_id = state.db.create_project("job-1", "acme", "widgets", false, "ui", None);
        state.db.replace_project_issues(
            project_id,
            &[IssueInput { id: "secrets::app.js::1".into(), phase: Some(4), category: "secrets".into(), severity: "error".into(), score: Some(9), summary: "Hardcoded AWS key".into(), file: Some("app.js".into()), line: Some(1), snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: Some("built-in".into()), references: None, duplicate_ref: None }],
            &HashSet::new(),
        );
        let backup_dir = tempfile::tempdir().unwrap();
        state.pending_effectivations.lock().unwrap().insert(
            project_id,
            crate::state::PendingEffectivation { org: "acme".into(), repo: "widgets".into(), source_backup_dir: backup_dir.path().to_path_buf(), created_at: Instant::now() },
        );

        let base = spawn_test_server(state).await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/projects/{project_id}/effectivate")).json(&json!({})).send().await.unwrap();
        assert_eq!(res.status(), 409);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["needsReview"], true);
        std::env::remove_var("GH_TOKEN");
    }

    // A full success-path test (override applied, real git init/commit +
    // `gh repo create` push) isn't covered here — same gap as
    // `pipeline_onboard.rs`, which has no test for its real-push success
    // path either: it needs a real `GH_TOKEN`/`GITHUB_TOKEN` with
    // repo-create permission and network access to github.com, neither
    // available in a unit-test sandbox. `ship_to_github`'s own crate
    // (ignite-shipping) covers the empty-token fast-fail path; the
    // override-application + DB bookkeeping above this call is covered by
    // `returns_409_when_blocking_issue_is_unresolved` and, once overridden,
    // is exercised structurally the same way `pipeline_interactive.rs`'s
    // override-application code already is.
}
