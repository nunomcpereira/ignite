//! GET /api/pipeline/:jobId/sarif — faithful port of routes/sarif.js.
//!
//! Both routes below set `Content-Disposition: attachment` (not just the
//! `application/sarif+json` content type `gh_upload_sarif`
//! (`github_pr_status.rs`) already pushes automatically) — a plain
//! `<a href>`/`window.location` hit therefore downloads a real `.sarif`
//! file browsers save to disk instead of rendering the JSON inline, which
//! is what lets someone who wants to upload it to GitHub by hand (`gh api
//! .../code-scanning/sarifs` themselves, or a CI step Ignite doesn't run)
//! actually get a file rather than having to copy raw response text.

use crate::routes::job_issues::lookup_job_issues;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use std::sync::Arc;

fn sarif_response(doc: ignite_sarif::SarifDocument, filename_stem: &str) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/sarif+json".to_string()), (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename_stem}.sarif\""))], Json(doc)).into_response()
}

async fn sarif_handler(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let job_id = job_id.trim();
    let Some(issues) = lookup_job_issues(&state, job_id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "Unknown job id." }))).into_response();
    };
    let doc = ignite_sarif::build_sarif(&issues);
    sarif_response(doc, &format!("ignite-{job_id}"))
}

/// Same document, looked up by `projects.id` instead of a job id — the
/// history panel and the onboarded-repos table both already key their own
/// "view findings" calls off a project id rather than a job id, so this
/// avoids forcing every such caller to first resolve one into the other.
async fn sarif_by_project_handler(State(state): State<Arc<AppState>>, Path(project_id): Path<i64>) -> Response {
    let Some(project) = state.db.get_project(project_id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "Unknown project id." }))).into_response();
    };
    let issues = state.db.get_project_issues(project_id);
    let doc = ignite_sarif::build_sarif(&issues);
    sarif_response(doc, &format!("ignite-{}-{}-{project_id}", project.org, project.repo))
}

/// Same document again, looked up by `(org, repo)` and resolved to that
/// repository's most recently created project — the one identifier a
/// headless caller (MCP tool, CLI) is most likely to have in hand without
/// having tracked a jobId/projectId from the run that produced it.
async fn sarif_by_repo_handler(State(state): State<Arc<AppState>>, Path((org, repo)): Path<(String, String)>) -> Response {
    let Some((project_id, _job_id)) = state.db.get_latest_project_for_org_repo(&org, &repo) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "No scan found for this org/repo." }))).into_response();
    };
    let issues = state.db.get_project_issues(project_id);
    let doc = ignite_sarif::build_sarif(&issues);
    sarif_response(doc, &format!("ignite-{org}-{repo}-{project_id}"))
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/pipeline/:job_id/sarif", get(sarif_handler))
        .route("/api/projects/:project_id/sarif", get(sarif_by_project_handler))
        .route("/api/repositories/:org/:repo/sarif", get(sarif_by_repo_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state;
    use parking_lot::Mutex;
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
            fix_pr_previews: Mutex::new(HashMap::new()),
            audit_http: reqwest::Client::new(),
        });
        (app_state, db_dir)
    }

    #[tokio::test]
    async fn sarif_by_project_sets_a_downloadable_attachment_filename() {
        let (state, _dir) = build_state();
        let project_id = state.db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let resp = sarif_by_project_handler(State(state), Path(project_id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let disposition = resp.headers().get(header::CONTENT_DISPOSITION).unwrap().to_str().unwrap();
        assert!(disposition.starts_with("attachment;"));
        assert!(disposition.contains("acme-widgets"));
        assert!(disposition.ends_with(".sarif\""));
    }

    #[tokio::test]
    async fn sarif_by_project_404s_for_an_unknown_project() {
        let (state, _dir) = build_state();
        let resp = sarif_by_project_handler(State(state), Path(999)).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn sarif_by_repo_resolves_the_latest_project_for_that_org_repo() {
        let (state, _dir) = build_state();
        state.db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let resp = sarif_by_repo_handler(State(state), Path(("acme".to_string(), "widgets".to_string()))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let disposition = resp.headers().get(header::CONTENT_DISPOSITION).unwrap().to_str().unwrap();
        assert!(disposition.contains("acme-widgets"));
    }

    #[tokio::test]
    async fn sarif_by_repo_404s_when_no_scan_exists_for_that_org_repo() {
        let (state, _dir) = build_state();
        let resp = sarif_by_repo_handler(State(state), Path(("acme".to_string(), "does-not-exist".to_string()))).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
