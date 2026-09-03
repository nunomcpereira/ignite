//! `GET /api/onboarded-repos` — one row per distinct (org, repo) ever
//! onboarded, backing the web UI's "Onboarded Repos" nav view: the latest
//! run's open-issue counts (license-compliance + total), plus every
//! acknowledgment and PR Ignite has ever recorded for that repo across all
//! its runs. Thin pass-through to `db-store`'s own aggregation query — see
//! `DbStore::list_onboarded_repo_summaries`.

use crate::state::AppState;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use std::sync::Arc;

async fn list_onboarded_repos(State(state): State<Arc<AppState>>) -> Response {
    Json(state.db.list_onboarded_repo_summaries()).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/onboarded-repos", get(list_onboarded_repos))
}
