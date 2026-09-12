//! `/api/campaigns` — security campaigns (Milestone 3.2): a saved
//! category/min-score filter with a burndown-progress snapshot, backing
//! the "Security Campaigns" card in the UI. See
//! `ignite_db_store::DbStore`'s `campaigns.rs` for the actual burndown
//! math (`initial_open_count` at creation vs. the live matching count).

use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::sync::Arc;

async fn list_campaigns(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth) -> Response {
    Json(state.db.list_campaigns()).into_response()
}

async fn create_campaign(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Json(body): Json<Value>) -> Response {
    let Some(title) = body.get("title").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Request body must include a non-empty title." }))).into_response();
    };
    let description = body.get("description").and_then(|v| v.as_str());
    let category = body.get("category").and_then(|v| v.as_str());
    let min_score = body.get("minScore").and_then(|v| v.as_i64());
    let target_date = body.get("targetDate").and_then(|v| v.as_str());
    let created_by = body.get("createdBy").and_then(|v| v.as_str());
    let id = state.db.create_campaign(title, description, category, min_score, target_date, created_by);
    match state.db.get_campaign(id) {
        Some(campaign) => (StatusCode::CREATED, Json(campaign)).into_response(),
        None => Json(json!({ "ok": true, "id": id })).into_response(),
    }
}

async fn close_campaign(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Path(id): Path<i64>) -> Response {
    let closed = state.db.close_campaign(id);
    Json(json!({ "ok": closed, "id": id })).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/campaigns", get(list_campaigns).post(create_campaign))
        .route("/api/campaigns/:id/close", post(close_campaign))
}
