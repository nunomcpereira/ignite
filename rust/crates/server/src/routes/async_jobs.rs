//! Start-then-poll runs. A real `onboard`/`validate-all` takes minutes, which
//! is longer than many HTTP clients, proxies and MCP transports will hold one
//! request open. With `"async": true` in the body the run is started in the
//! background and the call returns `202` with a job id at once; the finished
//! response — exactly what the synchronous call would have returned, plus its
//! HTTP status — is read from `GET /api/pipeline/:jobId/async-result`.
//!
//! Opt-in: without `async` nothing changes. Combined with `idempotencyKey`, a
//! caller that loses the job id can re-send the same request and be pointed at
//! the run it already started.

use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use futures::FutureExt;
use serde_json::{json, Value};
use std::future::Future;
use std::sync::Arc;

/// How long a caller is told to wait between polls.
const POLL_AFTER_MS: u64 = 2000;
/// Finished job results are kept this long (see `fail_unfinished_async_jobs`).
pub const KEEP_FINISHED_JOBS_DAYS: i64 = 7;

/// Key the start handler injects so the pipeline uses the async job's id as its
/// own job id (which lets `GET /api/pipeline/:jobId/status` follow progress).
/// Never trusted from a client: every handler strips it before use.
pub const ASYNC_JOB_ID_KEY: &str = "_asyncJobId";

pub fn wants_async(body: &Value) -> bool {
    body.get("async").and_then(|v| v.as_bool()).unwrap_or(false)
}

/// The job id an async start injected, if any (a well-formed UUID only).
pub fn injected_job_id(body: &Value) -> Option<String> {
    body.get(ASYNC_JOB_ID_KEY).and_then(|v| v.as_str()).filter(|s| uuid::Uuid::parse_str(s).is_ok()).map(str::to_string)
}

/// Drops any client-supplied `_asyncJobId` — a client must not choose the id a
/// pipeline run (and its DB rows) is filed under.
pub fn strip_client_job_id(body: &mut Value) {
    if let Some(obj) = body.as_object_mut() {
        obj.remove(ASYNC_JOB_ID_KEY);
    }
}

/// Registers the job, runs `run` in the background and answers `202`. `run`
/// yields the `(http_status, body)` the synchronous call would have produced.
/// Auth and scope checks belong *before* this call so a rejected caller gets
/// its 401/403 immediately instead of through a poll.
pub fn start<F, Fut>(state: Arc<AppState>, kind: &'static str, owner_user_id: Option<i64>, headers: HeaderMap, mut body: Value, run: F) -> Response
where
    F: FnOnce(Arc<AppState>, HeaderMap, Value) -> Fut + Send + 'static,
    Fut: Future<Output = (u16, Value)> + Send + 'static,
{
    let job_id = uuid::Uuid::new_v4().to_string();
    if let Some(obj) = body.as_object_mut() {
        obj.insert(ASYNC_JOB_ID_KEY.to_string(), json!(job_id));
    }
    state.db.create_async_job(&job_id, kind, owner_user_id);

    let job = job_id.clone();
    let task_state = state.clone();
    tokio::spawn(async move {
        let (status, value) = match std::panic::AssertUnwindSafe(run(task_state.clone(), headers, body)).catch_unwind().await {
            Ok(outcome) => outcome,
            Err(_) => (500, json!({ "ok": false, "error": "internal error while running the job", "code": "internal" })),
        };
        task_state.db.finish_async_job(&job, status, &serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string()));
    });

    (
        StatusCode::ACCEPTED,
        Json(json!({
            "ok": true,
            "async": true,
            "state": "running",
            "kind": kind,
            "jobId": job_id,
            "pollUrl": format!("/api/pipeline/{job_id}/async-result"),
            "statusUrl": format!("/api/pipeline/{job_id}/status"),
            "pollAfterMs": POLL_AFTER_MS,
        })),
    )
        .into_response()
}

/// `GET /api/pipeline/:jobId/async-result` — `202` while running; `200` once
/// finished, carrying the original response under `result` and the status it
/// would have had under `httpStatus`. A job started by an authenticated user is
/// visible only to that user (`404` for anyone else, so existence isn't
/// confirmed); an unauthenticated job is readable by whoever holds its
/// unguessable id.
async fn async_result(Path(job_id): Path<String>, State(state): State<Arc<AppState>>, crate::auth::OptionalUser(user): crate::auth::OptionalUser) -> Response {
    let not_found = || (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "error": "Unknown job id.", "code": "unknown_job" }))).into_response();
    let Some(job) = state.db.get_async_job(&job_id) else { return not_found() };
    if let Some(owner) = job.owner_user_id {
        if user.as_ref().map(|u| u.id) != Some(owner) {
            return not_found();
        }
    }
    if job.state == "running" {
        return (StatusCode::ACCEPTED, Json(json!({ "ok": true, "state": "running", "kind": job.kind, "jobId": job.job_id, "pollAfterMs": POLL_AFTER_MS }))).into_response();
    }
    let result: Value = job.result_json.as_deref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    (StatusCode::OK, Json(json!({ "ok": true, "state": job.state, "kind": job.kind, "jobId": job.job_id, "httpStatus": job.http_status, "result": result }))).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/pipeline/:job_id/async-result", get(async_result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_cannot_choose_the_job_id() {
        let mut body = json!({ "async": true, ASYNC_JOB_ID_KEY: "11111111-1111-4111-8111-111111111111" });
        assert!(wants_async(&body));
        assert!(injected_job_id(&body).is_some());
        strip_client_job_id(&mut body);
        assert!(injected_job_id(&body).is_none());
        assert!(wants_async(&body), "stripping only removes the id");
    }

    #[test]
    fn only_a_well_formed_uuid_is_accepted_as_an_injected_id() {
        assert_eq!(injected_job_id(&json!({ ASYNC_JOB_ID_KEY: "not-a-uuid" })), None);
        assert_eq!(injected_job_id(&json!({})), None);
        assert!(!wants_async(&json!({ "async": "yes" })));
        assert!(!wants_async(&json!({})));
    }
}
