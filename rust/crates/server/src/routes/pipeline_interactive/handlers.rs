//! HTTP handlers for `POST /api/pipeline` and `POST
//! /api/pipeline/:jobId/review-decision`, plus this route group's
//! `router()` — split out of `pipeline_interactive.rs`.

use super::run::run_interactive_pipeline;
use super::*;

async fn pipeline(State(state): State<Arc<AppState>>, headers: axum::http::HeaderMap, multipart: Multipart) -> Response {
    let upload = match parse_multipart(multipart).await {
        Ok(u) => u,
        Err((status, body)) => return (status, axum::Json(body)).into_response(),
    };

    let session_gh_token = crate::auth::resolve_effective_github_token(&headers, &state.db);
    let job_id = uuid::Uuid::new_v4().to_string();
    tracing::info!(job_id = %job_id, org = %upload.org, repo = %upload.repo, dry_run = upload.dry_run, "starting interactive pipeline run");
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let log = Arc::new(EventLog { state: state.clone(), meta: super::super::phase_meta::resolve_phase_meta(&state.config), tx, record: Mutex::new(HashMap::new()), project_id: Mutex::new(None), job_id: job_id.clone() });

    let job_id_task = job_id.clone();
    tokio::spawn(async move {
        run_interactive_pipeline(state, upload, log, job_id_task, session_gh_token).await;
    });

    let stream = UnboundedReceiverStream::new(rx).map(Ok::<String, std::io::Error>);
    let body = Body::from_stream(stream);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header(header::CACHE_CONTROL, "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(body)
        .unwrap()
}

/// `POST /api/pipeline/:jobId/review-decision` — resolves a run paused at
/// the review gate. Thin enough to live here rather than waiting on the
/// full routes/review_gate.js port (studio.js's file-browsing endpoints,
/// which share that file, are the parts still not ported).
async fn review_decision(axum::extract::Path(job_id): axum::extract::Path<String>, State(state): State<Arc<AppState>>, crate::auth::OptionalUser(user): crate::auth::OptionalUser, axum::Json(body): axum::Json<Value>) -> Response {
    let proceed = body.get("proceed").and_then(|v| v.as_bool()).unwrap_or(false);
    let overrides: Vec<SubmittedOverride> = body
        .get("overrides")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(|o| SubmittedOverride { 
            issue_id: o.get("issueId").and_then(|v| v.as_str()).unwrap_or("").to_string(), 
            justification: o.get("justification").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            code: o.get("code").and_then(|v| v.as_str()).map(|s| s.to_string()),
        }).collect())
        .unwrap_or_default();
    // The actor comes from the authenticated session when there is one,
    // else from a client-supplied {email, name} in the body — same
    // resolution `routes/effectivate.rs` uses. Only actually overriding a
    // blocking finding needs a real identity for the audit trail; a bare
    // decline (`proceed: false`, no overrides) or a continue with nothing
    // left to justify has nothing to attribute, so those go through
    // unauthenticated. This matters in practice: this is also the request
    // Esc/✕ on the review modal sends (as a decline), and a session that
    // expired during a long-paused review must still be able to close that
    // modal — a hard 401 here used to leave it with no way out.
    let actor = if let Some(user) = user {
        Some(Actor { email: user.email.clone(), name: user.name.clone().unwrap_or(user.email) })
    } else {
        body.get("actor").and_then(|a| {
            let email = a.get("email").and_then(|v| v.as_str())?.trim();
            if email.is_empty() {
                return None;
            }
            let name = a.get("name").and_then(|v| v.as_str()).filter(|n| !n.trim().is_empty()).unwrap_or(email);
            Some(Actor { email: email.to_string(), name: name.to_string() })
        })
    };
    if !overrides.is_empty() && actor.is_none() {
        return (StatusCode::UNAUTHORIZED, axum::Json(json!({ "error": "Log in, or provide actor {email,name}, to submit overrides." }))).into_response();
    }
    let actor = actor.unwrap_or_default();
    let resolved = state.review_gate.resolve(&job_id, ReviewDecisionInput { proceed, overrides, actor });
    if !resolved {
        return (StatusCode::NOT_FOUND, axum::Json(json!({ "error": "No run is currently paused for review under this job id." }))).into_response();
    }
    (StatusCode::OK, axum::Json(json!({ "ok": true }))).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // Axum's `Multipart` extractor otherwise enforces its own default
        // 2MB whole-body limit (`DefaultBodyLimit`) — disabled here because
        // `parse_multipart`/`read_field_bytes_limited` now enforce the real
        // per-file/per-field-count limits matching server.js's multer
        // config exactly (MAX_FILE_BYTES/MAX_FILES above), which a single
        // whole-body cap can't express (a folder upload with many small
        // files can legitimately total well over 1GB in Node as long as no
        // single file exceeds it). Scoped to just this route, not the
        // whole router, so JSON endpoints elsewhere keep axum's smaller
        // stock default, closer to server.js's separate
        // `express.json({ limit: '1mb' })` cap on those.
        .route("/api/pipeline", post(pipeline).layer(axum::extract::DefaultBodyLimit::disable()))
        .route("/api/pipeline/:jobId/review-decision", post(review_decision))
}
