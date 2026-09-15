//! HTTP handlers for `POST /api/pipeline` and `POST
//! /api/pipeline/:jobId/review-decision`, plus this route group's
//! `router()` — split out of `pipeline_interactive.rs`.

use super::run::run_interactive_pipeline;
use super::*;

async fn pipeline(State(state): State<Arc<AppState>>, crate::auth::OptionalUser(user): crate::auth::OptionalUser, headers: axum::http::HeaderMap, multipart: Multipart) -> Response {
    let upload = match parse_multipart(multipart).await {
        Ok(u) => u,
        Err((status, body)) => return (status, axum::Json(body)).into_response(),
    };

    // A real session is required unless `security.allow_unauthenticated_interactive_dry_run`
    // is explicitly on *and* this is a simulation — a real provisioning+
    // push is independently blocked in `run_interactive_pipeline`'s own
    // Phase 1 (no session-backed GitHub token, dry_run false -> error),
    // but rejecting it here too means an unauthenticated caller gets a
    // clear 401 up front instead of watching Phase 1 fail after the
    // upload already streamed.
    let unauthenticated_dry_run_allowed = state.config.security.allow_unauthenticated_interactive_dry_run && upload.dry_run;
    if user.is_none() && !unauthenticated_dry_run_allowed {
        return (StatusCode::UNAUTHORIZED, axum::Json(json!({ "error": "Authentication required." }))).into_response();
    }

    let session_gh_token = crate::auth::resolve_effective_github_token(&headers, &state.db);
    let job_id = uuid::Uuid::new_v4().to_string();
    tracing::info!(job_id = %job_id, org = %upload.org, repo = %upload.repo, dry_run = upload.dry_run, "starting interactive pipeline run");
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let log = Arc::new(EventLog { state: state.clone(), meta: super::super::phase_meta::resolve_phase_meta(&state.config), tx, record: Mutex::new(HashMap::new()), project_id: Mutex::new(None), job_id: job_id.clone() });

    let job_id_task = job_id.clone();
    // Never a client-supplied identity (unlike `validate-all`'s body-actor
    // fallback) — an unauthenticated *simulation* has no session to
    // attribute it to, so it gets one clearly-labeled synthetic owner
    // rather than trusting anything the request itself claims to be.
    let owner_email = user.map(|u| u.email).unwrap_or_else(|| "unauthenticated-simulation@ignite.internal".to_string());
    tokio::spawn(async move {
        run_interactive_pipeline(state, upload, log, job_id_task, session_gh_token, owner_email).await;
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
async fn review_decision(axum::extract::Path(job_id): axum::extract::Path<String>, State(state): State<Arc<AppState>>, crate::auth::RequireAuth(user): crate::auth::RequireAuth, axum::Json(body): axum::Json<Value>) -> Response {
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
    // Every decision now requires a real authenticated session — an
    // unauthenticated `{"proceed": false}` or `{"proceed": true}` used to
    // go through unchecked (only submitting overrides required auth),
    // which let anyone who could guess/observe a job id abort or
    // force-proceed a run they had no relationship to at all. Identity
    // for the audit trail always comes from the session, never a
    // client-supplied {email, name}, which anyone could spoof.
    let actor = Actor { email: user.email.clone(), name: user.name.clone().unwrap_or_else(|| user.email.clone()) };
    // `ReviewGate::resolve` additionally verifies `user.email` matches
    // whoever started this run (`ReviewGate::wait`'s `owner_email`) — a
    // second layer beyond "must be logged in", since without it any
    // authenticated user could still decide any other user's paused run.
    match state.review_gate.resolve(&job_id, &user.email, ReviewDecisionInput { proceed, overrides, actor }) {
        crate::review_gate::ResolveOutcome::Resolved => (StatusCode::OK, axum::Json(json!({ "ok": true }))).into_response(),
        // US-04: the in-memory oneshot this run's paused task was
        // actually awaiting is gone after every process restart — true
        // resume-from-checkpoint execution isn't implemented (a much
        // larger architecture change than this pass attempts; see
        // CLAUDE.md's US-04 writeup). What *is* durable across a restart
        // is `pending_reviews` (US-04's persisted counterpart to
        // `ReviewGate::wait`): distinguishing "there never was a paused
        // run under this job id" from "there was one, but the server
        // restarted and it can't be resumed" is the honest, recoverable
        // failure this acceptance criterion actually asks for, instead of
        // a generic 404 that reads the same as a typo'd job id.
        crate::review_gate::ResolveOutcome::NotFound => match lost_pending_review(&state, &job_id, &user.email) {
            Some(true) => (
                StatusCode::GONE,
                axum::Json(json!({
                    "ok": false,
                    "error": "This run was awaiting review, but the server restarted and resuming an in-progress run isn't supported yet — the prior findings are still on record. Start a new scan to continue.",
                    "recoverable": true,
                })),
            )
                .into_response(),
            Some(false) => (StatusCode::FORBIDDEN, axum::Json(json!({ "error": "This run was started by a different user." }))).into_response(),
            None => (StatusCode::NOT_FOUND, axum::Json(json!({ "error": "No run is currently paused for review under this job id." }))).into_response(),
        },
        crate::review_gate::ResolveOutcome::Forbidden => (StatusCode::FORBIDDEN, axum::Json(json!({ "error": "This run was started by a different user." }))).into_response(),
    }
}

/// `Some(true)` — an unresolved `pending_reviews` row exists for this job
/// id and `caller_email` owns it (a restart-orphaned review). `Some(false)`
/// — the row exists but belongs to a different owner. `None` — no such
/// row at all (a genuinely unknown/already-resolved job id).
fn lost_pending_review(state: &AppState, job_id: &str, caller_email: &str) -> Option<bool> {
    let project_id = state.db.get_project_id_by_job_id(job_id)?;
    let review = state.db.get_pending_review_by_project(project_id).filter(|r| r.resolved_at.is_none())?;
    Some(review.owner_email == caller_email)
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
