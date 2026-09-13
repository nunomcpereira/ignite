//! GET /api/tools/status — faithful port of routes/tools-status.js.
//! GET /api/tools/status/stream — NDJSON progress variant of the same
//! probe set, for a UI that wants to show "N of 19 checked" while this
//! runs rather than a single opaque wait (ORT/CodeQL's JVM startup alone
//! routinely takes over a minute). Kept as a second endpoint rather than
//! changing `tools_status`'s response shape: the VS Code extension and
//! this crate's own self-test both call the plain JSON endpoint today
//! and neither wants NDJSON.

use crate::state::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_stream::StreamExt as _;

// Both endpoints spawn 19 concurrent subprocesses on every single call —
// unauthenticated and with no rate limiting, so a caller hitting either
// repeatedly can exhaust OS process limits / saturate CPU. Tooling
// presence/version on a given host essentially never changes minute to
// minute, so the result is cached with a short TTL instead.
static TOOLS_STATUS_CACHE: Lazy<Mutex<Option<(Instant, Value)>>> = Lazy::new(|| Mutex::new(None));
const TOOLS_STATUS_TTL: Duration = Duration::from_secs(10 * 60);

/// Single-flight guard: without it, N concurrent requests arriving right
/// after the cache expires all see a miss and each spawn all 19 probe
/// subprocesses independently (N=50 -> 950 concurrent processes,
/// including JVM-heavy ORT/CodeQL) — a self-inflicted fork-bomb-shaped
/// DoS from completely ordinary concurrent traffic, not anything
/// adversarial. Holding this for the whole "check cache, maybe run
/// probes, store cache" section serializes callers onto one real probe
/// run per cache expiry; everyone else just waits and then reads the
/// cache the first caller populated.
static TOOLS_STATUS_LOCK: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

fn cached_tools_status() -> Option<Value> {
    let cache = TOOLS_STATUS_CACHE.lock();
    cache.as_ref().filter(|(at, _)| at.elapsed() < TOOLS_STATUS_TTL).map(|(_, v)| v.clone())
}

fn store_tools_status_cache(value: Value) {
    *TOOLS_STATUS_CACHE.lock() = Some((Instant::now(), value));
}

fn bool_probe(ok: bool) -> Value {
    json!({ "ok": ok })
}

fn with_enabled(mut v: Value, enabled: bool) -> Value {
    v["enabled"] = json!(enabled);
    v
}

/// A tooling-probe struct should always serialize (plain data, no NaN
/// floats, no non-string map keys) — but a probe response is external
/// tool output flowing through these structs, and this endpoint is
/// unauthenticated, so a bad serialize must degrade to a reported failure
/// rather than `.unwrap()`-panicking the request/stream.
fn probe_to_value(v: &impl serde::Serialize) -> Value {
    serde_json::to_value(v).unwrap_or_else(|e| json!({ "ok": false, "error": format!("probe result failed to serialize: {e}") }))
}

/// Every probe run concurrently, each result annotated with its configured
/// enabled flag. jscpd/trivyImage read the live config (both default off,
/// see config.json); the rest are always-on or have no disable toggle in
/// the JS original either.
async fn tools_status(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth) -> Json<Value> {
    if let Some(cached) = cached_tools_status() {
        return Json(cached);
    }
    let _guard = TOOLS_STATUS_LOCK.lock().await;
    if let Some(cached) = cached_tools_status() {
        return Json(cached);
    }
    let r = &state.runner;
    let (ort, licensee, gitleaks, trivy, trivy_image, checkov, hadolint, syft, cosign, semgrep, bearer, jscpd, gocloc, spectral, guarddog, codeql, picklescan, oasdiff, zizmor) = tokio::join!(
        ignite_dependency_license_scan::ort_tooling(r),
        ignite_dependency_license_scan::licensee_tooling(r),
        ignite_secrets::gitleaks_tooling(r),
        ignite_iac_security::trivy_tooling(r),
        ignite_container_image_vulnerabilities::trivy_image_tooling(r),
        ignite_iac_security::checkov_tooling(r),
        ignite_iac_security::hadolint_tooling(r),
        ignite_sbom::syft_tooling(r),
        ignite_image_provenance::cosign_tooling(r),
        ignite_semantic_sast::semgrep_tooling(r),
        ignite_pii_dataflow::bearer_tooling(r),
        ignite_code_duplication::jscpd_tooling(r),
        ignite_loc_metrics::gocloc_tooling(r),
        ignite_api_schema::spectral_tooling(r),
        ignite_malicious_dependencies::guarddog_tooling(r),
        ignite_codeql_cross_file::codeql_tooling(r),
        ignite_model_artifact_security::picklescan_tooling(r),
        ignite_api_schema_drift::oasdiff_tooling(r),
        ignite_gha_security::zizmor_tooling(r),
    );

    let result = json!({
        "ort": with_enabled(bool_probe(ort), true),
        "licensee": with_enabled(bool_probe(licensee), true),
        "gitleaks": with_enabled(bool_probe(gitleaks), true),
        "trivy": with_enabled(bool_probe(trivy), true),
        "trivyImage": with_enabled(probe_to_value(&trivy_image), state.config.security.trivy_image.enabled),
        "checkov": with_enabled(bool_probe(checkov), true),
        "hadolint": with_enabled(bool_probe(hadolint), true),
        "syft": with_enabled(probe_to_value(&syft), true),
        "cosign": with_enabled(bool_probe(cosign), true),
        "semgrep": with_enabled(probe_to_value(&semgrep), true),
        "bearer": with_enabled(bool_probe(bearer), true),
        "jscpd": with_enabled(bool_probe(jscpd), state.config.metrics.jscpd.enabled),
        "gocloc": with_enabled(bool_probe(gocloc), true),
        "spectral": with_enabled(bool_probe(spectral), true),
        "guarddog": with_enabled(probe_to_value(&guarddog), true),
        "codeql": with_enabled(probe_to_value(&codeql), true),
        "picklescan": with_enabled(bool_probe(picklescan), true),
        "oasdiff": with_enabled(probe_to_value(&oasdiff), true),
        "zizmor": with_enabled(bool_probe(zizmor), state.config.security.zizmor.enabled),
    });
    store_tools_status_cache(result.clone());
    Json(result)
}

/// Total probe count both endpoints report against — kept as one constant
/// so the stream's `"total"` field and the plain endpoint's key count can
/// never silently drift apart if a probe is ever added/removed.
const TOOL_COUNT: usize = 19;

async fn tools_status_stream(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth) -> Response {
    let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    if let Some(cached) = cached_tools_status() {
        tokio::spawn(replay_cached_tools_status_stream(cached, out_tx));
    } else {
        // Same single-flight guard as the plain JSON endpoint — acquired
        // inside the spawned task (not here) so this handler itself
        // returns immediately with the streaming response, same as
        // before; only the actual probe run serializes.
        tokio::spawn(async move {
            let _guard = TOOLS_STATUS_LOCK.lock().await;
            if let Some(cached) = cached_tools_status() {
                replay_cached_tools_status_stream(cached, out_tx).await;
            } else {
                run_tools_status_stream(state, out_tx).await;
            }
        });
    }
    let stream = UnboundedReceiverStream::new(out_rx).map(Ok::<String, std::io::Error>);
    let body = Body::from_stream(stream);
    Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE, "application/x-ndjson").body(body).unwrap()
}

/// Replays a cached `tools_status` result as the same `progress`/`done`
/// NDJSON shape `run_tools_status_stream` produces from a live probe run,
/// so a fresh-cache hit is indistinguishable to the client from a real run
/// that happened to already be done.
async fn replay_cached_tools_status_stream(cached: Value, out_tx: tokio::sync::mpsc::UnboundedSender<String>) {
    let Some(map) = cached.as_object() else { return };
    for (done, key) in map.keys().enumerate() {
        let _ = out_tx.send(format!("{}\n", json!({ "type": "progress", "tool": key, "done": done + 1, "total": TOOL_COUNT })));
    }
    let _ = out_tx.send(format!("{}\n", json!({ "type": "done", "status": cached })));
}

/// Each probe is spawned into its own task (not `tokio::join!`, which only
/// resolves once every future in it has) so a completion can be reported
/// the moment it happens, not only once the single slowest probe finishes.
/// Every task sends `(key, value-with-enabled-already-applied)` into one
/// shared channel; this function just relays each arrival as a `progress`
/// NDJSON line and, once all `TOOL_COUNT` have arrived, emits one `done`
/// line carrying the exact same object shape `tools_status` above returns
/// (so the two endpoints stay trivially comparable / the frontend can
/// reuse one render function for the final result either way).
async fn run_tools_status_stream(state: Arc<AppState>, out_tx: tokio::sync::mpsc::UnboundedSender<String>) {
    let (probe_tx, mut probe_rx) = tokio::sync::mpsc::unbounded_channel::<(&'static str, Value)>();

    macro_rules! spawn_probe {
        ($key:literal, $future:expr) => {{
            let tx = probe_tx.clone();
            tokio::spawn(async move {
                let v = $future.await;
                let _ = tx.send(($key, v));
            });
        }};
    }

    {
        let s = state.clone();
        spawn_probe!("ort", async move { with_enabled(bool_probe(ignite_dependency_license_scan::ort_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        spawn_probe!("licensee", async move { with_enabled(bool_probe(ignite_dependency_license_scan::licensee_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        spawn_probe!("gitleaks", async move { with_enabled(bool_probe(ignite_secrets::gitleaks_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        spawn_probe!("trivy", async move { with_enabled(bool_probe(ignite_iac_security::trivy_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        let enabled = state.config.security.trivy_image.enabled;
        spawn_probe!("trivyImage", async move { with_enabled(probe_to_value(&ignite_container_image_vulnerabilities::trivy_image_tooling(&s.runner).await), enabled) });
    }
    {
        let s = state.clone();
        spawn_probe!("checkov", async move { with_enabled(bool_probe(ignite_iac_security::checkov_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        spawn_probe!("hadolint", async move { with_enabled(bool_probe(ignite_iac_security::hadolint_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        spawn_probe!("syft", async move { with_enabled(probe_to_value(&ignite_sbom::syft_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        spawn_probe!("cosign", async move { with_enabled(bool_probe(ignite_image_provenance::cosign_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        spawn_probe!("semgrep", async move { with_enabled(probe_to_value(&ignite_semantic_sast::semgrep_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        spawn_probe!("bearer", async move { with_enabled(bool_probe(ignite_pii_dataflow::bearer_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        let enabled = state.config.metrics.jscpd.enabled;
        spawn_probe!("jscpd", async move { with_enabled(bool_probe(ignite_code_duplication::jscpd_tooling(&s.runner).await), enabled) });
    }
    {
        let s = state.clone();
        spawn_probe!("gocloc", async move { with_enabled(bool_probe(ignite_loc_metrics::gocloc_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        spawn_probe!("spectral", async move { with_enabled(bool_probe(ignite_api_schema::spectral_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        spawn_probe!("guarddog", async move { with_enabled(probe_to_value(&ignite_malicious_dependencies::guarddog_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        spawn_probe!("codeql", async move { with_enabled(probe_to_value(&ignite_codeql_cross_file::codeql_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        spawn_probe!("picklescan", async move { with_enabled(bool_probe(ignite_model_artifact_security::picklescan_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        spawn_probe!("oasdiff", async move { with_enabled(probe_to_value(&ignite_api_schema_drift::oasdiff_tooling(&s.runner).await), true) });
    }
    {
        let s = state.clone();
        let enabled = state.config.security.zizmor.enabled;
        spawn_probe!("zizmor", async move { with_enabled(bool_probe(ignite_gha_security::zizmor_tooling(&s.runner).await), enabled) });
    }
    drop(probe_tx);

    let mut done = 0usize;
    let mut merged = serde_json::Map::new();
    while let Some((key, value)) = probe_rx.recv().await {
        done += 1;
        merged.insert(key.to_string(), value);
        let _ = out_tx.send(format!("{}\n", json!({ "type": "progress", "tool": key, "done": done, "total": TOOL_COUNT })));
    }
    let status = Value::Object(merged);
    store_tools_status_cache(status.clone());
    let _ = out_tx.send(format!("{}\n", json!({ "type": "done", "status": status })));
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/tools/status", get(tools_status)).route("/api/tools/status/stream", get(tools_status_stream))
}
