//! Ignite's HTTP server — Rust port of `server.js`'s route layer. Starting
//! point: `GET /api/tools/status`, the first real HTTP endpoint, wiring
//! together every tooling probe ported across the check crates. Session
//! auth, the pipeline endpoints, and everything else in `routes/*.js`
//! aren't ported yet.

use axum::{routing::get, Json, Router};
use ignite_tool_runner::ToolRunner;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

struct AppState {
    runner: ToolRunner,
}

fn bin(name: &'static str) -> (&'static str, String) {
    (name, name.to_string())
}

fn default_runner() -> ToolRunner {
    let binaries: HashMap<&'static str, String> = [
        bin("trivy"),
        bin("checkov"),
        bin("hadolint"),
        bin("syft"),
        bin("cosign"),
        bin("semgrep"),
        bin("bearer"),
        bin("jscpd"),
        bin("gocloc"),
        bin("spectral"),
        bin("guarddog"),
        bin("codeql"),
        bin("picklescan"),
        bin("oasdiff"),
        bin("gitleaks"),
        bin("rm"),
    ]
    .into_iter()
    .collect();
    ToolRunner::new(binaries)
}

fn bool_probe(ok: bool) -> Value {
    json!({ "ok": ok })
}

/// Faithful port of `routes/tools-status.js`'s handler — every probe run
/// concurrently, each result annotated with its "on by default" enabled
/// flag (see project CLAUDE.md: everything here defaults to `true` except
/// jscpd and trivyImage). ORT/licensee/gitleaks are always-on (no
/// disable toggle in the JS original either).
async fn tools_status(state: Arc<AppState>) -> Json<Value> {
    let r = &state.runner;
    let (ort, licensee, gitleaks, trivy, trivy_image, checkov, hadolint, syft, cosign, semgrep, bearer, jscpd, gocloc, spectral, guarddog, codeql, picklescan, oasdiff) = tokio::join!(
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
    );

    fn with_enabled(mut v: Value, enabled: bool) -> Value {
        v["enabled"] = json!(enabled);
        v
    }

    Json(json!({
        "ort": with_enabled(bool_probe(ort), true),
        "licensee": with_enabled(bool_probe(licensee), true),
        "gitleaks": with_enabled(bool_probe(gitleaks), true),
        "trivy": with_enabled(bool_probe(trivy), true),
        "trivyImage": with_enabled(serde_json::to_value(&trivy_image).unwrap(), false),
        "checkov": with_enabled(bool_probe(checkov), true),
        "hadolint": with_enabled(bool_probe(hadolint), true),
        "syft": with_enabled(serde_json::to_value(&syft).unwrap(), true),
        "cosign": with_enabled(bool_probe(cosign), true),
        "semgrep": with_enabled(serde_json::to_value(&semgrep).unwrap(), true),
        "bearer": with_enabled(bool_probe(bearer), true),
        "jscpd": with_enabled(bool_probe(jscpd), false),
        "gocloc": with_enabled(bool_probe(gocloc), true),
        "spectral": with_enabled(bool_probe(spectral), true),
        "guarddog": with_enabled(serde_json::to_value(&guarddog).unwrap(), true),
        "codeql": with_enabled(serde_json::to_value(&codeql).unwrap(), true),
        "picklescan": with_enabled(bool_probe(picklescan), true),
        "oasdiff": with_enabled(serde_json::to_value(&oasdiff).unwrap(), true),
    }))
}

fn build_router(state: Arc<AppState>) -> Router {
    Router::new().route("/api/tools/status", get(move || tools_status(state.clone())))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let state = Arc::new(AppState { runner: default_runner() });
    let app = build_router(state);

    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(51337);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await.expect("failed to bind port");
    tracing::info!("Ignite (Rust) listening on http://0.0.0.0:{port}");
    axum::serve(listener, app).await.expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tools_status_returns_every_expected_key() {
        let state = Arc::new(AppState { runner: default_runner() });
        let app = build_router(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();
        let res = client.get(format!("http://{addr}/api/tools/status")).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        for key in ["ort", "licensee", "gitleaks", "trivy", "trivyImage", "checkov", "hadolint", "syft", "cosign", "semgrep", "bearer", "jscpd", "gocloc", "spectral", "guarddog", "codeql", "picklescan", "oasdiff"] {
            assert!(body.get(key).is_some(), "missing key: {key}");
            assert!(body[key].get("ok").is_some(), "missing ok for: {key}");
            assert!(body[key].get("enabled").is_some(), "missing enabled for: {key}");
        }
    }
}
