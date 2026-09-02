//! GET /api/tools/status — faithful port of routes/tools-status.js.

use crate::state::AppState;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::sync::Arc;

fn bool_probe(ok: bool) -> Value {
    json!({ "ok": ok })
}

fn with_enabled(mut v: Value, enabled: bool) -> Value {
    v["enabled"] = json!(enabled);
    v
}

/// Every probe run concurrently, each result annotated with its configured
/// enabled flag. jscpd/trivyImage read the live config (both default off,
/// see config.json); the rest are always-on or have no disable toggle in
/// the JS original either.
async fn tools_status(State(state): State<Arc<AppState>>) -> Json<Value> {
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

    Json(json!({
        "ort": with_enabled(bool_probe(ort), true),
        "licensee": with_enabled(bool_probe(licensee), true),
        "gitleaks": with_enabled(bool_probe(gitleaks), true),
        "trivy": with_enabled(bool_probe(trivy), true),
        "trivyImage": with_enabled(serde_json::to_value(&trivy_image).unwrap(), state.config.security.trivy_image.enabled),
        "checkov": with_enabled(bool_probe(checkov), true),
        "hadolint": with_enabled(bool_probe(hadolint), true),
        "syft": with_enabled(serde_json::to_value(&syft).unwrap(), true),
        "cosign": with_enabled(bool_probe(cosign), true),
        "semgrep": with_enabled(serde_json::to_value(&semgrep).unwrap(), true),
        "bearer": with_enabled(bool_probe(bearer), true),
        "jscpd": with_enabled(bool_probe(jscpd), state.config.metrics.jscpd.enabled),
        "gocloc": with_enabled(bool_probe(gocloc), true),
        "spectral": with_enabled(bool_probe(spectral), true),
        "guarddog": with_enabled(serde_json::to_value(&guarddog).unwrap(), true),
        "codeql": with_enabled(serde_json::to_value(&codeql).unwrap(), true),
        "picklescan": with_enabled(bool_probe(picklescan), true),
        "oasdiff": with_enabled(serde_json::to_value(&oasdiff).unwrap(), true),
        "zizmor": with_enabled(bool_probe(zizmor), state.config.security.zizmor.enabled),
    }))
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/tools/status", get(tools_status))
}
