//! GET /api/config — faithful port of routes/config.js. Safe subset of
//! config for the frontend.

use crate::routes::phase_meta::resolve_phase_meta;
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

const IGNITE_VERSION: &str = "0.1.0";

async fn config(State(state): State<Arc<AppState>>) -> Json<Value> {
    let http = reqwest::Client::new();
    let ai_available = ignite_llm_client::llm_available(&http, &state.llm_config).await;

    let meta = resolve_phase_meta(&state.config);
    // Phase 4 still runs everything else with no LLM configured or
    // reachable — only its LLM deep-scan sub-check is skipped — so its
    // displayed name shouldn't claim an "AI" check ran when it didn't.
    let default_phase4_title = crate::routes::phase_meta::DEFAULT_PHASE_META
        .iter()
        .find(|(id, ..)| *id == 4)
        .map(|(_, t, ..)| *t)
        .unwrap_or("");
    let phases: Vec<Value> = meta
        .iter()
        .map(|p| {
            let display_title = if p.id == 4 && !ai_available && p.title == default_phase4_title {
                "Security & Compliance Scan"
            } else {
                p.title.as_str()
            };
            json!({ "id": p.id, "title": display_title, "desc": p.desc, "enabled": p.enabled })
        })
        .collect();

    let orgs = state
        .config
        .github
        .orgs
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect::<Vec<_>>();

    Json(json!({ "orgs": orgs, "phases": phases, "version": IGNITE_VERSION }))
}

pub fn router() -> axum::Router<Arc<AppState>> {
    axum::Router::new().route("/api/config", axum::routing::get(config))
}

#[cfg(test)]
mod tests {
    #[test]
    fn phase_4_default_title_matches_config_json_shape() {
        let default_phase4_title = crate::routes::phase_meta::DEFAULT_PHASE_META
            .iter()
            .find(|(id, ..)| *id == 4)
            .map(|(_, t, ..)| *t)
            .unwrap_or("");
        assert_eq!(default_phase4_title, "Security & AI Compliance Scan");
    }
}
