//! GET /api/config — faithful port of routes/config.js. Safe subset of
//! config for the frontend. `CONFIG.github.orgs` isn't wired to a real
//! config source yet (no config.json loading in this server), so `orgs`
//! is always empty for now.

use crate::routes::phase_meta::PHASE_META;
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

const IGNITE_VERSION: &str = "0.1.0";

async fn config(State(state): State<Arc<AppState>>) -> Json<Value> {
    let http = reqwest::Client::new();
    let ai_available = ignite_llm_client::llm_available(&http, &state.llm_config).await;

    // Phase 4 still runs everything else with no LLM configured or
    // reachable — only its LLM deep-scan sub-check is skipped — so its
    // displayed name shouldn't claim an "AI" check ran when it didn't.
    let default_phase4_title = PHASE_META.iter().find(|(id, ..)| *id == 4).map(|(_, t, ..)| *t).unwrap_or("");
    let phases: Vec<Value> = PHASE_META
        .iter()
        .map(|(id, title, desc, enabled)| {
            let display_title = if *id == 4 && !ai_available && *title == default_phase4_title { "Security & Compliance Scan" } else { title };
            json!({ "id": id, "title": display_title, "desc": desc, "enabled": enabled })
        })
        .collect();

    Json(json!({ "orgs": Vec::<String>::new(), "phases": phases, "version": IGNITE_VERSION }))
}

pub fn router() -> axum::Router<Arc<AppState>> {
    axum::Router::new().route("/api/config", axum::routing::get(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_4_default_title_matches_config_json_shape() {
        let default_phase4_title = PHASE_META.iter().find(|(id, ..)| *id == 4).map(|(_, t, ..)| *t).unwrap_or("");
        assert_eq!(default_phase4_title, "Security & AI Compliance Scan");
    }
}
