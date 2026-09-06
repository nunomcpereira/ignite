//! Shared phase metadata — faithful port of server.js's DEFAULT_PHASE_META/
//! PHASE_META/PHASE_TITLES/PHASE_ENABLED. `CONFIG.phases` (config.json)
//! per-id title/desc/enabled overrides are applied in `resolve_phase_meta`,
//! matching server.js:1839-1847 exactly, including the `PHASE_ALWAYS_ENABLED`
//! set (ids 1/3/6 can never be disabled via config).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseMeta {
    pub id: i64,
    pub title: String,
    pub desc: String,
    pub enabled: bool,
}

pub const DEFAULT_PHASE_META: &[(i64, &str, &str, bool)] = &[
    (1, "Input & Metadata Configuration", "Validate archive and target repository metadata", true),
    (2, "GxP Validation Documents", "Mandatory for GxP processes · documents archived to the database", false),
    (3, "Extraction, Structure Audit & Unit Tests", "Unpack to staging · deny raw .env* files · auto-detect Node/Go/Rust/Python/Java and run its native test suite in an isolated Docker container", true),
    (4, "Security & AI Compliance Scan", "Credential leak regex · LangChain/LangGraph governance · LLM deep-scan", true),
    (5, "Org Governance CI — GitHub Actions", "Runs devops-governance org workflows locally in Docker via act", true),
    (6, "Provisioning & Shipping", "git init · gh repo create --private · push to main", true),
];

/// Phases everything downstream structurally depends on — same
/// `PHASE_ALWAYS_ENABLED` set as server.js: an `enabled: false` override on
/// these ids is ignored rather than silently breaking the run.
const PHASE_ALWAYS_ENABLED: &[i64] = &[1, 3, 6];

/// Applies `config.phases` (id -> {title?, desc?, enabled?}) overrides onto
/// `DEFAULT_PHASE_META`, in id order — server.js's `PHASE_META`.
pub fn resolve_phase_meta(config: &ignite_config::Config) -> Vec<PhaseMeta> {
    DEFAULT_PHASE_META
        .iter()
        .map(|(id, title, desc, enabled)| {
            let override_val = config.phases.iter().find(|p| {
                p.get("id").and_then(|v| v.as_i64()) == Some(*id)
            });
            let title = override_val
                .and_then(|o| o.get("title"))
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| (*title).to_string());
            let desc = override_val
                .and_then(|o| o.get("desc"))
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| (*desc).to_string());
            let enabled = if PHASE_ALWAYS_ENABLED.contains(id) {
                true
            } else {
                override_val
                    .and_then(|o| o.get("enabled"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(*enabled)
            };
            PhaseMeta { id: *id, title, desc, enabled }
        })
        .collect()
}

pub fn phase_title(meta: &[PhaseMeta], phase: i64) -> String {
    meta.iter().find(|p| p.id == phase).map(|p| p.title.clone()).unwrap_or_else(|| "Unknown".to_string())
}

pub fn phase_enabled(meta: &[PhaseMeta], phase: i64) -> bool {
    meta.iter().find(|p| p.id == phase).map(|p| p.enabled).unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_node_hardcoded_table_when_config_has_no_phases() {
        let cfg = ignite_config::Config::default();
        let meta = resolve_phase_meta(&cfg);
        assert_eq!(meta.len(), 6);
        assert_eq!(phase_title(&meta, 4), "Security & AI Compliance Scan");
        assert!(phase_enabled(&meta, 4));
        assert_eq!(phase_title(&meta, 99), "Unknown");
    }

    #[test]
    fn config_can_disable_phase_4_and_override_title() {
        let cfg = ignite_config::Config { phases: vec![serde_json::json!({ "id": 4, "enabled": false, "title": "Custom Scan" })], ..Default::default() };
        let meta = resolve_phase_meta(&cfg);
        assert!(!phase_enabled(&meta, 4));
        assert_eq!(phase_title(&meta, 4), "Custom Scan");
    }

    #[test]
    fn phase_always_enabled_ids_ignore_disable_override() {
        let cfg = ignite_config::Config {
            phases: vec![
                serde_json::json!({ "id": 1, "enabled": false }),
                serde_json::json!({ "id": 3, "enabled": false }),
                serde_json::json!({ "id": 6, "enabled": false }),
            ],
            ..Default::default()
        };
        let meta = resolve_phase_meta(&cfg);
        assert!(phase_enabled(&meta, 1));
        assert!(phase_enabled(&meta, 3));
        assert!(phase_enabled(&meta, 6));
    }

    #[test]
    fn phase_2_can_be_toggled_since_its_not_in_always_enabled_set() {
        let cfg = ignite_config::Config { phases: vec![serde_json::json!({ "id": 2, "enabled": true })], ..Default::default() };
        let meta = resolve_phase_meta(&cfg);
        assert!(phase_enabled(&meta, 2));
    }
}
