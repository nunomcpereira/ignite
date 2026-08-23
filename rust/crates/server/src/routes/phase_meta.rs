//! Shared phase metadata — faithful port of server.js's DEFAULT_PHASE_META/
//! PHASE_TITLES/PHASE_ENABLED. `CONFIG.phases` (config.json) per-id title/
//! desc/enabled overrides aren't wired yet, so this is always the
//! hardcoded default table.

pub const PHASE_META: &[(i64, &str, &str, bool)] = &[
    (1, "Input & Metadata Configuration", "Validate archive and target repository metadata", true),
    (2, "GxP Validation Documents", "Mandatory for GxP processes · documents archived to the database", false),
    (3, "Extraction, Structure Audit & Unit Tests", "Unpack to staging · deny raw .env* files · auto-detect Node/Go/Rust/Python/Java and run its native test suite in an isolated Docker container", true),
    (4, "Security & AI Compliance Scan", "Credential leak regex · LangChain/LangGraph governance · LLM deep-scan", true),
    (5, "Org Governance CI — GitHub Actions", "Runs devops-governance org workflows locally in Docker via act", true),
    (6, "Provisioning & Shipping", "git init · gh repo create --private · push to main", true),
];

pub fn phase_title(phase: i64) -> &'static str {
    PHASE_META.iter().find(|(id, ..)| *id == phase).map(|(_, t, ..)| *t).unwrap_or("Unknown")
}

pub fn phase_enabled(phase: i64) -> bool {
    PHASE_META.iter().find(|(id, ..)| *id == phase).map(|(_, _, _, e)| *e).unwrap_or(true)
}
