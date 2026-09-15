//! US-05: the versioned evidence manifest — a reproducible record of the
//! source, tools, and policy behind one scan run's decision, assembled
//! *by the caller* from data every other crate already computes
//! (`ignite-provenance`'s content-addressed source digest, `ignite-policy`'s
//! per-check `CheckCoverage`, `ignite-config`'s `Config`). No I/O beyond
//! hashing a caller-supplied config value — this crate never walks a
//! filesystem or touches the database itself.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Deterministic digest of the *effective* configuration a run used —
/// `serde_json::Value` serializes object keys in sorted order (this
/// workspace never enables `preserve_order`), so two runs under
/// byte-identical settings hash identically regardless of how config.json
/// happened to order its keys on disk. The serialized form is hashed and
/// discarded, never persisted or returned — `Config` carries real secrets
/// (SMTP password, webhook secrets, configured API tokens) that must
/// never leave this function as plaintext.
pub fn config_digest(config: &ignite_config::Config) -> String {
    let canonical = serde_json::to_string(config).unwrap_or_default();
    format!("sha256:{:x}", Sha256::digest(canonical.as_bytes()))
}

/// A content-addressed reference to one artifact this run produced
/// (a SARIF upload, a dependency-graph snapshot, ...) — the manifest
/// records that *something specific* was produced and its digest, not
/// the artifact bytes themselves.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactDigest {
    pub name: String,
    pub digest: String,
}

/// The versioned record itself. Every field here is either a digest, a
/// count, a timestamp, or already-redacted structured data
/// (`ignite_policy::CheckCoverage` carries no file contents or secrets) —
/// safe to serialize wholesale into an API response or an exported file
/// without a second redaction pass, which is what makes "evidence export
/// ... without exposing secrets or absolute host paths" true by
/// construction rather than by a filter someone has to remember to apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceManifest {
    /// Bumped only on a breaking change to this shape — a consumer that
    /// reads an old manifest back can tell it apart from a new one.
    pub manifest_version: u32,
    pub source_digest: String,
    pub source_file_count: usize,
    pub commit_sha: Option<String>,
    pub policy_version: String,
    pub config_digest: String,
    pub coverage: Vec<ignite_policy::CheckCoverage>,
    pub artifact_digests: Vec<ArtifactDigest>,
    pub created_at: String,
}

pub const MANIFEST_VERSION: u32 = 1;

#[allow(clippy::too_many_arguments)]
pub fn build_evidence_manifest(
    source_digest: impl Into<String>,
    source_file_count: usize,
    commit_sha: Option<String>,
    policy_version: impl Into<String>,
    config_digest: impl Into<String>,
    coverage: Vec<ignite_policy::CheckCoverage>,
    artifact_digests: Vec<ArtifactDigest>,
    created_at: impl Into<String>,
) -> EvidenceManifest {
    EvidenceManifest {
        manifest_version: MANIFEST_VERSION,
        source_digest: source_digest.into(),
        source_file_count,
        commit_sha,
        policy_version: policy_version.into(),
        config_digest: config_digest.into(),
        coverage,
        artifact_digests,
        created_at: created_at.into(),
    }
}

/// Current UTC time in the same ISO-8601 shape (`YYYY-MM-DDTHH:MM:SS.sssZ`)
/// `ignite-provenance`'s own `iso8601_now` produces, kept as one call here
/// (backed by `chrono`, already a workspace dependency) rather than a
/// second hand-rolled implementation.
pub fn now_iso8601() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_digest_is_deterministic_and_never_leaks_a_secret_value() {
        let mut cfg = ignite_config::Config::default();
        cfg.notifications.smtp.pass = Some("super-secret-password".to_string());
        let d1 = config_digest(&cfg);
        let d2 = config_digest(&cfg);
        assert_eq!(d1, d2);
        assert!(!d1.contains("super-secret-password"));
        assert!(d1.starts_with("sha256:"));
    }

    #[test]
    fn config_digest_changes_when_a_setting_changes() {
        let cfg1 = ignite_config::Config::default();
        let mut cfg2 = ignite_config::Config::default();
        cfg2.policy.strict = !cfg2.policy.strict;
        assert_ne!(config_digest(&cfg1), config_digest(&cfg2));
    }

    #[test]
    fn build_evidence_manifest_round_trips_through_json() {
        let manifest = build_evidence_manifest("sha256:abc", 3, Some("deadbeef".to_string()), "legacy-compatible-v1", "sha256:cfg", vec![], vec![ArtifactDigest { name: "sarif".to_string(), digest: "sha256:xyz".to_string() }], "2026-01-01T00:00:00.000Z");
        let json = serde_json::to_string(&manifest).unwrap();
        let back: EvidenceManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.source_digest, "sha256:abc");
        assert_eq!(back.manifest_version, MANIFEST_VERSION);
        assert_eq!(back.artifact_digests.len(), 1);
    }
}
