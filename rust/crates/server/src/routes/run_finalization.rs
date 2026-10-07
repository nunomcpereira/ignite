//! US-14: the end-of-scan record every pipeline entry point writes once its
//! checks are done — `validate-all`, `onboard` and the interactive upload
//! all call [`record_scan_evidence`], so which entry point ran a scan no
//! longer decides how much evidence and finding history it leaves behind.
//!
//! Called once Phase 4 has produced its issue list, for passing *and*
//! blocked runs alike (a blocked run is the one most worth tracing later),
//! while the scanned tree still exists on disk. The policy decision is
//! persisted separately by [`super::policy_finalization::finalize`], since
//! it also depends on the review outcome, which only the caller knows.

use crate::state::AppState;
use ignite_override_engine::{Issue, Severity};
use std::collections::HashSet;
use std::path::Path;

pub struct ScanEvidence<'a> {
    pub run_id: i64,
    pub org: &'a str,
    pub repo: &'a str,
    /// The tree the checks actually scanned.
    pub root: &'a Path,
    pub coverage: &'a [ignite_policy::CheckCoverage],
    pub issues: &'a [Issue],
}

/// Re-points the run's snapshot at the real content digest, persists the
/// evidence manifest (US-05), and syncs the issues into the repository's
/// fingerprint-keyed findings (US-07). Best-effort: a failure is logged,
/// never surfaced as a scan failure.
pub async fn record_scan_evidence(state: &AppState, input: ScanEvidence<'_>) {
    let ScanEvidence { run_id, org, repo, root, coverage, issues } = input;
    let repository_id = state.db.resolve_repository(org, repo, None);

    // `unknown:project:<id>` was the only digest available when the run
    // was created (nothing was staged yet); byte-and-mode-identical
    // sources now dedupe onto one snapshot row whichever entry point ran.
    match ignite_provenance::digest_project_tree(root) {
        Ok(tree) => {
            // An upload has no `.git`, so this is `None` for it — recorded as
            // absent, never invented.
            let commit_sha = state
                .runner
                .run_tool("git", &["rev-parse".to_string(), "HEAD".to_string()], &root.to_string_lossy(), ignite_tool_runner::RunToolOptions::default())
                .await
                .ok()
                .map(|o| o.stdout.trim().to_string())
                .filter(|s| !s.is_empty());
            let source_digest = format!("sha256:{}", tree.sha256);
            state.db.finalize_scan_run_snapshot(run_id, repository_id, &source_digest, commit_sha.as_deref());

            let policy_version = if state.config.policy.strict { ignite_policy::PolicyVersion::strict_publication() } else { ignite_policy::PolicyVersion::legacy_compatible() };
            let manifest = ignite_evidence::build_evidence_manifest(
                source_digest,
                tree.file_count,
                commit_sha,
                policy_version.id.clone(),
                ignite_evidence::config_digest(&state.config),
                coverage.to_vec(),
                vec![],
                ignite_evidence::now_iso8601(),
            );
            if let Ok(manifest_json) = serde_json::to_string(&manifest) {
                state.db.save_evidence_manifest(run_id, &manifest_json);
            }
        }
        Err(e) => tracing::warn!("evidence: failed to compute snapshot digest for run {run_id}: {e}"),
    }

    // Only a check whose coverage says `Completed` this run can prove a
    // prior finding for its tool is gone; a failed/disabled/unavailable
    // check never resolves a finding by omission.
    let completed_tools: HashSet<String> = coverage.iter().filter(|c| c.outcome == ignite_policy::CheckOutcome::Completed).filter_map(|c| c.engine.as_deref()).map(|e| e.to_ascii_lowercase()).collect();
    let observations: Vec<ignite_db_store::FindingObservationInput> = issues
        .iter()
        .map(|issue| ignite_db_store::FindingObservationInput {
            legacy_issue_id: issue.id.clone(),
            category: issue.category.clone(),
            fingerprint: fingerprint_for(issue),
            file: issue.file.clone(),
            line: issue.line,
            severity: match issue.severity {
                Severity::Error => "error".to_string(),
                Severity::Warning => "warning".to_string(),
            },
            tool: issue.tool.clone(),
        })
        .collect();
    state.db.record_finding_observations(repository_id, run_id, &completed_tools, &observations);
}

/// The line-drift-tolerant identity of `issue` (US-07).
pub fn fingerprint_for(issue: &Issue) -> String {
    ignite_override_engine::fingerprint_for_issue_parts(&issue.id, &issue.category, issue.file.as_deref(), issue.snippet.as_ref(), issue.line)
}

/// Saves the reports Phase 4 generated (SBOM, LOC metrics, posture,
/// provenance, EU AI Act documents) as the project's documents, which
/// historical Studio shows when the source itself is gone, then drops the
/// same reports from the repo's older scans: only a repo's latest scan
/// keeps them. A fast run generates none and changes nothing.
pub fn persist_scan_reports(state: &AppState, project_id: i64, org: &str, repo: &str, documents: &ignite_phase4_orchestrator::Phase4Documents) {
    let mut named: Vec<(&str, &[u8])> = Vec::new();
    if let Some((name, data)) = &documents.sbom {
        named.push((name.as_str(), data));
    }
    for (name, data) in [
        ("loc-metrics.json", &documents.loc_metrics),
        ("posture-report.json", &documents.posture_report),
        ("provenance.json", &documents.provenance),
        ("ai-act-documents.json", &documents.ai_act_documents_report),
    ] {
        if let Some(data) = data {
            named.push((name, data));
        }
    }
    if named.is_empty() {
        return;
    }
    for (name, data) in named {
        state.db.add_upload_document(project_id, name, Some("application/json"), data.len() as i64, data);
    }
    state.db.delete_older_scan_reports(org, repo, project_id);
}

/// Keeps a copy of the scanned tree as `org/repo`'s latest scan source, so
/// Studio opens that scan fully (code, dependencies, SBOM, LOC, posture,
/// rescan) like a dashboard upload. One per repo: the previous scan's copy
/// is deleted once the new one is in place. Separate from the upload pool's
/// 5 full + 5 pruned sources, so an org sweep never evicts those.
pub fn retain_latest_repo_source(state: &AppState, project_id: i64, org: &str, repo: &str, root: &Path) {
    let retained_root = super::pipeline_interactive::ignite_data_dir().join("retained-projects");
    let dest = retained_root.join(project_id.to_string());
    if let Err(e) = std::fs::create_dir_all(&retained_root) {
        tracing::warn!("cannot keep the scanned source of {org}/{repo}: {e}");
        return;
    }
    let _ = std::fs::remove_dir_all(&dest);
    if let Err(e) = ignite_staging::clone_directory_without_symlinks(root, &dest) {
        tracing::warn!("cannot keep the scanned source of {org}/{repo}: {e}");
        let _ = std::fs::remove_dir_all(&dest);
        return;
    }
    let previous = state.db.list_repo_latest_retained_sources(org, repo);
    state.db.retain_project_source(project_id, &dest.to_string_lossy(), ignite_db_store::REPO_LATEST_TIER);
    for old in previous.into_iter().filter(|r| r.project_id != project_id) {
        let _ = std::fs::remove_dir_all(&old.dir_path);
        ignite_fs_utils::invalidate_walk_cache(Path::new(&old.dir_path));
        state.db.delete_retained_source(old.project_id);
    }
}
