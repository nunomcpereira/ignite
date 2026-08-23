//! Minimal build/commit provenance — always runs, no external tool.
//! Faithful port of `checks/provenance.js`. NOT a signed SLSA attestation
//! (no keyless/KMS signing, no transparency-log entry, no verified
//! builder identity) — a same-shape, unsigned in-toto Statement/SLSA-
//! provenance-v1 predicate recording what was scanned, by what, and when.

use ignite_fs_utils::walk_files;
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct TreeDigest {
    pub sha256: String,
    pub file_count: usize,
}

/// Content-addressed identity of exactly what was staged/scanned: a sha256
/// over every non-.git file's own sha256, sorted by relative path so the
/// digest is deterministic regardless of directory-walk order.
pub fn digest_project_tree(root: &Path) -> std::io::Result<TreeDigest> {
    let mut entries: Vec<(String, String)> = Vec::new();
    for file in walk_files(root)? {
        let rel = file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        let Ok(buffer) = std::fs::read(&file) else { continue };
        let mut hasher = Sha256::new();
        hasher.update(&buffer);
        let hash = hex_encode(&hasher.finalize());
        entries.push((rel, hash));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut combined = Sha256::new();
    for (rel, hash) in &entries {
        combined.update(format!("{}:{}\n", rel, hash).as_bytes());
    }
    Ok(TreeDigest { sha256: hex_encode(&combined.finalize()), file_count: entries.len() })
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Matches Node's `new Date().toISOString()` format
/// (YYYY-MM-DDTHH:MM:SS.sssZ), hand-rolled from a Unix timestamp rather
/// than pulling in a datetime crate for one formatted string.
fn iso8601_now() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs() as i64;
    let millis = now.subsec_millis();

    // Civil-from-days algorithm (Howard Hinnant's public-domain
    // date-algorithms), converting a Unix day count to a Gregorian
    // calendar date without a datetime crate dependency.
    let days = secs.div_euclid(86400);
    let secs_of_day = secs.rem_euclid(86400);
    let (hour, minute, second) = (secs_of_day / 3600, (secs_of_day / 60) % 60, secs_of_day % 60);

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if month <= 2 { y + 1 } else { y };

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", year, month, day, hour, minute, second, millis)
}

#[derive(Debug, Clone, Serialize)]
pub struct ProvenanceSubject {
    pub name: String,
    pub digest: SubjectDigest,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubjectDigest {
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildDefinition {
    pub build_type: &'static str,
    pub external_parameters: ExternalParameters,
    pub resolved_dependencies: Vec<ResolvedDependency>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalParameters {
    pub org: Option<String>,
    pub repo: Option<String>,
    #[serde(rename = "jobId")]
    pub job_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedDependency {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Builder {
    pub id: &'static str,
    pub version: BuilderVersion,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuilderVersion {
    pub ignite: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunMetadata {
    pub generated_at: String,
    pub file_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunDetails {
    pub builder: Builder,
    pub metadata: RunMetadata,
}

#[derive(Debug, Clone, Serialize)]
pub struct Predicate {
    pub build_definition: BuildDefinition,
    pub run_details: RunDetails,
}

#[derive(Debug, Clone, Serialize)]
pub struct Provenance {
    #[serde(rename = "_type")]
    pub type_: &'static str,
    pub subject: Vec<ProvenanceSubject>,
    pub predicate_type: &'static str,
    pub predicate: Predicate,
    pub note: &'static str,
}

pub struct ProvenanceParams<'a> {
    pub org: Option<&'a str>,
    pub repo: Option<&'a str>,
    pub job_id: Option<&'a str>,
}

pub async fn generate_provenance(root: &Path, runner: &ToolRunner, ignite_version: &str, params: ProvenanceParams<'_>) -> std::io::Result<Provenance> {
    let digest = digest_project_tree(root)?;

    let source_commit = runner
        .run_tool("git", &["rev-parse".to_string(), "HEAD".to_string()], &root.to_string_lossy(), RunToolOptions::default())
        .await
        .ok()
        .map(|o| o.stdout.trim().to_string())
        .filter(|s| !s.is_empty());

    let subject_name = match (params.org, params.repo) {
        (Some(org), Some(repo)) if !org.is_empty() && !repo.is_empty() => format!("{}/{}", org, repo),
        _ => "unknown".to_string(),
    };

    Ok(Provenance {
        type_: "https://in-toto.io/Statement/v1",
        subject: vec![ProvenanceSubject { name: subject_name, digest: SubjectDigest { sha256: digest.sha256.clone() } }],
        predicate_type: "https://slsa.dev/provenance/v1",
        predicate: Predicate {
            build_definition: BuildDefinition {
                build_type: "https://github.com/nunomcpereira/ignite/onboarding-pipeline/v1",
                external_parameters: ExternalParameters {
                    org: params.org.filter(|s| !s.is_empty()).map(String::from),
                    repo: params.repo.filter(|s| !s.is_empty()).map(String::from),
                    job_id: params.job_id.filter(|s| !s.is_empty()).map(String::from),
                },
                resolved_dependencies: source_commit.as_ref().map(|c| vec![ResolvedDependency { uri: format!("git+commit:{}", c) }]).unwrap_or_default(),
            },
            run_details: RunDetails {
                builder: Builder { id: "https://github.com/nunomcpereira/ignite", version: BuilderVersion { ignite: ignite_version.to_string() } },
                metadata: RunMetadata { generated_at: iso8601_now(), file_count: digest.file_count },
            },
        },
        note: "Minimal build/commit provenance for audit purposes — NOT a signed SLSA attestation (no keyless/KMS signing, no transparency-log entry, no verified builder identity). subject.digest is a sha256 over every staged file's own sha256, sorted by relative path.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn digest_is_deterministic_regardless_of_walk_order() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.js"), b"content a").unwrap();
        fs::write(root.join("b.js"), b"content b").unwrap();

        let d1 = digest_project_tree(root).unwrap();
        let d2 = digest_project_tree(root).unwrap();
        assert_eq!(d1.sha256, d2.sha256);
        assert_eq!(d1.file_count, 2);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn digest_changes_when_content_changes() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.js"), b"v1").unwrap();
        let d1 = digest_project_tree(root).unwrap();

        fs::write(root.join("a.js"), b"v2").unwrap();
        ignite_fs_utils::invalidate_walk_cache(root);
        let d2 = digest_project_tree(root).unwrap();
        assert_ne!(d1.sha256, d2.sha256);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn iso8601_now_has_expected_shape() {
        let ts = iso8601_now();
        assert_eq!(ts.len(), 24); // YYYY-MM-DDTHH:MM:SS.sssZ
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.chars().nth(4), Some('-'));
        assert_eq!(ts.chars().nth(10), Some('T'));
    }

    #[tokio::test]
    async fn generate_provenance_without_git_omits_source_commit() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("app.js"), b"x").unwrap();

        let provenance = generate_provenance(root, &ToolRunner::new(HashMap::new()), "1.0.0", ProvenanceParams { org: Some("acme"), repo: Some("widgets"), job_id: Some("job-1") }).await.unwrap();
        assert_eq!(provenance.subject[0].name, "acme/widgets");
        assert!(provenance.predicate.build_definition.resolved_dependencies.is_empty());
        assert_eq!(provenance.predicate.run_details.builder.version.ignite, "1.0.0");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn generate_provenance_unknown_subject_without_org_repo() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("app.js"), b"x").unwrap();

        let provenance = generate_provenance(root, &ToolRunner::new(HashMap::new()), "1.0.0", ProvenanceParams { org: None, repo: None, job_id: None }).await.unwrap();
        assert_eq!(provenance.subject[0].name, "unknown");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn generate_provenance_with_real_git_records_source_commit() {
        let mut check = std::process::Command::new("git");
        check.arg("--version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: git not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("app.js"), b"x").unwrap();
        let run = |args: &[&str]| {
            let status = std::process::Command::new("git").args(args).current_dir(root).env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@t").env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@t").status().unwrap();
            assert!(status.success());
        };
        run(&["init", "-q"]);
        run(&["add", "-A"]);
        run(&["commit", "-q", "-m", "init"]);

        let mut binaries = HashMap::new();
        binaries.insert("git", "git".to_string());
        let provenance = generate_provenance(root, &ToolRunner::new(binaries), "1.0.0", ProvenanceParams { org: Some("acme"), repo: Some("widgets"), job_id: None }).await.unwrap();
        assert_eq!(provenance.predicate.build_definition.resolved_dependencies.len(), 1);
        assert!(provenance.predicate.build_definition.resolved_dependencies[0].uri.starts_with("git+commit:"));
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}
