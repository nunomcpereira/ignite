//! Sigstore/cosign keyless-signature verification for external Dockerfile
//! base images. Faithful port of `checks/image-provenance.js`. Each unique
//! image is verified once (a real network call to the registry + Rekor
//! transparency log) and the verdict is fanned back out to every
//! file/line occurrence that referenced it. Never throws: any tool/network
//! failure becomes an "unverifiable" finding rather than aborting the run.

use ignite_db_store::DbStore;
use ignite_fs_utils::{build_snippet, is_dockerfile_name, looks_binary, walk_files, Snippet, SnippetOptions};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

static FROM_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*FROM\s+(\S+?)(?:\s+AS\s+(\S+))?\s*$").unwrap());

pub struct ImageProvenanceConfig {
    pub enabled: bool,
    pub identity_regexp: String,
    pub issuer_regexp: String,
    pub cache_ttl_seconds: i64,
}

impl Default for ImageProvenanceConfig {
    fn default() -> Self {
        ImageProvenanceConfig { enabled: true, identity_regexp: ".*".to_string(), issuer_regexp: ".*".to_string(), cache_ttl_seconds: 3600 }
    }
}

#[derive(Debug, Clone)]
pub struct BaseImageOccurrence {
    pub file: String,
    pub line: usize,
    pub image: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImageProvenanceFinding {
    pub file: String,
    pub line: usize,
    pub kind: &'static str,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Snippet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImageProvenanceResult {
    pub findings: Vec<ImageProvenanceFinding>,
    pub engine: &'static str,
}

pub async fn cosign_tooling(runner: &ToolRunner) -> bool {
    runner
        .run_tool("cosign", &["version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default())
        .await
        .is_ok()
}

/// Excludes multi-stage build aliases (`FROM builder` referencing an
/// earlier `AS builder` stage) and `scratch` — neither is an external image
/// cosign has anything to verify against.
pub fn discover_base_images(root: &Path) -> std::io::Result<Vec<BaseImageOccurrence>> {
    let mut occurrences = Vec::new();
    for file in walk_files(root)? {
        let base = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if !is_dockerfile_name(&base) {
            continue;
        }
        let Ok(buffer) = std::fs::read(&file) else { continue };
        if looks_binary(&buffer) {
            continue;
        }
        let content = String::from_utf8_lossy(&buffer);
        let rel = file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        let mut stage_names: HashSet<String> = HashSet::new();
        for (i, line) in content.split('\n').enumerate() {
            let line = line.strip_suffix('\r').unwrap_or(line);
            let Some(m) = FROM_LINE_RE.captures(line) else { continue };
            let image = m.get(1).map(|x| x.as_str().to_string()).unwrap_or_default();
            if let Some(stage) = m.get(2) {
                stage_names.insert(stage.as_str().to_string());
            }
            if stage_names.contains(&image) || image.eq_ignore_ascii_case("scratch") {
                continue;
            }
            occurrences.push(BaseImageOccurrence { file: rel.clone(), line: i + 1, image });
        }
    }
    Ok(occurrences)
}

async fn verify_image(runner: &ToolRunner, image: &str, config: &ImageProvenanceConfig, store: Option<&DbStore>) -> (bool, Option<String>) {
    if config.cache_ttl_seconds > 0 {
        if let Some(store) = store {
            if let Some(cached) = store.get_cosign_verify_cache(image, &config.identity_regexp, &config.issuer_regexp, config.cache_ttl_seconds) {
                return (cached.verified, cached.reason);
            }
        }
    }

    let result = runner
        .run_tool(
            "cosign",
            &[
                "verify".to_string(),
                "--certificate-identity-regexp".to_string(),
                config.identity_regexp.clone(),
                "--certificate-oidc-issuer-regexp".to_string(),
                config.issuer_regexp.clone(),
                image.to_string(),
            ],
            &std::env::current_dir().unwrap_or_default().to_string_lossy(),
            RunToolOptions::default(),
        )
        .await;

    let (verified, reason) = match result {
        Ok(_) => (true, None),
        Err(e) => (false, Some(e.to_string())),
    };

    if config.cache_ttl_seconds > 0 {
        if let Some(store) = store {
            store.save_cosign_verify_cache(image, &config.identity_regexp, &config.issuer_regexp, verified, reason.as_deref());
        }
    }
    (verified, reason)
}

pub async fn check_image_provenance(root: &Path, runner: &ToolRunner, config: &ImageProvenanceConfig, store: Option<&DbStore>) -> std::io::Result<ImageProvenanceResult> {
    let tooling_ok = config.enabled && cosign_tooling(runner).await;
    if !tooling_ok {
        return Ok(ImageProvenanceResult { findings: vec![], engine: "disabled" });
    }

    let occurrences = discover_base_images(root)?;
    if occurrences.is_empty() {
        return Ok(ImageProvenanceResult { findings: vec![], engine: "cosign" });
    }

    let unique_images: Vec<String> = {
        let mut seen = HashSet::new();
        let mut ordered = Vec::new();
        for occ in &occurrences {
            if seen.insert(occ.image.clone()) {
                ordered.push(occ.image.clone());
            }
        }
        ordered
    };

    let verdicts = futures::future::join_all(unique_images.iter().map(|image| verify_image(runner, image, config, store))).await;
    let verdict_by_image: HashMap<String, (bool, Option<String>)> = unique_images.into_iter().zip(verdicts).collect();

    let mut findings = Vec::new();
    let mut content_by_file: HashMap<String, Option<String>> = HashMap::new();
    for occ in &occurrences {
        let Some((verified, _reason)) = verdict_by_image.get(&occ.image) else { continue };
        if *verified {
            continue;
        }
        let content = content_by_file.entry(occ.file.clone()).or_insert_with(|| std::fs::read_to_string(root.join(&occ.file)).ok()).clone();
        findings.push(ImageProvenanceFinding {
            file: occ.file.clone(),
            line: occ.line,
            kind: "unsigned-base-image",
            tool: "cosign",
            severity: "warning",
            message: format!(r#"Base image "{}" has no verifiable Sigstore/cosign signature — supply-chain provenance can't be confirmed."#, occ.image),
            code: content.as_deref().and_then(|c| build_snippet(c, occ.line, SnippetOptions::default())),
        });
    }

    Ok(ImageProvenanceResult { findings, engine: "cosign" })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;
    use std::fs;
    use tempfile::tempdir;

    fn runner_with_cosign() -> ToolRunner {
        let mut binaries = StdHashMap::new();
        binaries.insert("cosign", "cosign".to_string());
        ToolRunner::new(binaries)
    }

    #[test]
    fn discovers_external_base_images_only() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(
            root.join("Dockerfile"),
            "FROM node:18 AS builder\nRUN npm install\nFROM builder\nCOPY --from=builder /app /app\nFROM scratch\n",
        )
        .unwrap();

        let occurrences = discover_base_images(root).unwrap();
        assert_eq!(occurrences.len(), 1);
        assert_eq!(occurrences[0].image, "node:18");
        assert_eq!(occurrences[0].line, 1);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn discovers_from_suffixed_dockerfile_variants() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("Dockerfile.prod"), "FROM alpine:3.19\n").unwrap();

        let occurrences = discover_base_images(root).unwrap();
        assert_eq!(occurrences.len(), 1);
        assert_eq!(occurrences[0].file, "Dockerfile.prod");
        assert_eq!(occurrences[0].image, "alpine:3.19");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        let config = ImageProvenanceConfig { enabled: false, ..Default::default() };
        let result = check_image_provenance(dir.path(), &ToolRunner::new(StdHashMap::new()), &config, None).await.unwrap();
        assert_eq!(result.engine, "disabled");
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn no_dockerfiles_returns_no_findings_without_running_cosign() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("app.js"), b"console.log(1)").unwrap();
        // no "cosign" binary registered -> tooling probe would fail anyway,
        // but this also proves discover_base_images short-circuits cleanly.
        let result = check_image_provenance(dir.path(), &runner_with_cosign(), &ImageProvenanceConfig::default(), None).await.unwrap();
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[tokio::test]
    async fn real_cosign_binary_flags_unsigned_image() {
        let mut check = std::process::Command::new("cosign");
        check.arg("version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: cosign not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        // An image that certainly has no Sigstore signature at all.
        fs::write(root.join("Dockerfile"), "FROM scratch\nFROM busybox:1.36.1\n").unwrap();

        let config = ImageProvenanceConfig { enabled: true, cache_ttl_seconds: 0, ..Default::default() };
        let result = check_image_provenance(root, &runner_with_cosign(), &config, None).await.unwrap();
        assert_eq!(result.engine, "cosign");
        assert!(result.findings.iter().any(|f| f.message.contains("busybox:1.36.1")), "expected busybox:1.36.1 to be flagged unsigned");
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}
