//! CycloneDX SBOM generation via Syft. Faithful port of `checks/sbom.js`.
//! Reuses `ignite-package-hallucination`'s `ManifestSpec`/
//! `ManifestDependency` (the same manifest parsers the JS original's
//! `scanDependencyLicensesFallback`/`studioManifests` share) rather than
//! redefining an identical manifest-parsing abstraction.

use ignite_package_hallucination::{ManifestDependency, ManifestSpec};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct SbomComponent {
    pub name: String,
    pub version: Option<String>,
    pub ecosystem: String,
    #[serde(rename = "type")]
    pub component_type: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct FallbackSbom {
    pub bom_format: &'static str,
    pub spec_version: Option<String>,
    pub components: Vec<SbomComponent>,
}

/// Best-effort component list built purely from this app's own manifest
/// parsers, used only when syft is disabled or not installed. Intentionally
/// minimal: name/version pairs per ecosystem, no dependency graph, no CPEs,
/// no license metadata.
pub fn generate_sbom_fallback(root: &Path, manifests: &[ManifestSpec], max_deps_per_manifest: usize) -> std::io::Result<FallbackSbom> {
    let mut components = Vec::new();
    for file in ignite_fs_utils::walk_files(root)? {
        let base = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let Some(spec) = manifests.iter().find(|m| m.file == base) else { continue };
        let Ok(content) = std::fs::read_to_string(&file) else { continue };
        let raw_deps: Vec<ManifestDependency> = (spec.parse)(&content).into_iter().take(max_deps_per_manifest).collect();
        for dep in raw_deps {
            components.push(SbomComponent { name: dep.name, version: dep.version_range, ecosystem: spec.ecosystem.to_string(), component_type: "library" });
        }
    }
    Ok(FallbackSbom { bom_format: "ignite-fallback", spec_version: None, components })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SbomToolingProbe {
    pub ok: bool,
    pub reason: Option<String>,
}

pub async fn syft_tooling(runner: &ToolRunner) -> SbomToolingProbe {
    match runner.run_tool("syft", &["version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default()).await {
        Ok(_) => SbomToolingProbe { ok: true, reason: None },
        Err(_) => SbomToolingProbe {
            ok: false,
            reason: Some("`syft` is not installed (brew install syft) — falling back to a minimal manifest-derived component list (no standards-format SBOM).".to_string()),
        },
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum SbomOutcome {
    Syft(serde_json::Value),
    Fallback(FallbackSbom),
}

#[derive(Debug, Clone, Serialize)]
pub struct SbomResult {
    pub engine: &'static str,
    pub sbom: SbomOutcome,
}

/// Never throws / never fails the caller: returns the built-in fallback
/// component list on any missing-tool/parse failure.
pub async fn generate_sbom(root: &Path, runner: &ToolRunner, enabled: bool, manifests: &[ManifestSpec], max_deps_per_manifest: usize) -> std::io::Result<SbomResult> {
    let tooling = if enabled {
        syft_tooling(runner).await
    } else {
        SbomToolingProbe { ok: false, reason: Some("syft is disabled (sbom.syft.enabled=false).".to_string()) }
    };
    if !tooling.ok {
        return Ok(SbomResult { engine: "fallback", sbom: SbomOutcome::Fallback(generate_sbom_fallback(root, manifests, max_deps_per_manifest)?) });
    }

    let report_path = std::env::temp_dir().join(format!("ignite-syft-{}.json", std::process::id()));
    let run_result = runner
        .run_tool(
            "syft",
            &[root.to_string_lossy().into_owned(), "-o".to_string(), format!("cyclonedx-json={}", report_path.to_string_lossy()), "--quiet".to_string()],
            &root.to_string_lossy(),
            RunToolOptions::default(),
        )
        .await;

    let result = match run_result {
        Ok(_) => match tokio::fs::read_to_string(&report_path).await {
            Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(sbom) => Ok(SbomResult { engine: "syft", sbom: SbomOutcome::Syft(sbom) }),
                Err(_) => Ok(SbomResult { engine: "fallback", sbom: SbomOutcome::Fallback(generate_sbom_fallback(root, manifests, max_deps_per_manifest)?) }),
            },
            Err(_) => Ok(SbomResult { engine: "fallback", sbom: SbomOutcome::Fallback(generate_sbom_fallback(root, manifests, max_deps_per_manifest)?) }),
        },
        Err(_) => Ok(SbomResult { engine: "fallback", sbom: SbomOutcome::Fallback(generate_sbom_fallback(root, manifests, max_deps_per_manifest)?) }),
    };
    let _ = tokio::fs::remove_file(&report_path).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ignite_package_hallucination::default_manifests;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    fn runner_without_syft() -> ToolRunner {
        ToolRunner::new(HashMap::new())
    }

    #[test]
    fn fallback_extracts_components_from_package_json() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"dependencies": {"express": "^4.0.0", "lodash": "^4.17.0"}}"#).unwrap();

        let sbom = generate_sbom_fallback(root, &default_manifests(), 1000).unwrap();
        assert_eq!(sbom.bom_format, "ignite-fallback");
        assert_eq!(sbom.components.len(), 2);
        assert!(sbom.components.iter().any(|c| c.name == "express" && c.ecosystem == "npm"));
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn fallback_respects_max_deps_per_manifest() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"dependencies": {"a": "1.0.0", "b": "1.0.0", "c": "1.0.0"}}"#).unwrap();

        let sbom = generate_sbom_fallback(root, &default_manifests(), 2).unwrap();
        assert_eq!(sbom.components.len(), 2);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn disabled_falls_back_without_probing_syft() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"dependencies": {"express": "^4.0.0"}}"#).unwrap();

        let result = generate_sbom(root, &runner_without_syft(), false, &default_manifests(), 1000).await.unwrap();
        assert_eq!(result.engine, "fallback");
        match result.sbom {
            SbomOutcome::Fallback(f) => assert_eq!(f.components.len(), 1),
            _ => panic!("expected fallback"),
        }
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn missing_binary_falls_back_gracefully() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"dependencies": {"express": "^4.0.0"}}"#).unwrap();

        // enabled: true, but the ToolRunner has no "syft" binary registered
        // -> resolve_binary fails -> tooling probe fails -> same fallback
        // path as "disabled".
        let result = generate_sbom(root, &runner_without_syft(), true, &default_manifests(), 1000).await.unwrap();
        assert_eq!(result.engine, "fallback");
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}
