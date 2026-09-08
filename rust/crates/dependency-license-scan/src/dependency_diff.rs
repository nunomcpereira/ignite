//! PR "Dependency Review" comment — GHAS-parity gap: `dependency-review-action`
//! posts a diff summary (added/removed/updated dependencies, license
//! changes) as a PR comment so a reviewer doesn't have to dig through CI
//! logs. Ignite has the same underlying data (`DbStore::save_dependency_scan_cache`'s
//! `scan_json`, already cached per project from the license-compliance
//! check) — this module diffs two such snapshots and renders the result
//! as markdown.
//!
//! **Baseline caveat**: `diff_dependency_scans` compares the *previous*
//! cached scan for this project (`DbStore::get_previous_dependency_scan_cache`)
//! against the current one, not a literal re-clone-and-rescan of the PR's
//! actual base branch. For the common case — a PR branched from, and
//! compared against, the same org/repo's default branch that Ignite most
//! recently scanned — this is equivalent and costs no second clone. It
//! diverges only when the previous scan wasn't actually the PR's base
//! (e.g. two PRs scanned back-to-back before either merges, or a
//! feature branch based on an older commit) — in which case the diff may
//! include changes that landed on the base branch too, not just this
//! PR's own changes. A full base-vs-head diff (second clone) is future
//! work, not implemented here.

use serde::Serialize;
use std::collections::HashMap;

/// Hidden marker prefixed onto every rendered comment body — lets
/// `GithubApi::gh_upsert_pr_sticky_comment` find and update its own prior
/// comment on a later push instead of appending a new one every time.
pub const DEPENDENCY_REVIEW_MARKER: &str = "<!-- ignite:dependency-review -->";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DependencyChangeKind {
    Added,
    Removed,
    VersionChanged,
    LicenseChanged,
}

#[derive(Debug, Clone, Serialize)]
pub struct DependencyChange {
    pub kind: DependencyChangeKind,
    pub ecosystem: String,
    pub name: String,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub from_licenses: Vec<String>,
    pub to_licenses: Vec<String>,
    /// `DependencyLicenseTier::as_str()`'s output ("green"/"warning"/"red"/
    /// "internal") for the dependency's state in the head scan — `None`
    /// for a `Removed` change, since there's no head-side tier to show.
    pub to_tier: Option<String>,
}

/// Mirrors just the fields of `LicenseScanManifest`/`LicenseScanDependency`
/// this module needs, deserialized straight from a cached `scan_json`
/// blob — those public types carry `&'static str` fields (`ecosystem`,
/// `source`) that can't implement `Deserialize` (nothing 'static to
/// borrow from at deserialize time), so a local mirror with owned
/// `String`s stands in for round-tripping through JSON.
#[derive(Debug, Clone, Default, serde::Deserialize)]
struct DiffManifestDep {
    name: String,
    version: Option<String>,
    #[serde(default)]
    licenses: Vec<String>,
    #[serde(default)]
    tier: String,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct DiffManifest {
    #[serde(default)]
    ecosystem: String,
    #[serde(default)]
    dependencies: Vec<DiffManifestDep>,
}

fn parse_scan_manifests(scan_json: &serde_json::Value) -> Vec<DiffManifest> {
    scan_json.get("manifests").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default()
}

fn kind_rank(kind: DependencyChangeKind) -> u8 {
    match kind {
        DependencyChangeKind::Added => 0,
        DependencyChangeKind::Removed => 1,
        DependencyChangeKind::VersionChanged => 2,
        DependencyChangeKind::LicenseChanged => 3,
    }
}

/// Diffs two cached `scan_json` blobs (see module doc for what "base"
/// actually means here) into a flat, deterministically-ordered list of
/// per-dependency changes. Dependencies are matched by `(ecosystem, name)`
/// — a dependency moving between manifests of the same ecosystem (e.g.
/// hoisted in a monorepo) isn't reported as added+removed, only a real
/// ecosystem-wide addition/removal is.
pub fn diff_dependency_scans(base_scan_json: &serde_json::Value, head_scan_json: &serde_json::Value) -> Vec<DependencyChange> {
    diff_dependency_manifests(&parse_scan_manifests(base_scan_json), &parse_scan_manifests(head_scan_json))
}

fn diff_dependency_manifests(base: &[DiffManifest], head: &[DiffManifest]) -> Vec<DependencyChange> {
    let mut base_map: HashMap<(String, String), &DiffManifestDep> = HashMap::new();
    for m in base {
        for d in &m.dependencies {
            base_map.insert((m.ecosystem.clone(), d.name.clone()), d);
        }
    }
    let mut head_map: HashMap<(String, String), &DiffManifestDep> = HashMap::new();
    for m in head {
        for d in &m.dependencies {
            head_map.insert((m.ecosystem.clone(), d.name.clone()), d);
        }
    }

    let mut changes = Vec::new();
    for (key, hd) in &head_map {
        match base_map.get(key) {
            None => changes.push(DependencyChange {
                kind: DependencyChangeKind::Added,
                ecosystem: key.0.clone(),
                name: key.1.clone(),
                from_version: None,
                to_version: hd.version.clone(),
                from_licenses: vec![],
                to_licenses: hd.licenses.clone(),
                to_tier: Some(hd.tier.clone()),
            }),
            Some(bd) => {
                if bd.version != hd.version {
                    changes.push(DependencyChange {
                        kind: DependencyChangeKind::VersionChanged,
                        ecosystem: key.0.clone(),
                        name: key.1.clone(),
                        from_version: bd.version.clone(),
                        to_version: hd.version.clone(),
                        from_licenses: bd.licenses.clone(),
                        to_licenses: hd.licenses.clone(),
                        to_tier: Some(hd.tier.clone()),
                    });
                } else if bd.licenses != hd.licenses {
                    changes.push(DependencyChange {
                        kind: DependencyChangeKind::LicenseChanged,
                        ecosystem: key.0.clone(),
                        name: key.1.clone(),
                        from_version: bd.version.clone(),
                        to_version: hd.version.clone(),
                        from_licenses: bd.licenses.clone(),
                        to_licenses: hd.licenses.clone(),
                        to_tier: Some(hd.tier.clone()),
                    });
                }
            }
        }
    }
    for (key, bd) in &base_map {
        if !head_map.contains_key(key) {
            changes.push(DependencyChange {
                kind: DependencyChangeKind::Removed,
                ecosystem: key.0.clone(),
                name: key.1.clone(),
                from_version: bd.version.clone(),
                to_version: None,
                from_licenses: bd.licenses.clone(),
                to_licenses: vec![],
                to_tier: None,
            });
        }
    }
    changes.sort_by(|a, b| (kind_rank(a.kind), &a.ecosystem, &a.name).cmp(&(kind_rank(b.kind), &b.ecosystem, &b.name)));
    changes
}

fn tier_badge(tier: Option<&str>) -> &'static str {
    match tier {
        Some("red") => "\u{1f534}",
        Some("warning") => "\u{1f7e1}",
        Some("green") => "\u{1f7e2}",
        _ => "\u{26aa}",
    }
}

fn join_or(items: &[String], fallback: &str) -> String {
    if items.is_empty() {
        fallback.to_string()
    } else {
        items.join(", ")
    }
}

/// Renders `changes` as the sticky PR comment body (marker included —
/// see `DEPENDENCY_REVIEW_MARKER`). `None` when there's nothing to say
/// (`changes` is empty) so a caller can skip posting/updating a comment
/// entirely rather than posting an empty-looking one.
pub fn render_dependency_diff_comment(changes: &[DependencyChange]) -> Option<String> {
    if changes.is_empty() {
        return None;
    }
    let added: Vec<&DependencyChange> = changes.iter().filter(|c| c.kind == DependencyChangeKind::Added).collect();
    let removed: Vec<&DependencyChange> = changes.iter().filter(|c| c.kind == DependencyChangeKind::Removed).collect();
    let updated: Vec<&DependencyChange> = changes.iter().filter(|c| c.kind == DependencyChangeKind::VersionChanged).collect();
    let license_changed: Vec<&DependencyChange> = changes.iter().filter(|c| c.kind == DependencyChangeKind::LicenseChanged).collect();

    let mut lines = vec![
        DEPENDENCY_REVIEW_MARKER.to_string(),
        "### \u{1f4e6} Dependency Review".to_string(),
        String::new(),
        format!("**{}** added \u{b7} **{}** removed \u{b7} **{}** updated \u{b7} **{}** license change(s)", added.len(), removed.len(), updated.len(), license_changed.len()),
        String::new(),
    ];

    if !added.is_empty() {
        lines.push(format!("<details open><summary>\u{2795} Added ({})</summary>", added.len()));
        lines.push(String::new());
        for c in &added {
            lines.push(format!("- {} `{}@{}` ({})", tier_badge(c.to_tier.as_deref()), c.name, c.to_version.as_deref().unwrap_or("?"), c.ecosystem));
        }
        lines.push(String::new());
        lines.push("</details>".to_string());
        lines.push(String::new());
    }
    if !removed.is_empty() {
        lines.push(format!("<details><summary>\u{2796} Removed ({})</summary>", removed.len()));
        lines.push(String::new());
        for c in &removed {
            lines.push(format!("- `{}@{}` ({})", c.name, c.from_version.as_deref().unwrap_or("?"), c.ecosystem));
        }
        lines.push(String::new());
        lines.push("</details>".to_string());
        lines.push(String::new());
    }
    if !updated.is_empty() {
        lines.push(format!("<details open><summary>\u{2b06}\u{fe0f} Updated ({})</summary>", updated.len()));
        lines.push(String::new());
        for c in &updated {
            lines.push(format!("- {} `{}` {} \u{2192} {} ({})", tier_badge(c.to_tier.as_deref()), c.name, c.from_version.as_deref().unwrap_or("?"), c.to_version.as_deref().unwrap_or("?"), c.ecosystem));
        }
        lines.push(String::new());
        lines.push("</details>".to_string());
        lines.push(String::new());
    }
    if !license_changed.is_empty() {
        lines.push(format!("<details open><summary>\u{2696}\u{fe0f} License changes ({})</summary>", license_changed.len()));
        lines.push(String::new());
        for c in &license_changed {
            lines.push(format!("- {} `{}` {} \u{2192} {} ({})", tier_badge(c.to_tier.as_deref()), c.name, join_or(&c.from_licenses, "unknown"), join_or(&c.to_licenses, "unknown"), c.ecosystem));
        }
        lines.push(String::new());
        lines.push("</details>".to_string());
        lines.push(String::new());
    }
    lines.push("_Posted automatically by [Ignite](https://github.com/nunomcpereira/ignite)'s dependency review \u{2014} updates on every push._".to_string());
    Some(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scan(manifests: serde_json::Value) -> serde_json::Value {
        json!({ "ok": true, "manifests": manifests })
    }

    #[test]
    fn diff_detects_added_dependency() {
        let base = scan(json!([{"file": "package.json", "ecosystem": "npm", "dependencies": []}]));
        let head = scan(json!([{"file": "package.json", "ecosystem": "npm", "dependencies": [{"name": "lodash", "version": "4.17.21", "licenses": ["MIT"], "tier": "green"}]}]));
        let changes = diff_dependency_scans(&base, &head);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, DependencyChangeKind::Added);
        assert_eq!(changes[0].name, "lodash");
        assert_eq!(changes[0].to_version.as_deref(), Some("4.17.21"));
    }

    #[test]
    fn diff_detects_removed_dependency() {
        let base = scan(json!([{"file": "package.json", "ecosystem": "npm", "dependencies": [{"name": "left-pad", "version": "1.0.0", "licenses": ["MIT"], "tier": "green"}]}]));
        let head = scan(json!([{"file": "package.json", "ecosystem": "npm", "dependencies": []}]));
        let changes = diff_dependency_scans(&base, &head);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, DependencyChangeKind::Removed);
        assert_eq!(changes[0].name, "left-pad");
    }

    #[test]
    fn diff_detects_version_change() {
        let base = scan(json!([{"file": "Cargo.toml", "ecosystem": "cargo", "dependencies": [{"name": "serde", "version": "1.0.100", "licenses": ["MIT"], "tier": "green"}]}]));
        let head = scan(json!([{"file": "Cargo.toml", "ecosystem": "cargo", "dependencies": [{"name": "serde", "version": "1.0.200", "licenses": ["MIT"], "tier": "green"}]}]));
        let changes = diff_dependency_scans(&base, &head);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, DependencyChangeKind::VersionChanged);
        assert_eq!(changes[0].from_version.as_deref(), Some("1.0.100"));
        assert_eq!(changes[0].to_version.as_deref(), Some("1.0.200"));
    }

    #[test]
    fn diff_detects_license_change_when_version_is_unchanged() {
        let base = scan(json!([{"file": "package.json", "ecosystem": "npm", "dependencies": [{"name": "weird-pkg", "version": "1.0.0", "licenses": ["MIT"], "tier": "green"}]}]));
        let head = scan(json!([{"file": "package.json", "ecosystem": "npm", "dependencies": [{"name": "weird-pkg", "version": "1.0.0", "licenses": ["GPL-3.0"], "tier": "red"}]}]));
        let changes = diff_dependency_scans(&base, &head);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, DependencyChangeKind::LicenseChanged);
        assert_eq!(changes[0].to_tier.as_deref(), Some("red"));
    }

    #[test]
    fn diff_is_empty_when_nothing_changed() {
        let m = json!([{"file": "package.json", "ecosystem": "npm", "dependencies": [{"name": "lodash", "version": "4.17.21", "licenses": ["MIT"], "tier": "green"}]}]);
        let scan_json = scan(m);
        assert!(diff_dependency_scans(&scan_json, &scan_json).is_empty());
    }

    #[test]
    fn render_returns_none_for_empty_diff() {
        assert!(render_dependency_diff_comment(&[]).is_none());
    }

    #[test]
    fn render_includes_marker_and_sections() {
        let base = scan(json!([{"file": "package.json", "ecosystem": "npm", "dependencies": []}]));
        let head = scan(json!([{"file": "package.json", "ecosystem": "npm", "dependencies": [{"name": "lodash", "version": "4.17.21", "licenses": ["MIT"], "tier": "green"}]}]));
        let changes = diff_dependency_scans(&base, &head);
        let body = render_dependency_diff_comment(&changes).unwrap();
        assert!(body.starts_with(DEPENDENCY_REVIEW_MARKER));
        assert!(body.contains("Added (1)"));
        assert!(body.contains("lodash@4.17.21"));
    }
}
