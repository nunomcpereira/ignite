//! Auto-fix PR bot — the Dependabot-parity gap `scheduled-rescan` leaves
//! open: Ignite's `dependency-vulnerability` check (deps.dev advisories,
//! see `ignite-dependency-license-scan`) *detects* a known-vulnerable
//! dependency but never proposes the fix the way Dependabot's version-bump
//! PRs do. This crate closes that gap for every manifest ecosystem
//! `ignite-studio-manifests` parses (npm/pypi/cargo/go/maven/gradle/nuget):
//! for each vulnerable dependency, look up the advisory's minimum fixed
//! version (OSV.dev — deps.dev's own advisory schema doesn't carry a
//! per-package fixed-version field, only the generic CVE/GHSA metadata
//! `VulnFinding` already captures), bump exactly that one manifest line,
//! and open a PR.
//!
//! **Deliberately conservative, not a full Dependabot replacement:**
//! - Only a single, simple version constraint is auto-edited (a bare
//!   version or one with a `^`/`~`/`==`/`>=`-style prefix). Anything more
//!   complex (OR ranges, wildcards, multiple comparators) is left for a
//!   human — see `is_simple_range`.
//! - A fix that crosses a semver major version is flagged
//!   (`FixCandidate::major_bump`) but never auto-applied — a major bump
//!   can be a real breaking change, which is exactly the kind of judgment
//!   call this tool shouldn't make unattended. `--apply` skips these;
//!   they still show up in the dry-run/plan output for a human to action.
//! - Only the first `fixed` event OSV reports for the matching
//!   `affected` package entry is used, not a full range-intersection
//!   resolution. Good enough to propose *a* correct fix version in the
//!   overwhelming common case (one vulnerable range, one fix); a
//!   multi-range advisory could in principle want a different minimum —
//!   still strictly better than the silence Ignite ships today.
//! - One branch + PR per (manifest file, dependency, fixed version) by
//!   default, matching Dependabot's own per-dependency granularity rather
//!   than bundling a repo's fixes into one PR a reviewer has to
//!   accept/reject as a unit. `--group-by ecosystem` (CLI-only, opt-in —
//!   see `GroupBy`/`group_candidates`/`apply_fix_group`) is Dependabot's
//!   `groups:` config parity for the opposite case: bundle every
//!   candidate for one package manager (never mixing a vulnerability fix
//!   with a routine update) into a single PR instead.
//! - Idempotent via branch name alone (`git ls-remote --heads` before
//!   creating): no attempt to auto-merge, close stale fix PRs when a
//!   dependency is later fixed some other way, or track an in-flight
//!   PR's review state. An operator/cron still supervises this the same
//!   way `scheduled-rescan` is supervised.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

mod dependabot_config;

use ignite_dependency_license_scan::{scan_dependency_vulnerabilities, VulnScanManifest};
use ignite_deps_dev_client::{parse_semver, DepsDevClient};
use ignite_github_api::GithubApi;
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use serde::Serialize;
use std::path::{Path, PathBuf};

pub use dependabot_config::{is_ignored as dependabot_ignores, load_dependabot_ignore_rules, IgnoreRule as DependabotIgnoreRule};

/// Which discovery path produced a [`FixCandidate`] — drives wording in
/// `pr_title_for`/`pr_body_for` (an advisory-driven fix cites the CVE/GHSA
/// and OSV.dev; a routine update cites "latest available release")
/// but nothing about `apply_fix`'s actual mechanics differs between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixKind {
    /// Driven by a known advisory (`discover_fix_candidates` / OSV.dev).
    Vulnerability,
    /// Dependabot's other half — no known vulnerability, just proposing
    /// the latest available non-major release (`discover_routine_update_candidates`).
    RoutineUpdate,
}

#[derive(Debug, Clone, Serialize)]
pub struct FixCandidate {
    pub manifest_file: String,
    pub ecosystem: &'static str,
    pub dep_name: String,
    pub dep_line: usize,
    pub current_range: String,
    pub resolved_version: Option<String>,
    pub fixed_version: String,
    /// Empty for `FixKind::RoutineUpdate` — there's no advisory driving it.
    pub advisory_id: String,
    pub summary: String,
    /// Fixed version crosses a semver major from the resolved installed
    /// version — never auto-applied, see the module doc.
    pub major_bump: bool,
    pub kind: FixKind,
}

/// `ignite-studio-manifests`' ecosystem tag -> OSV.dev's own ecosystem
/// name (they don't match: OSV uses "PyPI"/"crates.io"/"Go"/"Maven", not
/// deps.dev's lowercase "pypi"/"cargo"/"go"/"maven").
fn osv_ecosystem(ecosystem: &str) -> Option<&'static str> {
    match ecosystem {
        "npm" => Some("npm"),
        "pypi" => Some("PyPI"),
        "cargo" => Some("crates.io"),
        "go" => Some("Go"),
        "maven" => Some("Maven"),
        // Gradle artifacts resolve via Maven Central coordinates and OSV
        // advisories for them are filed under the "Maven" ecosystem too —
        // same "gradle folds into maven" convention `dependency-license-
        // scan`'s own `map_ort_ecosystem` already uses for ORT-detected
        // findings.
        "gradle" => Some("Maven"),
        "nuget" => Some("NuGet"),
        _ => None,
    }
}

/// The leading constraint-operator characters a manifest version string
/// can carry (`^1.2.3`, `~=1.2.3`, `==1.2.3`, `>=1.2.3`) — everything
/// after this prefix is expected to be a plain version. Includes `v`
/// (Go modules are always `v`-prefixed, e.g. `v1.2.3`) so `rewrite_range`
/// preserves it instead of emitting an invalid bare version into go.mod.
const RANGE_PREFIX_CHARS: &[char] = &['^', '~', '=', '<', '>', '!', 'v', ' '];

/// True only for a single simple constraint this tool knows how to bump
/// in place — a bare version, or one prefix-operator plus a plain
/// version. Rejects OR-ranges (`||`, `,`), wildcards (`*`), and
/// hyphen-ranges (`1.0.0 - 2.0.0`) — anything ambiguous is left alone
/// rather than guessed at.
pub fn is_simple_range(range: &str) -> bool {
    if range.is_empty() {
        return false;
    }
    let rest: String = range.chars().skip_while(|c| RANGE_PREFIX_CHARS.contains(c)).collect();
    if rest.is_empty() || rest.contains(['x', 'X', '*']) {
        return false;
    }
    // Gradle's dynamic-version wildcard is a trailing `+` (`1.2.+`), not
    // `x`/`*` like the other ecosystems above — reject only a *bare*
    // trailing `+` (no more characters after it), so real semver build
    // metadata (`1.2.3+build.1`, accepted by the character class below)
    // is unaffected.
    if rest.ends_with('+') {
        return false;
    }
    rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+')
}

/// Rebuilds a version constraint at `fixed_version`, preserving whatever
/// leading operator/prefix the original range used (`^1.2.3` -> `^2.0.1`,
/// `==1.2.3` -> `==2.0.1`, bare `1.2.3` -> bare `2.0.1`).
pub fn rewrite_range(old_range: &str, fixed_version: &str) -> String {
    let prefix: String = old_range.chars().take_while(|c| RANGE_PREFIX_CHARS.contains(c)).collect();
    format!("{prefix}{fixed_version}")
}

/// True when `fixed` and `resolved` both parse as semver and represent a
/// breaking bump: a differing major component, or — per semver's own 0.x
/// convention, where every `0.y.z` minor is allowed to break — a differing
/// minor while major is `0`. Unparseable versions (Go pseudo-versions, some
/// Maven schemes) are never flagged — no false confidence either way, but
/// erring toward "let a human look" only makes sense when we can actually
/// tell there's a breaking jump.
pub fn is_major_bump(resolved: &str, fixed: &str) -> bool {
    match (parse_semver(resolved), parse_semver(fixed)) {
        (Some((rm, rn, _)), Some((fm, fn_, _))) => rm != fm || (rm == 0 && rn != fn_),
        _ => false,
    }
}

/// True when `fixed` is not a strict semver improvement over `resolved` —
/// OSV.dev's `ranges`/`events` schema can list an earlier `fixed` window
/// that a later `introduced` event re-opens, so naively taking the first
/// `fixed` event (see `fetch_osv_fixed_version`) can propose a version
/// that's actually a downgrade, or no improvement at all, over what's
/// already installed. Unparseable versions are never flagged as
/// regressions — we can't tell, so we don't block the candidate.
fn is_non_improving_fix(resolved: &str, fixed: &str) -> bool {
    matches!((parse_semver(resolved), parse_semver(fixed)), (Some(r), Some(f)) if f <= r)
}

/// Queries OSV.dev directly for `advisory_id`'s full record and returns
/// the first `fixed` version event under the `affected` entry matching
/// `dep_name`/`ecosystem`. deps.dev's own advisory API (already used by
/// `ignite-dependency-license-scan`) proxies a subset of OSV that drops
/// per-package affected/fixed ranges, so this goes to the source.
pub async fn fetch_osv_fixed_version(http: &reqwest::Client, advisory_id: &str, ecosystem: &str, dep_name: &str) -> Option<String> {
    let osv_eco = osv_ecosystem(ecosystem)?;
    let url = format!("https://api.osv.dev/v1/vulns/{}", advisory_id);
    let resp = http.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    let affected = body.get("affected")?.as_array()?;
    for entry in affected {
        let pkg = entry.get("package")?;
        let name_matches = pkg.get("name").and_then(|v| v.as_str()).map(|n| n.eq_ignore_ascii_case(dep_name)).unwrap_or(false);
        let eco_matches = pkg.get("ecosystem").and_then(|v| v.as_str()).map(|e| e.eq_ignore_ascii_case(osv_eco)).unwrap_or(false);
        if !name_matches || !eco_matches {
            continue;
        }
        if let Some(ranges) = entry.get("ranges").and_then(|r| r.as_array()) {
            for range in ranges {
                if let Some(events) = range.get("events").and_then(|e| e.as_array()) {
                    for event in events {
                        if let Some(fixed) = event.get("fixed").and_then(|f| f.as_str()) {
                            return Some(fixed.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Runs the real dependency-vulnerability scan against a checked-out repo
/// and, for every finding whose manifest line is a simple constraint,
/// resolves a proposed fix version via OSV.dev.
pub async fn discover_fix_candidates(root: &Path, deps_client: &DepsDevClient, http: &reqwest::Client) -> Vec<FixCandidate> {
    let manifests: Vec<VulnScanManifest> = scan_dependency_vulnerabilities(root, deps_client).await.unwrap_or_default();
    let ignore_rules = load_dependabot_ignore_rules(root);
    let mut candidates = Vec::new();

    for manifest in &manifests {
        for dep in &manifest.dependencies {
            let Some(line) = dep.line else { continue };
            if !is_simple_range(&dep.version_range) {
                continue;
            }
            if dependabot_ignores(&ignore_rules, manifest.ecosystem, &dep.name) {
                continue;
            }
            for vuln in &dep.vulnerabilities {
                let Some(advisory_id) = vuln.id.clone().or_else(|| vuln.aliases.first().cloned()) else { continue };
                let Some(fixed_version) = fetch_osv_fixed_version(http, &advisory_id, manifest.ecosystem, &dep.name).await else { continue };
                if dep.version.as_deref().is_some_and(|resolved| is_non_improving_fix(resolved, &fixed_version)) {
                    continue;
                }
                let major_bump = dep.version.as_deref().map(|resolved| is_major_bump(resolved, &fixed_version)).unwrap_or(false);
                let mut summary = format!("{}@{} -> {fixed_version} ({advisory_id})", dep.name, dep.version.clone().unwrap_or_else(|| dep.version_range.clone()));
                if let Some(title) = &vuln.title {
                    summary.push_str(&format!(": {title}"));
                }
                candidates.push(FixCandidate {
                    manifest_file: manifest.file.clone(),
                    ecosystem: manifest.ecosystem,
                    dep_name: dep.name.clone(),
                    dep_line: line,
                    current_range: dep.version_range.clone(),
                    resolved_version: dep.version.clone(),
                    fixed_version,
                    advisory_id,
                    summary,
                    major_bump,
                    kind: FixKind::Vulnerability,
                });
            }
        }
    }
    candidates
}

/// Highest parseable, non-prerelease (no `-` suffix, e.g. `1.2.3-rc.1`)
/// semver in `versions` — deps.dev's version list isn't guaranteed sorted,
/// and Dependabot's own default posture for routine version updates
/// (unlike security updates, which must take whatever fixed version an
/// advisory names) is to never propose a pre-release.
fn latest_stable_version(versions: &[String]) -> Option<String> {
    versions
        .iter()
        .filter(|v| !v.contains('-'))
        .filter_map(|v| parse_semver(v).map(|parsed| (parsed, v.clone())))
        .max_by(|a, b| ignite_deps_dev_client::compare_semver(a.0, b.0))
        .map(|(_, v)| v)
}

/// Dependabot's other half of dependency automation: propose bumping
/// every manifest dependency to its latest available release, regardless
/// of whether anything currently flags it vulnerable. Complements
/// `discover_fix_candidates` rather than replacing it — a dependency can
/// appear in both lists with different target versions (its OSV fix vs.
/// its actual latest release); `apply_fix`'s branch-per-(dep,version)
/// naming means the two never collide, they'd just open two PRs.
///
/// Same conservatism as the vulnerability path: only a simple version
/// constraint is considered (`is_simple_range`), and a fix crossing a
/// semver major is still returned (so a dry-run plan shows it) but flagged
/// `major_bump` so `apply_fix` skips it unattended — a routine update is
/// exactly the case where "the tool decided a major bump was fine" is
/// least acceptable to ship unreviewed.
pub async fn discover_routine_update_candidates(root: &Path, deps_client: &DepsDevClient) -> Vec<FixCandidate> {
    let mut candidates = Vec::new();
    let Ok(files) = ignite_fs_utils::walk_files(root) else { return candidates };
    let ignore_rules = load_dependabot_ignore_rules(root);

    for file in files {
        let base = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let Some(spec) = ignite_studio_manifests::find_manifest_spec(&base) else { continue };
        let Ok(content) = std::fs::read_to_string(&file) else { continue };
        let raw_deps: Vec<ignite_studio_manifests::ManifestDep> = (spec.parse)(&content).into_iter().take(ignite_studio_manifests::STUDIO_MAX_DEPS_PER_MANIFEST).collect();
        let lockfile_versions = ignite_dependency_license_scan::resolve_lockfile_versions(&file, root, spec.ecosystem);
        let rel_file = file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");

        for dep in &raw_deps {
            if !is_simple_range(&dep.version_range) {
                continue;
            }
            if dependabot_ignores(&ignore_rules, spec.ecosystem, &dep.name) {
                continue;
            }
            let Some(current) = lockfile_versions.get(&dep.name).cloned().or_else(|| ignite_license_classification::best_effort_version(&dep.version_range)) else { continue };
            let Some(versions) = deps_client.fetch_version_list(spec.system, &dep.name).await else { continue };
            let Some(latest) = latest_stable_version(&versions) else { continue };
            if is_non_improving_fix(&current, &latest) {
                continue;
            }
            let Some(line) = ignite_deps_dev_client::find_manifest_dep_line(&content, &dep.name, spec.ecosystem) else { continue };
            let major_bump = is_major_bump(&current, &latest);
            candidates.push(FixCandidate {
                manifest_file: rel_file.clone(),
                ecosystem: spec.ecosystem,
                dep_name: dep.name.clone(),
                dep_line: line,
                current_range: dep.version_range.clone(),
                resolved_version: Some(current.clone()),
                fixed_version: latest.clone(),
                advisory_id: String::new(),
                summary: format!("{}@{current} -> {latest} (routine update)", dep.name),
                major_bump,
                kind: FixKind::RoutineUpdate,
            });
        }
    }
    candidates
}

/// Deterministic per-fix branch name — doubles as the idempotency key
/// (see `branch_exists_on_remote`): re-running this tool against an
/// unchanged advisory/fix pair always names the same branch.
pub fn branch_name_for(candidate: &FixCandidate) -> String {
    let slug: String = candidate.dep_name.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).collect();
    format!("ignite/autofix/{}-{}-{}", candidate.ecosystem, slug, candidate.fixed_version)
}

/// Dependabot's `groups:` config parity: without it, `auto-fix-pr` opens
/// one PR per dependency, which floods a legacy/stale repo with dozens of
/// PRs when many candidates surface at once. `Ecosystem` is the one
/// strategy implemented — Dependabot's own most common grouping pattern
/// (bundle every compatible update for one package manager into a single
/// PR) — deliberately never mixing `FixKind::Vulnerability` with
/// `FixKind::RoutineUpdate` in the same group even under `Ecosystem`,
/// since their commit-prefix/PR wording and urgency genuinely differ.
/// `None` (the default — an existing deployment's PR-per-fix behavior
/// never changes unless `--group-by` is passed) keeps every candidate in
/// its own singleton group, which `apply_fix_group`'s single-member
/// fast-path then hands straight to the original `apply_fix` — so
/// branch names/idempotency for the ungrouped case are byte-identical to
/// before this existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBy {
    None,
    Ecosystem,
}

impl std::str::FromStr for GroupBy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ecosystem" => Ok(GroupBy::Ecosystem),
            other => Err(format!("unknown --group-by value \"{other}\" (expected: ecosystem)")),
        }
    }
}

/// Partitions `candidates` per `group_by` — see [`GroupBy`]. Group order
/// and each group's member order are otherwise stable (first-seen order
/// from `candidates`), so a re-run with the same discovery results
/// produces the same groups in the same order.
pub fn group_candidates(candidates: Vec<FixCandidate>, group_by: GroupBy) -> Vec<Vec<FixCandidate>> {
    match group_by {
        GroupBy::None => candidates.into_iter().map(|c| vec![c]).collect(),
        GroupBy::Ecosystem => {
            let mut order: Vec<(&'static str, FixKind)> = Vec::new();
            let mut groups: std::collections::HashMap<(&'static str, FixKind), Vec<FixCandidate>> = std::collections::HashMap::new();
            for candidate in candidates {
                let key = (candidate.ecosystem, candidate.kind);
                if !groups.contains_key(&key) {
                    order.push(key);
                }
                groups.entry(key).or_default().push(candidate);
            }
            order.into_iter().map(|key| groups.remove(&key).unwrap_or_default()).collect()
        }
    }
}

/// FNV-1a 64-bit — not cryptographic, just a short deterministic digest so
/// [`group_branch_name`] doesn't need to embed every member's name/version
/// verbatim (a group can have dozens of members) while still changing
/// whenever the group's actual membership changes, so a re-run with an
/// unchanged set of candidates always names the same branch (the group
/// equivalent of `branch_name_for`'s per-candidate idempotency key).
fn fnv1a64(data: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in data.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Deterministic branch name for a *group* of candidates — the multi-
/// member counterpart to `branch_name_for`. Hashes the sorted
/// `dep@version` pairs of every member so the branch name changes exactly
/// when group membership changes (a dependency added, removed, or
/// re-resolved to a different fixed version), same idempotency guarantee
/// `branch_exists_on_remote` relies on for the single-candidate path.
pub fn group_branch_name(ecosystem: &str, kind: FixKind, group: &[FixCandidate]) -> String {
    let mut keys: Vec<String> = group.iter().map(|c| format!("{}@{}", c.dep_name, c.fixed_version)).collect();
    keys.sort();
    let hash = fnv1a64(&keys.join(","));
    let kind_tag = match kind {
        FixKind::Vulnerability => "vuln",
        FixKind::RoutineUpdate => "routine",
    };
    format!("ignite/autofix-group/{ecosystem}-{kind_tag}-{hash:016x}")
}

pub fn pr_title_for_group(ecosystem: &str, kind: FixKind, member_count: usize) -> String {
    match kind {
        FixKind::Vulnerability => format!("[Ignite auto-fix] bump {member_count} {ecosystem} dependencies (grouped)"),
        FixKind::RoutineUpdate => format!("[Ignite routine update] bump {member_count} {ecosystem} dependencies (grouped)"),
    }
}

/// `lockfile_notes`: one line per distinct lockfile path this group
/// touched, already formatted (regenerated vs. failed) — built by the
/// caller since it has the actual regeneration results, not by this
/// function.
pub fn pr_body_for_group(kind: FixKind, group: &[FixCandidate], lockfile_notes: &[String]) -> String {
    let intro = match kind {
        FixKind::Vulnerability => "Ignite's scheduled dependency-vulnerability scan flagged the following dependencies for known advisories, grouped into one PR per Dependabot's own `groups:` convention:\n\n",
        FixKind::RoutineUpdate => "Ignite's routine dependency-update sweep found newer releases for the following dependencies. No known vulnerability is driving this — it's a routine version-currency update, grouped into one PR per Dependabot's own `groups:` convention:\n\n",
    };
    let mut body = String::from(intro);
    for candidate in group {
        let target = candidate.resolved_version.as_deref().unwrap_or(&candidate.current_range);
        match candidate.kind {
            FixKind::Vulnerability => body.push_str(&format!("- `{}`: `{target}` -> `{}` in `{}` ({})\n", candidate.dep_name, candidate.fixed_version, candidate.manifest_file, candidate.advisory_id)),
            FixKind::RoutineUpdate => body.push_str(&format!("- `{}`: `{target}` -> `{}` in `{}`\n", candidate.dep_name, candidate.fixed_version, candidate.manifest_file)),
        }
    }
    if !lockfile_notes.is_empty() {
        body.push('\n');
        for note in lockfile_notes {
            body.push_str(note);
            body.push('\n');
        }
    }
    body.push_str(
        "\nOpened automatically by `auto-fix-pr --group-by ecosystem` (dry-run reviewed before `--apply`). \
         Verify the bumps don't break anything before merging — these are targeted \
         version-constraint edits, not a full compatibility check.\n",
    );
    body
}

pub fn pr_title_for(candidate: &FixCandidate) -> String {
    match candidate.kind {
        FixKind::Vulnerability => format!("[Ignite auto-fix] bump {} to {} ({})", candidate.dep_name, candidate.fixed_version, candidate.advisory_id),
        FixKind::RoutineUpdate => format!("[Ignite routine update] bump {} to {}", candidate.dep_name, candidate.fixed_version),
    }
}

/// `lockfile_status`: `Some(Ok(path))` when the lockfile at `path` was
/// regenerated alongside the manifest edit, `Some(Err(reason))` when
/// regeneration was attempted but failed, `None` when this ecosystem/repo
/// has no separate lockfile to regenerate.
pub fn pr_body_for(candidate: &FixCandidate, lockfile_status: Option<Result<&str, &str>>) -> String {
    let lockfile_note = match lockfile_status {
        Some(Ok(path)) => format!("- Lockfile: `{path}` regenerated to match.\n"),
        Some(Err(reason)) => format!("- Lockfile: **not** regenerated ({reason}) — this PR's manifest edit alone may not be mergeable if CI enforces a lockfile check; finish the lockfile update locally before merging.\n"),
        None => String::new(),
    };
    let (intro, fixed_line) = match candidate.kind {
        FixKind::Vulnerability => (
            format!("Ignite's scheduled dependency-vulnerability scan flagged **{}@{}** in `{}` for a known advisory.\n\n- Advisory: {}\n", candidate.dep_name, candidate.resolved_version.as_deref().unwrap_or(&candidate.current_range), candidate.manifest_file, candidate.advisory_id),
            format!("- Fixed version (per OSV.dev): `{}`\n", candidate.fixed_version),
        ),
        FixKind::RoutineUpdate => (
            format!("Ignite's routine dependency-update sweep found a newer release of **{}@{}** in `{}`. No known vulnerability is driving this — it's a routine version-currency update, Dependabot's other half.\n\n", candidate.dep_name, candidate.resolved_version.as_deref().unwrap_or(&candidate.current_range), candidate.manifest_file),
            format!("- Latest available version: `{}`\n", candidate.fixed_version),
        ),
    };
    format!(
        "{intro}{fixed_line}- Change: `{}` -> `{}`\n\
         {lockfile_note}\n\
         Opened automatically by `auto-fix-pr` (dry-run reviewed before `--apply`). \
         Verify the bump doesn't break anything before merging — this is a targeted \
         version-constraint edit, not a full compatibility check.\n",
        candidate.current_range,
        rewrite_range(&candidate.current_range, &candidate.fixed_version),
    )
}

/// Rewrites `content`'s `dep_line` (1-indexed) by replacing the first
/// occurrence of `old_range` with its bumped equivalent. Returns `None`
/// (never edits) if the line doesn't actually contain `old_range` — a
/// stale line number or a range that changed between scan and edit is a
/// reason to skip, not to guess at the wrong line.
pub fn apply_fix_to_content(content: &str, dep_line: usize, old_range: &str, fixed_version: &str) -> Option<String> {
    if dep_line == 0 {
        return None;
    }
    let mut lines: Vec<&str> = content.split('\n').collect();
    let idx = dep_line - 1;
    let line = lines.get(idx)?;
    // Replace the *last* occurrence of `old_range` on the line, not the
    // first: every supported manifest shape puts the dependency name
    // before its version constraint on the line (npm's `"name": "range"`,
    // Cargo's `name = "range"`, requirements.txt's `name==range`, go.mod's
    // `name range`, pom.xml's `<artifactId>..</artifactId><version>range`)
    // — so the version is always the rightmost match. A first-occurrence
    // replace corrupts the package name itself whenever `old_range`
    // happens to also be a substring of it (e.g. a dep literally named
    // `my-1.2.3-lib` being fixed to version `1.2.3`).
    let match_start = line.rfind(old_range)?;
    let new_range = rewrite_range(old_range, fixed_version);
    let mut new_line = String::with_capacity(line.len() - old_range.len() + new_range.len());
    new_line.push_str(&line[..match_start]);
    new_line.push_str(&new_range);
    new_line.push_str(&line[match_start + old_range.len()..]);
    lines[idx] = &new_line;
    // `lines[idx]` borrows `new_line`, which would be dropped at scope
    // end — join immediately instead of returning the borrowed Vec.
    Some(lines.join("\n"))
}

#[derive(Debug)]
pub struct FixOutcome {
    pub candidate_summary: String,
    pub branch: String,
    pub applied: bool,
    pub skipped_reason: Option<String>,
    pub pr_url: Option<String>,
    pub error: Option<String>,
}

/// True if `branch` already exists on `origin` — the idempotency check.
/// Read-only, safe in dry-run.
pub async fn branch_exists_on_remote(runner: &ToolRunner, clone_dir: &str, branch: &str) -> bool {
    match runner.run_tool("git", &["ls-remote".to_string(), "--heads".to_string(), "origin".to_string(), branch.to_string()], clone_dir, RunToolOptions::default()).await {
        Ok(out) => !out.stdout.trim().is_empty(),
        Err(_) => false,
    }
}

/// The package-manager invocation that regenerates `manifest_dir`'s
/// lockfile in place, and the lockfile's own filename (relative to
/// `manifest_dir`), for the three ecosystems that carry a lockfile
/// distinct from the manifest itself — `requirements.txt`/pypi is
/// already the fully-pinned file (no separate lock step) and Maven's
/// `pom.xml` has no lockfile concept at all, so neither needs this.
/// Returns `None` when the ecosystem's expected lockfile isn't actually
/// present (e.g. an npm project with no committed lockfile): nothing to
/// regenerate, and creating one from scratch would be an unrelated
/// change this tool shouldn't make unattended.
fn lockfile_command(manifest_dir: &Path, candidate: &FixCandidate) -> Option<(&'static str, Vec<String>, &'static str)> {
    match candidate.ecosystem {
        "npm" => {
            if manifest_dir.join("package-lock.json").is_file() {
                Some(("npm", vec!["install".to_string(), "--package-lock-only".to_string(), "--no-audit".to_string(), "--no-fund".to_string()], "package-lock.json"))
            } else if manifest_dir.join("yarn.lock").is_file() {
                Some(("yarn", vec!["install".to_string(), "--mode".to_string(), "update-lockfile".to_string()], "yarn.lock"))
            } else if manifest_dir.join("pnpm-lock.yaml").is_file() {
                Some(("pnpm", vec!["install".to_string(), "--lockfile-only".to_string()], "pnpm-lock.yaml"))
            } else {
                None
            }
        }
        "cargo" if manifest_dir.join("Cargo.lock").is_file() => {
            Some(("cargo", vec!["update".to_string(), "-p".to_string(), candidate.dep_name.clone(), "--precise".to_string(), candidate.fixed_version.clone()], "Cargo.lock"))
        }
        "go" if manifest_dir.join("go.sum").is_file() => Some(("go", vec!["mod".to_string(), "tidy".to_string()], "go.sum")),
        // `dotnet restore` regenerates `packages.lock.json` in place when
        // the project already opts into
        // `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`
        // — same "only regenerate if the lockfile already exists" gate
        // every other ecosystem here uses, so a project that never opted
        // into lockfiles at all is left untouched.
        "nuget" if manifest_dir.join("packages.lock.json").is_file() => {
            Some(("dotnet", vec!["restore".to_string(), "--force-evaluate".to_string()], "packages.lock.json"))
        }
        // A single-module Gradle project's lockfile sits right next to its
        // `build.gradle` as `gradle.lockfile` — a multi-module project
        // instead writes one lockfile per subproject
        // (`gradle/dependency-locks/*.lockfile`), which this doesn't
        // attempt to locate; same posture as every other best-effort step
        // here, a miss just means the lockfile doesn't get regenerated,
        // not that the fix fails.
        "gradle" if manifest_dir.join("gradle.lockfile").is_file() => {
            Some(("gradle", vec!["dependencies".to_string(), "--write-locks".to_string()], "gradle.lockfile"))
        }
        _ => None,
    }
}

/// Regenerates the ecosystem's lockfile after the manifest edit — the
/// Dependabot-parity gap a manifest-only edit leaves open, since most
/// CI setups fail a build whose lockfile no longer matches its manifest.
/// Best-effort: any failure (missing package-manager binary, network,
/// a version-resolution conflict) is folded into a warning string
/// rather than failing the whole fix — the PR still carries a correct
/// manifest edit, and a human can finish the lockfile by running the
/// same command locally. Returns the lockfile's path relative to
/// `clone_dir` (to stage alongside the manifest) when regeneration
/// actually ran and succeeded.
async fn regenerate_lockfile(runner: &ToolRunner, clone_dir: &str, candidate: &FixCandidate) -> (Option<String>, Option<String>) {
    let manifest_dir = Path::new(clone_dir).join(&candidate.manifest_file).parent().map(|p| p.to_path_buf()).unwrap_or_else(|| Path::new(clone_dir).to_path_buf());
    let Some((tool, args, lockfile_name)) = lockfile_command(&manifest_dir, candidate) else {
        return (None, None);
    };
    let dir_str = manifest_dir.to_string_lossy().into_owned();
    match runner.run_tool(tool, &args, &dir_str, RunToolOptions { timeout_ms: Some(5 * 60_000), ..Default::default() }).await {
        Ok(_) => {
            let rel_lockfile = Path::new(&candidate.manifest_file).parent().map(|p| p.join(lockfile_name)).unwrap_or_else(|| PathBuf::from(lockfile_name));
            (Some(rel_lockfile.to_string_lossy().into_owned()), None)
        }
        Err(e) => (None, Some(format!("{tool} {}: {e}", args.join(" ")))),
    }
}

/// Applies one fix candidate against an already-cloned `clone_dir`
/// (checked out at `base_branch`): creates/resets a deterministic branch
/// off `base_branch`, edits the one manifest line, commits, and — only
/// when `apply` is true — pushes and opens a PR. Leaves `clone_dir`
/// checked out on `base_branch` again afterward so the caller can process
/// the next candidate against a clean base.
#[allow(clippy::too_many_arguments)]
pub async fn apply_fix(runner: &ToolRunner, github_api: &GithubApi<'_>, full_name: &str, base_branch: &str, clone_dir: &str, candidate: &FixCandidate, token: &str, apply: bool) -> FixOutcome {
    let branch = branch_name_for(candidate);
    let candidate_summary = candidate.summary.clone();

    if candidate.major_bump {
        return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: Some("fix crosses a semver major version — needs manual review".to_string()), pr_url: None, error: None };
    }

    if branch_exists_on_remote(runner, clone_dir, &branch).await {
        return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: Some("branch already exists on origin — fix already proposed".to_string()), pr_url: None, error: None };
    }

    let manifest_path = Path::new(clone_dir).join(&candidate.manifest_file);
    let content = match std::fs::read_to_string(&manifest_path) {
        Ok(c) => c,
        Err(e) => return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: None, pr_url: None, error: Some(format!("failed to read {}: {e}", candidate.manifest_file)) },
    };
    let Some(new_content) = apply_fix_to_content(&content, candidate.dep_line, &candidate.current_range, &candidate.fixed_version) else {
        return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: Some(format!("manifest line {} no longer matches the scanned range — skipping (file changed since scan?)", candidate.dep_line)), pr_url: None, error: None };
    };

    if !apply {
        return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: Some("dry-run — pass --apply to open this PR".to_string()), pr_url: None, error: None };
    }

    let steps: Vec<(&str, Vec<String>)> = vec![("git", vec!["checkout".to_string(), "-B".to_string(), branch.clone(), base_branch.to_string()])];
    for (tool, args) in steps {
        if let Err(e) = runner.run_tool(tool, &args, clone_dir, RunToolOptions::default()).await {
            return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: None, pr_url: None, error: Some(format!("{tool} {}: {e}", args.join(" "))) };
        }
    }

    if let Err(e) = std::fs::write(&manifest_path, new_content) {
        let _ = runner.run_tool("git", &["checkout".to_string(), base_branch.to_string()], clone_dir, RunToolOptions::default()).await;
        return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: None, pr_url: None, error: Some(format!("failed to write {}: {e}", candidate.manifest_file)) };
    }

    let (lockfile_path, lockfile_warning) = regenerate_lockfile(runner, clone_dir, candidate).await;

    let mut add_args = vec!["add".to_string(), candidate.manifest_file.clone()];
    if let Some(lockfile_path) = &lockfile_path {
        add_args.push(lockfile_path.clone());
    }
    let prefix = match candidate.kind {
        FixKind::Vulnerability => format!("fix({}): bump {} to {} ({})", candidate.ecosystem, candidate.dep_name, candidate.fixed_version, candidate.advisory_id),
        FixKind::RoutineUpdate => format!("chore({}): bump {} to {}", candidate.ecosystem, candidate.dep_name, candidate.fixed_version),
    };
    let commit_message = match &lockfile_warning {
        Some(w) => format!("{prefix}\n\nLockfile regeneration skipped: {w}"),
        None => prefix,
    };
    let commit_steps: Vec<Vec<String>> = vec![
        add_args,
        vec!["-c".to_string(), "user.email=ignite-bot@localhost".to_string(), "-c".to_string(), "user.name=Ignite Auto-Fix".to_string(), "commit".to_string(), "-m".to_string(), commit_message],
    ];
    for args in commit_steps {
        if let Err(e) = runner.run_tool("git", &args, clone_dir, RunToolOptions::default()).await {
            let _ = runner.run_tool("git", &["checkout".to_string(), base_branch.to_string()], clone_dir, RunToolOptions::default()).await;
            return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: None, pr_url: None, error: Some(format!("git {}: {e}", args.join(" "))) };
        }
    }

    // Same `http.extraheader` convention `GithubApi::gh_clone_repo_branch`'s
    // token-only fallback uses — a one-off override for this invocation
    // only, never written into the clone's own `.git/config` (unlike
    // embedding the token in the remote URL, which would be).
    let push_result = runner
        .run_tool("git", &["-c".to_string(), format!("http.extraheader=AUTHORIZATION: bearer {token}"), "push".to_string(), "origin".to_string(), format!("HEAD:refs/heads/{branch}")], clone_dir, RunToolOptions::default())
        .await;
    // Always return to base_branch before reporting, so the caller can
    // process the next candidate regardless of how this one ended.
    let _ = runner.run_tool("git", &["checkout".to_string(), base_branch.to_string()], clone_dir, RunToolOptions::default()).await;

    if let Err(e) = push_result {
        return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: None, pr_url: None, error: Some(format!("git push: {e}")) };
    }

    let lockfile_status = match (&lockfile_path, &lockfile_warning) {
        (Some(path), _) => Some(Ok(path.as_str())),
        (None, Some(reason)) => Some(Err(reason.as_str())),
        (None, None) => None,
    };
    match github_api.gh_create_pr(full_name, base_branch, &branch, &pr_title_for(candidate), &pr_body_for(candidate, lockfile_status), token).await {
        Ok(pr) => FixOutcome { candidate_summary, branch, applied: true, skipped_reason: None, pr_url: Some(pr.url), error: None },
        Err(e) => FixOutcome { candidate_summary, branch, applied: true, skipped_reason: None, pr_url: None, error: Some(format!("branch pushed but PR creation failed: {e}")) },
    }
}

#[derive(Debug)]
pub struct GroupFixOutcome {
    pub group_summary: String,
    pub branch: String,
    pub applied: bool,
    pub skipped_reason: Option<String>,
    pub pr_url: Option<String>,
    pub error: Option<String>,
    /// Per-member status line, always populated (even on a whole-group
    /// skip/error) so a caller can print exactly which candidates ended up
    /// in the PR and which were individually skipped (major bump, stale
    /// manifest line).
    pub member_summaries: Vec<String>,
}

impl GroupFixOutcome {
    fn from_single(outcome: FixOutcome, major_bump_skips: &[&FixCandidate]) -> Self {
        let mut member_summaries = vec![outcome.candidate_summary.clone()];
        member_summaries.extend(major_bump_skips.iter().map(|c| format!("{} (skipped: crosses a semver major version)", c.summary)));
        GroupFixOutcome { group_summary: outcome.candidate_summary, branch: outcome.branch, applied: outcome.applied, skipped_reason: outcome.skipped_reason, pr_url: outcome.pr_url, error: outcome.error, member_summaries }
    }
}

/// Applies a *group* of fix candidates (same ecosystem + [`FixKind`], see
/// [`group_candidates`]) as a single branch/commit/PR instead of one per
/// candidate — Dependabot's `groups:` parity. `group` must already be
/// filtered to one `(ecosystem, kind)` bucket; mixing ecosystems or kinds
/// here would produce a branch name / commit prefix that doesn't actually
/// describe its contents.
///
/// A single-member group is handed straight to [`apply_fix`] unchanged —
/// same branch name, same commit/PR shape as before grouping existed —
/// so `--group-by` never changes behavior for a repo that only ever has
/// one candidate per ecosystem at a time.
///
/// Candidates whose manifest line no longer matches what was scanned
/// (edited since the scan ran) are individually skipped and reported in
/// `member_summaries`, same as `apply_fix`'s single-candidate skip —
/// grouping never turns one member's stale-line skip into a whole-group
/// failure as long as at least one other member still applies.
#[allow(clippy::too_many_arguments)]
pub async fn apply_fix_group(runner: &ToolRunner, github_api: &GithubApi<'_>, full_name: &str, base_branch: &str, clone_dir: &str, group: &[FixCandidate], token: &str, apply: bool) -> GroupFixOutcome {
    let (usable, major_bump_skips): (Vec<&FixCandidate>, Vec<&FixCandidate>) = group.iter().partition(|c| !c.major_bump);

    if usable.is_empty() {
        return GroupFixOutcome {
            group_summary: format!("{} candidate(s)", group.len()),
            branch: String::new(),
            applied: false,
            skipped_reason: Some("every candidate in this group crosses a semver major version — needs manual review".to_string()),
            pr_url: None,
            error: None,
            member_summaries: group.iter().map(|c| c.summary.clone()).collect(),
        };
    }

    if usable.len() == 1 {
        let outcome = apply_fix(runner, github_api, full_name, base_branch, clone_dir, usable[0], token, apply).await;
        return GroupFixOutcome::from_single(outcome, &major_bump_skips);
    }

    let ecosystem = usable[0].ecosystem;
    let kind = usable[0].kind;
    let owned: Vec<FixCandidate> = usable.iter().map(|c| (*c).clone()).collect();
    let branch = group_branch_name(ecosystem, kind, &owned);
    let group_summary = format!("{} {ecosystem} {} candidate(s)", owned.len(), match kind { FixKind::Vulnerability => "vulnerability", FixKind::RoutineUpdate => "routine-update" });

    let mut member_summaries: Vec<String> = major_bump_skips.iter().map(|c| format!("{} (skipped: crosses a semver major version)", c.summary)).collect();

    if branch_exists_on_remote(runner, clone_dir, &branch).await {
        member_summaries.extend(owned.iter().map(|c| c.summary.clone()));
        return GroupFixOutcome { group_summary, branch, applied: false, skipped_reason: Some("branch already exists on origin — this group's fixes are already proposed".to_string()), pr_url: None, error: None, member_summaries };
    }

    // Validate every member's manifest line still matches what was
    // scanned, and pre-compute its edit — before touching git, same as
    // `apply_fix`'s single-candidate ordering (major_bump -> branch-exists
    // -> read+validate -> dry-run early return -> git).
    let mut manifest_cache: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut applicable: Vec<&FixCandidate> = Vec::new();
    for candidate in &owned {
        let content = match manifest_cache.entry(candidate.manifest_file.clone()) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let path = Path::new(clone_dir).join(&candidate.manifest_file);
                match std::fs::read_to_string(&path) {
                    Ok(c) => e.insert(c),
                    Err(err) => {
                        member_summaries.push(format!("{} (skipped: failed to read {}: {err})", candidate.summary, candidate.manifest_file));
                        continue;
                    }
                }
            }
        };
        match apply_fix_to_content(content, candidate.dep_line, &candidate.current_range, &candidate.fixed_version) {
            Some(new_content) => {
                manifest_cache.insert(candidate.manifest_file.clone(), new_content);
                applicable.push(candidate);
            }
            None => member_summaries.push(format!("{} (skipped: manifest line no longer matches the scanned range)", candidate.summary)),
        }
    }

    if applicable.is_empty() {
        member_summaries.extend(owned.iter().map(|c| c.summary.clone()));
        return GroupFixOutcome { group_summary, branch, applied: false, skipped_reason: Some("no member's manifest line still matched what was scanned".to_string()), pr_url: None, error: None, member_summaries };
    }

    member_summaries.extend(applicable.iter().map(|c| c.summary.clone()));

    if !apply {
        return GroupFixOutcome { group_summary, branch, applied: false, skipped_reason: Some("dry-run — pass --apply to open this PR".to_string()), pr_url: None, error: None, member_summaries };
    }

    if let Err(e) = runner.run_tool("git", &["checkout".to_string(), "-B".to_string(), branch.clone(), base_branch.to_string()], clone_dir, RunToolOptions::default()).await {
        return GroupFixOutcome { group_summary, branch, applied: false, skipped_reason: None, pr_url: None, error: Some(format!("git checkout -B: {e}")), member_summaries };
    }

    // Write every touched manifest's final (all-edits-applied) content —
    // `manifest_cache` holds the fully-edited content per file since
    // multiple candidates can share one manifest (edits never move lines,
    // so applying them in any order onto the same in-memory content is safe).
    let mut add_paths: Vec<String> = Vec::new();
    for manifest_file in applicable.iter().map(|c| c.manifest_file.clone()).collect::<std::collections::BTreeSet<_>>() {
        let content = manifest_cache.get(&manifest_file).expect("edited manifest must be in cache");
        let path = Path::new(clone_dir).join(&manifest_file);
        if let Err(e) = std::fs::write(&path, content) {
            let _ = runner.run_tool("git", &["checkout".to_string(), base_branch.to_string()], clone_dir, RunToolOptions::default()).await;
            return GroupFixOutcome { group_summary, branch, applied: false, skipped_reason: None, pr_url: None, error: Some(format!("failed to write {manifest_file}: {e}")), member_summaries };
        }
        add_paths.push(manifest_file);
    }

    let mut lockfile_notes: Vec<String> = Vec::new();
    let mut lockfile_paths_seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for candidate in &applicable {
        let (lockfile_path, lockfile_warning) = regenerate_lockfile(runner, clone_dir, candidate).await;
        if let Some(path) = lockfile_path {
            if lockfile_paths_seen.insert(path.clone()) {
                lockfile_notes.push(format!("- Lockfile: `{path}` regenerated to match."));
                add_paths.push(path);
            }
        } else if let Some(reason) = lockfile_warning {
            let note = format!("- Lockfile: **not** regenerated for `{}` ({reason}).", candidate.dep_name);
            if !lockfile_notes.contains(&note) {
                lockfile_notes.push(note);
            }
        }
    }

    let prefix = match kind {
        FixKind::Vulnerability => format!("fix({ecosystem}): bump {} dependencies (grouped)", applicable.len()),
        FixKind::RoutineUpdate => format!("chore({ecosystem}): bump {} dependencies (grouped)", applicable.len()),
    };
    let bullet_list: String = applicable.iter().map(|c| format!("- {}: {} -> {}\n", c.dep_name, c.current_range, c.fixed_version)).collect();
    let commit_message = format!("{prefix}\n\n{bullet_list}");

    let mut add_args = vec!["add".to_string()];
    add_args.extend(add_paths);
    let commit_steps: Vec<Vec<String>> = vec![
        add_args,
        vec!["-c".to_string(), "user.email=ignite-bot@localhost".to_string(), "-c".to_string(), "user.name=Ignite Auto-Fix".to_string(), "commit".to_string(), "-m".to_string(), commit_message],
    ];
    for args in commit_steps {
        if let Err(e) = runner.run_tool("git", &args, clone_dir, RunToolOptions::default()).await {
            let _ = runner.run_tool("git", &["checkout".to_string(), base_branch.to_string()], clone_dir, RunToolOptions::default()).await;
            return GroupFixOutcome { group_summary, branch, applied: false, skipped_reason: None, pr_url: None, error: Some(format!("git {}: {e}", args.join(" "))), member_summaries };
        }
    }

    let push_result = runner
        .run_tool("git", &["-c".to_string(), format!("http.extraheader=AUTHORIZATION: bearer {token}"), "push".to_string(), "origin".to_string(), format!("HEAD:refs/heads/{branch}")], clone_dir, RunToolOptions::default())
        .await;
    let _ = runner.run_tool("git", &["checkout".to_string(), base_branch.to_string()], clone_dir, RunToolOptions::default()).await;

    if let Err(e) = push_result {
        return GroupFixOutcome { group_summary, branch, applied: false, skipped_reason: None, pr_url: None, error: Some(format!("git push: {e}")), member_summaries };
    }

    let owned_applicable: Vec<FixCandidate> = applicable.into_iter().cloned().collect();
    let title = pr_title_for_group(ecosystem, kind, owned_applicable.len());
    let body = pr_body_for_group(kind, &owned_applicable, &lockfile_notes);
    match github_api.gh_create_pr(full_name, base_branch, &branch, &title, &body, token).await {
        Ok(pr) => GroupFixOutcome { group_summary, branch, applied: true, skipped_reason: None, pr_url: Some(pr.url), error: None, member_summaries },
        Err(e) => GroupFixOutcome { group_summary, branch, applied: true, skipped_reason: None, pr_url: None, error: Some(format!("branch pushed but PR creation failed: {e}")), member_summaries },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn is_simple_range_accepts_bare_and_prefixed_versions() {
        assert!(is_simple_range("1.2.3"));
        assert!(is_simple_range("^1.2.3"));
        assert!(is_simple_range("~=1.2.3"));
        assert!(is_simple_range("==1.2.3"));
        assert!(is_simple_range(">=1.2.3"));
        assert!(is_simple_range("v1.2.3"));
    }

    #[test]
    fn is_simple_range_rejects_or_ranges_and_wildcards() {
        assert!(!is_simple_range("1.x"));
        assert!(!is_simple_range("^1.0.0 || ^2.0.0"));
        assert!(!is_simple_range("1.0.0, <2.0.0"));
        assert!(!is_simple_range(""));
        assert!(!is_simple_range("1.0.0 - 2.0.0"));
    }

    #[test]
    fn is_simple_range_rejects_gradle_dynamic_version_but_accepts_build_metadata() {
        assert!(!is_simple_range("1.2.+"));
        // Real semver build metadata, not a dynamic-version wildcard —
        // must stay accepted.
        assert!(is_simple_range("1.2.3+build.1"));
    }

    #[test]
    fn rewrite_range_preserves_prefix() {
        assert_eq!(rewrite_range("^1.2.3", "2.0.1"), "^2.0.1");
        assert_eq!(rewrite_range("==1.2.3", "2.0.1"), "==2.0.1");
        assert_eq!(rewrite_range("1.2.3", "2.0.1"), "2.0.1");
        assert_eq!(rewrite_range(">=1.2.3", "2.0.1"), ">=2.0.1");
    }

    #[test]
    fn is_major_bump_detects_major_version_change() {
        assert!(is_major_bump("1.2.3", "2.0.0"));
        assert!(!is_major_bump("1.2.3", "1.5.0"));
        assert!(!is_major_bump("not-semver", "2.0.0"));
    }

    #[test]
    fn apply_fix_to_content_rewrites_only_the_target_line() {
        let content = "{\n  \"dependencies\": {\n    \"lodash\": \"^4.17.15\",\n    \"other\": \"^1.0.0\"\n  }\n}";
        let out = apply_fix_to_content(content, 3, "^4.17.15", "4.17.21").unwrap();
        assert!(out.contains("\"lodash\": \"^4.17.21\""));
        assert!(out.contains("\"other\": \"^1.0.0\""));
    }

    #[test]
    fn apply_fix_to_content_skips_when_range_no_longer_matches() {
        let content = "lodash==4.17.15\n";
        assert!(apply_fix_to_content(content, 1, "^99.0.0", "4.17.21").is_none());
    }

    #[test]
    fn apply_fix_to_content_skips_invalid_line_number() {
        let content = "lodash==4.17.15\n";
        assert!(apply_fix_to_content(content, 0, "4.17.15", "4.17.21").is_none());
        assert!(apply_fix_to_content(content, 50, "4.17.15", "4.17.21").is_none());
    }

    /// Real network call against the live OSV.dev API — a known GHSA
    /// advisory for `lodash` on npm (prototype pollution, fixed in
    /// 4.17.19) that's been stable for years, so this shouldn't flake on
    /// advisory content changing. Self-skips if the network is
    /// unreachable, same convention as this repo's other real-binary/
    /// real-network integration tests.
    #[tokio::test]
    async fn fetch_osv_fixed_version_resolves_a_real_advisory() {
        let http = reqwest::Client::new();
        let result = fetch_osv_fixed_version(&http, "GHSA-p6mc-m468-83gw", "npm", "lodash").await;
        let Some(fixed) = result else {
            eprintln!("skipping: could not reach OSV.dev (network unavailable in this environment) or advisory shape changed");
            return;
        };
        assert!(parse_semver(&fixed).is_some(), "expected a semver-shaped fixed version, got {fixed}");
    }

    #[test]
    fn branch_name_for_is_deterministic_and_slugified() {
        let candidate = FixCandidate {
            manifest_file: "package.json".to_string(),
            ecosystem: "npm",
            dep_name: "@scope/pkg-name".to_string(),
            dep_line: 3,
            current_range: "^1.0.0".to_string(),
            resolved_version: Some("1.0.0".to_string()),
            fixed_version: "1.2.0".to_string(),
            advisory_id: "GHSA-xxxx".to_string(),
            summary: String::new(),
            major_bump: false,
            kind: FixKind::Vulnerability,
        };
        let branch = branch_name_for(&candidate);
        assert_eq!(branch, "ignite/autofix/npm--scope-pkg-name-1.2.0");
        assert_eq!(branch, branch_name_for(&candidate));
    }

    fn npm_candidate() -> FixCandidate {
        FixCandidate {
            manifest_file: "package.json".to_string(),
            ecosystem: "npm",
            dep_name: "lodash".to_string(),
            dep_line: 3,
            current_range: "^4.17.15".to_string(),
            resolved_version: Some("4.17.15".to_string()),
            fixed_version: "4.17.21".to_string(),
            advisory_id: "GHSA-xxxx".to_string(),
            summary: String::new(),
            major_bump: false,
            kind: FixKind::Vulnerability,
        }
    }

    #[test]
    fn lockfile_command_picks_npm_when_package_lock_present() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package-lock.json"), "{}").unwrap();
        let (tool, args, name) = lockfile_command(dir.path(), &npm_candidate()).unwrap();
        assert_eq!(tool, "npm");
        assert!(args.contains(&"--package-lock-only".to_string()));
        assert_eq!(name, "package-lock.json");
    }

    #[test]
    fn lockfile_command_prefers_yarn_lock_over_pnpm_when_both_absent_package_lock() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("yarn.lock"), "").unwrap();
        let (tool, _, name) = lockfile_command(dir.path(), &npm_candidate()).unwrap();
        assert_eq!(tool, "yarn");
        assert_eq!(name, "yarn.lock");
    }

    #[test]
    fn lockfile_command_none_when_no_npm_lockfile_present() {
        let dir = tempfile::tempdir().unwrap();
        assert!(lockfile_command(dir.path(), &npm_candidate()).is_none());
    }

    #[test]
    fn lockfile_command_cargo_update_uses_precise_dep_version() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("Cargo.lock"), "").unwrap();
        let mut candidate = npm_candidate();
        candidate.ecosystem = "cargo";
        candidate.dep_name = "serde".to_string();
        candidate.fixed_version = "1.0.200".to_string();
        let (tool, args, name) = lockfile_command(dir.path(), &candidate).unwrap();
        assert_eq!(tool, "cargo");
        assert_eq!(args, vec!["update", "-p", "serde", "--precise", "1.0.200"]);
        assert_eq!(name, "Cargo.lock");
    }

    #[test]
    fn lockfile_command_go_mod_tidy_when_go_sum_present() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("go.sum"), "").unwrap();
        let mut candidate = npm_candidate();
        candidate.ecosystem = "go";
        let (tool, args, name) = lockfile_command(dir.path(), &candidate).unwrap();
        assert_eq!(tool, "go");
        assert_eq!(args, vec!["mod", "tidy"]);
        assert_eq!(name, "go.sum");
    }

    #[test]
    fn lockfile_command_dotnet_restore_when_packages_lock_json_present() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("packages.lock.json"), "{}").unwrap();
        let mut candidate = npm_candidate();
        candidate.ecosystem = "nuget";
        let (tool, args, name) = lockfile_command(dir.path(), &candidate).unwrap();
        assert_eq!(tool, "dotnet");
        assert_eq!(args, vec!["restore", "--force-evaluate"]);
        assert_eq!(name, "packages.lock.json");
    }

    #[test]
    fn lockfile_command_none_for_nuget_without_packages_lock_json() {
        let dir = tempfile::tempdir().unwrap();
        let mut candidate = npm_candidate();
        candidate.ecosystem = "nuget";
        assert!(lockfile_command(dir.path(), &candidate).is_none());
    }

    #[test]
    fn lockfile_command_gradle_write_locks_when_gradle_lockfile_present() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("gradle.lockfile"), "").unwrap();
        let mut candidate = npm_candidate();
        candidate.ecosystem = "gradle";
        let (tool, args, name) = lockfile_command(dir.path(), &candidate).unwrap();
        assert_eq!(tool, "gradle");
        assert_eq!(args, vec!["dependencies", "--write-locks"]);
        assert_eq!(name, "gradle.lockfile");
    }

    #[test]
    fn lockfile_command_none_for_pypi_and_maven() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("poetry.lock"), "").unwrap();
        let mut candidate = npm_candidate();
        candidate.ecosystem = "pypi";
        assert!(lockfile_command(dir.path(), &candidate).is_none());
        candidate.ecosystem = "maven";
        assert!(lockfile_command(dir.path(), &candidate).is_none());
    }

    #[test]
    fn pr_body_for_reports_regenerated_lockfile() {
        let body = pr_body_for(&npm_candidate(), Some(Ok("package-lock.json")));
        assert!(body.contains("`package-lock.json` regenerated"));
    }

    #[test]
    fn pr_body_for_warns_when_lockfile_regeneration_failed() {
        let body = pr_body_for(&npm_candidate(), Some(Err("npm: command not found")));
        assert!(body.contains("not** regenerated"));
        assert!(body.contains("npm: command not found"));
    }

    #[test]
    fn pr_body_for_omits_lockfile_section_when_not_applicable() {
        let body = pr_body_for(&npm_candidate(), None);
        assert!(!body.contains("Lockfile"));
    }

    #[test]
    fn latest_stable_version_picks_highest_semver_and_skips_prereleases() {
        let versions = vec!["1.0.0".to_string(), "2.1.0-rc.1".to_string(), "1.9.0".to_string(), "2.0.0".to_string(), "not-semver".to_string()];
        assert_eq!(latest_stable_version(&versions), Some("2.0.0".to_string()));
    }

    #[test]
    fn latest_stable_version_empty_when_only_prereleases_or_unparseable() {
        let versions = vec!["1.0.0-beta".to_string(), "nope".to_string()];
        assert_eq!(latest_stable_version(&versions), None);
    }

    #[test]
    fn routine_update_pr_title_and_body_never_mention_an_advisory() {
        let mut candidate = npm_candidate();
        candidate.advisory_id = String::new();
        candidate.kind = FixKind::RoutineUpdate;
        let title = pr_title_for(&candidate);
        assert!(!title.contains("()"), "empty advisory parens leaked into title: {title}");
        assert!(title.contains("routine update") || title.to_lowercase().contains("routine"));
        let body = pr_body_for(&candidate, None);
        assert!(body.contains("routine version-currency update"));
        assert!(!body.contains("Advisory:"));
    }

    fn candidate(ecosystem: &'static str, kind: FixKind, dep_name: &str, fixed_version: &str) -> FixCandidate {
        FixCandidate {
            manifest_file: "package.json".to_string(),
            ecosystem,
            dep_name: dep_name.to_string(),
            dep_line: 1,
            current_range: "1.0.0".to_string(),
            resolved_version: Some("1.0.0".to_string()),
            fixed_version: fixed_version.to_string(),
            advisory_id: if kind == FixKind::Vulnerability { "GHSA-xxxx".to_string() } else { String::new() },
            summary: format!("{dep_name}@1.0.0 -> {fixed_version}"),
            major_bump: false,
            kind,
        }
    }

    #[test]
    fn group_by_none_keeps_every_candidate_in_its_own_singleton_group() {
        let candidates = vec![candidate("npm", FixKind::Vulnerability, "a", "2.0.0"), candidate("npm", FixKind::Vulnerability, "b", "2.0.0")];
        let groups = group_candidates(candidates, GroupBy::None);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 1);
        assert_eq!(groups[1].len(), 1);
    }

    #[test]
    fn group_by_ecosystem_bundles_same_ecosystem_and_kind() {
        let candidates = vec![candidate("npm", FixKind::Vulnerability, "a", "2.0.0"), candidate("npm", FixKind::Vulnerability, "b", "2.0.0"), candidate("cargo", FixKind::Vulnerability, "c", "2.0.0")];
        let groups = group_candidates(candidates, GroupBy::Ecosystem);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups.iter().map(|g| g.len()).sum::<usize>(), 3);
    }

    #[test]
    fn group_by_ecosystem_never_mixes_vulnerability_and_routine_update() {
        let candidates = vec![candidate("npm", FixKind::Vulnerability, "a", "2.0.0"), candidate("npm", FixKind::RoutineUpdate, "b", "2.0.0")];
        let groups = group_candidates(candidates, GroupBy::Ecosystem);
        assert_eq!(groups.len(), 2);
        assert_ne!(groups[0][0].kind, groups[1][0].kind);
    }

    #[test]
    fn group_by_from_str_accepts_ecosystem_and_rejects_others() {
        assert_eq!("ecosystem".parse::<GroupBy>(), Ok(GroupBy::Ecosystem));
        assert!("bogus".parse::<GroupBy>().is_err());
    }

    #[test]
    fn group_branch_name_is_deterministic_and_order_independent() {
        let a = candidate("npm", FixKind::Vulnerability, "a", "2.0.0");
        let b = candidate("npm", FixKind::Vulnerability, "b", "3.0.0");
        let forward = group_branch_name("npm", FixKind::Vulnerability, &[a.clone(), b.clone()]);
        let reversed = group_branch_name("npm", FixKind::Vulnerability, &[b, a]);
        assert_eq!(forward, reversed);
        assert!(forward.starts_with("ignite/autofix-group/npm-vuln-"));
    }

    #[test]
    fn group_branch_name_changes_when_membership_changes() {
        let a = candidate("npm", FixKind::Vulnerability, "a", "2.0.0");
        let b = candidate("npm", FixKind::Vulnerability, "b", "3.0.0");
        let c = candidate("npm", FixKind::Vulnerability, "c", "4.0.0");
        let group1 = group_branch_name("npm", FixKind::Vulnerability, &[a.clone(), b.clone()]);
        let group2 = group_branch_name("npm", FixKind::Vulnerability, &[a, b, c]);
        assert_ne!(group1, group2);
    }

    #[test]
    fn pr_title_for_group_reflects_kind_and_count() {
        assert_eq!(pr_title_for_group("npm", FixKind::Vulnerability, 3), "[Ignite auto-fix] bump 3 npm dependencies (grouped)");
        assert_eq!(pr_title_for_group("cargo", FixKind::RoutineUpdate, 2), "[Ignite routine update] bump 2 cargo dependencies (grouped)");
    }

    #[test]
    fn pr_body_for_group_lists_every_member_and_lockfile_note() {
        let group = vec![candidate("npm", FixKind::Vulnerability, "a", "2.0.0"), candidate("npm", FixKind::Vulnerability, "b", "3.0.0")];
        let body = pr_body_for_group(FixKind::Vulnerability, &group, &["- Lockfile: `package-lock.json` regenerated to match.".to_string()]);
        assert!(body.contains("`a`"));
        assert!(body.contains("`b`"));
        assert!(body.contains("GHSA-xxxx"));
        assert!(body.contains("package-lock.json` regenerated"));
    }

    #[test]
    fn pr_body_for_group_routine_update_omits_advisory_text() {
        let group = vec![candidate("npm", FixKind::RoutineUpdate, "a", "2.0.0")];
        let body = pr_body_for_group(FixKind::RoutineUpdate, &group, &[]);
        assert!(!body.contains("Advisory"));
        assert!(body.contains("routine version-currency update"));
    }

    #[tokio::test]
    async fn apply_fix_group_single_member_delegates_to_apply_fix_and_reports_dry_run() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{\n  \"dependencies\": {\n    \"lodash\": \"^4.17.15\"\n  }\n}").unwrap();
        let mut c = npm_candidate();
        c.dep_line = 3;
        c.current_range = "^4.17.15".to_string();
        let runner = ToolRunner::new(std::collections::HashMap::new());
        let github_api = GithubApi::new(&runner);
        let outcome = apply_fix_group(&runner, &github_api, "acme/widgets", "main", &dir.path().to_string_lossy(), &[c], "token", false).await;
        assert!(!outcome.applied);
        assert_eq!(outcome.skipped_reason.as_deref(), Some("dry-run — pass --apply to open this PR"));
        assert_eq!(outcome.member_summaries.len(), 1);
    }

    #[tokio::test]
    async fn apply_fix_group_all_major_bumps_skips_whole_group() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = npm_candidate();
        a.major_bump = true;
        let mut b = npm_candidate();
        b.dep_name = "other".to_string();
        b.major_bump = true;
        let runner = ToolRunner::new(std::collections::HashMap::new());
        let github_api = GithubApi::new(&runner);
        let outcome = apply_fix_group(&runner, &github_api, "acme/widgets", "main", &dir.path().to_string_lossy(), &[a, b], "token", false).await;
        assert!(!outcome.applied);
        assert!(outcome.skipped_reason.unwrap().contains("semver major"));
        assert_eq!(outcome.member_summaries.len(), 2);
    }

    #[tokio::test]
    async fn discover_routine_update_candidates_finds_a_bumpable_npm_dep() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"dependencies": {"left-pad": "1.0.0"}}"#).unwrap();
        let deps_client = DepsDevClient::new();
        let candidates = discover_routine_update_candidates(dir.path(), &deps_client).await;
        if candidates.is_empty() {
            eprintln!("skipping: could not reach deps.dev (network unavailable in this environment) or left-pad has no newer stable release");
            return;
        }
        let c = &candidates[0];
        assert_eq!(c.dep_name, "left-pad");
        assert_eq!(c.kind, FixKind::RoutineUpdate);
        assert!(c.advisory_id.is_empty());
        assert_ne!(c.fixed_version, "1.0.0");
    }

    #[tokio::test]
    async fn discover_routine_update_candidates_respects_a_dependabot_yml_ignore_rule() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"dependencies": {"left-pad": "1.0.0"}}"#).unwrap();
        fs::create_dir_all(dir.path().join(".github")).unwrap();
        fs::write(dir.path().join(".github/dependabot.yml"), "version: 2\nupdates:\n  - package-ecosystem: \"npm\"\n    directory: \"/\"\n    ignore:\n      - dependency-name: \"left-pad\"\n").unwrap();
        let deps_client = DepsDevClient::new();
        let candidates = discover_routine_update_candidates(dir.path(), &deps_client).await;
        assert!(candidates.is_empty(), "a dependency ignored in dependabot.yml must never surface as a candidate, network available or not: {candidates:?}");
    }
}
