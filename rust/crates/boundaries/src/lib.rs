//! Built-in architecture-boundary enforcement. Faithful port of
//! `checks/boundaries.js`. Reuses `ignite-module-graph`'s import graph
//! rather than a second parser. Off by default — a wrong/default zone
//! layout on a project that doesn't follow one would be pure noise, so
//! this only activates on explicit opt-in (`preset` and/or custom `zones`).

use ignite_fs_utils::{build_snippet, SnippetOptions};
use ignite_module_graph::build_module_graph;
use regex::Regex;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct Zone {
    pub name: String,
    pub pattern: String,
    pub allow: Vec<String>,
}

fn zone(name: &str, pattern: &str, allow: &[&str]) -> Zone {
    Zone { name: name.to_string(), pattern: pattern.to_string(), allow: allow.iter().map(|s| s.to_string()).collect() }
}

pub fn preset_zones(preset: &str) -> Option<Vec<Zone>> {
    match preset {
        "bulletproof" => Some(vec![
            zone("shared", "src/shared/**", &[]),
            zone("features", "src/features/*/**", &["shared"]),
            zone("app", "src/app/**", &["shared", "features"]),
        ]),
        "layered" => Some(vec![
            zone("domain", "{src,lib}/domain/**", &[]),
            zone("service", "{src,lib}/service*/**", &["domain"]),
            zone("controller", "{src,lib}/{controllers,routes,api}/**", &["service", "domain"]),
        ]),
        "hexagonal" => Some(vec![
            zone("domain", "{src,lib}/domain/**", &[]),
            zone("ports", "{src,lib}/ports/**", &["domain"]),
            zone("adapters", "{src,lib}/adapters/**", &["ports", "domain"]),
        ]),
        "feature-sliced" => Some(vec![
            zone("shared", "src/shared/**", &[]),
            zone("entities", "src/entities/*/**", &["shared"]),
            zone("features", "src/features/*/**", &["shared", "entities"]),
            zone("widgets", "src/widgets/*/**", &["shared", "entities", "features"]),
            zone("pages", "src/pages/*/**", &["shared", "entities", "features", "widgets"]),
        ]),
        _ => None,
    }
}

/// Minimal glob-ish matcher: `**` = any depth, `*` = one path segment
/// (captured, so callers can tell sibling instances of the same zone
/// apart), `{a,b}` = alternation.
pub fn glob_to_regex(glob: &str) -> Regex {
    let mut out = String::from("^");
    let chars: Vec<char> = glob.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '*' && chars.get(i + 1) == Some(&'*') {
            out.push_str(".*");
            i += 2;
        } else if c == '*' {
            out.push_str("([^/]*)");
            i += 1;
        } else if c == '{' {
            let end = chars[i..].iter().position(|&c| c == '}').map(|p| i + p).unwrap_or(chars.len());
            let alts: Vec<String> = chars[i + 1..end]
                .iter()
                .collect::<String>()
                .split(',')
                .map(|a| escape_glob_literal(a.trim()))
                .collect();
            out.push_str(&format!("(?:{})", alts.join("|")));
            i = end + 1;
        } else if ".+^${}()|[]\\".contains(c) {
            out.push('\\');
            out.push(c);
            i += 1;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out.push('$');
    Regex::new(&out).unwrap()
}

fn escape_glob_literal(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if ".+^${}()|[]\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

pub fn resolve_zones(preset: Option<&str>, custom_zones: &[Zone]) -> Vec<Zone> {
    if let Some(base) = preset.and_then(preset_zones) {
        if custom_zones.is_empty() {
            return base;
        }
        // Preset + overrides: custom zones win by name, rest of preset kept.
        let mut by_name: Vec<Zone> = base;
        for z in custom_zones {
            if let Some(existing) = by_name.iter_mut().find(|b| b.name == z.name) {
                *existing = z.clone();
            } else {
                by_name.push(z.clone());
            }
        }
        return by_name;
    }
    custom_zones.to_vec()
}

pub struct ZoneMatch<'a> {
    pub zone: &'a Zone,
    pub instance: Option<String>,
}

/// Returns the first zone whose pattern matches `rel`, plus the first
/// captured `*` segment (e.g. "auth" for `src/features/auth/index.js`
/// under `src/features/*/**`) — `None` when the zone's pattern has no
/// single-`*` segment (a zone with no sibling concept, like "shared").
pub fn zone_of<'a>(zones: &'a [Zone], rel: &str) -> Option<ZoneMatch<'a>> {
    for z in zones {
        let re = glob_to_regex(&z.pattern);
        if let Some(caps) = re.captures(rel) {
            let instance = caps.get(1).map(|m| m.as_str().to_string());
            return Some(ZoneMatch { zone: z, instance });
        }
    }
    None
}

#[derive(Debug, Clone, Serialize)]
pub struct BoundaryFinding {
    pub file: String,
    pub line: usize,
    pub kind: &'static str,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<ignite_fs_utils::Snippet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BoundariesResult {
    pub findings: Vec<BoundaryFinding>,
    pub engine: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_count: Option<usize>,
}

pub struct BoundariesConfig {
    pub enabled: bool,
    pub preset: Option<String>,
    pub zones: Vec<Zone>,
}

pub fn check_boundaries(root: &Path, config: &BoundariesConfig) -> std::io::Result<BoundariesResult> {
    if !config.enabled {
        return Ok(BoundariesResult { findings: vec![], engine: "disabled", zone_count: None });
    }
    let zones = resolve_zones(config.preset.as_deref(), &config.zones);
    if zones.is_empty() {
        return Ok(BoundariesResult { findings: vec![], engine: "unconfigured", zone_count: None });
    }

    let mg = build_module_graph(root)?;
    let mut findings = Vec::new();

    for (file, node) in &mg.graph {
        let rel = rel_str(root, file);
        let Some(from) = zone_of(&zones, &rel) else { continue };
        for imp in &node.imports {
            let imp_rel = rel_str(root, imp);
            let Some(to) = zone_of(&zones, &imp_rel) else { continue };
            // Same zone AND same sibling instance (or a zone with no
            // sibling concept at all) — an ordinary same-feature import,
            // always allowed.
            let same_instance = to.zone.name == from.zone.name && to.instance == from.instance;
            if same_instance {
                continue;
            }
            let allowed = from.zone.allow.contains(&to.zone.name);
            if allowed {
                continue;
            }
            let imp_stem = imp.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            let line_idx = node.content.split('\n').position(|l| {
                l.contains(imp_rel.as_str()) || (l.contains("import") && l.contains(&imp_stem))
            });
            let line = line_idx.map(|i| i + 1).unwrap_or(1);
            let to_label = if to.zone.name == from.zone.name {
                format!("{} (sibling \"{}\")", to.zone.name, to.instance.as_deref().unwrap_or(""))
            } else {
                to.zone.name.clone()
            };
            let allow_list = if from.zone.allow.is_empty() { "none".to_string() } else { from.zone.allow.join(", ") };
            findings.push(BoundaryFinding {
                file: rel.clone(),
                line,
                kind: "boundary-violation",
                tool: "ignite-built-in",
                severity: "warning",
                message: format!(
                    "Zone \"{}\"{} imports from zone \"{to_label}\" ({imp_rel}), which its allowed-imports list ({allow_list}) doesn't permit — architecture drift from the configured {} layout.",
                    from.zone.name,
                    from.instance.as_deref().map(|i| format!(" (sibling \"{i}\")")).unwrap_or_default(),
                    config.preset.as_deref().unwrap_or("custom"),
                ),
                code: build_snippet(&node.content, line, SnippetOptions::default()),
            });
        }
    }

    Ok(BoundariesResult { findings, engine: "built-in", zone_count: Some(zones.len()) })
}

fn rel_str(root: &Path, file: &Path) -> String {
    file.strip_prefix(root).unwrap_or(file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn glob_star_captures_single_segment_for_sibling_detection() {
        let re = glob_to_regex("src/features/*/**");
        let caps = re.captures("src/features/auth/index.js").unwrap();
        assert_eq!(&caps[1], "auth");
    }

    #[test]
    fn glob_brace_alternation_matches_either_branch() {
        let re = glob_to_regex("{src,lib}/domain/**");
        assert!(re.is_match("src/domain/user.js"));
        assert!(re.is_match("lib/domain/user.js"));
        assert!(!re.is_match("test/domain/user.js"));
    }

    #[test]
    fn resolve_zones_preset_plus_override_wins_by_name() {
        let custom = vec![zone("shared", "shared-lib/**", &[])];
        let resolved = resolve_zones(Some("bulletproof"), &custom);
        assert_eq!(resolved.len(), 3); // still shared+features+app, just shared's pattern overridden
        let shared = resolved.iter().find(|z| z.name == "shared").unwrap();
        assert_eq!(shared.pattern, "shared-lib/**");
    }

    #[test]
    fn cross_feature_import_without_allow_is_flagged() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("src/features/auth")).unwrap();
        fs::create_dir_all(root.join("src/features/billing")).unwrap();
        fs::write(root.join("src/features/auth/index.js"), "import x from '../billing/index.js';\n").unwrap();
        fs::write(root.join("src/features/billing/index.js"), "export const x = 1;\n").unwrap();

        let config = BoundariesConfig { enabled: true, preset: Some("bulletproof".into()), zones: vec![] };
        let result = check_boundaries(root, &config).unwrap();
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].message.contains("sibling"));
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn same_feature_sibling_import_is_allowed() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("src/features/auth")).unwrap();
        fs::write(root.join("src/features/auth/index.js"), "import x from './helper.js';\n").unwrap();
        fs::write(root.join("src/features/auth/helper.js"), "export const x = 1;\n").unwrap();

        let config = BoundariesConfig { enabled: true, preset: Some("bulletproof".into()), zones: vec![] };
        let result = check_boundaries(root, &config).unwrap();
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn allowed_direction_features_import_shared_is_fine() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("src/features/auth")).unwrap();
        fs::create_dir_all(root.join("src/shared")).unwrap();
        fs::write(root.join("src/features/auth/index.js"), "import x from '../../shared/util.js';\n").unwrap();
        fs::write(root.join("src/shared/util.js"), "export const x = 1;\n").unwrap();

        let config = BoundariesConfig { enabled: true, preset: Some("bulletproof".into()), zones: vec![] };
        let result = check_boundaries(root, &config).unwrap();
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn disallowed_direction_shared_import_features_is_flagged() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("src/features/auth")).unwrap();
        fs::create_dir_all(root.join("src/shared")).unwrap();
        fs::write(root.join("src/shared/util.js"), "import x from '../features/auth/index.js';\n").unwrap();
        fs::write(root.join("src/features/auth/index.js"), "export const x = 1;\n").unwrap();

        let config = BoundariesConfig { enabled: true, preset: Some("bulletproof".into()), zones: vec![] };
        let result = check_boundaries(root, &config).unwrap();
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].message.contains("Zone \"shared\""));
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn disabled_or_unconfigured_short_circuit() {
        let dir = tempdir().unwrap();
        let disabled = check_boundaries(dir.path(), &BoundariesConfig { enabled: false, preset: None, zones: vec![] }).unwrap();
        assert_eq!(disabled.engine, "disabled");
        let unconfigured = check_boundaries(dir.path(), &BoundariesConfig { enabled: true, preset: None, zones: vec![] }).unwrap();
        assert_eq!(unconfigured.engine, "unconfigured");
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }
}
