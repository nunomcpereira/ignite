//! SPDX license tier classification and version-range helpers shared by
//! the dependency license/vulnerability scanning subsystem. Faithful port
//! of the pure (no-network) pieces of server.js's dependency-license
//! logic: `LICENSE_TIERS`, `normalizeLicenseId`, `classifyLicenseTier`,
//! `bestEffortVersion`, `isInternalDependencyRef`.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

/// Full open source — permissive, no reciprocal/attribution-beyond-notice
/// obligations.
pub static LICENSE_TIER_GREEN: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "MIT", "MIT-0", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear", "ISC", "0BSD", "Unlicense", "Zlib", "Python-2.0", "PostgreSQL", "CC0-1.0", "WTFPL", "BlueOak-1.0.0",
        "BSD-4-Clause", "X11", "Artistic-2.0", "OFL-1.1", "OFL-1.0",
    ]
    .into_iter()
    .collect()
});

/// Copyleft/reciprocal open-source licenses — still genuinely open
/// source, but the kind of obligation that pushes many vendors toward a
/// dual "Community Edition (GPL) / Enterprise (commercial)" split.
pub static LICENSE_TIER_WARNING: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "LGPL-2.1", "LGPL-2.1-only",
        "LGPL-2.1-or-later", "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later", "MPL-1.1", "MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1", "CeCILL-2.1",
    ]
    .into_iter()
    .collect()
});

/// Source-available but not OSI-approved open source — the "commercial
/// product with the source visible" pattern.
pub static LICENSE_TIER_RED: Lazy<HashSet<&'static str>> = Lazy::new(|| ["SSPL-1.0", "BUSL-1.1", "Commons-Clause", "UNLICENSED", "LicenseRef-Proprietary", "Elastic-2.0", "Elastic-1.0"].into_iter().collect());

/// Non-standard spellings of a real SPDX id observed in the wild (e.g.
/// npm package.json `license` field typos/variants) — normalized here so
/// the fix applies everywhere classify_license_tier is called (ORT,
/// licensee, deps.dev, and the npm-registry placeholder fallback).
static LICENSE_ALIASES: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    HashMap::from([
        ("mitclause", "MIT"),
        ("mitlicense", "MIT"),
        ("themitlicense", "MIT"),
        ("apache2", "Apache-2.0"),
        ("apache20", "Apache-2.0"),
        ("apachelicense2.0", "Apache-2.0"),
        ("apachelicense", "Apache-2.0"),
        ("bsd2clause", "BSD-2-Clause"),
        ("bsd3clause", "BSD-3-Clause"),
    ])
});

static ALIAS_STRIP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[\s.\-_]").unwrap());

pub fn normalize_license_id(raw: &str) -> String {
    let trimmed = raw.trim();
    let key = ALIAS_STRIP_RE.replace_all(&trimmed.to_lowercase(), "").into_owned();
    LICENSE_ALIASES.get(key.as_str()).map(|s| s.to_string()).unwrap_or_else(|| trimmed.to_string())
}

static COMMERCIAL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)commercial|proprietary").unwrap());

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    Green,
    Warning,
    Red,
}

#[derive(Debug, Clone, Serialize)]
pub struct LicenseClassification {
    pub tier: LicenseTier,
    pub reason: String,
}

/// `licenses` may be empty, a single license string, or a list — mirrors
/// the JS original's tolerant `Array.isArray(licenses) ? licenses :
/// licenses ? [licenses] : []` normalization.
pub fn classify_license_tier(licenses: &[String]) -> LicenseClassification {
    let list: Vec<String> = licenses.iter().filter(|l| !l.is_empty()).map(|l| normalize_license_id(l)).collect();
    if list.is_empty() {
        return LicenseClassification { tier: LicenseTier::Red, reason: "No license identified.".to_string() };
    }
    if list.iter().any(|l| LICENSE_TIER_RED.contains(l.as_str()) || COMMERCIAL_RE.is_match(l)) {
        return LicenseClassification { tier: LicenseTier::Red, reason: format!("Commercial/restrictive license: {}", list.join(", ")) };
    }
    if list.iter().any(|l| LICENSE_TIER_GREEN.contains(l.as_str())) {
        return LicenseClassification { tier: LicenseTier::Green, reason: list.join(", ") };
    }
    if list.iter().any(|l| LICENSE_TIER_WARNING.contains(l.as_str())) {
        return LicenseClassification { tier: LicenseTier::Warning, reason: format!("Copyleft license: {}", list.join(", ")) };
    }
    LicenseClassification { tier: LicenseTier::Red, reason: format!("Unrecognized license — treat as risk until reviewed: {}", list.join(", ")) }
}

static BEST_EFFORT_VERSION_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)").unwrap());

pub fn best_effort_version(raw: &str) -> Option<String> {
    BEST_EFFORT_VERSION_RE.find(raw).map(|m| m.as_str().to_string())
}

/// pnpm/bun/yarn-workspaces alias protocols ("catalog:dev", "workspace:*",
/// "link:../foo", "file:../foo", "portal:../foo", "patch:...") name no
/// real published package+version — resolved by the package manager
/// itself from local workspace/catalog config not present in a single
/// manifest file, so there is no license or CVE to look up.
static INTERNAL_DEP_REF_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^(workspace|catalog|link|file|portal|patch):").unwrap());

pub fn is_internal_dependency_ref(version_range: &str) -> bool {
    INTERNAL_DEP_REF_RE.is_match(version_range.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_green_licenses() {
        let c = classify_license_tier(&["MIT".to_string()]);
        assert_eq!(c.tier, LicenseTier::Green);
    }

    #[test]
    fn classifies_warning_copyleft_licenses() {
        let c = classify_license_tier(&["GPL-3.0".to_string()]);
        assert_eq!(c.tier, LicenseTier::Warning);
        assert!(c.reason.contains("Copyleft"));
    }

    #[test]
    fn classifies_red_commercial_licenses() {
        let c = classify_license_tier(&["SSPL-1.0".to_string()]);
        assert_eq!(c.tier, LicenseTier::Red);
    }

    #[test]
    fn classifies_red_for_commercial_keyword_not_in_set() {
        let c = classify_license_tier(&["Some Proprietary License".to_string()]);
        assert_eq!(c.tier, LicenseTier::Red);
        assert!(c.reason.contains("Commercial/restrictive"));
    }

    #[test]
    fn classifies_red_for_empty_license_list() {
        let c = classify_license_tier(&[]);
        assert_eq!(c.tier, LicenseTier::Red);
        assert_eq!(c.reason, "No license identified.");
    }

    #[test]
    fn classifies_red_for_unrecognized_license() {
        let c = classify_license_tier(&["Some-Made-Up-License-9000".to_string()]);
        assert_eq!(c.tier, LicenseTier::Red);
        assert!(c.reason.contains("Unrecognized license"));
    }

    #[test]
    fn red_takes_priority_over_green_when_both_present() {
        let c = classify_license_tier(&["MIT".to_string(), "SSPL-1.0".to_string()]);
        assert_eq!(c.tier, LicenseTier::Red);
    }

    #[test]
    fn normalizes_known_license_aliases() {
        assert_eq!(normalize_license_id("MITClause"), "MIT");
        assert_eq!(normalize_license_id("Apache 2.0"), "Apache-2.0");
        assert_eq!(normalize_license_id("MIT"), "MIT"); // already canonical, unaffected
    }

    #[test]
    fn faithful_port_quirk_apachelicense_dotted_alias_key_is_unreachable() {
        // Confirmed against the live JS: the "apachelicense2.0" alias-map
        // key contains a literal dot, but the lookup key strips dots
        // before matching — so this alias entry can never fire in either
        // port. Preserved as-is (dead code, not a bug worth "fixing" here,
        // since it changes nothing observable and the port's goal is
        // faithful parity).
        assert_eq!(normalize_license_id("Apache License 2.0"), "Apache License 2.0");
    }

    #[test]
    fn best_effort_version_extracts_leading_version_string() {
        assert_eq!(best_effort_version("^1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(best_effort_version("~4.5"), Some("4.5".to_string()));
        assert_eq!(best_effort_version("1.0.0-beta.1"), Some("1.0.0-beta.1".to_string()));
        assert_eq!(best_effort_version("git+https://github.com/x/y.git"), None);
    }

    #[test]
    fn is_internal_dependency_ref_matches_workspace_protocols() {
        assert!(is_internal_dependency_ref("workspace:*"));
        assert!(is_internal_dependency_ref("catalog:dev"));
        assert!(is_internal_dependency_ref("link:../foo"));
        assert!(is_internal_dependency_ref("file:../foo"));
        assert!(is_internal_dependency_ref("portal:../foo"));
        assert!(is_internal_dependency_ref("patch:lodash@1.0.0"));
        assert!(!is_internal_dependency_ref("^1.2.3"));
    }
}
