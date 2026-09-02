//! Faithful port of `lib/sarif.js`'s `buildSarif` — reshapes Ignite's flat
//! issue list into SARIF 2.1.0. Pulled out from the route so the mapping
//! (severity→level, stable id→partialFingerprints, etc.) is testable
//! without booting a server. `routes/sarif.js`'s HTTP wiring (live
//! in-flight job vs. completed-job DB read vs. 404) isn't ported here —
//! it needs the HTTP server layer, which doesn't exist yet.

use ignite_db_store::IssueRow;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value};

const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

static NON_RULE_ID_CHAR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[^a-zA-Z0-9._-]").unwrap());

pub fn sarif_level(issue: &IssueRow) -> &'static str {
    if issue.status == "overridden" {
        return "note";
    }
    if issue.severity == "error" {
        "error"
    } else {
        "warning"
    }
}

pub fn rule_id_for(issue: &IssueRow) -> String {
    let category = if issue.category.is_empty() { "ignite-finding" } else { &issue.category };
    NON_RULE_ID_CHAR_RE.replace_all(category, "-").into_owned()
}

#[derive(Debug, Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: Message,
    #[serde(rename = "partialFingerprints")]
    partial_fingerprints: PartialFingerprints,
    properties: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locations: Option<Vec<Location>>,
}

#[derive(Debug, Serialize)]
struct Message {
    text: String,
}

#[derive(Debug, Serialize)]
struct PartialFingerprints {
    #[serde(rename = "igniteIssueId")]
    ignite_issue_id: String,
}

#[derive(Debug, Serialize)]
struct Location {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

#[derive(Debug, Serialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: ArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<Region>,
}

#[derive(Debug, Serialize)]
struct ArtifactLocation {
    uri: String,
}

#[derive(Debug, Serialize)]
struct Region {
    #[serde(rename = "startLine")]
    start_line: i64,
}

fn to_sarif_result(issue: &IssueRow) -> SarifResult {
    let mut properties = Map::new();
    properties.insert("status".to_string(), Value::String(issue.status.clone()));
    if let Some(score) = issue.score {
        properties.insert("igniteScore".to_string(), Value::from(score));
    }
    if issue.cross_file {
        properties.insert("crossFile".to_string(), Value::Bool(true));
    }
    if let Some(chain) = &issue.chain {
        properties.insert("chain".to_string(), chain.clone());
    }
    if let Some(cwe) = &issue.cwe {
        properties.insert("cwe".to_string(), Value::String(cwe.clone()));
    }
    // `references.cve` (and its sibling advisory-id buckets) is only ever
    // non-empty when the underlying scanner reported a real published
    // advisory id — surfaced here so a SARIF consumer (e.g. GitHub code
    // scanning) sees the actual CVE, not just the generic CWE weakness
    // classification every issue gets.
    if let Some(cve) = issue.references.as_ref().and_then(|r| r.get("cve")).filter(|c| c.as_array().is_some_and(|a| !a.is_empty())) {
        properties.insert("cve".to_string(), cve.clone());
    }

    let locations = issue.file.as_ref().map(|file| {
        vec![Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation { uri: file.clone() },
                region: issue.line.filter(|&l| l > 0).map(|start_line| Region { start_line }),
            },
        }]
    });

    SarifResult {
        rule_id: rule_id_for(issue),
        level: sarif_level(issue).to_string(),
        message: Message { text: if issue.summary.is_empty() { "(no summary)".to_string() } else { issue.summary.clone() } },
        partial_fingerprints: PartialFingerprints { ignite_issue_id: issue.id.clone() },
        properties,
        locations,
    }
}

#[derive(Debug, Serialize)]
struct Rule {
    id: String,
    #[serde(rename = "shortDescription")]
    short_description: Message,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: DefaultConfiguration,
}

#[derive(Debug, Serialize)]
struct DefaultConfiguration {
    level: String,
}

#[derive(Debug, Serialize)]
struct Driver {
    name: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<Rule>,
}

#[derive(Debug, Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Debug, Serialize)]
struct Run {
    tool: Tool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
pub struct SarifDocument {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<Run>,
}

pub fn build_sarif(issues: &[IssueRow]) -> SarifDocument {
    let mut rule_ids_seen = Vec::new();
    let mut rules: std::collections::HashMap<String, Rule> = std::collections::HashMap::new();
    for issue in issues {
        let id = rule_id_for(issue);
        if !rules.contains_key(&id) {
            rule_ids_seen.push(id.clone());
            rules.insert(
                id.clone(),
                Rule {
                    id: id.clone(),
                    short_description: Message { text: issue.category.clone() },
                    default_configuration: DefaultConfiguration { level: if issue.severity == "error" { "error".to_string() } else { "warning".to_string() } },
                },
            );
        }
    }
    let ordered_rules = rule_ids_seen.into_iter().map(|id| rules.remove(&id).unwrap()).collect();

    SarifDocument {
        schema: SARIF_SCHEMA.to_string(),
        version: "2.1.0".to_string(),
        runs: vec![Run {
            tool: Tool { driver: Driver { name: "Ignite".to_string(), information_uri: "https://github.com/nunomcpereira/ignite".to_string(), rules: ordered_rules } },
            results: issues.iter().map(to_sarif_result).collect(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_issue(status: &str, severity: &str) -> IssueRow {
        IssueRow {
            id: "secret::src/app.js::12".to_string(),
            phase: Some(4),
            category: "secret".to_string(),
            severity: severity.to_string(),
            score: Some(9),
            summary: "Hardcoded AWS key detected.".to_string(),
            file: Some("src/app.js".to_string()),
            line: Some(12),
            snippet: None,
            cross_file: false,
            chain: None,
            cwe: None,
            owasp: None,
            tool: None,
            references: None,
            status: status.to_string(),
            created_at: String::new(),
        }
    }

    #[test]
    fn top_level_shape_matches_sarif_2_1_0() {
        let doc = build_sarif(&[make_issue("open", "error")]);
        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].as_str().unwrap().contains("sarif-schema-2.1.0"));
        assert_eq!(v["runs"].as_array().unwrap().len(), 1);
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "Ignite");
    }

    #[test]
    fn error_issue_maps_to_error_level() {
        let doc = build_sarif(&[make_issue("open", "error")]);
        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn warning_issue_maps_to_warning_level() {
        let doc = build_sarif(&[make_issue("open", "warning")]);
        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(v["runs"][0]["results"][0]["level"], "warning");
    }

    #[test]
    fn overridden_issue_downgrades_to_note_regardless_of_severity() {
        let doc = build_sarif(&[make_issue("overridden", "error")]);
        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(v["runs"][0]["results"][0]["level"], "note");
    }

    #[test]
    fn result_carries_location_and_stable_fingerprint() {
        let doc = build_sarif(&[make_issue("open", "error")]);
        let v = serde_json::to_value(&doc).unwrap();
        let result = &v["runs"][0]["results"][0];
        assert_eq!(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/app.js");
        assert_eq!(result["locations"][0]["physicalLocation"]["region"]["startLine"], 12);
        assert_eq!(result["partialFingerprints"]["igniteIssueId"], "secret::src/app.js::12");
    }

    #[test]
    fn cve_reference_surfaces_as_a_sarif_property() {
        let mut issue = make_issue("open", "error");
        issue.references = Some(serde_json::json!({ "cve": ["CVE-2024-1"], "ghsa": ["GHSA-xxxx"] }));
        let doc = build_sarif(&[issue]);
        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(v["runs"][0]["results"][0]["properties"]["cve"], serde_json::json!(["CVE-2024-1"]));
    }

    #[test]
    fn empty_cve_reference_list_is_omitted() {
        let mut issue = make_issue("open", "error");
        issue.references = Some(serde_json::json!({ "cve": [] }));
        let doc = build_sarif(&[issue]);
        let v = serde_json::to_value(&doc).unwrap();
        assert!(v["runs"][0]["results"][0]["properties"].get("cve").is_none());
    }

    #[test]
    fn project_wide_issue_with_no_file_has_no_locations() {
        let mut issue = make_issue("open", "error");
        issue.file = None;
        issue.line = None;
        let doc = build_sarif(&[issue]);
        let v = serde_json::to_value(&doc).unwrap();
        assert!(v["runs"][0]["results"][0].get("locations").is_none());
    }

    #[test]
    fn dedups_rules_by_category() {
        let mut a = make_issue("open", "error");
        a.id = "a".to_string();
        let mut b = make_issue("open", "error");
        b.id = "b".to_string();
        b.file = Some("other.js".to_string());
        let mut c = make_issue("open", "error");
        c.id = "c".to_string();
        c.category = "ai-governance".to_string();

        let doc = build_sarif(&[a, b, c]);
        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 2);
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn cross_file_codeql_findings_preserve_cross_file_and_chain() {
        let mut issue = make_issue("open", "error");
        issue.category = "codeql".to_string();
        issue.cross_file = true;
        issue.chain = Some(serde_json::json!([{"file": "a.js", "line": 1}, {"file": "b.js", "line": 9}]));
        let doc = build_sarif(&[issue]);
        let v = serde_json::to_value(&doc).unwrap();
        let props = &v["runs"][0]["results"][0]["properties"];
        assert_eq!(props["crossFile"], true);
        assert_eq!(props["chain"], serde_json::json!([{"file": "a.js", "line": 1}, {"file": "b.js", "line": 9}]));
    }
}
