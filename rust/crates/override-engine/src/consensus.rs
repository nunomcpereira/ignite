//! Engine consensus for code-analysis findings. Several SAST engines run
//! side by side (CodeQL, Semgrep, Bearer); reporting every engine's findings
//! as blocking adds up every engine's false positives (measured on the OWASP
//! Benchmark: the combined run scored lower than CodeQL alone — see
//! `docs-site/docs/detection-quality.md`).
//!
//! [`apply_engine_consensus`] keeps a blocking code-analysis finding
//! blocking only when it came from a trusted engine; in a file whose
//! language a trusted engine actually analyzed this run, other engines'
//! findings are advisory; elsewhere they need enough distinct engines to
//! report the same weakness (same file, same CWE family, nearby lines). Anything else is downgraded to a warning — still reported, with a
//! note saying why — never dropped. Findings with no CWE can't be matched
//! across engines and are left as they are.

use crate::model::{Issue, Severity};
use crate::scoring::score_for_issue;
use std::collections::{BTreeSet, HashMap};

/// Categories produced by code-analysis engines.
pub const CODE_ANALYSIS_CATEGORIES: &[&str] = &["codeql-sast", "semantic-sast", "pii-dataflow"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusPolicy {
    /// Engines (`Issue::tool`, lowercase) whose findings keep blocking on their own.
    pub trusted_engines: Vec<String>,
    /// Distinct engines that must report a weakness for it to keep blocking.
    pub min_engines: usize,
    /// Two findings are the same weakness when their lines are at most this
    /// far apart; `None` = anywhere in the same file.
    pub line_window: Option<i64>,
    /// File extensions (`.java`) a trusted engine analyzed this run. In such
    /// a file only trusted findings block: on the OWASP Benchmark, other
    /// engines added false positives and no true positives once CodeQL ran.
    pub trusted_covers: Vec<String>,
}

impl Default for ConsensusPolicy {
    fn default() -> Self {
        ConsensusPolicy { trusted_engines: vec!["codeql".to_string()], min_engines: 2, line_window: Some(10), trusted_covers: vec![] }
    }
}

/// Source file extensions of the CodeQL languages Ignite analyzes.
pub fn extensions_for_languages(languages: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for l in languages {
        let exts: &[&str] = match l.as_str() {
            "java" => &[".java", ".kt"],
            "javascript" => &[".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"],
            "python" => &[".py"],
            "go" => &[".go"],
            "csharp" => &[".cs"],
            "ruby" => &[".rb"],
            "cpp" => &[".c", ".cc", ".cpp", ".h", ".hpp"],
            "swift" => &[".swift"],
            _ => &[],
        };
        out.extend(exts.iter().map(|e| e.to_string()));
    }
    out
}

fn covered(file: &str, extensions: &[String]) -> bool {
    let lower = file.to_ascii_lowercase();
    extensions.iter().any(|e| lower.ends_with(e.as_str()))
}

/// Closely related CWEs engines report for the same defect, folded to one
/// family id so a CodeQL CWE-328 and a Semgrep CWE-327 on the same weak hash
/// count as agreement.
pub fn cwe_family(cwe: u32) -> u32 {
    match cwe {
        326 | 327 | 328 | 916 => 327,
        330 | 338 => 330,
        22 | 23 | 36 | 73 => 22,
        77 | 78 => 78,
        79 | 80 | 83 => 79,
        89 | 564 => 89,
        other => other,
    }
}

fn cwe_families(issue: &Issue) -> BTreeSet<u32> {
    issue
        .cwe
        .iter()
        .chain(issue.references.cwe.iter())
        .filter_map(|c| {
            let t = c.trim();
            let digits: String = t.strip_prefix("CWE-").or_else(|| t.strip_prefix("cwe-")).unwrap_or(t).chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse::<u32>().ok().map(cwe_family)
        })
        .collect()
}

fn engine(issue: &Issue) -> String {
    issue.tool.as_deref().unwrap_or("unknown").to_ascii_lowercase()
}

/// Downgrades uncorroborated blocking code-analysis findings to warnings.
/// Returns how many were downgraded. Order and every other field of
/// `issues` is preserved.
pub fn apply_engine_consensus(issues: &mut [Issue], policy: &ConsensusPolicy) -> usize {
    // (file, cwe family) -> every code-analysis report of it: (line, engine).
    let mut reports: HashMap<(String, u32), Vec<(Option<i64>, String)>> = HashMap::new();
    for issue in issues.iter().filter(|i| CODE_ANALYSIS_CATEGORIES.contains(&i.category.as_str())) {
        let Some(file) = issue.file.clone() else { continue };
        for family in cwe_families(issue) {
            reports.entry((file.clone(), family)).or_default().push((issue.line, engine(issue)));
        }
    }
    let near = |a: Option<i64>, b: Option<i64>| match (policy.line_window, a, b) {
        (None, _, _) => true,
        (Some(w), Some(x), Some(y)) => (x - y).abs() <= w,
        _ => true,
    };

    let mut downgraded = 0;
    for issue in issues.iter_mut() {
        if issue.severity != Severity::Error || !CODE_ANALYSIS_CATEGORIES.contains(&issue.category.as_str()) {
            continue;
        }
        let own = engine(issue);
        if policy.trusted_engines.iter().any(|t| t.eq_ignore_ascii_case(&own)) {
            continue;
        }
        let Some(file) = issue.file.clone() else { continue };
        if covered(&file, &policy.trusted_covers) {
            issue.severity = Severity::Warning;
            issue.score = score_for_issue(&issue.category, Severity::Warning);
            issue.summary = format!("{} [advisory: {} analyzed this file; only its findings block here (engine consensus)]", issue.summary, policy.trusted_engines.join("/"));
            downgraded += 1;
            continue;
        }
        let families = cwe_families(issue);
        if families.is_empty() {
            continue;
        }
        let engines: BTreeSet<String> = families
            .iter()
            .filter_map(|f| reports.get(&(file.clone(), *f)))
            .flatten()
            .filter(|(line, _)| near(*line, issue.line))
            .map(|(_, e)| e.clone())
            .collect();
        if engines.len() >= policy.min_engines.max(1) {
            continue;
        }
        issue.severity = Severity::Warning;
        issue.score = score_for_issue(&issue.category, Severity::Warning);
        issue.summary = format!("{} [not corroborated: only {own} reported this; engine consensus made it a warning]", issue.summary);
        downgraded += 1;
    }
    downgraded
}

/// Downgrades blocking findings whose `(tool, rule)` is in `rules` (both
/// lowercase) to warnings, appending `note`. Returns how many.
pub fn downgrade_rules(issues: &mut [Issue], rules: &std::collections::HashSet<(String, String)>, note: &str) -> usize {
    let mut n = 0;
    for issue in issues.iter_mut().filter(|i| i.severity == Severity::Error) {
        let (Some(tool), Some(rule)) = (issue.tool.as_deref(), issue.rule.as_deref()) else { continue };
        if rules.contains(&(tool.to_ascii_lowercase(), rule.to_ascii_lowercase())) {
            issue.severity = Severity::Warning;
            issue.score = score_for_issue(&issue.category, Severity::Warning);
            issue.summary = format!("{} [{note}]", issue.summary);
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::IssueReferences;

    fn sast(category: &str, tool: &str, file: &str, line: i64, cwe: Option<&str>) -> Issue {
        Issue {
            id: format!("{category}::{file}::{line}::{tool}"),
            category: category.into(),
            severity: Severity::Error,
            score: 8,
            summary: "finding".into(),
            file: Some(file.into()),
            line: Some(line),
            snippet: None,
            cross_file: false,
            chain: None,
            duplicate_ref: None,
            cwe: cwe.map(str::to_string),
            owasp: None,
            tool: Some(tool.into()),
            references: IssueReferences::default(),
            author: None,
            rule: None,
        }
    }

    #[test]
    fn trusted_and_corroborated_findings_keep_blocking() {
        let mut issues = vec![
            sast("codeql-sast", "codeql", "a.java", 10, Some("CWE-89")),
            sast("semantic-sast", "semgrep", "a.java", 12, Some("CWE-89")), // agrees with codeql nearby
            sast("semantic-sast", "semgrep", "b.java", 5, Some("CWE-78")),  // alone
            sast("pii-dataflow", "bearer", "c.java", 3, Some("CWE-327")),
            sast("semantic-sast", "semgrep", "c.java", 4, Some("CWE-328")), // same family as bearer's
        ];
        let n = apply_engine_consensus(&mut issues, &ConsensusPolicy::default());
        assert_eq!(n, 1);
        let sev: Vec<Severity> = issues.iter().map(|i| i.severity).collect();
        assert_eq!(sev, vec![Severity::Error, Severity::Error, Severity::Warning, Severity::Error, Severity::Error]);
        assert!(issues[2].summary.contains("not corroborated: only semgrep"));
        assert!(issues[2].score < 8);
    }

    #[test]
    fn rules_learned_as_false_positives_stop_blocking() {
        let mut a = sast("semantic-sast", "semgrep", "a.java", 1, None);
        a.rule = Some("Java.Weak-Hash".into());
        let mut issues = vec![a, sast("semantic-sast", "semgrep", "b.java", 1, None)];
        let rules = [("semgrep".to_string(), "java.weak-hash".to_string())].into_iter().collect();
        assert_eq!(downgrade_rules(&mut issues, &rules, "learned"), 1);
        assert_eq!(issues[0].severity, Severity::Warning);
        assert!(issues[0].summary.ends_with("[learned]"));
        assert_eq!(issues[1].severity, Severity::Error, "no rule id: untouched");
    }

    #[test]
    fn in_a_file_the_trusted_engine_analyzed_only_its_findings_block() {
        let mut issues = vec![
            sast("codeql-sast", "codeql", "A.java", 10, Some("CWE-89")),
            sast("semantic-sast", "semgrep", "A.java", 10, Some("CWE-89")),
            sast("pii-dataflow", "bearer", "A.java", 11, Some("CWE-89")),
            sast("semantic-sast", "semgrep", "b.rb", 5, Some("CWE-78")),
            sast("pii-dataflow", "bearer", "b.rb", 6, Some("CWE-78")),
        ];
        let policy = ConsensusPolicy { trusted_covers: extensions_for_languages(&["java".to_string()]), ..Default::default() };
        assert_eq!(apply_engine_consensus(&mut issues, &policy), 2);
        let sev: Vec<Severity> = issues.iter().map(|i| i.severity).collect();
        assert_eq!(sev, vec![Severity::Error, Severity::Warning, Severity::Warning, Severity::Error, Severity::Error], "Ruby isn't covered: two agreeing engines still block");
        assert!(issues[1].summary.contains("advisory: codeql analyzed this file"));
    }

    #[test]
    fn far_apart_lines_and_findings_without_cwe_are_handled_conservatively() {
        let mut issues = vec![
            sast("semantic-sast", "semgrep", "a.java", 10, Some("CWE-89")),
            sast("pii-dataflow", "bearer", "a.java", 90, Some("CWE-89")),
            sast("semantic-sast", "semgrep", "a.java", 20, None),
            sast("secret", "gitleaks", "a.java", 1, Some("CWE-798")),
        ];
        assert_eq!(apply_engine_consensus(&mut issues, &ConsensusPolicy::default()), 2, "two lone SQLi reports 80 lines apart");
        assert_eq!(issues[2].severity, Severity::Error, "no CWE: can't judge, left alone");
        assert_eq!(issues[3].severity, Severity::Error, "not a code-analysis category");

        let mut whole_file = vec![sast("semantic-sast", "semgrep", "a.java", 10, Some("CWE-89")), sast("pii-dataflow", "bearer", "a.java", 90, Some("CWE-89"))];
        assert_eq!(apply_engine_consensus(&mut whole_file, &ConsensusPolicy { line_window: None, ..Default::default() }), 0);
    }
}
