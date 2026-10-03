//! Detection-quality scoring against the OWASP Benchmark for Java (US-13).
//!
//! Pure scoring only — fetching the Benchmark and running Phase 4 against it
//! live in `main.rs`. The Benchmark itself is GPL-2.0 and is never vendored
//! into this repository; `main.rs` clones it into a cache directory.
//!
//! Matching follows the Benchmark's own scorecard convention: each test case
//! (`BenchmarkTestNNNNN.java`) belongs to exactly one vulnerability category
//! with one CWE, and a tool "flags" that test case when it reports a finding
//! in that file whose CWE is accepted for the test's category
//! ([`accepted_cwes`]). A finding with a CWE outside the test's own category
//! is "off-category": it neither helps nor hurts that test case, as in the
//! official scorecards. A finding with no CWE at all is "unmapped" and is
//! never counted as a true positive.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use ignite_override_engine::Issue;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The Benchmark commit this crate's numbers are pinned to (`master` of
/// github.com/OWASP-Benchmark/BenchmarkJava, Benchmark version 1.2).
pub const BENCHMARK_REPO: &str = "https://github.com/OWASP-Benchmark/BenchmarkJava";
pub const BENCHMARK_COMMIT: &str = "8b67a88d73b2594570fc21150705283de884620b";
pub const EXPECTED_RESULTS_FILE: &str = "expectedresults-1.2.csv";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestCase {
    pub name: String,
    pub category: String,
    pub real_vulnerability: bool,
    pub cwe: u32,
}

/// Parses the Benchmark's `expectedresults-*.csv`
/// (`BenchmarkTest00001,pathtraver,true,22`; `#`-prefixed header).
pub fn parse_expected_results(csv: &str) -> Result<Vec<TestCase>, String> {
    let mut out = Vec::new();
    for (i, raw) in csv.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split(',').map(str::trim).collect();
        if cols.len() < 4 {
            return Err(format!("line {}: expected 4 columns, got {}", i + 1, cols.len()));
        }
        let real_vulnerability = match cols[2] {
            "true" => true,
            "false" => false,
            other => return Err(format!("line {}: bad 'real vulnerability' value {other:?}", i + 1)),
        };
        let cwe = cols[3].parse::<u32>().map_err(|_| format!("line {}: bad CWE {:?}", i + 1, cols[3]))?;
        out.push(TestCase { name: cols[0].to_string(), category: cols[1].to_string(), real_vulnerability, cwe });
    }
    if out.is_empty() {
        return Err("no test cases found".to_string());
    }
    Ok(out)
}

/// CWEs accepted as flagging a test case of the given category CWE. Beyond
/// the exact CWE, this accepts the closely related CWEs real tools commonly
/// report for the same defect (e.g. CWE-327 "broken crypto" for a weak hash
/// test, CWE-338 "weak PRNG" for a weak-randomness test). Listed in the
/// scorecard so the mapping is never hidden.
pub fn accepted_cwes(category_cwe: u32) -> &'static [u32] {
    match category_cwe {
        22 => &[22, 23, 36, 73],
        78 => &[78, 77],
        79 => &[79, 80, 83],
        89 => &[89, 564],
        90 => &[90],
        327 => &[327, 326],
        328 => &[328, 327, 916],
        330 => &[330, 338],
        501 => &[501],
        614 => &[614],
        643 => &[643],
        _ => &[],
    }
}

/// Every CWE number an issue carries (`cwe` plus `references.cwe`), parsed
/// from forms like `CWE-89`, `cwe-89`, `89`.
pub fn issue_cwes(issue: &Issue) -> BTreeSet<u32> {
    issue.cwe.iter().chain(issue.references.cwe.iter()).filter_map(|c| parse_cwe(c)).collect()
}

fn parse_cwe(s: &str) -> Option<u32> {
    let t = s.trim();
    let digits = t.strip_prefix("CWE-").or_else(|| t.strip_prefix("cwe-")).unwrap_or(t);
    let digits: String = digits.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// `BenchmarkTest00042` from any path ending in `BenchmarkTest00042.java`.
pub fn test_case_name_for_path(path: &str) -> Option<String> {
    let file = path.rsplit(['/', '\\']).next()?;
    let stem = file.strip_suffix(".java")?;
    let rest = stem.strip_prefix("BenchmarkTest")?;
    (!rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())).then(|| stem.to_string())
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Confusion {
    pub tp: u32,
    pub fp: u32,
    pub fn_: u32,
    pub tn: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Rates {
    /// TP / (TP + FN).
    pub recall: f64,
    /// FP / (FP + TN).
    pub false_positive_rate: f64,
    /// TP / (TP + FP); `None` when nothing was flagged.
    pub precision: Option<f64>,
    /// The Benchmark's own score: recall minus false-positive rate.
    pub benchmark_score: f64,
}

impl Confusion {
    pub fn rates(&self) -> Rates {
        let ratio = |a: u32, b: u32| if a + b == 0 { 0.0 } else { round4(a as f64 / (a + b) as f64) };
        let recall = ratio(self.tp, self.fn_);
        let fpr = ratio(self.fp, self.tn);
        Rates {
            recall,
            false_positive_rate: fpr,
            precision: (self.tp + self.fp > 0).then(|| ratio(self.tp, self.fp)),
            benchmark_score: round4(recall - fpr),
        }
    }

    fn add(&mut self, other: &Confusion) {
        self.tp += other.tp;
        self.fp += other.fp;
        self.fn_ += other.fn_;
        self.tn += other.tn;
    }
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CategoryScore {
    pub category: String,
    pub cwe: u32,
    pub accepted_cwes: Vec<u32>,
    pub test_cases: u32,
    pub confusion: Confusion,
    pub rates: Rates,
    /// Tools whose findings produced at least one true positive here.
    pub contributing_tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Scorecard {
    pub categories: Vec<CategoryScore>,
    /// Sum of every category's confusion matrix.
    pub totals: Confusion,
    pub total_rates: Rates,
    /// Mean of per-category Benchmark scores (how OWASP's own scorecards
    /// report an overall number, so a big category can't dominate it).
    pub average_category_score: f64,
    pub findings_in_test_cases: u32,
    /// Findings in a test-case file whose CWE belongs to a different
    /// category than that test case's own (ignored for scoring).
    pub off_category_findings: u32,
    /// Findings in a test-case file with no CWE at all, by category id.
    pub unmapped_findings: BTreeMap<String, u32>,
    pub findings_outside_test_cases: u32,
}

/// Scores `issues` against `cases`. Deterministic: output ordering depends
/// only on the inputs' content, never on iteration order of hash maps.
pub fn score(cases: &[TestCase], issues: &[Issue]) -> Scorecard {
    let by_name: HashMap<&str, &TestCase> = cases.iter().map(|c| (c.name.as_str(), c)).collect();
    // test case name -> tools that flagged it with an accepted CWE.
    let mut flagged: HashMap<&str, BTreeSet<String>> = HashMap::new();
    let mut findings_in_test_cases = 0u32;
    let mut off_category = 0u32;
    let mut unmapped: BTreeMap<String, u32> = BTreeMap::new();
    let mut outside = 0u32;

    for issue in issues {
        let Some(case) = issue.file.as_deref().and_then(test_case_name_for_path).and_then(|n| by_name.get(n.as_str()).copied()) else {
            outside += 1;
            continue;
        };
        findings_in_test_cases += 1;
        let cwes = issue_cwes(issue);
        if cwes.is_empty() {
            *unmapped.entry(issue.category.clone()).or_default() += 1;
            continue;
        }
        let accepted = accepted_cwes(case.cwe);
        if cwes.iter().any(|c| accepted.contains(c)) {
            flagged.entry(case.name.as_str()).or_default().insert(issue.tool.clone().unwrap_or_else(|| "unknown".to_string()));
        } else {
            off_category += 1;
        }
    }

    let mut per_cat: BTreeMap<(&str, u32), (Confusion, u32, BTreeSet<String>)> = BTreeMap::new();
    for case in cases {
        let entry = per_cat.entry((case.category.as_str(), case.cwe)).or_default();
        entry.1 += 1;
        let tools = flagged.get(case.name.as_str());
        match (case.real_vulnerability, tools.is_some()) {
            (true, true) => {
                entry.0.tp += 1;
                entry.2.extend(tools.into_iter().flatten().cloned());
            }
            (true, false) => entry.0.fn_ += 1,
            (false, true) => entry.0.fp += 1,
            (false, false) => entry.0.tn += 1,
        }
    }

    let mut totals = Confusion::default();
    let categories: Vec<CategoryScore> = per_cat
        .into_iter()
        .map(|((category, cwe), (confusion, n, tools))| {
            totals.add(&confusion);
            CategoryScore {
                category: category.to_string(),
                cwe,
                accepted_cwes: accepted_cwes(cwe).to_vec(),
                test_cases: n,
                rates: confusion.rates(),
                confusion,
                contributing_tools: tools.into_iter().collect(),
            }
        })
        .collect();
    let average_category_score = if categories.is_empty() { 0.0 } else { round4(categories.iter().map(|c| c.rates.benchmark_score).sum::<f64>() / categories.len() as f64) };

    Scorecard {
        total_rates: totals.rates(),
        totals,
        average_category_score,
        categories,
        findings_in_test_cases,
        off_category_findings: off_category,
        unmapped_findings: unmapped,
        findings_outside_test_cases: outside,
    }
}

/// One engine/check's coverage as recorded for a benchmark run.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EngineRun {
    pub check_id: String,
    pub outcome: String,
    pub engine: Option<String>,
    pub engine_version: Option<String>,
    pub is_fallback: bool,
}

pub fn engine_runs(coverage: &[ignite_policy::CheckCoverage]) -> Vec<EngineRun> {
    let mut v: Vec<EngineRun> = coverage
        .iter()
        .map(|c| EngineRun {
            check_id: c.check_id.clone(),
            outcome: serde_json::to_value(c.outcome).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_else(|| format!("{:?}", c.outcome)),
            engine: c.engine.clone(),
            engine_version: c.engine_version.clone(),
            is_fallback: c.is_fallback,
        })
        .collect();
    v.sort_by(|a, b| a.check_id.cmp(&b.check_id));
    v
}

/// One engine's overall numbers when scored on its own findings only.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ToolScore {
    pub tool: String,
    pub totals: Confusion,
    pub total_rates: Rates,
    pub average_category_score: f64,
}

/// Scores each tool that reported a finding in a test case on its own, so a
/// scorecard shows what every engine adds (and costs in false positives)
/// to the combined result.
pub fn score_by_tool(cases: &[TestCase], issues: &[Issue]) -> Vec<ToolScore> {
    let tools: BTreeSet<String> = issues.iter().filter(|i| i.file.as_deref().and_then(test_case_name_for_path).is_some()).map(|i| i.tool.clone().unwrap_or_else(|| "unknown".to_string())).collect();
    tools
        .into_iter()
        .map(|tool| {
            let own: Vec<Issue> = issues.iter().filter(|i| i.tool.as_deref().unwrap_or("unknown") == tool).cloned().collect();
            let s = score(cases, &own);
            ToolScore { tool, totals: s.totals, total_rates: s.total_rates, average_category_score: s.average_category_score }
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModeResult {
    /// `full` (external tools as installed) or `fallback` (built-ins only).
    pub mode: String,
    pub duration_secs: f64,
    pub engines: Vec<EngineRun>,
    pub scorecard: Scorecard,
    pub by_tool: Vec<ToolScore>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchReport {
    pub benchmark_repo: String,
    pub benchmark_commit: String,
    pub test_cases: u32,
    pub ignite_commit: Option<String>,
    pub generated_at: String,
    pub modes: Vec<ModeResult>,
}

/// Phase 4 checks whose findings can land on a Benchmark test case — listed
/// with their engine in the scorecard so a missing tool is visible.
pub const CODE_ANALYSIS_CHECKS: &[&str] = &["semanticSast", "codeql", "pii"];

fn pct(x: f64) -> String {
    format!("{:.1}%", x * 100.0)
}

/// Markdown scorecard for `docs-site/docs/detection-quality.md`.
pub fn render_markdown(report: &BenchReport) -> String {
    let mut md = String::new();
    md.push_str("# Detection quality — OWASP Benchmark\n\n");
    md.push_str(&format!(
        "Generated {} against [OWASP Benchmark for Java]({}) commit `{}` ({} test cases), Ignite commit `{}`.\n\n",
        report.generated_at,
        report.benchmark_repo,
        report.benchmark_commit,
        report.test_cases,
        report.ignite_commit.as_deref().unwrap_or("unknown")
    ));
    md.push_str("**Benchmark score** = recall (true-positive rate) minus false-positive rate; 0 is no better than guessing, 100% is perfect. A test case counts as flagged when Ignite reports a finding in that test's file whose CWE is accepted for the test's category (see the *Accepted CWEs* column). Findings with no CWE are listed as unmapped and never count as true positives.\n\n");
    for m in &report.modes {
        let s = &m.scorecard;
        md.push_str(&format!("## Mode: `{}`\n\n", m.mode));
        md.push_str(&format!(
            "Average category score **{}** · overall recall {} · overall false-positive rate {} · precision {} · run time {:.0}s\n\n",
            pct(s.average_category_score),
            pct(s.total_rates.recall),
            pct(s.total_rates.false_positive_rate),
            s.total_rates.precision.map(pct).unwrap_or_else(|| "n/a".into()),
            m.duration_secs
        ));
        md.push_str("| Category | CWE | Accepted CWEs | Tests | TP | FP | FN | TN | Recall | FPR | Precision | Score | Tools |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
        for c in &s.categories {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                c.category,
                c.cwe,
                c.accepted_cwes.iter().map(u32::to_string).collect::<Vec<_>>().join(", "),
                c.test_cases,
                c.confusion.tp,
                c.confusion.fp,
                c.confusion.fn_,
                c.confusion.tn,
                pct(c.rates.recall),
                pct(c.rates.false_positive_rate),
                c.rates.precision.map(pct).unwrap_or_else(|| "n/a".into()),
                pct(c.rates.benchmark_score),
                if c.contributing_tools.is_empty() { "—".to_string() } else { c.contributing_tools.join(", ") }
            ));
        }
        md.push_str(&format!(
            "\nFindings in test-case files: {} (off-category: {}, unmapped/no CWE: {}). Findings outside test cases: {}.\n\n",
            s.findings_in_test_cases,
            s.off_category_findings,
            s.unmapped_findings.values().sum::<u32>(),
            s.findings_outside_test_cases
        ));
        if !m.by_tool.is_empty() {
            md.push_str("Each engine scored on its own findings:\n\n| Engine | TP | FP | FN | TN | Recall | FPR | Precision | Average category score |\n|---|---|---|---|---|---|---|---|---|\n");
            for t in &m.by_tool {
                md.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                    t.tool,
                    t.totals.tp,
                    t.totals.fp,
                    t.totals.fn_,
                    t.totals.tn,
                    pct(t.total_rates.recall),
                    pct(t.total_rates.false_positive_rate),
                    t.total_rates.precision.map(pct).unwrap_or_else(|| "n/a".into()),
                    pct(t.average_category_score)
                ));
            }
            md.push('\n');
        }
        let sast: Vec<&EngineRun> = m.engines.iter().filter(|e| CODE_ANALYSIS_CHECKS.contains(&e.check_id.as_str())).collect();
        if !sast.is_empty() {
            md.push_str("Code-analysis engines this run:\n\n");
            for e in sast {
                md.push_str(&format!(
                    "- `{}`: {} — engine `{}`{}{}\n",
                    e.check_id,
                    e.outcome,
                    e.engine.as_deref().unwrap_or("none"),
                    e.engine_version.as_deref().map(|v| format!(" {v}")).unwrap_or_default(),
                    if e.is_fallback { " (built-in fallback)" } else { "" }
                ));
            }
            md.push('\n');
        }
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use ignite_override_engine::{IssueReferences, Severity};

    fn issue(file: &str, cwe: Option<&str>, tool: &str) -> Issue {
        Issue {
            id: format!("x::{file}::1"),
            category: "semantic-sast".into(),
            severity: Severity::Error,
            score: 8,
            summary: "s".into(),
            file: Some(file.into()),
            line: Some(1),
            snippet: None,
            cross_file: false,
            chain: None,
            duplicate_ref: None,
            cwe: cwe.map(str::to_string),
            owasp: None,
            tool: Some(tool.into()),
            references: IssueReferences::default(),
            author: None,
        }
    }

    const CSV: &str = "# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1
BenchmarkTest00001,sqli,true,89
BenchmarkTest00002,sqli,false,89
BenchmarkTest00003,sqli,true,89
BenchmarkTest00004,sqli,false,89
BenchmarkTest00005,hash,true,328
BenchmarkTest00006,hash,false,328
";

    const DIR: &str = "src/main/java/org/owasp/benchmark/testcode/";

    #[test]
    fn parses_expected_results_and_rejects_garbage() {
        let cases = parse_expected_results(CSV).unwrap();
        assert_eq!(cases.len(), 6);
        assert_eq!(cases[4], TestCase { name: "BenchmarkTest00005".into(), category: "hash".into(), real_vulnerability: true, cwe: 328 });
        assert!(parse_expected_results("BenchmarkTest00001,sqli,maybe,89").is_err());
        assert!(parse_expected_results("# only a header\n").is_err());
    }

    #[test]
    fn test_case_names_come_only_from_benchmark_files() {
        assert_eq!(test_case_name_for_path(&format!("{DIR}BenchmarkTest00042.java")).as_deref(), Some("BenchmarkTest00042"));
        assert_eq!(test_case_name_for_path("BenchmarkTest00042.java").as_deref(), Some("BenchmarkTest00042"));
        assert!(test_case_name_for_path("src/helpers/ThingUtil.java").is_none());
        assert!(test_case_name_for_path("BenchmarkTest.java").is_none());
        assert!(test_case_name_for_path("BenchmarkTest00042.java.bak").is_none());
    }

    #[test]
    fn scores_a_confusion_matrix_per_category() {
        let cases = parse_expected_results(CSV).unwrap();
        let issues = vec![
            issue(&format!("{DIR}BenchmarkTest00001.java"), Some("CWE-89"), "semgrep"), // TP
            issue(&format!("{DIR}BenchmarkTest00001.java"), Some("CWE-89"), "codeql"),  // same TP, second tool
            issue(&format!("{DIR}BenchmarkTest00002.java"), Some("CWE-89"), "semgrep"), // FP
            issue(&format!("{DIR}BenchmarkTest00003.java"), Some("CWE-79"), "semgrep"), // off-category -> FN
            issue(&format!("{DIR}BenchmarkTest00005.java"), Some("CWE-327"), "semgrep"), // accepted alias -> TP
            issue(&format!("{DIR}BenchmarkTest00006.java"), None, "built-in"),          // unmapped -> TN
            issue("src/main/java/Other.java", Some("CWE-89"), "semgrep"),               // outside
        ];
        let s = score(&cases, &issues);
        let sqli = s.categories.iter().find(|c| c.category == "sqli").unwrap();
        assert_eq!(sqli.confusion, Confusion { tp: 1, fp: 1, fn_: 1, tn: 1 });
        assert_eq!(sqli.rates.recall, 0.5);
        assert_eq!(sqli.rates.false_positive_rate, 0.5);
        assert_eq!(sqli.rates.benchmark_score, 0.0);
        assert_eq!(sqli.contributing_tools, vec!["codeql".to_string(), "semgrep".to_string()]);
        let hash = s.categories.iter().find(|c| c.category == "hash").unwrap();
        assert_eq!(hash.confusion, Confusion { tp: 1, fp: 0, fn_: 0, tn: 1 });
        assert_eq!(hash.rates.benchmark_score, 1.0);
        assert_eq!(s.totals, Confusion { tp: 2, fp: 1, fn_: 1, tn: 2 });
        assert_eq!(s.average_category_score, 0.5);
        assert_eq!(s.findings_in_test_cases, 6);
        assert_eq!(s.off_category_findings, 1);
        assert_eq!(s.unmapped_findings.get("semantic-sast"), Some(&1));
        assert_eq!(s.findings_outside_test_cases, 1);
    }

    #[test]
    fn scoring_is_independent_of_finding_order() {
        let cases = parse_expected_results(CSV).unwrap();
        let mut issues = vec![
            issue(&format!("{DIR}BenchmarkTest00001.java"), Some("CWE-89"), "semgrep"),
            issue(&format!("{DIR}BenchmarkTest00002.java"), Some("89"), "codeql"),
            issue(&format!("{DIR}BenchmarkTest00005.java"), Some("cwe-328"), "bearer"),
        ];
        let a = score(&cases, &issues);
        issues.reverse();
        assert_eq!(a, score(&cases, &issues));
    }

    #[test]
    fn each_tool_is_scored_on_its_own_findings() {
        let cases = parse_expected_results(CSV).unwrap();
        let issues = vec![
            issue(&format!("{DIR}BenchmarkTest00001.java"), Some("CWE-89"), "semgrep"),
            issue(&format!("{DIR}BenchmarkTest00002.java"), Some("CWE-89"), "codeql"),
        ];
        let by_tool = score_by_tool(&cases, &issues);
        assert_eq!(by_tool.iter().map(|t| t.tool.as_str()).collect::<Vec<_>>(), vec!["codeql", "semgrep"]);
        assert_eq!(by_tool[0].totals, Confusion { tp: 0, fp: 1, fn_: 3, tn: 2 });
        assert_eq!(by_tool[1].totals, Confusion { tp: 1, fp: 0, fn_: 2, tn: 3 });
    }

    #[test]
    fn no_findings_scores_zero_with_no_precision() {
        let cases = parse_expected_results(CSV).unwrap();
        let s = score(&cases, &[]);
        assert_eq!(s.total_rates.recall, 0.0);
        assert_eq!(s.total_rates.precision, None);
        assert_eq!(s.average_category_score, 0.0);
    }

    #[test]
    fn cwes_are_read_from_references_too() {
        let mut i = issue("BenchmarkTest00001.java", None, "semgrep");
        i.references.cwe = vec!["CWE-89".into(), "CWE-564".into()];
        assert_eq!(issue_cwes(&i), BTreeSet::from([89, 564]));
    }

    #[test]
    fn markdown_lists_every_category_and_mode() {
        let cases = parse_expected_results(CSV).unwrap();
        let report = BenchReport {
            benchmark_repo: BENCHMARK_REPO.into(),
            benchmark_commit: BENCHMARK_COMMIT.into(),
            test_cases: cases.len() as u32,
            ignite_commit: Some("abc123".into()),
            generated_at: "2026-10-03T00:00:00Z".into(),
            modes: vec![ModeResult { mode: "fallback".into(), duration_secs: 1.0, engines: vec![], scorecard: score(&cases, &[]), by_tool: vec![] }],
        };
        let md = render_markdown(&report);
        assert!(md.contains("## Mode: `fallback`"));
        assert!(md.contains("| sqli | 89 |"));
        assert!(md.contains("| hash | 328 | 328, 327, 916 |"));
        assert!(md.contains("abc123"));
    }
}
