//! Faithful port of `lib/github-annotations.js`'s `buildGithubAnnotations`
//! — reshapes the flat issue list into GitHub Actions workflow-command
//! annotations (`::error file=...,line=...::message`), printed to a job's
//! own stdout so they appear inline on the "Files changed" / job log view
//! with no upload step or extra permissions. `routes/github-annotations.js`'s
//! HTTP wiring isn't ported here — needs the HTTP server layer.

use ignite_db_store::IssueRow;

pub fn annotation_level(issue: &IssueRow) -> &'static str {
    if issue.severity == "error" {
        "error"
    } else {
        "warning"
    }
}

// Workflow-command property/data values can't contain raw CR/LF/%, or the
// command parser misreads them — GitHub's own escaping table.
fn escape_data(s: &str) -> String {
    s.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A")
}

fn escape_property(s: &str) -> String {
    s.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A").replace(':', "%3A").replace(',', "%2C")
}

fn to_annotation_line(issue: &IssueRow) -> String {
    let level = annotation_level(issue);
    let mut props = Vec::new();
    if let Some(file) = &issue.file {
        props.push(format!("file={}", escape_property(file)));
    }
    if let Some(line) = issue.line.filter(|&l| l > 0) {
        props.push(format!("line={line}"));
    }
    let category = if issue.category.is_empty() { "finding" } else { &issue.category };
    props.push(format!("title=Ignite: {}", escape_property(category)));
    let prop_str = props.join(",");
    let summary = if issue.summary.is_empty() { "(no summary)" } else { &issue.summary };
    format!("::{level} {prop_str}::{}", escape_data(summary))
}

pub fn build_github_annotations(issues: &[IssueRow]) -> String {
    issues.iter().filter(|issue| issue.status != "overridden").map(to_annotation_line).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_issue(severity: &str, status: &str) -> IssueRow {
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
            status: status.to_string(),
            created_at: String::new(),
        }
    }

    #[test]
    fn error_severity_maps_to_error() {
        let out = build_github_annotations(&[make_issue("error", "open")]);
        assert!(out.starts_with("::error "));
    }

    #[test]
    fn warning_severity_maps_to_warning() {
        let out = build_github_annotations(&[make_issue("warning", "open")]);
        assert!(out.starts_with("::warning "));
    }

    #[test]
    fn includes_file_line_and_message() {
        let out = build_github_annotations(&[make_issue("error", "open")]);
        assert!(out.contains("file=src/app.js"));
        assert!(out.contains("line=12"));
        assert!(out.ends_with("::Hardcoded AWS key detected."));
    }

    #[test]
    fn overridden_issues_omitted() {
        let out = build_github_annotations(&[make_issue("error", "overridden")]);
        assert_eq!(out, "");
    }

    #[test]
    fn project_wide_issue_omits_file_property() {
        let mut issue = make_issue("error", "open");
        issue.file = None;
        issue.line = None;
        let out = build_github_annotations(&[issue]);
        assert!(!out.contains("file="));
        assert!(!out.contains("line="));
    }

    #[test]
    fn escapes_newlines_and_commas() {
        let mut issue = make_issue("error", "open");
        issue.summary = "line1\nline2".to_string();
        issue.category = "a,b".to_string();
        let out = build_github_annotations(&[issue]);
        assert!(!out.contains('\n'));
        assert!(out.contains("%0A"));
        assert!(out.contains("title=Ignite: a%2Cb"));
    }

    #[test]
    fn one_line_per_issue() {
        let mut a = make_issue("error", "open");
        a.id = "a".to_string();
        let mut b = make_issue("error", "open");
        b.id = "b".to_string();
        b.file = Some("other.js".to_string());
        let out = build_github_annotations(&[a, b]);
        assert_eq!(out.split('\n').count(), 2);
    }
}
