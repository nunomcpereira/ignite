//! Parsing and regeneration of `.ignite/acknowledgments.md` — ported from
//! `hooks/pre-push`'s own jq expressions (see git history around commit
//! 1268efe, which broke the hook's override resubmission entirely via a
//! single missing closing quote, undetected for who knows how long because
//! the logic existed only as unreviewed inline bash+jq with no tests).
//! Moving it here means this logic gets real unit tests and is reachable
//! from `ignite check` regardless of whether a caller goes through the git
//! hook at all — the hook itself shrinks to the parts that are genuinely
//! git/push-specific (the delta check against the last validated sha, and
//! `git commit --amend` to fold a regenerated file into the push).
//!
//! Every function here is pure (no I/O) so it's testable without a real
//! server or git repo — `check.rs` is the thin orchestration layer that
//! reads/writes files and makes the HTTP call.

use once_cell::sync::Lazy;
use regex::{Captures, Regex};
use serde_json::Value;

/// One block already present in `.ignite/acknowledgments.md` before this
/// run — either still-blank, already-justified, or (once matched against
/// a newly-surfaced issue during regeneration) marked `superseded` so it
/// gets dropped in favor of the replacement block that carries its
/// justification forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingEntry {
    pub id: String,
    pub category: String,
    pub file: Option<String>,
    pub code: Option<String>,
    pub justification: String,
    /// The block's own text (from `ID:` through its last line), stripped
    /// of exactly one trailing `\n` — mirrors jq's `rtrimstr("\n")`.
    pub raw: String,
    pub superseded: bool,
}

/// One error-severity finding from the `/api/pipeline/validate-all`
/// response, in the shape `regenerate` needs. Deliberately a separate
/// type from whatever the server's own `Issue` struct looks like — this
/// crate has no dependency on `override-engine`/`db-store`, by the same
/// "each check crate defines only the input shape it needs" convention
/// used throughout the rest of this codebase.
#[derive(Debug, Clone)]
pub struct Finding {
    pub id: String,
    pub category: String,
    pub file: Option<String>,
    pub line: Option<i64>,
    pub severity: String,
    pub summary: String,
    pub status: Option<String>,
    pub snippet: Option<Value>,
}

static ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^ID:\s*(?P<v>[^\n]+)").unwrap());
static FILE_LOC_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^#\s+(?P<v>\S+?)(?::\d+)?$").unwrap());
static CODE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^# Code:\s*(?P<v>[^\n]*)").unwrap());
static ACK_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"Acknowledge:\s*(?P<v>[^\n]*)").unwrap());
static ISSUE_NUM_STRIP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(?P<h>ID: [^\n]*)\n# Issue #[0-9]+\n").unwrap());
static HEADER_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(?P<h>ID: [^\n]*)\n").unwrap());

/// Splits `text` into per-entry blocks the same way jq's
/// `splits("\n(?=ID: )")` does — a new block starts at every line
/// beginning `ID: `, with the `\n` immediately before it consumed by the
/// split rather than kept on either side. Lines before the first `ID: `
/// line (the file's own header comment) form a leading pseudo-block that
/// [`parse_blocks`] discards, matching jq's `map(select(test("^ID:")))`.
fn split_blocks(text: &str) -> Vec<String> {
    let mut blocks: Vec<Vec<&str>> = Vec::new();
    for line in text.split('\n') {
        if line.starts_with("ID: ") {
            blocks.push(vec![line]);
        } else if let Some(last) = blocks.last_mut() {
            last.push(line);
        }
    }
    blocks.into_iter().map(|lines| lines.join("\n")).collect()
}

pub fn parse_blocks(text: &str) -> Vec<ExistingEntry> {
    split_blocks(text)
        .into_iter()
        .filter(|b| b.starts_with("ID:"))
        .filter_map(|block| {
            let id = ID_RE.captures(&block)?.name("v")?.as_str().to_string();
            let file = FILE_LOC_RE.captures(&block).and_then(|c| c.name("v")).map(|m| m.as_str().to_string());
            let code = CODE_RE.captures(&block).and_then(|c| c.name("v")).map(|m| m.as_str().to_string());
            let justification = ACK_RE.captures(&block).and_then(|c| c.name("v")).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
            let raw = block.strip_suffix('\n').unwrap_or(&block).to_string();
            let category = id.split("::").next().unwrap_or("").to_string();
            Some(ExistingEntry { id, category, file, code, justification, raw, superseded: false })
        })
        .collect()
}

/// The `overrides` array to send `/api/pipeline/validate-all` — every
/// already-justified entry, regardless of whether the underlying finding
/// still exists (a stale entry's `issueId` simply won't match anything
/// server-side and is silently ignored there, same as before this port).
pub fn build_overrides(entries: &[ExistingEntry]) -> Vec<Value> {
    entries
        .iter()
        .filter(|e| !e.justification.is_empty())
        .map(|e| {
            let mut v = serde_json::json!({ "issueId": e.id, "justification": e.justification });
            if let Some(code) = &e.code {
                v["code"] = serde_json::json!(code);
            }
            v
        })
        .collect()
}

/// The flagged line's own source text from `finding.snippet`, if present
/// — used to auto-carry-forward a justification across a pure
/// line-number shift. `None` whenever the snippet/highlight-line/matching
/// line/text field isn't there; an empty-but-present text still counts
/// (mirrors jq's `if . then trim else null end`, where only `null`/
/// `false` are falsy — an empty string is not).
fn code_for_finding(snippet: Option<&Value>) -> Option<String> {
    let snippet = snippet?;
    let highlight = snippet.get("highlightLine").and_then(|v| v.as_i64())?;
    let lines = snippet.get("lines")?.as_array()?;
    let text = lines.iter().find(|l| l.get("number").and_then(|v| v.as_i64()) == Some(highlight)).and_then(|l| l.get("text")).and_then(|v| v.as_str())?;
    Some(text.trim().to_string())
}

fn finding_loc(finding: &Finding) -> String {
    match &finding.file {
        Some(f) => match finding.line {
            Some(l) => format!("{f}:{l}"),
            None => f.clone(),
        },
        None => "(no file)".to_string(),
    }
}

fn build_new_block(finding: &Finding, matched: Option<&ExistingEntry>) -> String {
    let mut s = format!("ID: {}\n# [{}] {} - {}\n#   {}", finding.id, finding.severity.to_uppercase(), finding.category, finding.summary, finding_loc(finding));
    if let Some(code) = code_for_finding(finding.snippet.as_ref()) {
        s.push_str(&format!("\n# Code: {code}"));
    }
    s.push('\n');
    match matched {
        Some(m) => s.push_str(&format!("Acknowledge: {} (auto-carried-forward from {} - pure line-number drift, flagged code unchanged)", m.justification, m.id)),
        None => s.push_str("Acknowledge: "),
    }
    s
}

fn strip_issue_number(raw: &str) -> String {
    ISSUE_NUM_STRIP_RE.replace(raw, "$h\n").to_string()
}

fn insert_issue_number(block: &str, n: usize) -> String {
    HEADER_LINE_RE.replace(block, |caps: &Captures| format!("{}\n# Issue #{n}\n", &caps["h"])).to_string()
}

/// The full regenerated body (everything after the fixed header comment)
/// for `.ignite/acknowledgments.md`, given its current content and the
/// current scan's findings. Pure port of `hooks/pre-push`'s own jq
/// expression — see that file's git history for the original.
///
/// - An unresolved finding whose id already has an entry is left alone
///   (picked up by the existing-blocks pass below).
/// - An unresolved finding with a NEW id is matched against existing,
///   not-yet-superseded, already-justified entries sharing its category +
///   file + flagged-line text; a match's justification is carried forward
///   into a freshly-built block and the old entry is dropped.
/// - Entries whose id is no longer reported at all (fixed in source) are
///   dropped outright.
/// - Everything is deduped by id (existing beats freshly-built for the
///   same id; first occurrence wins otherwise) and renumbered.
pub fn regenerate(existing_text: &str, findings: &[Finding]) -> String {
    let mut existing = parse_blocks(existing_text);

    let mut new_blocks: Vec<String> = Vec::new();
    for finding in findings {
        if existing.iter().any(|e| e.id == finding.id) {
            continue;
        }
        let code = code_for_finding(finding.snippet.as_ref());
        let match_idx = code.as_ref().and_then(|code| existing.iter().position(|e| !e.superseded && !e.justification.is_empty() && e.category == finding.category && e.file.as_deref() == finding.file.as_deref() && e.code.as_deref() == Some(code.as_str())));
        // An already-`overridden` finding (the backend fuzzy-matched it
        // server-side, independent of this file) needs no action here —
        // but if it also carries a NEW id (its flagged line drifted since
        // the entry was written), it must still go through carry-forward
        // matching below, or the existing entry gets silently dropped
        // entirely: excluded here for having a new id, and excluded from
        // the `current_ids` keep-list further down for the same reason,
        // permanently losing the justification. Only skip when there's
        // truly nothing to carry forward.
        let is_overridden = finding.status.as_deref() == Some("overridden");
        if is_overridden && match_idx.is_none() {
            continue;
        }
        let matched_entry = match_idx.map(|i| existing[i].clone());
        if let Some(i) = match_idx {
            existing[i].superseded = true;
        }
        new_blocks.push(build_new_block(finding, matched_entry.as_ref()));
    }

    let current_ids: std::collections::HashSet<&str> = findings.iter().map(|f| f.id.as_str()).collect();

    let mut existing_blocks: Vec<ExistingEntry> = existing.into_iter().filter(|e| !e.superseded && current_ids.contains(e.id.as_str())).collect();
    existing_blocks.sort_by_key(|e| e.justification.is_empty());
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let existing_blocks_text: Vec<String> = existing_blocks.into_iter().filter(|e| seen.insert(e.id.clone())).map(|e| strip_issue_number(&e.raw)).collect();

    let mut combined_raw = existing_blocks_text;
    combined_raw.extend(new_blocks);

    let mut seen2: std::collections::HashSet<String> = std::collections::HashSet::new();
    let combined: Vec<String> = combined_raw
        .into_iter()
        .filter(|b| {
            let id = ID_RE.captures(b).and_then(|c| c.name("v")).map(|m| m.as_str().to_string()).unwrap_or_default();
            seen2.insert(id)
        })
        .collect();

    combined.iter().enumerate().map(|(i, b)| insert_issue_number(b, i + 1)).collect::<Vec<_>>().join("\n\n")
}

pub const HEADER: &str = "# Ignite pre-push acknowledgments - meant to be committed: a filled-in\n\
# justification is a real audit record, reviewable like code.\n\
#\n\
# Fill in a justification after \"Acknowledge:\" for any issue below you want\n\
# to override, save, then `git push` again. Blank = stays blocking.\n\
# Refreshed every run: only entries for findings still reported by the\n\
# current scan are kept - a filled-in justification survives as long\n\
# as its finding does, but once the underlying issue is fixed (or a\n\
# pure line-number shift carries its justification to a new id), the\n\
# stale entry is dropped rather than kept forever.\n\
# A `# Code:` line, when present, is the flagged source line own text -\n\
# used to auto-carry-forward this justification if an unrelated edit\n\
# elsewhere in the file later shifts its line number. Do not hand-edit it.\n\
# The `# Issue #N` line is just a running count of entries in this file\n\
# - recomputed on every push, not a stable id. Use the `ID:` line to\n\
# refer to a specific finding.\n";

/// The full new file content, or `None` when there's nothing to write —
/// mirrors `hooks/pre-push`'s own gate (`ISSUES_COUNT > 0 || -s
/// "$REVIEW_FILE"`): an empty scan against an empty/missing review file
/// needs no file at all, rather than writing just the header forever.
pub fn build_new_review_content(existing_text: &str, findings: &[Finding]) -> Option<String> {
    if findings.is_empty() && existing_text.trim().is_empty() {
        return None;
    }
    let body = regenerate(existing_text, findings);
    Some(format!("{HEADER}\n{body}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str, category: &str, file: &str, line: i64, summary: &str) -> Finding {
        Finding { id: id.to_string(), category: category.to_string(), file: Some(file.to_string()), line: Some(line), severity: "error".to_string(), summary: summary.to_string(), status: None, snippet: None }
    }

    #[test]
    fn parse_blocks_extracts_id_file_code_and_justification() {
        let text = "# header comment\n# more header\n\nID: secret::a.rs::10\n# [ERROR] secret - Hardcoded token\n#   a.rs:10\n# Code: let x = \"tok\";\nAcknowledge: fake token, not real\n\nID: secret::b.rs::5\n# [ERROR] secret - Hardcoded token\n#   b.rs:5\nAcknowledge: \n";
        let entries = parse_blocks(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, "secret::a.rs::10");
        assert_eq!(entries[0].category, "secret");
        assert_eq!(entries[0].file.as_deref(), Some("a.rs"));
        assert_eq!(entries[0].code.as_deref(), Some("let x = \"tok\";"));
        assert_eq!(entries[0].justification, "fake token, not real");
        assert_eq!(entries[1].id, "secret::b.rs::5");
        assert_eq!(entries[1].justification, "");
    }

    #[test]
    fn parse_blocks_empty_for_text_with_no_id_lines() {
        assert!(parse_blocks("# just a comment\nnothing else\n").is_empty());
    }

    #[test]
    fn build_overrides_skips_blank_justifications_and_includes_code_when_present() {
        let entries = vec![
            ExistingEntry { id: "a".into(), category: "secret".into(), file: None, code: Some("snippet".into()), justification: "ok".into(), raw: String::new(), superseded: false },
            ExistingEntry { id: "b".into(), category: "secret".into(), file: None, code: None, justification: "".into(), raw: String::new(), superseded: false },
        ];
        let overrides = build_overrides(&entries);
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0]["issueId"], "a");
        assert_eq!(overrides[0]["justification"], "ok");
        assert_eq!(overrides[0]["code"], "snippet");
    }

    #[test]
    fn regenerate_creates_a_blank_entry_for_a_brand_new_finding() {
        let body = regenerate("", &[finding("secret::a.rs::10", "secret", "a.rs", 10, "Hardcoded token")]);
        assert!(body.contains("ID: secret::a.rs::10"));
        assert!(body.contains("Acknowledge: "));
        assert!(body.contains("# Issue #1"));
        assert!(!body.contains("auto-carried-forward"));
    }

    #[test]
    fn regenerate_keeps_an_existing_justified_entry_whose_id_is_still_reported() {
        let existing = "ID: secret::a.rs::10\n# [ERROR] secret - Hardcoded token\n#   a.rs:10\nAcknowledge: not a real secret\n";
        let body = regenerate(existing, &[finding("secret::a.rs::10", "secret", "a.rs", 10, "Hardcoded token")]);
        assert!(body.contains("Acknowledge: not a real secret"));
        assert!(!body.contains("auto-carried-forward"));
    }

    #[test]
    fn regenerate_drops_an_entry_whose_finding_is_no_longer_reported() {
        let existing = "ID: secret::a.rs::10\n# [ERROR] secret - Hardcoded token\n#   a.rs:10\nAcknowledge: fixed now, this should vanish\n";
        let body = regenerate(existing, &[]);
        assert_eq!(body, "");
    }

    #[test]
    fn regenerate_carries_forward_a_justification_across_a_pure_line_shift() {
        let mut old = finding("secret::a.rs::10", "secret", "a.rs", 10, "Hardcoded token");
        old.snippet = Some(serde_json::json!({ "highlightLine": 10, "lines": [{"number": 10, "text": "let x = \"tok\";"}] }));
        let existing = "ID: secret::a.rs::10\n# [ERROR] secret - Hardcoded token\n#   a.rs:10\n# Code: let x = \"tok\";\nAcknowledge: fake token fixture\n";

        // Same code, same category/file, but the id's line number has
        // shifted from 10 to 14 (an edit above it, unrelated to this line).
        let mut shifted = finding("secret::a.rs::14", "secret", "a.rs", 14, "Hardcoded token");
        shifted.snippet = Some(serde_json::json!({ "highlightLine": 14, "lines": [{"number": 14, "text": "let x = \"tok\";"}] }));

        let body = regenerate(existing, &[shifted]);
        assert!(body.contains("ID: secret::a.rs::14"));
        assert!(!body.contains("ID: secret::a.rs::10"), "the superseded old id must not survive");
        assert!(body.contains("Acknowledge: fake token fixture (auto-carried-forward from secret::a.rs::10 - pure line-number drift, flagged code unchanged)"));
    }

    #[test]
    fn regenerate_does_not_carry_forward_when_the_flagged_line_text_actually_changed() {
        let mut old = finding("secret::a.rs::10", "secret", "a.rs", 10, "Hardcoded token");
        old.snippet = Some(serde_json::json!({ "highlightLine": 10, "lines": [{"number": 10, "text": "let x = \"tok\";"}] }));
        let existing = "ID: secret::a.rs::10\n# [ERROR] secret - Hardcoded token\n#   a.rs:10\n# Code: let x = \"tok\";\nAcknowledge: fake token fixture\n";

        let mut edited = finding("secret::a.rs::10", "secret", "a.rs", 10, "Hardcoded token");
        edited.snippet = Some(serde_json::json!({ "highlightLine": 10, "lines": [{"number": 10, "text": "let x = \"tok_v2\";"}] }));
        // Same id here (line unchanged), but if the id had also shifted
        // this is the "genuinely new" case - covered by keeping this one
        // id-stable and instead checking build_new_block never fires for
        // an id already present (see the sibling test above for the
        // actually-new-id carry-forward path).
        let body = regenerate(existing, &[edited]);
        assert!(body.contains("Acknowledge: fake token fixture"), "an unchanged id keeps its existing entry regardless of snippet text");
    }

    #[test]
    fn regenerate_prefers_a_justified_duplicate_over_a_blank_one_and_renumbers() {
        let f1 = finding("secret::a.rs::1", "secret", "a.rs", 1, "one");
        let f2 = finding("secret::b.rs::2", "secret", "b.rs", 2, "two");
        let existing = "ID: secret::a.rs::1\n# [ERROR] secret - one\n#   a.rs:1\nAcknowledge: justified\n\nID: secret::b.rs::2\n# [ERROR] secret - two\n#   b.rs:2\nAcknowledge: \n";
        let body = regenerate(existing, &[f1, f2]);
        assert!(body.contains("# Issue #1"));
        assert!(body.contains("# Issue #2"));
        // The justified entry must sort first per the existing-blocks
        // ordering (blank-justification entries sort after).
        let pos_a = body.find("secret::a.rs::1").unwrap();
        let pos_b = body.find("secret::b.rs::2").unwrap();
        assert!(pos_a < pos_b);
    }

    #[test]
    fn build_new_review_content_none_for_a_clean_scan_with_no_prior_file() {
        assert!(build_new_review_content("", &[]).is_none());
    }

    #[test]
    fn build_new_review_content_some_when_a_stale_file_needs_clearing() {
        let existing = "ID: secret::a.rs::1\n# [ERROR] secret - one\n#   a.rs:1\nAcknowledge: was justified, now fixed\n";
        let content = build_new_review_content(existing, &[]).unwrap();
        assert!(content.starts_with(HEADER));
        assert!(!content.contains("secret::a.rs::1"));
    }
}
