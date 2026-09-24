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
use regex::Regex;
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

/// Collapses duplicate entries for the same finding (same `ID:`, i.e. the
/// same category + file + line) down to one, keeping the **latest supplied
/// justification**: writers append newer entries after older ones, so the
/// last entry with a non-blank justification wins — a later blank entry
/// never erases an earlier filled-in one. The survivor takes the position
/// of the id's first occurrence, so the file's order stays stable.
pub fn dedupe_latest(entries: Vec<ExistingEntry>) -> Vec<ExistingEntry> {
    let mut order: Vec<String> = Vec::new();
    let mut chosen: std::collections::HashMap<String, ExistingEntry> = std::collections::HashMap::new();
    for entry in entries {
        match chosen.get(&entry.id) {
            None => {
                order.push(entry.id.clone());
                chosen.insert(entry.id.clone(), entry);
            }
            Some(_) if !entry.justification.is_empty() => {
                chosen.insert(entry.id.clone(), entry);
            }
            Some(_) => {}
        }
    }
    order.into_iter().filter_map(|id| chosen.remove(&id)).collect()
}

/// The `overrides` array to send `/api/pipeline/validate-all` — every
/// already-justified entry, regardless of whether the underlying finding
/// still exists (a stale entry's `issueId` simply won't match anything
/// server-side and is silently ignored there, same as before this port).
pub fn build_overrides(entries: &[ExistingEntry]) -> Vec<Value> {
    dedupe_latest(entries.to_vec())
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

fn build_new_block(finding: &Finding, justification: &str) -> String {
    let mut s = format!("ID: {}\n# [{}] {} - {}\n#   {}", one_line(&finding.id), one_line(&finding.severity).to_uppercase(), one_line(&finding.category), one_line(&finding.summary), one_line(&finding_loc(finding)));
    if let Some(code) = code_for_finding(finding.snippet.as_ref()) {
        s.push_str(&format!("\n# Code: {}", one_line(&code)));
    }
    s.push_str(&format!("\nAcknowledge: {}", one_line(justification)));
    s
}

fn strip_issue_number(raw: &str) -> String {
    ISSUE_NUM_STRIP_RE.replace(raw, "$h\n").to_string()
}

static CARRY_NOTE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r" \(auto-carried-forward from [^()]* - pure line-number drift, flagged code unchanged\)").unwrap());

/// A justification without the "(auto-carried-forward from … )" notes older
/// versions appended on every line-number move — the `# Code:` line already
/// records why a moved finding still matches, so the notes only grew.
fn clean_justification(justification: &str) -> String {
    CARRY_NOTE_RE.replace_all(justification, "").trim().to_string()
}

/// One entry's text in the current file format: no `# Issue #N` line and no
/// carry-forward notes on its `Acknowledge:` line.
fn normalize_block(raw: &str) -> String {
    let stripped = strip_issue_number(raw);
    stripped
        .trim_end()
        .lines()
        .map(|l| match l.strip_prefix("Acknowledge:") {
            Some(rest) => {
                let j = clean_justification(rest);
                if j.is_empty() { "Acknowledge: ".to_string() } else { format!("Acknowledge: {j}") }
            }
            None => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Entries sorted by `ID:` and separated by a blank line — the file's one
/// canonical order, so rewriting it never reshuffles anything by itself.
fn render_body(mut blocks: Vec<(String, String)>) -> String {
    blocks.sort_by(|a, b| a.0.cmp(&b.0));
    blocks.into_iter().map(|(_, b)| b).collect::<Vec<_>>().join("\n\n")
}

/// Whether `entry` is a justified entry for `finding` whose line merely
/// moved: same category and file, and the same flagged source line (`# Code:`).
fn follows_code(entry: &ExistingEntry, finding: &Finding, code: &str) -> bool {
    !entry.justification.is_empty() && entry.category == finding.category && entry.file.as_deref() == finding.file.as_deref() && entry.code.as_deref() == Some(code)
}

/// The regenerated body (everything after [`HEADER`]) for
/// `.ignite/acknowledgments.md`, or `None` when the file doesn't need to
/// change. Stable by design, so a push whose checks pass leaves the file
/// exactly as committed:
///
/// - A finding already overridden by the server needs nothing — including
///   one whose line moved: the server matched it through the entry's
///   `# Code:` line, so its old `ID:` is left alone rather than rewritten.
/// - The file only changes when a still-unresolved finding needs an entry:
///   either a blank `Acknowledge:` entry for a new finding, or an existing
///   justified entry re-keyed to a finding's new `ID:` because its code moved
///   and the server didn't match it (e.g. the entry predates `# Code:`).
/// - When it does change, it's written in one canonical form: one entry per
///   `ID:` (latest justification, [`dedupe_latest`]), sorted by `ID:`, no
///   running numbers, no carry-forward notes, and entries whose finding is
///   no longer reported (fixed, or re-keyed away) are dropped.
pub fn regenerate(existing_text: &str, findings: &[Finding]) -> Option<String> {
    let mut existing = dedupe_latest(parse_blocks(existing_text));
    let mut new_blocks: Vec<(String, String)> = Vec::new();
    let mut changed = false;

    for finding in findings.iter().filter(|f| f.status.as_deref() != Some("overridden")) {
        if existing.iter().any(|e| e.id == finding.id) || new_blocks.iter().any(|(id, _)| id == &finding.id) {
            continue;
        }
        let code = code_for_finding(finding.snippet.as_ref());
        let moved = code.as_deref().and_then(|c| existing.iter().position(|e| !e.superseded && follows_code(e, finding, c)));
        let justification = match moved {
            Some(i) => {
                existing[i].superseded = true;
                clean_justification(&existing[i].justification)
            }
            None => String::new(),
        };
        new_blocks.push((finding.id.clone(), build_new_block(finding, &justification)));
        changed = true;
    }
    if !changed {
        return None;
    }

    // Keep every entry whose finding is still reported this run — overridden
    // (possibly through a moved line: keyed by any finding following its code)
    // or not — and drop the rest.
    let current_ids: std::collections::HashSet<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    let still_reported = |e: &ExistingEntry| {
        current_ids.contains(e.id.as_str())
            || findings.iter().any(|f| f.status.as_deref() == Some("overridden") && code_for_finding(f.snippet.as_ref()).is_some_and(|c| follows_code(e, f, &c)))
    };
    let mut blocks: Vec<(String, String)> = existing.iter().filter(|e| !e.superseded && still_reported(e)).map(|e| (e.id.clone(), normalize_block(&e.raw))).collect();
    blocks.extend(new_blocks);
    Some(render_body(blocks))
}

pub const HEADER: &str = "# Ignite pre-push acknowledgments - meant to be committed: a filled-in\n\
# justification is a real audit record, reviewable like code.\n\
#\n\
# Fill in a justification after \"Acknowledge:\" for any issue below you want\n\
# to override, save, commit, then `git push` again. Blank = stays blocking.\n\
# Entries are sorted by ID, one per finding. The file is only rewritten when\n\
# a new finding needs an entry - then entries for findings that are no\n\
# longer reported are dropped.\n\
# A `# Code:` line, when present, is the flagged source line's own text -\n\
# it lets this justification keep matching after an unrelated edit\n\
# elsewhere in the file shifts its line number. Do not hand-edit it.\n";

/// The full new file content, or `None` when the file should be left as is
/// (nothing new to add — including every push whose checks pass).
pub fn build_new_review_content(existing_text: &str, findings: &[Finding]) -> Option<String> {
    let body = regenerate(existing_text, findings)?;
    Some(format!("{HEADER}\n{body}"))
}

/// One already-approved override to write into `.ignite/acknowledgments.md`
/// — the server-side (DB-sourced) counterpart to a hand-filled
/// `Acknowledge:` line. Deliberately carries no snippet, so the entry has
/// no `# Code:` line (line-drift carry-forward simply doesn't apply to it;
/// an exact `ID:` match still does).
#[derive(Debug, Clone)]
pub struct AckInput {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub summary: String,
    pub file: Option<String>,
    pub line: Option<i64>,
    pub justification: String,
    /// Who justified it — recorded as an `# Justified-by:` comment, since
    /// attribution otherwise disappears once the entry lives in a file.
    pub justified_by: Option<String>,
}

/// Collapses anything that could start a new line to a single space, so a
/// justification/actor/summary string can never forge an extra `ID:` block
/// (or otherwise break the file's line-oriented format) once written out.
fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn build_ack_block(ack: &AckInput) -> String {
    let loc = match (&ack.file, ack.line) {
        (Some(f), Some(l)) => format!("{}:{l}", one_line(f)),
        (Some(f), None) => one_line(f),
        _ => "(no file)".to_string(),
    };
    let mut s = format!("ID: {}\n# [{}] {} - {}\n#   {loc}", one_line(&ack.id), one_line(&ack.severity).to_uppercase(), one_line(&ack.category), one_line(&ack.summary));
    if let Some(who) = ack.justified_by.as_deref().map(one_line).filter(|w| !w.is_empty()) {
        s.push_str(&format!("\n# Justified-by: {who}"));
    }
    s.push_str(&format!("\nAcknowledge: {}", one_line(&ack.justification)));
    s
}

/// Merges already-approved overrides into an existing
/// `.ignite/acknowledgments.md`, returning the full new file content —
/// or `None` when there's nothing to change (no usable acks, or every one
/// already has a filled-in entry in `existing_text`).
///
/// Unlike [`regenerate`], this never drops a finding's entry: it runs
/// outside a scan, so it has no "current findings" list to prune against.
/// Duplicates are always collapsed to one entry per `ID:` (same finding on
/// the same line), keeping the latest supplied justification: an ack
/// replaces an existing entry for its `ID:` unless that entry already has
/// the same justification; an ack with no entry is appended; and existing
/// duplicate entries are merged per [`dedupe_latest`] even when no ack
/// changes anything.
pub fn merge_acknowledgments(existing_text: &str, acks: &[AckInput]) -> Option<String> {
    // `acks` arrive oldest first, so for a finding justified more than once
    // the last ack is the latest supplied justification — keep only that one.
    let mut usable: Vec<&AckInput> = Vec::new();
    for a in acks.iter().filter(|a| !a.id.trim().is_empty() && !a.justification.trim().is_empty()) {
        match usable.iter().position(|u| one_line(&u.id) == one_line(&a.id)) {
            Some(i) => usable[i] = a,
            None => usable.push(a),
        }
    }
    let parsed = parse_blocks(existing_text);
    let had_duplicates = {
        let mut ids = std::collections::HashSet::new();
        parsed.iter().any(|e| !ids.insert(e.id.as_str()))
    };
    let existing = dedupe_latest(parsed);
    // The ack is the latest supplied justification, so it replaces an
    // existing entry unless that entry already says exactly the same thing.
    let already_same = |a: &AckInput| existing.iter().any(|e| e.id == one_line(&a.id) && e.justification == one_line(&a.justification));
    let to_write: Vec<&AckInput> = usable.into_iter().filter(|a| !already_same(a)).collect();
    if to_write.is_empty() && !had_duplicates {
        return None;
    }

    let mut blocks: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for e in &existing {
        if !seen.insert(e.id.clone()) {
            continue;
        }
        let replacement = to_write.iter().find(|a| one_line(&a.id) == e.id).map(|a| build_ack_block(a));
        blocks.push((e.id.clone(), replacement.unwrap_or_else(|| normalize_block(&e.raw))));
    }
    for a in &to_write {
        let id = one_line(&a.id);
        if seen.insert(id.clone()) {
            blocks.push((id, build_ack_block(a)));
        }
    }

    Some(format!("{HEADER}\n{}\n", render_body(blocks)))
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

    fn with_code(mut f: Finding, code: &str) -> Finding {
        let line = f.line.unwrap_or(1);
        f.snippet = Some(serde_json::json!({ "highlightLine": line, "lines": [{"number": line, "text": code}] }));
        f
    }

    fn overridden(mut f: Finding) -> Finding {
        f.status = Some("overridden".to_string());
        f
    }

    const JUSTIFIED_A10: &str = "ID: secret::a.rs::10\n# [ERROR] secret - Hardcoded token\n#   a.rs:10\n# Code: let x = \"tok\";\nAcknowledge: fake token fixture\n";

    #[test]
    fn regenerate_creates_a_blank_entry_for_a_brand_new_finding() {
        let body = regenerate("", &[finding("secret::a.rs::10", "secret", "a.rs", 10, "Hardcoded token")]).unwrap();
        assert!(body.contains("ID: secret::a.rs::10"));
        assert!(body.ends_with("Acknowledge: "));
        assert!(!body.contains("# Issue #"), "no running numbers");
    }

    #[test]
    fn a_passing_push_never_rewrites_the_file() {
        // Every finding already justified (overridden by the server): nothing to write.
        let f = overridden(with_code(finding("secret::a.rs::10", "secret", "a.rs", 10, "Hardcoded token"), "let x = \"tok\";"));
        assert!(regenerate(JUSTIFIED_A10, &[f]).is_none());
        assert!(build_new_review_content(JUSTIFIED_A10, &[]).is_none(), "a fixed finding alone doesn't trigger a rewrite either");
        assert!(build_new_review_content("", &[]).is_none());
    }

    #[test]
    fn a_line_move_the_server_already_matched_leaves_the_file_alone() {
        // The flagged line moved 10 -> 14; the server matched it via `# Code:` and reports it overridden.
        let moved = overridden(with_code(finding("secret::a.rs::14", "secret", "a.rs", 14, "Hardcoded token"), "let x = \"tok\";"));
        assert!(regenerate(JUSTIFIED_A10, &[moved]).is_none());
    }

    #[test]
    fn an_unmatched_line_move_rekeys_the_entry_without_carry_forward_notes() {
        // Same code moved to line 14 but still unresolved (e.g. overrides weren't sent with code).
        let moved = with_code(finding("secret::a.rs::14", "secret", "a.rs", 14, "Hardcoded token"), "let x = \"tok\";");
        let body = regenerate(JUSTIFIED_A10, &[moved]).unwrap();
        assert!(body.contains("ID: secret::a.rs::14"));
        assert!(!body.contains("ID: secret::a.rs::10"), "the old id must not survive");
        assert!(body.contains("Acknowledge: fake token fixture\n") || body.ends_with("Acknowledge: fake token fixture"));
        assert!(!body.contains("auto-carried-forward"));
    }

    #[test]
    fn a_changed_flagged_line_is_a_new_finding_not_a_carry_forward() {
        let edited = with_code(finding("secret::a.rs::14", "secret", "a.rs", 14, "Hardcoded token"), "let x = \"tok_v2\";");
        let body = regenerate(JUSTIFIED_A10, &[edited]).unwrap();
        let entries = parse_blocks(&body);
        assert_eq!(entries.len(), 1, "the old entry's finding isn't reported anymore, so it's dropped on rewrite");
        assert_eq!(entries[0].id, "secret::a.rs::14");
        assert_eq!(entries[0].justification, "");
    }

    #[test]
    fn a_rewrite_is_sorted_by_id_unnumbered_and_strips_old_carry_forward_notes() {
        let existing = "ID: secret::z.rs::1\n# Issue #1\n# [ERROR] secret - z\n#   z.rs:1\nAcknowledge: zed (auto-carried-forward from secret::z.rs::3 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::z.rs::2 - pure line-number drift, flagged code unchanged)\n\nID: secret::b.rs::2\n# Issue #2\n# [ERROR] secret - b\n#   b.rs:2\nAcknowledge: bee\n";
        let findings = [
            overridden(finding("secret::z.rs::1", "secret", "z.rs", 1, "z")),
            overridden(finding("secret::b.rs::2", "secret", "b.rs", 2, "b")),
            finding("secret::m.rs::5", "secret", "m.rs", 5, "new one"),
        ];
        let body = regenerate(existing, &findings).unwrap();
        let ids: Vec<String> = parse_blocks(&body).into_iter().map(|e| e.id).collect();
        assert_eq!(ids, vec!["secret::b.rs::2", "secret::m.rs::5", "secret::z.rs::1"]);
        assert!(!body.contains("# Issue #"));
        assert!(body.ends_with("Acknowledge: zed") && !body.contains("auto-carried-forward"), "carry-forward notes are stripped: {body}");
    }

    #[test]
    fn rewriting_twice_is_stable() {
        let findings = [finding("secret::m.rs::5", "secret", "m.rs", 5, "new one"), overridden(finding("secret::a.rs::10", "secret", "a.rs", 10, "Hardcoded token"))];
        let first = build_new_review_content(JUSTIFIED_A10, &findings).unwrap();
        // Next run: same findings, the blank entry already exists -> nothing to write.
        assert!(build_new_review_content(&first, &findings).is_none());
    }

    #[test]
    fn a_rewrite_drops_entries_for_findings_no_longer_reported() {
        let existing = "ID: secret::gone.rs::1\n# [ERROR] secret - fixed\n#   gone.rs:1\nAcknowledge: was justified, now fixed\n";
        let body = regenerate(existing, &[finding("secret::new.rs::1", "secret", "new.rs", 1, "new")]).unwrap();
        assert!(!body.contains("gone.rs"));
        assert!(body.contains("ID: secret::new.rs::1"));
    }

    fn ack(id: &str, justification: &str) -> AckInput {
        AckInput { id: id.to_string(), category: "secret".to_string(), severity: "error".to_string(), summary: "Hardcoded token".to_string(), file: Some("a.rs".to_string()), line: Some(10), justification: justification.to_string(), justified_by: Some("dev@example.com".to_string()) }
    }

    #[test]
    fn merge_appends_new_entry_and_round_trips_through_parse() {
        let out = merge_acknowledgments("", &[ack("secret::a.rs::10", "fake token")]).unwrap();
        let entries = parse_blocks(&out);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "secret::a.rs::10");
        assert_eq!(entries[0].justification, "fake token");
        assert_eq!(entries[0].file.as_deref(), Some("a.rs"));
        assert!(out.contains("# Justified-by: dev@example.com"));
        assert!(!out.contains("# Issue #"));
    }

    #[test]
    fn merge_returns_none_when_the_same_justification_is_already_there() {
        let existing = merge_acknowledgments("", &[ack("secret::a.rs::10", "same wording")]).unwrap();
        assert!(merge_acknowledgments(&existing, &[ack("secret::a.rs::10", "same wording")]).is_none());
    }

    #[test]
    fn merge_replaces_an_existing_justification_with_the_latest_supplied_one() {
        let existing = merge_acknowledgments("", &[ack("secret::a.rs::10", "old wording")]).unwrap();
        let out = merge_acknowledgments(&existing, &[ack("secret::a.rs::10", "new wording")]).unwrap();
        let entries = parse_blocks(&out);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].justification, "new wording");
    }

    #[test]
    fn merge_collapses_repeated_acks_for_one_finding_to_the_latest() {
        let out = merge_acknowledgments("", &[ack("secret::a.rs::10", "first"), ack("secret::a.rs::10", "second"), ack("secret::a.rs::10", "third")]).unwrap();
        let entries = parse_blocks(&out);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].justification, "third");
        assert!(!out.contains("# Issue #"));
    }

    #[test]
    fn merge_cleans_up_duplicates_already_in_the_file_even_with_nothing_new() {
        let dup = "ID: secret::a.rs::10\n# [ERROR] secret - x\n#   a.rs:10\nAcknowledge: older\n\nID: secret::a.rs::10\n# [ERROR] secret - x\n#   a.rs:10\nAcknowledge: newer\n\nID: secret::a.rs::10\n# [ERROR] secret - x\n#   a.rs:10\nAcknowledge: \n";
        let out = merge_acknowledgments(dup, &[]).unwrap();
        let entries = parse_blocks(&out);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].justification, "newer", "a later blank entry must not erase the latest filled one");
    }

    #[test]
    fn dedupe_latest_keeps_first_position_and_last_filled_justification() {
        let text = "ID: a::x::1\nAcknowledge: a-old\n\nID: b::y::2\nAcknowledge: b\n\nID: a::x::1\nAcknowledge: a-new\n";
        let entries = dedupe_latest(parse_blocks(text));
        assert_eq!(entries.iter().map(|e| (e.id.as_str(), e.justification.as_str())).collect::<Vec<_>>(), vec![("a::x::1", "a-new"), ("b::y::2", "b")]);
    }

    #[test]
    fn build_overrides_sends_only_the_latest_justification_per_finding() {
        let text = "ID: a::x::1\nAcknowledge: old\n\nID: a::x::1\nAcknowledge: new\n";
        let overrides = build_overrides(&parse_blocks(text));
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0]["justification"], "new");
    }

    #[test]
    fn regenerate_keeps_the_latest_justification_for_duplicate_entries() {
        let text = "ID: secret::a.rs::10\n# [ERROR] secret - x\n#   a.rs:10\nAcknowledge: older\n\nID: secret::a.rs::10\n# [ERROR] secret - x\n#   a.rs:10\nAcknowledge: newer\n";
        let existing_finding = Finding { id: "secret::a.rs::10".into(), category: "secret".into(), severity: "error".into(), summary: "x".into(), file: Some("a.rs".into()), line: Some(10), snippet: None, status: Some("overridden".into()) };
        let new_finding = Finding { id: "secret::b.rs::1".into(), category: "secret".into(), severity: "error".into(), summary: "y".into(), file: Some("b.rs".into()), line: Some(1), snippet: None, status: None };
        let entries = parse_blocks(&regenerate(text, &[existing_finding, new_finding]).unwrap());
        assert_eq!(entries.iter().filter(|e| e.id == "secret::a.rs::10").count(), 1);
        assert_eq!(entries[0].justification, "newer");
    }

    #[test]
    fn merge_fills_blank_entry_and_keeps_others() {
        let existing = "ID: secret::b.rs::5\n# [ERROR] secret - x\n#   b.rs:5\nAcknowledge: keep me\n\nID: secret::a.rs::10\n# [ERROR] secret - x\n#   a.rs:10\nAcknowledge: \n";
        let out = merge_acknowledgments(existing, &[ack("secret::a.rs::10", "now justified")]).unwrap();
        let entries = parse_blocks(&out);
        assert_eq!(entries.len(), 2);
        let by_id = |id: &str| entries.iter().find(|e| e.id == id).unwrap().justification.clone();
        assert_eq!(by_id("secret::b.rs::5"), "keep me");
        assert_eq!(by_id("secret::a.rs::10"), "now justified");
        assert_eq!(entries[0].id, "secret::a.rs::10", "entries are sorted by ID");
    }

    #[test]
    fn merge_cannot_be_used_to_forge_an_extra_id_block() {
        let out = merge_acknowledgments("", &[ack("secret::a.rs::10", "ok\nID: secret::evil::1\nAcknowledge: pwned")]).unwrap();
        let entries = parse_blocks(&out);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "secret::a.rs::10");
    }

    #[test]
    fn merge_skips_blank_justifications() {
        assert!(merge_acknowledgments("", &[ack("secret::a.rs::10", "   ")]).is_none());
    }
}
