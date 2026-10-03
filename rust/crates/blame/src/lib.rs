//! Line-level authorship for findings: who last changed the flagged line
//! (`git blame`), not whoever made the repo's latest commit. Fills
//! `Issue::author` so a report, the Sentinel payload or a UI can name an
//! owner per finding.
//!
//! Two sources, picked by what the checkout has:
//! - **Full history** (pre-push hook, CLI, a normal clone): local
//!   `git blame --line-porcelain`, only for the flagged lines. Free.
//! - **Shallow clone** (org scans, `scheduled-rescan`: `--depth 1`): a local
//!   blame would credit every line to the one fetched commit, so it asks
//!   GitHub's GraphQL `blame` at the scanned commit instead. That API is
//!   rate-limited, so per-file ranges are cached in `blame_cache` keyed by
//!   the file's **blob SHA** (a file unchanged since the last scan is never
//!   asked about again, however far HEAD moves), files are batched several
//!   per query, each scan asks about at most `max_remote_files` new files,
//!   and it stops early when the token's remaining GraphQL budget drops
//!   below `min_rate_limit_remaining`. Whatever is skipped is picked up by
//!   the next scan.
//!
//! Everything is best-effort: a failure leaves `author` as `None` and never
//! fails the scan.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use futures::stream::{self, StreamExt};
use ignite_db_store::DbStore;
use ignite_override_engine::{Issue, IssueAuthor};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

/// Files per GraphQL query (aliased `blame` fields on one commit).
const FILES_PER_QUERY: usize = 8;
/// Concurrent local `git blame` processes.
const LOCAL_CONCURRENCY: usize = 8;
/// Above this many flagged lines in one file, blame the whole file once
/// instead of passing one `-L` per line.
const MAX_LINE_RANGES: usize = 50;
/// Failed (non-rate-limit) batches in a row before giving up for this scan.
const MAX_CONSECUTIVE_FAILURES: usize = 3;
const UNCOMMITTED_SHA: &str = "0000000000000000000000000000000000000000";

#[derive(Debug, Clone)]
pub struct BlameOptions {
    /// New (uncached) files one scan may ask GitHub about.
    pub max_remote_files: usize,
    /// Stop asking GitHub once the token's GraphQL budget falls below this.
    pub min_rate_limit_remaining: i64,
}

impl Default for BlameOptions {
    fn default() -> Self {
        BlameOptions { max_remote_files: 300, min_rate_limit_remaining: 1000 }
    }
}

/// GitHub coordinates of the scanned checkout, for the shallow-clone path.
pub struct RemoteRepo<'a> {
    pub org: &'a str,
    pub repo: &'a str,
    pub token: &'a str,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlameStats {
    /// `"git"`, `"github"`, or `"none"` (no git history / nothing to do).
    pub source: &'static str,
    pub attributed: usize,
    pub files: usize,
    pub cache_hits: usize,
    pub remote_files: usize,
    /// Files left unattributed this scan (budget cap or rate limit).
    pub deferred_files: usize,
}

/// One contiguous run of lines last changed by the same commit — the unit
/// cached per file (GitHub returns blame this way too).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlameRange {
    pub start: i64,
    pub end: i64,
    pub author: IssueAuthor,
}

fn author_for_line(ranges: &[BlameRange], line: i64) -> Option<&IssueAuthor> {
    ranges.iter().find(|r| r.start <= line && line <= r.end).map(|r| &r.author)
}

async fn git(runner: &ToolRunner, cwd: &Path, args: &[&str]) -> Option<String> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    runner.run_tool("git", &args, &cwd.to_string_lossy(), RunToolOptions { timeout_ms: Some(120_000), ..Default::default() }).await.ok().map(|o| o.stdout)
}

/// Fills `author` on every issue with a file and line, from the git
/// history at `root`. `boundary` is the outermost directory whose `.git`
/// may be used (the staging dir), so a checkout without its own `.git`
/// never picks up an unrelated enclosing repository.
pub async fn attribute_issues(runner: &ToolRunner, db: &DbStore, root: &Path, boundary: &Path, remote: Option<RemoteRepo<'_>>, opts: &BlameOptions, issues: &mut [Issue]) -> BlameStats {
    let mut stats = BlameStats { source: "none", ..Default::default() };
    let mut wanted: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();
    for issue in issues.iter() {
        if let (Some(file), Some(line)) = (issue.file.as_deref(), issue.line) {
            if line >= 1 && issue.author.is_none() && !file.is_empty() {
                wanted.entry(normalize_path(file)).or_default().insert(line);
            }
        }
    }
    if wanted.is_empty() {
        return stats;
    }
    let Some(toplevel) = git(runner, root, &["rev-parse", "--show-toplevel"]).await.map(|s| s.trim().to_string()) else {
        return stats;
    };
    let within = |p: &Path| std::fs::canonicalize(p).ok();
    match (within(Path::new(&toplevel)), within(boundary)) {
        (Some(top), Some(bound)) if top.starts_with(&bound) => {}
        _ => return stats,
    }
    stats.files = wanted.len();
    let shallow = git(runner, root, &["rev-parse", "--is-shallow-repository"]).await.map(|s| s.trim() == "true").unwrap_or(false);

    let ranges: HashMap<String, Vec<BlameRange>> = if !shallow {
        stats.source = "git";
        local_blame(runner, root, &toplevel, &wanted).await
    } else if let Some(remote) = remote {
        stats.source = "github";
        remote_blame(runner, db, root, &remote, opts, &wanted, &mut stats).await
    } else {
        // Shallow and no way to ask GitHub: a local blame would name the
        // wrong person for every line, which is worse than no name.
        return stats;
    };

    for issue in issues.iter_mut() {
        if issue.author.is_some() {
            continue;
        }
        if let (Some(file), Some(line)) = (issue.file.as_deref(), issue.line) {
            if let Some(author) = ranges.get(&normalize_path(file)).and_then(|r| author_for_line(r, line)) {
                issue.author = Some(author.clone());
                stats.attributed += 1;
            }
        }
    }
    stats
}

fn normalize_path(p: &str) -> String {
    p.trim_start_matches("./").replace('\\', "/")
}

// ---------------- local git blame ----------------

async fn local_blame(runner: &ToolRunner, root: &Path, toplevel: &str, wanted: &BTreeMap<String, BTreeSet<i64>>) -> HashMap<String, Vec<BlameRange>> {
    let ignore_revs = Path::new(toplevel).join(".git-blame-ignore-revs");
    let ignore_revs = ignore_revs.is_file().then(|| ignore_revs.to_string_lossy().into_owned());
    let jobs: Vec<(String, Vec<i64>)> = wanted.iter().map(|(f, l)| (f.clone(), l.iter().copied().collect())).collect();
    let results: Vec<(String, Vec<BlameRange>)> = stream::iter(jobs).map(|(file, lines)| blame_file(runner, root, ignore_revs.clone(), file, lines)).buffer_unordered(LOCAL_CONCURRENCY).collect().await;
    results.into_iter().filter(|(_, r)| !r.is_empty()).collect()
}

async fn blame_file(runner: &ToolRunner, root: &Path, ignore_revs: Option<String>, file: String, lines: Vec<i64>) -> (String, Vec<BlameRange>) {
    let mut args: Vec<String> = vec!["blame".into(), "--line-porcelain".into(), "-w".into()];
    if lines.len() <= MAX_LINE_RANGES {
        for l in &lines {
            args.push("-L".into());
            args.push(format!("{l},{l}"));
        }
    }
    let with_file = |mut a: Vec<String>| {
        a.push("--".into());
        a.push(file.clone());
        a
    };
    let mut out = None;
    if let Some(f) = &ignore_revs {
        let mut a = args.clone();
        a.push("--ignore-revs-file".into());
        a.push(f.clone());
        let a = with_file(a);
        out = git(runner, root, &a.iter().map(String::as_str).collect::<Vec<_>>()).await;
    }
    // No ignore-revs file, or one naming an unknown commit (which makes
    // blame fail outright): plain blame.
    if out.is_none() {
        let a = with_file(args);
        out = git(runner, root, &a.iter().map(String::as_str).collect::<Vec<_>>()).await;
    }
    let ranges = out.map(|o| parse_line_porcelain(&o)).unwrap_or_default();
    (file, ranges)
}

static NOREPLY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(?:\d+\+)?([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)@users\.noreply\.github\.com$").unwrap_or_else(|_| unreachable!()));

/// GitHub login encoded in a `users.noreply.github.com` address, if any.
pub fn login_from_email(email: &str) -> Option<String> {
    NOREPLY_RE.captures(email).map(|c| c[1].to_string())
}

fn rfc3339_from_epoch(secs: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(secs, 0).map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// Parses `git blame --line-porcelain` into one single-line range per
/// blamed line. Uncommitted lines are left out (no author to name).
pub fn parse_line_porcelain(out: &str) -> Vec<BlameRange> {
    let mut ranges = Vec::new();
    let mut header: Option<(String, i64)> = None;
    let (mut name, mut email, mut time) = (None::<String>, None::<String>, None::<i64>);
    for line in out.lines() {
        if let Some(_content) = line.strip_prefix('\t') {
            if let Some((sha, final_line)) = header.take() {
                if sha != UNCOMMITTED_SHA {
                    let email = email.take().filter(|e| !e.is_empty());
                    let login = email.as_deref().and_then(login_from_email);
                    ranges.push(BlameRange { start: final_line, end: final_line, author: IssueAuthor { name: name.take(), email, login, commit: sha, date: time.take().and_then(rfc3339_from_epoch) } });
                }
            }
            name = None;
            email = None;
            time = None;
        } else if let Some(v) = line.strip_prefix("author-mail ") {
            email = Some(v.trim().trim_start_matches('<').trim_end_matches('>').to_string());
        } else if let Some(v) = line.strip_prefix("author-time ") {
            time = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("author ") {
            name = Some(v.to_string());
        } else if header.is_none() {
            let mut parts = line.split(' ');
            if let (Some(sha), Some(_orig), Some(fin)) = (parts.next(), parts.next(), parts.next()) {
                if sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                    if let Ok(fin) = fin.parse() {
                        header = Some((sha.to_string(), fin));
                    }
                }
            }
        }
    }
    ranges
}

// ---------------- GitHub GraphQL blame (shallow clones) ----------------

async fn remote_blame(runner: &ToolRunner, db: &DbStore, root: &Path, remote: &RemoteRepo<'_>, opts: &BlameOptions, wanted: &BTreeMap<String, BTreeSet<i64>>, stats: &mut BlameStats) -> HashMap<String, Vec<BlameRange>> {
    let mut result = HashMap::new();
    let Some(head) = git(runner, root, &["rev-parse", "HEAD"]).await.map(|s| s.trim().to_string()).filter(|s| s.len() == 40) else {
        return result;
    };
    let prefix = git(runner, root, &["rev-parse", "--show-prefix"]).await.map(|s| s.trim().to_string()).unwrap_or_default();
    let blobs = blob_shas(runner, root, wanted.keys()).await;

    // (file relative to root, path relative to the repo root, blob sha)
    let mut misses: Vec<(String, String, String)> = Vec::new();
    for file in wanted.keys() {
        let full = format!("{prefix}{file}");
        let Some(blob) = blobs.get(&full) else { continue };
        match db.get_blame_cache(remote.org, remote.repo, &full, blob).and_then(|j| serde_json::from_str::<Vec<BlameRange>>(&j).ok()) {
            Some(ranges) => {
                stats.cache_hits += 1;
                result.insert(file.clone(), ranges);
            }
            None => misses.push((file.clone(), full, blob.clone())),
        }
    }
    if misses.is_empty() {
        return result;
    }
    db.prune_blame_cache();

    let github = ignite_github_api::GithubApi::new(runner);
    let budget = misses.len().min(opts.max_remote_files);
    let mut looked_up = 0usize;
    let mut consecutive_failures = 0usize;
    for batch in misses[..budget].chunks(FILES_PER_QUERY) {
        let paths: Vec<&str> = batch.iter().map(|(_, full, _)| full.as_str()).collect();
        let (per_file, remaining, rate_limited) = match query_blame(&github, remote, &head, &paths).await {
            Ok(r) => r,
            Err(e) if is_rate_limit_error(&e) => {
                tracing::info!(org = remote.org, repo = remote.repo, "GitHub rate limit hit; remaining blame lookups deferred to the next scan");
                break;
            }
            Err(e) => {
                // A timeout/5xx on one batch (e.g. very large files) shouldn't
                // cost the rest; give up only if GitHub keeps failing.
                tracing::warn!(org = remote.org, repo = remote.repo, error = %e, "GitHub blame query failed for one batch");
                consecutive_failures += 1;
                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    break;
                }
                continue;
            }
        };
        consecutive_failures = 0;
        for ((file, full, blob), ranges) in batch.iter().zip(per_file) {
            let Some(ranges) = ranges else { continue };
            if let Ok(j) = serde_json::to_string(&ranges) {
                db.put_blame_cache(remote.org, remote.repo, full, blob, &j);
            }
            result.insert(file.clone(), ranges);
            looked_up += 1;
        }
        if rate_limited || remaining.is_some_and(|r| r < opts.min_rate_limit_remaining) {
            tracing::info!(org = remote.org, repo = remote.repo, remaining = ?remaining, "GitHub GraphQL budget low; remaining blame lookups deferred to the next scan");
            break;
        }
    }
    stats.remote_files = looked_up;
    stats.deferred_files = misses.len() - looked_up;
    result
}

/// Blob SHA at HEAD for each file (keyed by repo-root-relative path). Uses
/// the local tree, which a shallow clone has in full.
async fn blob_shas<'a>(runner: &ToolRunner, root: &Path, files: impl Iterator<Item = &'a String>) -> HashMap<String, String> {
    let files: Vec<&String> = files.collect();
    let mut out = HashMap::new();
    for chunk in files.chunks(200) {
        let mut args: Vec<&str> = vec!["ls-tree", "--full-name", "-r", "HEAD", "--"];
        args.extend(chunk.iter().map(|s| s.as_str()));
        let Some(listing) = git(runner, root, &args).await else { continue };
        out.extend(parse_ls_tree(&listing));
    }
    out
}

/// `<mode> blob <sha>\t<path>` lines → path → sha.
pub fn parse_ls_tree(listing: &str) -> HashMap<String, String> {
    listing
        .lines()
        .filter_map(|l| {
            let (meta, path) = l.split_once('\t')?;
            let mut parts = meta.split_whitespace();
            let (_mode, kind, sha) = (parts.next()?, parts.next()?, parts.next()?);
            (kind == "blob").then(|| (path.to_string(), sha.to_string()))
        })
        .collect()
}

/// Primary (403/429 with a rate-limit message) or secondary rate limit.
fn is_rate_limit_error(e: &str) -> bool {
    let e = e.to_ascii_lowercase();
    e.contains("rate limit") || e.contains("429") || e.contains("abuse")
}

pub fn build_blame_query(count: usize) -> String {
    let vars: String = (0..count).map(|i| format!(", $p{i}: String!")).collect();
    let fields: String = (0..count).map(|i| format!(" f{i}: blame(path: $p{i}) {{ ...R }}")).collect();
    format!(
        "query($owner: String!, $name: String!, $oid: GitObjectID!{vars}) {{ rateLimit {{ remaining }} repository(owner: $owner, name: $name) {{ object(oid: $oid) {{ ... on Commit {{{fields} }} }} }} }} \
         fragment R on Blame {{ ranges {{ startingLine endingLine commit {{ oid authoredDate author {{ name email user {{ login }} }} }} }} }}"
    )
}

type BlameBatch = (Vec<Option<Vec<BlameRange>>>, Option<i64>, bool);

async fn query_blame(github: &ignite_github_api::GithubApi<'_>, remote: &RemoteRepo<'_>, oid: &str, paths: &[&str]) -> Result<BlameBatch, String> {
    let mut vars = json!({ "owner": remote.org, "name": remote.repo, "oid": oid });
    for (i, p) in paths.iter().enumerate() {
        vars[format!("p{i}")] = json!(p);
    }
    let body = json!({ "query": build_blame_query(paths.len()), "variables": vars });
    // Not `github_graphql_request`: that fails the whole batch on any
    // error, but one missing path shouldn't lose the other files' blame.
    let resp = github.github_api_request(remote.token, "POST", "/graphql", Some(&body), None).await.map_err(|e| e.to_string())?.unwrap_or(Value::Null);
    Ok(parse_blame_response(&resp, paths.len()))
}

/// Per-path ranges (in request order; `None` for a path GitHub couldn't
/// blame), the remaining GraphQL budget, and whether GitHub said the token
/// is rate limited.
pub fn parse_blame_response(resp: &Value, count: usize) -> BlameBatch {
    let rate_limited = resp["errors"].as_array().is_some_and(|errs| errs.iter().any(|e| e["type"].as_str() == Some("RATE_LIMITED")));
    let remaining = resp["data"]["rateLimit"]["remaining"].as_i64();
    let commit = &resp["data"]["repository"]["object"];
    let per_file = (0..count)
        .map(|i| {
            let ranges = commit[format!("f{i}")]["ranges"].as_array()?;
            Some(
                ranges
                    .iter()
                    .filter_map(|r| {
                        let c = &r["commit"];
                        let email = c["author"]["email"].as_str().filter(|e| !e.is_empty()).map(str::to_string);
                        let login = c["author"]["user"]["login"].as_str().map(str::to_string).or_else(|| email.as_deref().and_then(login_from_email));
                        Some(BlameRange {
                            start: r["startingLine"].as_i64()?,
                            end: r["endingLine"].as_i64()?,
                            author: IssueAuthor { name: c["author"]["name"].as_str().map(str::to_string), email, login, commit: c["oid"].as_str()?.to_string(), date: c["authoredDate"].as_str().map(str::to_string) },
                        })
                    })
                    .collect(),
            )
        })
        .collect();
    (per_file, remaining, rate_limited)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn sh_git(dir: &Path, args: &[&str], author: Option<(&str, &str)>) {
        let mut c = Command::new("git");
        c.current_dir(dir).args(args).env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1");
        if let Some((n, e)) = author {
            c.env("GIT_AUTHOR_NAME", n).env("GIT_AUTHOR_EMAIL", e).env("GIT_COMMITTER_NAME", n).env("GIT_COMMITTER_EMAIL", e);
        }
        let out = c.output().expect("git");
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    /// Two authors: alice writes lines 1-3, bob later edits only line 2.
    fn two_author_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        sh_git(p, &["init", "-q", "-b", "main"], None);
        std::fs::write(p.join("app.py"), "a = 1\nkey = 'x'\nc = 3\n").unwrap();
        sh_git(p, &["add", "."], None);
        sh_git(p, &["commit", "-q", "-m", "one"], Some(("Alice", "alice@example.com")));
        std::fs::write(p.join("app.py"), "a = 1\nkey = 'SECRET'\nc = 3\n").unwrap();
        sh_git(p, &["commit", "-q", "-am", "two"], Some(("Bob", "12345+bob-gh@users.noreply.github.com")));
        dir
    }

    fn issue(file: &str, line: i64) -> Issue {
        Issue {
            id: format!("secret::{file}::{line}"),
            category: "secret".into(),
            severity: ignite_override_engine::Severity::Error,
            score: 9,
            summary: "s".into(),
            file: Some(file.into()),
            line: Some(line),
            snippet: None,
            cross_file: false,
            chain: None,
            duplicate_ref: None,
            cwe: None,
            owasp: None,
            tool: None,
            references: Default::default(),
            author: None,
            rule: None,
        }
    }

    fn db() -> (tempfile::TempDir, DbStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("t.db")).unwrap();
        (dir, db)
    }

    #[tokio::test]
    async fn full_history_names_the_author_of_each_line_not_the_latest_committer() {
        let repo = two_author_repo();
        let (_d, db) = db();
        let runner = ToolRunner::new(HashMap::new());
        let mut issues = vec![issue("app.py", 1), issue("app.py", 2), issue("gone.py", 1)];
        let stats = attribute_issues(&runner, &db, repo.path(), repo.path(), None, &BlameOptions::default(), &mut issues).await;
        assert_eq!(stats.source, "git");
        assert_eq!(stats.attributed, 2);
        let a1 = issues[0].author.as_ref().unwrap();
        assert_eq!((a1.name.as_deref(), a1.email.as_deref(), a1.login.as_deref()), (Some("Alice"), Some("alice@example.com"), None));
        let a2 = issues[1].author.as_ref().unwrap();
        assert_eq!((a2.name.as_deref(), a2.login.as_deref()), (Some("Bob"), Some("bob-gh")));
        assert_eq!(a2.commit.len(), 40);
        assert!(a2.date.as_deref().unwrap().ends_with('Z'));
        assert!(issues[2].author.is_none(), "untracked file stays unattributed");
    }

    #[tokio::test]
    async fn a_checkout_outside_the_boundary_is_never_blamed() {
        let repo = two_author_repo();
        let sub = repo.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let (_d, db) = db();
        let mut issues = vec![issue("app.py", 1)];
        let stats = attribute_issues(&ToolRunner::new(HashMap::new()), &db, &sub, &sub, None, &BlameOptions::default(), &mut issues).await;
        assert_eq!(stats.source, "none");
        assert!(issues[0].author.is_none());
    }

    #[tokio::test]
    async fn a_shallow_clone_uses_the_blob_keyed_cache_and_never_local_blame() {
        let repo = two_author_repo();
        let clone_parent = tempfile::tempdir().unwrap();
        let clone = clone_parent.path().join("c");
        sh_git(clone_parent.path(), &["clone", "-q", "--depth", "1", &format!("file://{}", repo.path().display()), "c"], None);
        let (_d, db) = db();
        let runner = ToolRunner::new(HashMap::new());

        // Without GitHub coordinates a shallow clone is left alone.
        let mut issues = vec![issue("app.py", 1)];
        let stats = attribute_issues(&runner, &db, &clone, &clone, None, &BlameOptions::default(), &mut issues).await;
        assert_eq!(stats.source, "none");
        assert!(issues[0].author.is_none());

        // Pre-seed the cache for this exact blob: no network call is needed.
        let blob = parse_ls_tree(&String::from_utf8(Command::new("git").current_dir(&clone).args(["ls-tree", "--full-name", "-r", "HEAD"]).output().unwrap().stdout).unwrap())["app.py"].clone();
        let alice = IssueAuthor { name: Some("Alice".into()), email: Some("alice@example.com".into()), login: Some("alice".into()), commit: "a".repeat(40), date: None };
        let ranges = vec![BlameRange { start: 1, end: 1, author: alice.clone() }, BlameRange { start: 2, end: 3, author: IssueAuthor { name: Some("Bob".into()), commit: "b".repeat(40), ..Default::default() } }];
        db.put_blame_cache("acme", "widgets", "app.py", &blob, &serde_json::to_string(&ranges).unwrap());
        let mut issues = vec![issue("app.py", 1), issue("app.py", 3)];
        let remote = RemoteRepo { org: "Acme", repo: "Widgets", token: "unused" };
        let stats = attribute_issues(&runner, &db, &clone, &clone, Some(remote), &BlameOptions::default(), &mut issues).await;
        assert_eq!((stats.source, stats.cache_hits, stats.remote_files, stats.attributed), ("github", 1, 0, 2));
        assert_eq!(issues[0].author.as_ref(), Some(&alice));
        assert_eq!(issues[1].author.as_ref().unwrap().name.as_deref(), Some("Bob"));
    }

    #[test]
    fn parses_graphql_blame_with_partial_errors_and_budget() {
        let resp = json!({
            "data": { "rateLimit": { "remaining": 42 }, "repository": { "object": {
                "f0": { "ranges": [ { "startingLine": 1, "endingLine": 4, "commit": { "oid": "c1", "authoredDate": "2026-01-02T03:04:05Z", "author": { "name": "Ann", "email": "ann@x.io", "user": { "login": "ann" } } } } ] },
                "f1": null
            } } },
            "errors": [ { "type": "NOT_FOUND", "path": ["repository", "object", "f1"] } ]
        });
        let (per_file, remaining, limited) = parse_blame_response(&resp, 2);
        assert_eq!(remaining, Some(42));
        assert!(!limited);
        let r0 = per_file[0].as_ref().unwrap();
        assert_eq!((r0[0].start, r0[0].end, r0[0].author.login.as_deref(), r0[0].author.commit.as_str()), (1, 4, Some("ann"), "c1"));
        assert!(per_file[1].is_none());
        let (_, _, limited) = parse_blame_response(&json!({ "errors": [ { "type": "RATE_LIMITED" } ] }), 1);
        assert!(limited);
    }

    #[test]
    fn query_declares_one_variable_and_alias_per_path() {
        let q = build_blame_query(2);
        assert!(q.contains("$oid: GitObjectID!, $p0: String!, $p1: String!"));
        assert!(q.contains("f0: blame(path: $p0)") && q.contains("f1: blame(path: $p1)"));
        assert!(q.contains("rateLimit { remaining }"));
    }

    #[test]
    fn rate_limit_errors_are_told_apart_from_other_failures() {
        assert!(is_rate_limit_error("GitHub API POST /graphql failed (403): API rate limit exceeded for installation"));
        assert!(is_rate_limit_error("GitHub API POST /graphql failed (403): You have exceeded a secondary rate limit"));
        assert!(is_rate_limit_error("GitHub API POST /graphql failed (429): slow down"));
        assert!(!is_rate_limit_error("error sending request: operation timed out"));
        assert!(!is_rate_limit_error("GitHub API POST /graphql failed (502): Bad Gateway"));
    }

    #[test]
    fn noreply_emails_yield_the_login() {
        assert_eq!(login_from_email("12345+octo-cat@users.noreply.github.com").as_deref(), Some("octo-cat"));
        assert_eq!(login_from_email("octocat@users.noreply.github.com").as_deref(), Some("octocat"));
        assert_eq!(login_from_email("dev@corp.com"), None);
    }
}
