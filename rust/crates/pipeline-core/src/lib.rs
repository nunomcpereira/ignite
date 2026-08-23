//! Pipeline orchestration helpers shared across `validate-all`/`onboard`/
//! the interactive SSE pipeline routes in server.js. Faithful port of the
//! framework-agnostic pieces: request-source/actor resolution, project
//! staging (zip-slip-guarded copy from an existing local path), and the
//! .env-file / CODEOWNERS presence checks. HTTP-framework-specific pieces
//! (Express's `req`/`res`, multer upload handling) are represented here as
//! plain structs an axum handler will construct, not ported as-is.

use ignite_auth::is_valid_email;
use ignite_fs_utils::{is_env_template_file, is_gitignored, load_gitignore_patterns, walk_files};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::path::Path;

/// Zip-bomb guard: total staged/extracted size is capped project-wide.
pub const MAX_EXTRACTED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Onboarded-projects history annotates *how* a run was kicked off — the
/// browser UI, a direct API call, or MCP (`mcp-server.js`'s proxy sets this
/// header on every call). An audit label, not a trust/security boundary.
pub fn resolve_request_source(client_header: Option<&str>, fallback: &'static str) -> &'static str {
    if client_header == Some("mcp") {
        "mcp"
    } else {
        fallback
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Actor {
    pub email: String,
    pub name: String,
}

/// Overriding a flagged guideline must be attributable to a real person —
/// either the logged-in session, or, when auth isn't enforced globally, an
/// explicit actor identity on the request body. Returns `None` (caller
/// responds 401) if neither is present.
pub fn resolve_actor(session_user_email: Option<&str>, session_user_name: Option<&str>, body_actor_email: Option<&str>, body_actor_name: Option<&str>) -> Option<Actor> {
    if let Some(email) = session_user_email {
        let name = session_user_name.filter(|n| !n.is_empty()).unwrap_or(email);
        return Some(Actor { email: email.to_string(), name: name.to_string() });
    }
    let email = body_actor_email.unwrap_or("").trim().to_lowercase();
    let name = body_actor_name.unwrap_or("").trim().to_string();
    if !is_valid_email(&email) {
        return None;
    }
    let name = if name.is_empty() { email.clone() } else { name };
    Some(Actor { email, name })
}

pub fn resolve_project_root(staging_dir: &Path) -> std::io::Result<std::path::PathBuf> {
    let mut entries: Vec<_> = std::fs::read_dir(staging_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            name != "__MACOSX" && name != ".DS_Store"
        })
        .collect();
    if entries.len() == 1 {
        let entry = entries.remove(0);
        if entry.file_type()?.is_dir() {
            return Ok(staging_dir.join(entry.file_name()));
        }
    }
    Ok(staging_dir.to_path_buf())
}

#[derive(Debug)]
pub struct StageResult {
    pub file_count: usize,
    pub total_bytes: u64,
}

/// Copies an existing local project directory into a staging dir, with the
/// same zip-slip-style guard ZIP extraction uses (every resolved target
/// must stay inside the staging root) and the same MAX_EXTRACTED_BYTES
/// cap. Also best-effort copies `.git` (skipped by `walk_files`'s SKIP_DIRS
/// during the per-file copy) so an incremental PII scan (Bearer `--diff`)
/// can still find real git history — never blocks staging if that copy
/// fails.
pub fn stage_existing_project(source_dir: &Path, dest_dir: &Path, mut log: impl FnMut(&str)) -> std::io::Result<StageResult> {
    let metadata = std::fs::metadata(source_dir).map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, format!("projectPath does not exist or is not a directory: {}", source_dir.display())))?;
    if !metadata.is_dir() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("projectPath does not exist or is not a directory: {}", source_dir.display())));
    }

    std::fs::create_dir_all(dest_dir)?;

    let mut total_bytes: u64 = 0;
    let mut file_count = 0usize;
    for file in walk_files(source_dir)? {
        let rel = file.strip_prefix(source_dir).unwrap_or(&file);
        let target = dest_dir.join(rel);
        let target_resolved = path_clean(&target);
        let dest_resolved = path_clean(dest_dir);
        if target_resolved != dest_resolved && !target_resolved.starts_with(&dest_resolved) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Blocked path traversal while staging project file: {}", rel.display())));
        }
        let file_size = std::fs::metadata(&file)?.len();
        total_bytes += file_size;
        if total_bytes > MAX_EXTRACTED_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Project exceeds maximum staged size. Aborting validation."));
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&file, &target)?;
        file_count += 1;
    }

    let source_git_dir = source_dir.join(".git");
    if source_git_dir.is_dir() {
        if let Err(e) = copy_dir_recursive(&source_git_dir, &dest_dir.join(".git")) {
            log(&format!("⚠ Could not copy .git history into the staging dir (non-blocking, incremental PII scanning will fall back to a full scan): {}", e));
        }
    }

    log(&format!("Staged existing project: {} files ({:.1} KB).", file_count, total_bytes as f64 / 1024.0));
    Ok(StageResult { file_count, total_bytes })
}

fn path_clean(p: &Path) -> std::path::PathBuf {
    // Lightweight lexical normalization (no filesystem access, unlike
    // `canonicalize`) — matches Node's `path.resolve` semantics closely
    // enough for the containment check above, which only needs component-
    // level comparison, not symlink resolution.
    let mut out = std::path::PathBuf::new();
    for comp in p.components() {
        match comp {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let target = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct EnvFilesCheckResult {
    pub blocking: Vec<String>,
    pub ignored: Vec<String>,
}

/// Flags raw .env files in the project. `blocking` (real env files that
/// must be removed) is separate from `ignored` (env files already listed
/// in the project's own .gitignore — surfaced as informational, since
/// they'd never be committed/pushed by this same pipeline).
pub fn check_env_files(root: &Path) -> std::io::Result<EnvFilesCheckResult> {
    let gitignore_patterns = load_gitignore_patterns(root);
    let mut blocking = Vec::new();
    let mut ignored = Vec::new();

    for file in walk_files(root)? {
        let base = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if base != ".env" && !base.starts_with(".env.") {
            continue;
        }
        if is_env_template_file(&base) {
            continue;
        }
        let rel = file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        if !gitignore_patterns.is_empty() && is_gitignored(&gitignore_patterns, &rel) {
            ignored.push(rel);
        } else {
            blocking.push(rel);
        }
    }
    Ok(EnvFilesCheckResult { blocking, ignored })
}

/// GitHub recognizes CODEOWNERS in exactly these three locations (root,
/// .github/, docs/) and uses the first one found, in that order.
const CODEOWNERS_LOCATIONS: &[&str] = &["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"];
static EMAIL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[\w.+-]+@[\w-]+\.[\w.-]+").unwrap());

#[derive(Debug, Clone, Serialize)]
pub struct CodeownersCheckResult {
    pub found: bool,
    pub path: Option<&'static str>,
    pub emails: Vec<String>,
}

/// Advisory-only presence/contact check (never blocks onboarding): locates
/// a CODEOWNERS file and extracts any email-address owners from it.
pub fn check_codeowners(root: &Path) -> CodeownersCheckResult {
    for &rel in CODEOWNERS_LOCATIONS {
        let Ok(content) = std::fs::read_to_string(root.join(rel)) else { continue };
        let mut seen = std::collections::HashSet::new();
        let mut emails = Vec::new();
        for m in EMAIL_RE.find_iter(&content) {
            let email = m.as_str().to_lowercase();
            if seen.insert(email.clone()) {
                emails.push(email);
            }
        }
        return CodeownersCheckResult { found: true, path: Some(rel), emails };
    }
    CodeownersCheckResult { found: false, path: None, emails: vec![] }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn resolve_request_source_recognizes_mcp_header() {
        assert_eq!(resolve_request_source(Some("mcp"), "api"), "mcp");
        assert_eq!(resolve_request_source(Some("other"), "api"), "api");
        assert_eq!(resolve_request_source(None, "api"), "api");
    }

    #[test]
    fn resolve_actor_prefers_session_user() {
        let actor = resolve_actor(Some("user@example.com"), Some("User Name"), None, None).unwrap();
        assert_eq!(actor.email, "user@example.com");
        assert_eq!(actor.name, "User Name");
    }

    #[test]
    fn resolve_actor_falls_back_to_body_actor_with_valid_email() {
        let actor = resolve_actor(None, None, Some("Ci@Example.com"), Some("CI Bot")).unwrap();
        assert_eq!(actor.email, "ci@example.com");
        assert_eq!(actor.name, "CI Bot");
    }

    #[test]
    fn resolve_actor_rejects_invalid_body_email() {
        assert!(resolve_actor(None, None, Some("not-an-email"), None).is_none());
        assert!(resolve_actor(None, None, None, None).is_none());
    }

    #[test]
    fn resolve_project_root_unwraps_single_top_level_directory() {
        let dir = tempdir().unwrap();
        let staging = dir.path();
        fs::create_dir(staging.join("my-project")).unwrap();
        fs::write(staging.join("my-project/app.js"), b"x").unwrap();

        let root = resolve_project_root(staging).unwrap();
        assert_eq!(root, staging.join("my-project"));
    }

    #[test]
    fn resolve_project_root_returns_staging_dir_for_multiple_entries() {
        let dir = tempdir().unwrap();
        let staging = dir.path();
        fs::create_dir(staging.join("a")).unwrap();
        fs::create_dir(staging.join("b")).unwrap();

        let root = resolve_project_root(staging).unwrap();
        assert_eq!(root, staging);
    }

    #[test]
    fn resolve_project_root_ignores_macosx_and_ds_store() {
        let dir = tempdir().unwrap();
        let staging = dir.path();
        fs::create_dir(staging.join("__MACOSX")).unwrap();
        fs::write(staging.join(".DS_Store"), b"x").unwrap();
        fs::create_dir(staging.join("my-project")).unwrap();

        let root = resolve_project_root(staging).unwrap();
        assert_eq!(root, staging.join("my-project"));
    }

    #[test]
    fn stage_existing_project_copies_files_and_git_history() {
        let src_dir = tempdir().unwrap();
        let src = src_dir.path();
        fs::write(src.join("app.js"), b"console.log(1)").unwrap();
        fs::create_dir(src.join(".git")).unwrap();
        fs::write(src.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();

        let dest_dir = tempdir().unwrap();
        let dest = dest_dir.path().join("staged");
        let mut logs = Vec::new();
        let result = stage_existing_project(src, &dest, |m| logs.push(m.to_string())).unwrap();
        assert_eq!(result.file_count, 1);
        assert!(dest.join("app.js").exists());
        assert!(dest.join(".git/HEAD").exists());
        ignite_fs_utils::invalidate_walk_cache(src);
    }

    #[test]
    fn stage_existing_project_rejects_missing_source() {
        let dest_dir = tempdir().unwrap();
        let result = stage_existing_project(Path::new("/nonexistent/path/xyz"), &dest_dir.path().join("staged"), |_| {});
        assert!(result.is_err());
    }

    #[test]
    fn check_env_files_separates_blocking_from_gitignored() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join(".env"), b"SECRET=x").unwrap();
        fs::write(root.join(".env.production"), b"SECRET=y").unwrap();
        fs::write(root.join(".env.example"), b"SECRET=placeholder").unwrap(); // template, excluded
        fs::write(root.join(".gitignore"), ".env\n").unwrap();

        let result = check_env_files(root).unwrap();
        assert!(result.ignored.contains(&".env".to_string()));
        assert!(result.blocking.contains(&".env.production".to_string()));
        assert!(!result.blocking.iter().any(|f| f == ".env.example"));
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn check_codeowners_finds_root_file_and_extracts_emails() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("CODEOWNERS"), "* @someone team@example.com Team@Example.com\n").unwrap();

        let result = check_codeowners(root);
        assert!(result.found);
        assert_eq!(result.path, Some("CODEOWNERS"));
        assert_eq!(result.emails, vec!["team@example.com".to_string()]); // deduped case-insensitively
    }

    #[test]
    fn check_codeowners_prefers_root_over_github_and_docs() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join(".github")).unwrap();
        fs::write(root.join(".github/CODEOWNERS"), "* @x\n").unwrap();
        fs::write(root.join("CODEOWNERS"), "* @y\n").unwrap();

        let result = check_codeowners(root);
        assert_eq!(result.path, Some("CODEOWNERS"));
    }

    #[test]
    fn check_codeowners_reports_not_found() {
        let dir = tempdir().unwrap();
        let result = check_codeowners(dir.path());
        assert!(!result.found);
        assert!(result.emails.is_empty());
    }
}
