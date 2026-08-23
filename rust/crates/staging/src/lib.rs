//! Faithful port of `server.js`'s staging/extraction layer — the guarded
//! path between an upload (ZIP/folder) or a local `projectPath` and a
//! per-job staging directory every phase check then runs against.
//! Hardening invariants (see project CLAUDE.md): every archive entry's
//! resolved path must stay inside the staging root (zip-slip), symlink
//! entries are skipped and never followed, and extracted/staged size is
//! capped at `MAX_EXTRACTED_BYTES`.

use ignite_fs_utils::{is_env_template_file, is_gitignored, load_gitignore_patterns, walk_files};
use ignite_tool_runner::{sanitize_absolute_project_path, sanitize_upload_relative_path, ToolError};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const MAX_EXTRACTED_BYTES: u64 = 4 * 1024 * 1024 * 1024; // zip-bomb guard

#[derive(Debug, thiserror::Error)]
pub enum StagingError {
    #[error("Invalid path.")]
    InvalidPath,
    #[error("Blocked path-traversal: {0}")]
    PathTraversal(String),
    #[error("Blocked path traversal while staging project file: {0}")]
    ProjectFilePathTraversal(String),
    #[error("Blocked path-traversal entry in folder upload: {0}")]
    FolderUploadPathTraversal(String),
    #[error("Archive contains an invalid entry path.")]
    InvalidArchiveEntry,
    #[error("Archive exceeds maximum extracted size (possible zip bomb). Aborting.")]
    ZipBomb,
    #[error("Folder upload exceeds maximum staged size. Aborting.")]
    FolderUploadTooLarge,
    #[error("Project exceeds maximum staged size. Aborting validation.")]
    ProjectTooLarge,
    #[error("Folder upload malformed: file/path count mismatch.")]
    FolderUploadMismatch,
    #[error("{0} does not exist or is not a directory: {1}")]
    NotADirectory(&'static str, String),
    #[error(transparent)]
    Tool(#[from] ToolError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),
}

/// Resolves a relative path against a root and errors if it escapes that
/// root (zip-slip-style traversal) — shared by archive extraction and the
/// Ignite Studio file read/write endpoints, which both accept a
/// caller-supplied relative path.
pub fn resolve_within_root(root: &Path, rel_path: &str) -> Result<PathBuf, StagingError> {
    let entry_path = rel_path.replace('\\', "/");
    if entry_path.is_empty() || entry_path.contains('\0') {
        return Err(StagingError::InvalidPath);
    }
    let target = root.join(&entry_path);
    let normalized = normalize_lexically(&target);
    let root_normalized = normalize_lexically(root);
    if normalized != root_normalized && !normalized.starts_with(&root_normalized) {
        return Err(StagingError::PathTraversal(entry_path));
    }
    Ok(normalized)
}

/// `path.resolve`-equivalent lexical normalization (collapses `.`/`..`
/// without touching the filesystem) — matching Node's `path.resolve`
/// behavior on a path that may not exist yet.
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

pub struct StageResult {
    pub file_count: u64,
    pub total_bytes: u64,
}

/// Copies every real file under `source_dir` into `dest_dir`, enforcing
/// the same zip-slip and size guards as archive extraction. Used by
/// `validate-all`/the CLI, where the "upload" is already a local
/// directory. `.git`, if present, is copied best-effort afterward (not
/// size-capped — it's auxiliary metadata for PII-diff mode, not part of
/// what's being reviewed) by the caller, matching `stageExistingProject`'s
/// documented split with server.js's own separate `.git` copy step.
pub fn stage_existing_project(source_dir: &str, dest_dir: &Path) -> Result<StageResult, StagingError> {
    let safe_source = sanitize_absolute_project_path(source_dir)?;
    let meta = fs::metadata(&safe_source).ok();
    if meta.as_ref().map(|m| !m.is_dir()).unwrap_or(true) {
        return Err(StagingError::NotADirectory("projectPath", safe_source.to_string_lossy().into_owned()));
    }

    fs::create_dir_all(dest_dir)?;

    let mut total_bytes = 0u64;
    let mut file_count = 0u64;
    for file in walk_files(&safe_source)? {
        let rel = file.strip_prefix(&safe_source).unwrap_or(&file);
        let target = dest_dir.join(rel);
        let normalized = normalize_lexically(&target);
        let root_normalized = normalize_lexically(dest_dir);
        if normalized != root_normalized && !normalized.starts_with(&root_normalized) {
            return Err(StagingError::ProjectFilePathTraversal(rel.to_string_lossy().into_owned()));
        }
        let size = fs::metadata(&file)?.len();
        total_bytes += size;
        if total_bytes > MAX_EXTRACTED_BYTES {
            return Err(StagingError::ProjectTooLarge);
        }
        if let Some(parent) = normalized.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&file, &normalized)?;
        file_count += 1;
    }

    Ok(StageResult { file_count, total_bytes })
}

pub struct UploadFile {
    pub temp_path: PathBuf,
    pub rel_path: String,
    pub size: u64,
}

/// Direct folder upload: moves already-received temp files into the
/// staging dir at their client-provided relative paths. Same guards as
/// ZIP extraction.
pub fn stage_directory_upload(files: &[UploadFile], dest_dir: &Path) -> Result<StageResult, StagingError> {
    let mut total_bytes = 0u64;
    for f in files {
        let rel = sanitize_upload_relative_path(&f.rel_path)?;
        let target = dest_dir.join(&rel);
        let normalized = normalize_lexically(&target);
        let root_normalized = normalize_lexically(dest_dir);
        if normalized != root_normalized && !normalized.starts_with(&root_normalized) {
            return Err(StagingError::FolderUploadPathTraversal(rel));
        }
        total_bytes += f.size;
        if total_bytes > MAX_EXTRACTED_BYTES {
            return Err(StagingError::FolderUploadTooLarge);
        }
        if let Some(parent) = normalized.parent() {
            fs::create_dir_all(parent)?;
        }
        // Cross-device rename would fail in Node too (EXDEV) — fall back
        // to copy+remove, same as the JS original.
        if fs::rename(&f.temp_path, &normalized).is_err() {
            fs::copy(&f.temp_path, &normalized)?;
            let _ = fs::remove_file(&f.temp_path);
        }
    }
    Ok(StageResult { file_count: files.len() as u64, total_bytes })
}

/// Safe ZIP extraction: rejects entries that escape the staging root
/// (zip-slip), skips symlink entries, and enforces a total-size cap
/// checked against actual streamed bytes (not just the archive's own
/// forgeable declared sizes).
pub fn extract_zip(zip_path: &Path, dest_dir: &Path) -> Result<StageResult, StagingError> {
    let file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let mut total_bytes = 0u64;
    let mut file_count = 0u64;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if entry.is_dir() {
            continue;
        }

        let entry_path = entry.name().replace('\\', "/");
        if entry_path.is_empty() || entry_path.contains('\0') {
            return Err(StagingError::InvalidArchiveEntry);
        }

        let target = resolve_within_root(dest_dir, &entry_path)?;

        // Skip symlink entries (unix mode's file-type bits, S_IFLNK).
        if let Some(mode) = entry.unix_mode() {
            if (mode & 0o170000) == 0o120000 {
                continue;
            }
        }

        // Fast-path pre-check on the archive's own declared size (forgeable
        // metadata) — the enforced cap is the streamed total below.
        if total_bytes + entry.size() > MAX_EXTRACTED_BYTES {
            return Err(StagingError::ZipBomb);
        }

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut sink = fs::File::create(&target)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        }
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = entry.read(&mut buf)?;
            if n == 0 {
                break;
            }
            total_bytes += n as u64;
            if total_bytes > MAX_EXTRACTED_BYTES {
                drop(sink);
                let _ = fs::remove_file(&target);
                return Err(StagingError::ZipBomb);
            }
            std::io::Write::write_all(&mut sink, &buf[..n])?;
        }
        file_count += 1;
    }

    Ok(StageResult { file_count, total_bytes })
}

/// If the archive contains a single top-level folder (the common
/// "project-folder.zip" layout), descend into it so scans and git run at
/// the real project root.
pub fn resolve_project_root(staging_dir: &Path) -> std::io::Result<PathBuf> {
    let ignored: HashSet<&str> = ["__MACOSX", ".DS_Store"].into_iter().collect();
    let entries: Vec<_> = fs::read_dir(staging_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| !ignored.contains(e.file_name().to_string_lossy().as_ref()))
        .collect();
    if entries.len() == 1 && entries[0].file_type().map(|t| t.is_dir()).unwrap_or(false) {
        return Ok(staging_dir.join(entries[0].file_name()));
    }
    Ok(staging_dir.to_path_buf())
}

pub struct EnvFilesCheck {
    pub blocking: Vec<String>,
    pub ignored: Vec<String>,
}

/// Raw `.env*` files present on disk (excluding recognized templates like
/// `.env.example`) block onboarding unless the project's own `.gitignore`
/// already excludes them (in which case they'd never be committed/pushed
/// by this same pipeline, so they're surfaced as informational instead).
pub fn check_env_files(root: &Path) -> std::io::Result<EnvFilesCheck> {
    let gitignore_patterns = load_gitignore_patterns(root);
    let mut blocking = Vec::new();
    let mut ignored = Vec::new();
    for file in walk_files(root)? {
        let base = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if base != ".env" && !base.starts_with(".env.") {
            continue;
        }
        if is_env_template_file(base) {
            continue;
        }
        let rel = file.strip_prefix(root).unwrap_or(&file).to_string_lossy().into_owned();
        if !gitignore_patterns.is_empty() && is_gitignored(&gitignore_patterns, &rel) {
            ignored.push(rel);
        } else {
            blocking.push(rel);
        }
    }
    Ok(EnvFilesCheck { blocking, ignored })
}

// GitHub recognizes CODEOWNERS in exactly these three locations (root,
// .github/, docs/) and uses the first one found, in that order.
const CODEOWNERS_LOCATIONS: &[&str] = &["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"];
static EMAIL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[\w.+-]+@[\w-]+\.[\w.-]+").unwrap());

pub struct CodeownersCheck {
    pub found: bool,
    pub path: Option<String>,
    pub emails: Vec<String>,
}

/// Advisory-only presence/contact check (never blocks onboarding): locates
/// a CODEOWNERS file and extracts any email-address owners from it
/// (`@username` entries aren't actionable for automated notification, so
/// they're not collected here).
pub fn check_codeowners(root: &Path) -> CodeownersCheck {
    for rel in CODEOWNERS_LOCATIONS {
        let Ok(content) = fs::read_to_string(root.join(rel)) else { continue };
        let mut seen = HashSet::new();
        let mut emails = Vec::new();
        for m in EMAIL_RE.find_iter(&content) {
            let lower = m.as_str().to_lowercase();
            if seen.insert(lower.clone()) {
                emails.push(lower);
            }
        }
        return CodeownersCheck { found: true, path: Some(rel.to_string()), emails };
    }
    CodeownersCheck { found: false, path: None, emails: vec![] }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn resolve_within_root_allows_nested_paths() {
        let root = tempdir().unwrap();
        let target = resolve_within_root(root.path(), "src/app.js").unwrap();
        assert!(target.starts_with(root.path()));
    }

    #[test]
    fn resolve_within_root_blocks_traversal() {
        let root = tempdir().unwrap();
        assert!(resolve_within_root(root.path(), "../../etc/passwd").is_err());
    }

    #[test]
    fn resolve_within_root_blocks_null_byte() {
        let root = tempdir().unwrap();
        assert!(resolve_within_root(root.path(), "a\0b").is_err());
    }

    #[test]
    fn stage_existing_project_copies_files_and_reports_counts() {
        let source = tempdir().unwrap();
        fs::write(source.path().join("a.js"), "console.log(1);").unwrap();
        fs::create_dir_all(source.path().join("src")).unwrap();
        fs::write(source.path().join("src/b.js"), "console.log(2);").unwrap();

        let dest = tempdir().unwrap();
        let dest_dir = dest.path().join("staged");
        let result = stage_existing_project(source.path().to_str().unwrap(), &dest_dir).unwrap();

        assert_eq!(result.file_count, 2);
        assert!(dest_dir.join("a.js").exists());
        assert!(dest_dir.join("src/b.js").exists());
    }

    #[test]
    fn stage_existing_project_rejects_non_directory_source() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let dest = tempdir().unwrap();
        let result = stage_existing_project(file.path().to_str().unwrap(), &dest.path().join("staged"));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_project_root_descends_into_single_top_level_folder() {
        let staging = tempdir().unwrap();
        fs::create_dir_all(staging.path().join("my-project")).unwrap();
        let root = resolve_project_root(staging.path()).unwrap();
        assert_eq!(root, staging.path().join("my-project"));
    }

    #[test]
    fn resolve_project_root_ignores_macosx_and_ds_store() {
        let staging = tempdir().unwrap();
        fs::create_dir_all(staging.path().join("__MACOSX")).unwrap();
        fs::write(staging.path().join(".DS_Store"), "").unwrap();
        fs::create_dir_all(staging.path().join("my-project")).unwrap();
        let root = resolve_project_root(staging.path()).unwrap();
        assert_eq!(root, staging.path().join("my-project"));
    }

    #[test]
    fn resolve_project_root_stays_at_staging_root_when_multiple_entries() {
        let staging = tempdir().unwrap();
        fs::create_dir_all(staging.path().join("a")).unwrap();
        fs::create_dir_all(staging.path().join("b")).unwrap();
        let root = resolve_project_root(staging.path()).unwrap();
        assert_eq!(root, staging.path());
    }

    #[test]
    fn check_env_files_blocks_raw_env_and_allows_templates() {
        let root = tempdir().unwrap();
        fs::write(root.path().join(".env"), "SECRET=1").unwrap();
        fs::write(root.path().join(".env.example"), "SECRET=").unwrap();
        let result = check_env_files(root.path()).unwrap();
        assert_eq!(result.blocking, vec![".env".to_string()]);
    }

    #[test]
    fn check_env_files_moves_gitignored_env_to_ignored_list() {
        let root = tempdir().unwrap();
        fs::write(root.path().join(".gitignore"), ".env\n").unwrap();
        fs::write(root.path().join(".env"), "SECRET=1").unwrap();
        let result = check_env_files(root.path()).unwrap();
        assert!(result.blocking.is_empty());
        assert_eq!(result.ignored, vec![".env".to_string()]);
    }

    #[test]
    fn check_codeowners_finds_root_file_and_extracts_emails() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("CODEOWNERS"), "* @someone security@example.com\n").unwrap();
        let result = check_codeowners(root.path());
        assert!(result.found);
        assert_eq!(result.path.as_deref(), Some("CODEOWNERS"));
        assert_eq!(result.emails, vec!["security@example.com".to_string()]);
    }

    #[test]
    fn check_codeowners_prefers_root_over_github_location() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join(".github")).unwrap();
        fs::write(root.path().join(".github/CODEOWNERS"), "team@example.com").unwrap();
        fs::write(root.path().join("CODEOWNERS"), "root@example.com").unwrap();
        let result = check_codeowners(root.path());
        assert_eq!(result.path.as_deref(), Some("CODEOWNERS"));
        assert_eq!(result.emails, vec!["root@example.com".to_string()]);
    }

    #[test]
    fn check_codeowners_reports_not_found_when_absent() {
        let root = tempdir().unwrap();
        let result = check_codeowners(root.path());
        assert!(!result.found);
        assert!(result.emails.is_empty());
    }

    #[test]
    fn extract_zip_rejects_zip_slip_entries() {
        let dest = tempdir().unwrap();
        let zip_dir = tempdir().unwrap();
        let zip_path = zip_dir.path().join("evil.zip");
        {
            let file = fs::File::create(&zip_path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
            writer.start_file("../../evil.txt", opts).unwrap();
            std::io::Write::write_all(&mut writer, b"pwned").unwrap();
            writer.finish().unwrap();
        }
        let result = extract_zip(&zip_path, dest.path());
        assert!(result.is_err());
        assert!(!dest.path().parent().unwrap().join("evil.txt").exists());
    }

    #[test]
    fn extract_zip_extracts_regular_files() {
        let dest = tempdir().unwrap();
        let zip_dir = tempdir().unwrap();
        let zip_path = zip_dir.path().join("good.zip");
        {
            let file = fs::File::create(&zip_path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
            writer.start_file("src/app.js", opts).unwrap();
            std::io::Write::write_all(&mut writer, b"console.log(1);").unwrap();
            writer.finish().unwrap();
        }
        let result = extract_zip(&zip_path, dest.path()).unwrap();
        assert_eq!(result.file_count, 1);
        assert!(dest.path().join("src/app.js").exists());
    }
}
