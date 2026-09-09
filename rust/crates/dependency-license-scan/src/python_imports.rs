//! Python (pypi) import-level transitive reachability — the same signal
//! `ignite_module_graph::collect_imported_packages` provides for npm,
//! reimplemented here rather than shared: Python's import syntax has no
//! equivalent to JS/TS's, and — unlike npm, where the import specifier
//! *is* the package name by construction — a pip package name and its
//! importable module name routinely differ (`PyYAML` imports as `yaml`,
//! `beautifulsoup4` as `bs4`, `Pillow` as `PIL`, ...). [`PIP_NAME_ALIASES`]
//! covers the well-known, unambiguous cases; anything not in that table
//! falls back to PEP 503 normalization (lowercase, hyphens to
//! underscores), which correctly predicts the overwhelming majority of
//! packages not covered by the table.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// pip package name -> the actual top-level module name it's imported
/// under, for the well-known cases where the two differ. Deliberately
/// only the ones with one clear, unambiguous import name — a package
/// like `protobuf` (imports as `google.protobuf`, sharing the `google`
/// namespace package with dozens of unrelated `google-*` packages) is
/// left out rather than risk a misleading match.
static PIP_NAME_ALIASES: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    [
        ("pyyaml", "yaml"),
        ("beautifulsoup4", "bs4"),
        ("pillow", "pil"),
        ("python-dateutil", "dateutil"),
        ("python-dotenv", "dotenv"),
        ("opencv-python", "cv2"),
        ("opencv-python-headless", "cv2"),
        ("scikit-learn", "sklearn"),
        ("pycryptodome", "crypto"),
        ("pycrypto", "crypto"),
        ("msgpack-python", "msgpack"),
        ("python-jose", "jose"),
        ("grpcio", "grpc"),
        ("psycopg2-binary", "psycopg2"),
        ("attrs", "attr"),
        ("pyjwt", "jwt"),
        ("pysocks", "socks"),
        ("websocket-client", "websocket"),
        ("protobuf3-to-dict", "protobuf_to_dict"),
    ]
    .into_iter()
    .collect()
});

/// PEP 503-normalizes `pip_package_name` into its expected top-level
/// import module name — the alias table above when the package is a
/// known exception, otherwise lowercased with hyphens/dots turned into
/// underscores (pip's own normalization, and also how the overwhelming
/// majority of packages actually name their importable module).
pub fn expected_python_import_name(pip_package_name: &str) -> String {
    let normalized = pip_package_name.to_lowercase();
    if let Some(alias) = PIP_NAME_ALIASES.get(normalized.as_str()) {
        return alias.to_string();
    }
    normalized.replace(['-', '.'], "_")
}

static PY_IMPORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^\s*import\s+([A-Za-z_][\w]*)").unwrap());
static PY_FROM_IMPORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^\s*from\s+([A-Za-z_][\w]*)").unwrap());

/// Every distinct top-level module name imported (`import x`, `import
/// x.y`, `from x import y`, `from x.y import z`) anywhere in the
/// project's `.py` source — a relative import (`from . import x`,
/// `from .sibling import y`) never matches either regex (both require
/// the module name to start with a letter/underscore, not a `.`), so
/// only genuine external/absolute imports ever land in the result, the
/// same relative-vs-bare distinction `ignite_module_graph` makes for
/// JS/TS.
pub fn collect_python_imported_modules(root: &Path) -> HashSet<String> {
    let mut modules = HashSet::new();
    let Ok(files) = ignite_fs_utils::walk_files(root) else { return modules };
    for file in files.into_iter().filter(|f| f.extension().is_some_and(|e| e == "py")) {
        let Ok(content) = std::fs::read_to_string(&file) else { continue };
        for re in [&*PY_IMPORT_RE, &*PY_FROM_IMPORT_RE] {
            for cap in re.captures_iter(&content) {
                modules.insert(cap[1].to_lowercase());
            }
        }
    }
    modules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_python_import_name_uses_the_alias_table_when_present() {
        assert_eq!(expected_python_import_name("PyYAML"), "yaml");
        assert_eq!(expected_python_import_name("beautifulsoup4"), "bs4");
        assert_eq!(expected_python_import_name("Pillow"), "pil");
    }

    #[test]
    fn expected_python_import_name_falls_back_to_pep503_normalization() {
        assert_eq!(expected_python_import_name("requests"), "requests");
        assert_eq!(expected_python_import_name("Flask-SQLAlchemy"), "flask_sqlalchemy");
        assert_eq!(expected_python_import_name("some.dotted.name"), "some_dotted_name");
    }

    #[test]
    fn collect_python_imported_modules_finds_plain_and_from_imports() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "import requests\nfrom yaml import safe_load\nimport os.path\n").unwrap();
        let modules = collect_python_imported_modules(dir.path());
        assert!(modules.contains("requests"));
        assert!(modules.contains("yaml"));
        assert!(modules.contains("os"));
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[test]
    fn collect_python_imported_modules_ignores_relative_imports() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "from . import sibling\nfrom .utils import helper\n").unwrap();
        let modules = collect_python_imported_modules(dir.path());
        assert!(modules.is_empty(), "{modules:?}");
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[test]
    fn collect_python_imported_modules_empty_for_a_project_with_no_python_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("readme.txt"), "not python").unwrap();
        assert!(collect_python_imported_modules(dir.path()).is_empty());
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }
}
