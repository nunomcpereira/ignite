pub mod catalog;
pub mod checks;

pub use catalog::{get_guideline, guidelines, list_categories, list_guidelines, Guideline, Severity};
pub use checks::{check_content, check_project, run_check, CheckHit, ProjectCheckResult, Violation};
