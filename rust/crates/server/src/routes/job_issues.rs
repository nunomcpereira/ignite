//! Shared live-run/completed-job issue lookup — `routes/sarif.js` and
//! `routes/github-annotations.js` both do exactly this same lookup before
//! reshaping the result differently.

use crate::state::AppState;
use ignite_db_store::IssueRow;

pub fn lookup_job_issues(state: &AppState, job_id: &str) -> Option<Vec<IssueRow>> {
    let running = state.running_runs.lock().unwrap();
    if let Some(live) = running.get(job_id) {
        return Some(live.all_issues.clone());
    }
    drop(running);
    let project_id = state.db.get_project_id_by_job_id(job_id)?;
    Some(state.db.get_project_issues(project_id))
}
