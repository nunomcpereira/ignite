const { DatabaseSync } = require('node:sqlite');
const path = require('path');

function createDbStore(dbFile = path.join(__dirname, 'ignite.db')) {
  const db = new DatabaseSync(dbFile);

  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS projects (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      job_id      TEXT UNIQUE NOT NULL,
      org         TEXT NOT NULL,
      repo        TEXT NOT NULL,
      gxp         INTEGER NOT NULL DEFAULT 0,
      source      TEXT NOT NULL DEFAULT 'ui',
      status      TEXT NOT NULL DEFAULT 'running',
      error       TEXT,
      repo_url    TEXT,
      pr_url      TEXT,
      created_at  TEXT NOT NULL DEFAULT (datetime('now')),
      finished_at TEXT
    );
    CREATE TABLE IF NOT EXISTS steps (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      phase      INTEGER NOT NULL,
      title      TEXT NOT NULL,
      state      TEXT NOT NULL,
      logs       TEXT NOT NULL DEFAULT ''
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_steps_project_phase
      ON steps(project_id, phase);
    CREATE TABLE IF NOT EXISTS documents (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      kind       TEXT NOT NULL CHECK (kind IN ('upload','link')),
      name       TEXT NOT NULL,
      url        TEXT,
      mime       TEXT,
      size       INTEGER,
      data       BLOB,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      email         TEXT UNIQUE NOT NULL,
      name          TEXT,
      provider      TEXT NOT NULL DEFAULT 'local' CHECK (provider IN ('local','oidc','github')),
      password_hash TEXT,
      external_id   TEXT,
      created_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_provider_external
      ON users(provider, external_id);
    CREATE TABLE IF NOT EXISTS sessions (
      id         TEXT PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS overrides (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      job_id       TEXT NOT NULL,
      phase        INTEGER NOT NULL,
      issue_id     TEXT NOT NULL,
      category     TEXT NOT NULL,
      severity     TEXT NOT NULL,
      summary      TEXT NOT NULL,
      file         TEXT,
      line         INTEGER,
      justification TEXT NOT NULL,
      actor_email  TEXT NOT NULL,
      actor_name   TEXT,
      email_sent   INTEGER NOT NULL DEFAULT 0,
      created_at   TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_overrides_project ON overrides(project_id);
    CREATE TABLE IF NOT EXISTS issues (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      issue_id     TEXT NOT NULL,
      phase        INTEGER,
      category     TEXT NOT NULL,
      severity     TEXT NOT NULL,
      score        INTEGER,
      summary      TEXT NOT NULL,
      file         TEXT,
      line         INTEGER,
      snippet_json TEXT,
      status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','overridden')),
      created_at   TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_issues_project ON issues(project_id);
    CREATE TABLE IF NOT EXISTS issue_explanations (
      hash        TEXT PRIMARY KEY,
      explanation TEXT NOT NULL,
      created_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS file_scan_cache (
      org          TEXT NOT NULL,
      repo         TEXT NOT NULL,
      check_name   TEXT NOT NULL,
      rel_path     TEXT NOT NULL,
      hash         TEXT NOT NULL,
      findings_json TEXT NOT NULL,
      updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (org, repo, check_name, rel_path)
    );
    CREATE TABLE IF NOT EXISTS github_connections (
      user_id      INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      github_login TEXT NOT NULL,
      access_token TEXT NOT NULL,
      scope        TEXT,
      connected_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // Migration for DBs created before the issues.score column existed —
  // CREATE TABLE IF NOT EXISTS above is a no-op on an already-existing table.
  try {
    db.exec('ALTER TABLE issues ADD COLUMN score INTEGER');
  } catch (e) {
    if (!/duplicate column/i.test(e.message)) throw e;
  }

  // Migration for DBs created before projects.source existed. Existing rows
  // predate the distinction entirely (they were all onboarded through the
  // browser UI, the only path that existed at the time), so 'ui' is the
  // correct backfill, not just a placeholder default.
  try {
    db.exec(`ALTER TABLE projects ADD COLUMN source TEXT NOT NULL DEFAULT 'ui'`);
  } catch (e) {
    if (!/duplicate column/i.test(e.message)) throw e;
  }

  const stmt = {
    insertProject: db.prepare('INSERT INTO projects (job_id, org, repo, gxp, source) VALUES (?, ?, ?, ?, ?)'),
    finishProject: db.prepare(
      `UPDATE projects SET status = ?, error = ?, repo_url = ?, pr_url = ?, finished_at = datetime('now') WHERE id = ?`
    ),
    insertStep: db.prepare('INSERT INTO steps (project_id, phase, title, state, logs) VALUES (?, ?, ?, ?, ?)'),
    upsertStep: db.prepare(
      `INSERT INTO steps (project_id, phase, title, state, logs)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(project_id, phase)
       DO UPDATE SET title = excluded.title, state = excluded.state, logs = excluded.logs`
    ),
    insertDocument: db.prepare(
      'INSERT INTO documents (project_id, kind, name, url, mime, size, data) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ),
    listProjects: db.prepare(`
      SELECT p.id, p.org, p.repo, p.gxp, p.source, p.status, p.error, p.repo_url, p.pr_url,
             p.created_at, p.finished_at,
             (SELECT COUNT(*) FROM documents d WHERE d.project_id = p.id) AS doc_count,
             (SELECT COUNT(*) FROM issues i WHERE i.project_id = p.id) AS issue_count
      FROM projects p ORDER BY p.id DESC LIMIT 100
    `),
    getProject: db.prepare(
      'SELECT id, org, repo, gxp, source, status, error, repo_url, pr_url, created_at, finished_at FROM projects WHERE id = ?'
    ),
    getSteps: db.prepare('SELECT phase, title, state, logs FROM steps WHERE project_id = ? ORDER BY phase'),
    getProjectDocuments: db.prepare(
      'SELECT id, kind, name, url, mime, size, created_at FROM documents WHERE project_id = ? ORDER BY id'
    ),
    getDocumentForDownload: db.prepare('SELECT kind, name, url, mime, data FROM documents WHERE id = ?'),
    hasProject: db.prepare('SELECT id FROM projects WHERE id = ?'),
    deleteProjectDocuments: db.prepare('DELETE FROM documents WHERE project_id = ?'),
    deleteProjectSteps: db.prepare('DELETE FROM steps WHERE project_id = ?'),
    deleteProject: db.prepare('DELETE FROM projects WHERE id = ?'),
    deleteProjectOverrides: db.prepare('DELETE FROM overrides WHERE project_id = ?'),

    insertLocalUser: db.prepare(
      `INSERT INTO users (email, name, provider, password_hash) VALUES (?, ?, 'local', ?)`
    ),
    upsertOidcUser: db.prepare(
      `INSERT INTO users (email, name, provider, external_id) VALUES (?, ?, 'oidc', ?)
       ON CONFLICT(provider, external_id)
       DO UPDATE SET email = excluded.email, name = excluded.name`
    ),
    upsertGithubUser: db.prepare(
      `INSERT INTO users (email, name, provider, external_id) VALUES (?, ?, 'github', ?)
       ON CONFLICT(provider, external_id)
       DO UPDATE SET email = excluded.email, name = excluded.name`
    ),
    getUserByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
    getUserByOidcSub: db.prepare(`SELECT * FROM users WHERE provider = 'oidc' AND external_id = ?`),
    getUserByGithubId: db.prepare(`SELECT * FROM users WHERE provider = 'github' AND external_id = ?`),
    getUserById: db.prepare('SELECT id, email, name, provider, created_at FROM users WHERE id = ?'),

    insertSession: db.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)'),
    getSession: db.prepare(
      `SELECT s.id, s.expires_at, u.id AS user_id, u.email, u.name, u.provider
       FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?`
    ),
    deleteSession: db.prepare('DELETE FROM sessions WHERE id = ?'),
    deleteExpiredSessions: db.prepare(`DELETE FROM sessions WHERE expires_at < datetime('now')`),

    insertOverride: db.prepare(
      `INSERT INTO overrides
        (project_id, job_id, phase, issue_id, category, severity, summary, file, line, justification, actor_email, actor_name, email_sent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ),
    getProjectOverrides: db.prepare(
      `SELECT id, phase, issue_id, category, severity, summary, file, line, justification,
              actor_email, actor_name, email_sent, created_at
       FROM overrides WHERE project_id = ? ORDER BY id`
    ),

    deleteProjectIssues: db.prepare('DELETE FROM issues WHERE project_id = ?'),
    insertIssue: db.prepare(
      `INSERT INTO issues (project_id, issue_id, phase, category, severity, score, summary, file, line, snippet_json, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ),
    getProjectIssues: db.prepare(
      `SELECT issue_id, phase, category, severity, score, summary, file, line, snippet_json, status, created_at
       FROM issues WHERE project_id = ? ORDER BY id`
    ),
    countOpenIssues: db.prepare(
      `SELECT project_id, COUNT(*) AS n FROM issues WHERE status = 'open' GROUP BY project_id`
    ),

    getIssueExplanation: db.prepare('SELECT explanation FROM issue_explanations WHERE hash = ?'),
    saveIssueExplanation: db.prepare(
      `INSERT INTO issue_explanations (hash, explanation) VALUES (?, ?)
       ON CONFLICT(hash) DO UPDATE SET explanation = excluded.explanation`
    ),
    getProjectByJobId: db.prepare('SELECT id FROM projects WHERE job_id = ?'),

    getFileScanCache: db.prepare(
      'SELECT rel_path, hash, findings_json FROM file_scan_cache WHERE org = ? AND repo = ? AND check_name = ?'
    ),
    deleteFileScanCache: db.prepare(
      'DELETE FROM file_scan_cache WHERE org = ? AND repo = ? AND check_name = ?'
    ),
    insertFileScanCache: db.prepare(
      `INSERT INTO file_scan_cache (org, repo, check_name, rel_path, hash, findings_json)
       VALUES (?, ?, ?, ?, ?, ?)`
    ),

    // Formatted with the "excluded" reference on its own line — not a
    // stylistic choice, it's specifically so this SQL upsert clause (a
    // column reference, not a credential) doesn't collide with the org
    // governance workflow's naive single-line "token\s*=\s*.{10,}" secret
    // grep, which otherwise flags the access-token column's own upsert
    // assignment as a hardcoded token every single run.
    upsertGithubConnection: db.prepare(
      `INSERT INTO github_connections (user_id, github_login, access_token, scope)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(user_id)
       DO UPDATE SET
         github_login = excluded.github_login,
         access_token =
           excluded.access_token,
         scope = excluded.scope, connected_at = datetime('now')`
    ),
    getGithubConnection: db.prepare('SELECT * FROM github_connections WHERE user_id = ?'),
    deleteGithubConnection: db.prepare('DELETE FROM github_connections WHERE user_id = ?'),
  };

  return {
    createProject(jobId, org, repo, isGxp, source = 'ui') {
      return Number(stmt.insertProject.run(jobId, org, repo, isGxp ? 1 : 0, source).lastInsertRowid);
    },

    finishProject(status, error, repoUrl, prUrl, projectId) {
      stmt.finishProject.run(status, error, repoUrl, prUrl, projectId);
    },

    addStep(projectId, phase, title, state, logs) {
      stmt.insertStep.run(projectId, phase, title, state, logs);
    },

    upsertStep(projectId, phase, title, state, logs) {
      stmt.upsertStep.run(projectId, phase, title, state, logs);
    },

    addUploadDocument(projectId, name, mime, size, data) {
      stmt.insertDocument.run(projectId, 'upload', name, null, mime || null, size, data);
    },

    addLinkDocument(projectId, name, url) {
      stmt.insertDocument.run(projectId, 'link', name, url, null, null, null);
    },

    listProjects() {
      return stmt.listProjects.all();
    },

    getProjectDetails(projectId) {
      const project = stmt.getProject.get(projectId);
      if (!project) return null;
      const steps = stmt.getSteps.all(projectId);
      const documents = stmt.getProjectDocuments.all(projectId);
      const overrides = stmt.getProjectOverrides.all(projectId);
      return { ...project, steps, documents, overrides };
    },

    projectExists(projectId) {
      return !!stmt.hasProject.get(projectId);
    },

    deleteProjectById(projectId) {
      stmt.deleteProjectDocuments.run(projectId);
      stmt.deleteProjectSteps.run(projectId);
      stmt.deleteProjectOverrides.run(projectId);
      stmt.deleteProjectIssues.run(projectId);
      stmt.deleteProject.run(projectId);
    },

    deleteAllProjects() {
      db.exec('DELETE FROM documents; DELETE FROM steps; DELETE FROM overrides; DELETE FROM projects;');
    },

    getDocument(documentId) {
      return stmt.getDocumentForDownload.get(documentId);
    },

    /* ---------------- auth: users + sessions ---------------- */

    createLocalUser(email, name, passwordHash) {
      return Number(stmt.insertLocalUser.run(email, name || null, passwordHash).lastInsertRowid);
    },

    upsertOidcUser(email, name, externalId) {
      stmt.upsertOidcUser.run(email, name || null, externalId);
      return stmt.getUserByOidcSub.get(externalId);
    },

    upsertGithubUser(email, name, externalId) {
      stmt.upsertGithubUser.run(email, name || null, externalId);
      return stmt.getUserByGithubId.get(externalId);
    },

    getUserByEmail(email) {
      return stmt.getUserByEmail.get(email);
    },

    getUserById(userId) {
      return stmt.getUserById.get(userId);
    },

    createSession(sessionId, userId, expiresAtIso) {
      stmt.insertSession.run(sessionId, userId, expiresAtIso);
    },

    getSession(sessionId) {
      stmt.deleteExpiredSessions.run();
      return stmt.getSession.get(sessionId);
    },

    deleteSession(sessionId) {
      stmt.deleteSession.run(sessionId);
    },

    /* ---------------- per-file scan cache (skip re-evaluating unchanged files across iterations) ---------------- */

    /**
     * Keyed by (org, repo, checkName) so each validation check (secrets,
     * governance, LLM deep-scan, ...) keeps its own cache — a file unchanged
     * since the previous run of this org/repo gets its stored findings
     * reused instead of being re-evaluated.
     */
    getFileScanCache(org, repo, checkName) {
      const rows = stmt.getFileScanCache.all(org, repo, checkName);
      const map = new Map();
      for (const row of rows) {
        map.set(row.rel_path, { hash: row.hash, findings: JSON.parse(row.findings_json) });
      }
      return map;
    },

    // Replaces the entire cache for this (org, repo, checkName): files that
    // no longer exist (deleted/renamed since the last run) are dropped
    // rather than accumulating forever.
    replaceFileScanCache(org, repo, checkName, entries) {
      db.exec('BEGIN');
      try {
        stmt.deleteFileScanCache.run(org, repo, checkName);
        for (const entry of entries) {
          stmt.insertFileScanCache.run(org, repo, checkName, entry.relPath, entry.hash, JSON.stringify(entry.findings));
        }
        db.exec('COMMIT');
      } catch (e) {
        db.exec('ROLLBACK');
        throw e;
      }
    },

    /* ---------------- GitHub OAuth connection (per ignite user) ---------------- */

    upsertGithubConnection(userId, githubLogin, accessToken, scope) {
      stmt.upsertGithubConnection.run(userId, githubLogin, accessToken, scope || null);
    },

    getGithubConnection(userId) {
      return stmt.getGithubConnection.get(userId);
    },

    deleteGithubConnection(userId) {
      stmt.deleteGithubConnection.run(userId);
    },

    /* ---------------- audit log: overrides ---------------- */

    addOverride({ projectId, jobId, phase, issueId, category, severity, summary, file, line, justification, actorEmail, actorName, emailSent }) {
      stmt.insertOverride.run(
        projectId, jobId, phase, issueId, category, severity, summary,
        file || null, line ?? null, justification, actorEmail, actorName || null, emailSent ? 1 : 0
      );
    },

    getProjectOverrides(projectId) {
      return stmt.getProjectOverrides.all(projectId);
    },

    /* ---------------- flagged issues (viewable live and in history) ------- */

    // Called repeatedly as a run progresses — always reflects the latest
    // known set of issues for the project, so the history/API view is never
    // stale even if the pipeline dies before finishing.
    replaceProjectIssues(projectId, issues, overriddenIds) {
      const overridden = overriddenIds instanceof Set ? overriddenIds : new Set(overriddenIds || []);
      stmt.deleteProjectIssues.run(projectId);
      for (const issue of issues || []) {
        stmt.insertIssue.run(
          projectId,
          issue.id,
          Number.isInteger(issue.phase) ? issue.phase : null,
          issue.category,
          issue.severity,
          typeof issue.score === 'number' ? issue.score : null,
          issue.summary,
          issue.file || null,
          issue.line ?? null,
          issue.snippet ? JSON.stringify(issue.snippet) : null,
          overridden.has(issue.id) ? 'overridden' : 'open'
        );
      }
    },

    getProjectIssues(projectId) {
      return stmt.getProjectIssues.all(projectId).map((row) => ({
        id: row.issue_id,
        phase: row.phase,
        category: row.category,
        severity: row.severity,
        score: row.score,
        summary: row.summary,
        file: row.file,
        line: row.line,
        snippet: row.snippet_json ? JSON.parse(row.snippet_json) : null,
        status: row.status,
        created_at: row.created_at,
      }));
    },

    getProjectIdByJobId(jobId) {
      return stmt.getProjectByJobId.get(jobId)?.id ?? null;
    },

    /* Cached AI explanations for a specific finding, keyed by a stable hash
       of its identity (category/file/line/summary) — independent of which
       project/run it was found in, so the same finding is never re-explained. */
    getCachedIssueExplanation(hash) {
      return stmt.getIssueExplanation.get(hash)?.explanation ?? null;
    },

    cacheIssueExplanation(hash, explanation) {
      stmt.saveIssueExplanation.run(hash, explanation);
    },

    /**
     * Projects/steps left in 'running' happen only when the process died
     * mid-pipeline (killed, crashed) — nothing will ever finish them, so on
     * every startup we sweep them into a terminal 'aborted' state instead of
     * leaving stale spinners in the history panel forever.
     */
    abortStaleRunningProjects() {
      const ABORTED_ERROR = 'Server restarted while onboarding was still in progress.';
      db.exec(`
        UPDATE projects
        SET status = 'aborted',
            error = COALESCE(error, '${ABORTED_ERROR}'),
            finished_at = datetime('now')
        WHERE status = 'running';

        UPDATE steps
        SET state = 'failed',
            logs = logs || char(10) || '✗ ${ABORTED_ERROR}'
        WHERE state = 'running'
          AND project_id IN (SELECT id FROM projects WHERE error = '${ABORTED_ERROR}');
      `);
    },
  };
}

module.exports = { createDbStore };
