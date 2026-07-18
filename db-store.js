const { DatabaseSync } = require('node:sqlite');
const path = require('path');

function createDbStore(dbFile = path.join(__dirname, 'ignite.db')) {
  const db = new DatabaseSync(dbFile);

  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS projects (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      job_id      TEXT UNIQUE NOT NULL,
      org         TEXT NOT NULL,
      repo        TEXT NOT NULL,
      gxp         INTEGER NOT NULL DEFAULT 0,
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
      provider      TEXT NOT NULL DEFAULT 'local' CHECK (provider IN ('local','oidc')),
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
  `);

  const stmt = {
    insertProject: db.prepare('INSERT INTO projects (job_id, org, repo, gxp) VALUES (?, ?, ?, ?)'),
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
      SELECT p.id, p.org, p.repo, p.gxp, p.status, p.error, p.repo_url, p.pr_url,
             p.created_at, p.finished_at,
             (SELECT COUNT(*) FROM documents d WHERE d.project_id = p.id) AS doc_count
      FROM projects p ORDER BY p.id DESC LIMIT 100
    `),
    getProject: db.prepare(
      'SELECT id, org, repo, gxp, status, error, repo_url, pr_url, created_at, finished_at FROM projects WHERE id = ?'
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
    getUserByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
    getUserByOidcSub: db.prepare(`SELECT * FROM users WHERE provider = 'oidc' AND external_id = ?`),
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
  };

  return {
    createProject(jobId, org, repo, isGxp) {
      return Number(stmt.insertProject.run(jobId, org, repo, isGxp ? 1 : 0).lastInsertRowid);
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
  };
}

module.exports = { createDbStore };
