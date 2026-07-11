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
      return { ...project, steps, documents };
    },

    projectExists(projectId) {
      return !!stmt.hasProject.get(projectId);
    },

    deleteProjectById(projectId) {
      stmt.deleteProjectDocuments.run(projectId);
      stmt.deleteProjectSteps.run(projectId);
      stmt.deleteProject.run(projectId);
    },

    deleteAllProjects() {
      db.exec('DELETE FROM documents; DELETE FROM steps; DELETE FROM projects;');
    },

    getDocument(documentId) {
      return stmt.getDocumentForDownload.get(documentId);
    },
  };
}

module.exports = { createDbStore };
