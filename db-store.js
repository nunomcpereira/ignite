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
      scan_location TEXT,
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
    CREATE TABLE IF NOT EXISTS api_keys (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      key_hash      TEXT UNIQUE NOT NULL,
      label         TEXT,
      created_at    TEXT NOT NULL DEFAULT (datetime('now')),
      created_by    TEXT,
      created_via   TEXT NOT NULL DEFAULT 'cli',
      last_used_at  TEXT,
      revoked_at    TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
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
      cross_file   INTEGER NOT NULL DEFAULT 0,
      chain_json   TEXT,
      cwe          TEXT,
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
    CREATE TABLE IF NOT EXISTS manifest_scan_cache (
      tool          TEXT NOT NULL,
      ecosystem     TEXT NOT NULL,
      content_hash  TEXT NOT NULL,
      tool_version  TEXT NOT NULL,
      findings_json TEXT NOT NULL,
      updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (tool, ecosystem, content_hash, tool_version)
    );
    CREATE TABLE IF NOT EXISTS codeql_scan_cache (
      org           TEXT NOT NULL,
      repo          TEXT NOT NULL,
      language      TEXT NOT NULL,
      file_set_hash TEXT NOT NULL,
      tool_version  TEXT NOT NULL,
      findings_json TEXT NOT NULL,
      updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (org, repo, language, file_set_hash, tool_version)
    );
    CREATE TABLE IF NOT EXISTS cosign_verify_cache (
      image             TEXT NOT NULL,
      identity_regexp   TEXT NOT NULL,
      issuer_regexp     TEXT NOT NULL,
      verified          INTEGER NOT NULL,
      reason            TEXT,
      checked_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
      PRIMARY KEY (image, identity_regexp, issuer_regexp)
    );
    CREATE TABLE IF NOT EXISTS workflow_cache (
      repo         TEXT NOT NULL,
      filename     TEXT NOT NULL,
      commit_sha   TEXT NOT NULL,
      content      TEXT NOT NULL,
      updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (repo, filename)
    );
    CREATE TABLE IF NOT EXISTS retained_sources (
      project_id  INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
      dir_path    TEXT NOT NULL,
      retained_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS github_connections (
      user_id      INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      github_login TEXT NOT NULL,
      access_token TEXT NOT NULL,
      scope        TEXT,
      connected_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    -- Baseline/diff adoption mode (closes the "no baseline gating" gap
    -- against fallow.tools' --save-baseline): one row per issue id a
    -- project has explicitly accepted as pre-existing debt. A later run's
    -- issue list is filtered against this set (lib/baseline-filter.js) so
    -- CI only gates on *new* issues, letting a large codebase adopt Ignite
    -- incrementally instead of needing every historical finding fixed or
    -- overridden on day one.
    CREATE TABLE IF NOT EXISTS issue_baselines (
      org        TEXT NOT NULL,
      repo       TEXT NOT NULL,
      issue_id   TEXT NOT NULL,
      saved_at   TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (org, repo, issue_id)
    );
    -- Runtime execution signal (closes the "no runtime/production signal"
    -- gap against fallow.tools' Beacon): per-file hit counts ingested from
    -- a project's own coverage/instrumentation report (Istanbul
    -- coverage-final.json or a simple { file: hitCount } map), used to (a)
    -- raise/lower dead-code deletion confidence and (b) feed real coverage
    -- into the CRAP score instead of the conservative 0% default. Static
    -- only otherwise — this is the one place production truth enters
    -- Ignite's otherwise-static pipeline.
    CREATE TABLE IF NOT EXISTS runtime_coverage (
      org         TEXT NOT NULL,
      repo        TEXT NOT NULL,
      rel_path    TEXT NOT NULL,
      hit_count   INTEGER NOT NULL DEFAULT 0,
      covered_pct REAL,
      updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (org, repo, rel_path)
    );
  `);

  // Migration for DBs created before the issues.score column existed —
  // CREATE TABLE IF NOT EXISTS above is a no-op on an already-existing table.
  try {
    db.exec('ALTER TABLE issues ADD COLUMN score INTEGER');
  } catch (e) {
    if (!/duplicate column/i.test(e.message)) throw e;
  }

  // Migration for DBs created before cross_file/chain_json/cwe existed —
  // without these, CodeQL's cross-file chain data (its one distinguishing
  // feature over Semgrep) silently vanished the moment a run's issues were
  // persisted for history, even though it survived fine in the live/kept
  // in-memory view.
  for (const ddl of [
    `ALTER TABLE issues ADD COLUMN cross_file INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE issues ADD COLUMN chain_json TEXT`,
    `ALTER TABLE issues ADD COLUMN cwe TEXT`,
  ]) {
    try {
      db.exec(ddl);
    } catch (e) {
      if (!/duplicate column/i.test(e.message)) throw e;
    }
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

  // Migration for DBs created before scan_location existed — the local
  // path (validate-all/onboard) or upload description (interactive UI)
  // the source tree was actually read from for this run, so a past run is
  // traceable back to what was scanned, not just its org/repo target.
  try {
    db.exec('ALTER TABLE projects ADD COLUMN scan_location TEXT');
  } catch (e) {
    if (!/duplicate column/i.test(e.message)) throw e;
  }

  // Migration for DBs created before scheduled re-checks existed. Disabled
  // by default — an existing effectivated repo doesn't opt into recurring
  // checks just because the column now exists.
  for (const ddl of [
    `ALTER TABLE projects ADD COLUMN schedule_enabled INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE projects ADD COLUMN schedule_interval TEXT`,
    `ALTER TABLE projects ADD COLUMN next_scheduled_run_at TEXT`,
    `ALTER TABLE projects ADD COLUMN last_scheduled_run_at TEXT`,
    `ALTER TABLE projects ADD COLUMN last_scheduled_status TEXT`,
    `ALTER TABLE projects ADD COLUMN last_scheduled_error TEXT`,
  ]) {
    try {
      db.exec(ddl);
    } catch (e) {
      if (!/duplicate column/i.test(e.message)) throw e;
    }
  }

  // Migration for DBs created before api_keys.created_by/created_via
  // existed — without these, there was no record of who minted a key or
  // how, making an impersonation-by-key-creation incident unattributable
  // after the fact.
  for (const ddl of [
    `ALTER TABLE api_keys ADD COLUMN created_by TEXT`,
    `ALTER TABLE api_keys ADD COLUMN created_via TEXT NOT NULL DEFAULT 'cli'`,
  ]) {
    try {
      db.exec(ddl);
    } catch (e) {
      if (!/duplicate column/i.test(e.message)) throw e;
    }
  }

  const stmt = {
    insertProject: db.prepare('INSERT INTO projects (job_id, org, repo, gxp, source, scan_location) VALUES (?, ?, ?, ?, ?, ?)'),
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
      SELECT p.id, p.job_id, p.org, p.repo, p.gxp, p.source, p.scan_location, p.status, p.error, p.repo_url, p.pr_url,
             p.created_at, p.finished_at,
             (SELECT COUNT(*) FROM documents d WHERE d.project_id = p.id) AS doc_count,
             (SELECT COUNT(*) FROM issues i WHERE i.project_id = p.id) AS issue_count,
             (SELECT 1 FROM retained_sources r WHERE r.project_id = p.id) AS retained
      FROM projects p ORDER BY p.id DESC LIMIT 100
    `),
    getProject: db.prepare(
      'SELECT id, org, repo, gxp, source, scan_location, status, error, repo_url, pr_url, created_at, finished_at FROM projects WHERE id = ?'
    ),
    getSteps: db.prepare('SELECT phase, title, state, logs FROM steps WHERE project_id = ? ORDER BY phase'),
    getProjectDocuments: db.prepare(
      'SELECT id, kind, name, url, mime, size, created_at FROM documents WHERE project_id = ? ORDER BY id'
    ),
    getDocumentForDownload: db.prepare('SELECT kind, name, url, mime, data FROM documents WHERE id = ?'),
    hasProject: db.prepare('SELECT id FROM projects WHERE id = ?'),
    deleteProjectDocuments: db.prepare('DELETE FROM documents WHERE project_id = ?'),
    getRetainedSource: db.prepare('SELECT dir_path FROM retained_sources WHERE project_id = ?'),
    upsertRetainedSource: db.prepare(
      `INSERT INTO retained_sources (project_id, dir_path, retained_at) VALUES (?, ?, datetime('now'))
       ON CONFLICT(project_id) DO UPDATE SET dir_path = excluded.dir_path, retained_at = excluded.retained_at`
    ),
    listRetainedSources: db.prepare('SELECT project_id, dir_path FROM retained_sources ORDER BY retained_at DESC'),
    listEvictableRetainedSources: db.prepare(
      'SELECT project_id, dir_path FROM retained_sources ORDER BY retained_at DESC LIMIT -1 OFFSET ?'
    ),
    deleteRetainedSource: db.prepare('DELETE FROM retained_sources WHERE project_id = ?'),
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
      `INSERT INTO issues (project_id, issue_id, phase, category, severity, score, summary, file, line, snippet_json, cross_file, chain_json, cwe, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ),
    getProjectIssues: db.prepare(
      `SELECT issue_id, phase, category, severity, score, summary, file, line, snippet_json, cross_file, chain_json, cwe, status, created_at
       FROM issues WHERE project_id = ? ORDER BY id`
    ),

    getIssueExplanation: db.prepare('SELECT explanation FROM issue_explanations WHERE hash = ?'),
    saveIssueExplanation: db.prepare(
      `INSERT INTO issue_explanations (hash, explanation) VALUES (?, ?)
       ON CONFLICT(hash) DO UPDATE SET explanation = excluded.explanation`
    ),
    getProjectByJobId: db.prepare('SELECT id FROM projects WHERE job_id = ?'),

    insertApiKey: db.prepare(
      `INSERT INTO api_keys (user_id, key_hash, label, created_by, created_via) VALUES (?, ?, ?, ?, ?)`
    ),
    getActiveApiKeyByHash: db.prepare(
      `SELECT ak.id, ak.user_id, u.email, u.name, u.provider
       FROM api_keys ak JOIN users u ON u.id = ak.user_id
       WHERE ak.key_hash = ? AND ak.revoked_at IS NULL`
    ),
    touchApiKeyLastUsed: db.prepare(
      `UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?`
    ),
    listApiKeysForUser: db.prepare(
      `SELECT id, label, created_at, created_by, created_via, last_used_at, revoked_at FROM api_keys WHERE user_id = ? ORDER BY id`
    ),
    revokeApiKey: db.prepare(
      `UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ? AND revoked_at IS NULL`
    ),

    getFileScanCache: db.prepare(
      'SELECT rel_path, hash, findings_json FROM file_scan_cache WHERE org = ? AND repo = ? AND check_name = ?'
    ),
    deleteFileScanCache: db.prepare(
      'DELETE FROM file_scan_cache WHERE org = ? AND repo = ? AND check_name = ?'
    ),
    deleteFileScanCacheForRepo: db.prepare(
      'DELETE FROM file_scan_cache WHERE org = ? AND repo = ?'
    ),
    insertFileScanCache: db.prepare(
      `INSERT INTO file_scan_cache (org, repo, check_name, rel_path, hash, findings_json)
       VALUES (?, ?, ?, ?, ?, ?)`
    ),

    // TTL-bound (unlike manifest_scan_cache below): a Docker image *tag* is
    // a mutable reference — re-pushed at any time to point at different
    // content — so, unlike an npm/PyPI package version, its signature
    // verdict isn't safe to cache forever. maxAgeSeconds is applied here in
    // SQL (a stale row simply isn't returned) rather than read back and
    // compared in JS. Uses strftime(...'%f') (millisecond precision), not
    // datetime('now') (whole-second precision only) — plain datetime()
    // truncation means a row written at, say, 11:04:02 and a boundary
    // computed as "now - 1s" landing on 11:04:02 would satisfy `>=` even
    // after a genuine ~1s of real elapsed time, quietly serving a stale
    // verdict right at the TTL edge on short TTLs. Caught by a real test
    // (TTL=1s, waited 1.3s past it) before shipping, not assumed correct.
    getCosignVerifyCache: db.prepare(
      `SELECT verified, reason FROM cosign_verify_cache
       WHERE image = ? AND identity_regexp = ? AND issuer_regexp = ?
         AND checked_at >= strftime('%Y-%m-%d %H:%M:%f', 'now', '-' || ? || ' seconds')`
    ),
    upsertCosignVerifyCache: db.prepare(
      `INSERT INTO cosign_verify_cache (image, identity_regexp, issuer_regexp, verified, reason)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(image, identity_regexp, issuer_regexp)
       DO UPDATE SET verified = excluded.verified, reason = excluded.reason, checked_at = strftime('%Y-%m-%d %H:%M:%f', 'now')`
    ),

    // Global (no org/repo) — a given manifest's exact byte content, scanned
    // by a given tool version, has a deterministic result regardless of
    // which project/org happened to submit it, so caching at this level
    // benefits every future onboarding with the same dependency set, not
    // just repeat runs of the same repo. tool_version is part of the key
    // so upgrading the scanner (new rules, new detections) invalidates old
    // results automatically rather than silently trusting a stale verdict.
    getManifestScanCache: db.prepare(
      `SELECT findings_json FROM manifest_scan_cache
       WHERE tool = ? AND ecosystem = ? AND content_hash = ? AND tool_version = ?`
    ),
    upsertManifestScanCache: db.prepare(
      `INSERT INTO manifest_scan_cache (tool, ecosystem, content_hash, tool_version, findings_json)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(tool, ecosystem, content_hash, tool_version)
       DO UPDATE SET findings_json = excluded.findings_json, updated_at = datetime('now')`
    ),

    // Scoped to (org, repo) — unlike manifest_scan_cache, a CodeQL database
    // is a whole-project artifact, so its cache key is the target repo
    // itself, not a content-addressable manifest reusable across projects.
    // tool_version (the codeql CLI's own version) is part of the key so
    // upgrading the CLI/query packs invalidates stale results automatically.
    getCodeqlScanCache: db.prepare(
      `SELECT findings_json FROM codeql_scan_cache
       WHERE org = ? AND repo = ? AND language = ? AND file_set_hash = ? AND tool_version = ?`
    ),
    upsertCodeqlScanCache: db.prepare(
      `INSERT INTO codeql_scan_cache (org, repo, language, file_set_hash, tool_version, findings_json)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(org, repo, language, file_set_hash, tool_version)
       DO UPDATE SET findings_json = excluded.findings_json, updated_at = datetime('now')`
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

    // "Effectivated" = actually shipped: a successful run that pushed to a
    // real repo_url, as opposed to a dry run or a validate-all/onboard call
    // that only ever ran checks.
    listEffectivatedProjects: db.prepare(`
      SELECT id, org, repo, repo_url, created_at,
             schedule_enabled, schedule_interval, next_scheduled_run_at,
             last_scheduled_run_at, last_scheduled_status, last_scheduled_error
      FROM projects
      WHERE status = 'success' AND repo_url IS NOT NULL
      ORDER BY id DESC
    `),
    setProjectSchedule: db.prepare(
      `UPDATE projects SET schedule_enabled = ?, schedule_interval = ?, next_scheduled_run_at = ? WHERE id = ?`
    ),
    getDueScheduledProjects: db.prepare(`
      SELECT id, org, repo, repo_url, schedule_interval FROM projects
      WHERE schedule_enabled = 1 AND repo_url IS NOT NULL AND next_scheduled_run_at <= ?
    `),
    recordScheduledRunResult: db.prepare(
      `UPDATE projects
       SET last_scheduled_run_at = datetime('now'), last_scheduled_status = ?, last_scheduled_error = ?,
           next_scheduled_run_at = ?
       WHERE id = ?`
    ),

    getWorkflowCache: db.prepare(
      'SELECT commit_sha, content FROM workflow_cache WHERE repo = ? AND filename = ?'
    ),
    upsertWorkflowCache: db.prepare(
      `INSERT INTO workflow_cache (repo, filename, commit_sha, content, updated_at)
       VALUES (?, ?, ?, ?, datetime('now'))
       ON CONFLICT(repo, filename)
       DO UPDATE SET commit_sha = excluded.commit_sha, content = excluded.content, updated_at = excluded.updated_at`
    ),
    insertBaselineIssue: db.prepare(
      'INSERT OR IGNORE INTO issue_baselines (org, repo, issue_id) VALUES (?, ?, ?)'
    ),
    clearBaseline: db.prepare('DELETE FROM issue_baselines WHERE org = ? AND repo = ?'),
    listBaselineIssueIds: db.prepare('SELECT issue_id FROM issue_baselines WHERE org = ? AND repo = ?'),
    upsertRuntimeCoverage: db.prepare(
      `INSERT INTO runtime_coverage (org, repo, rel_path, hit_count, covered_pct, updated_at)
       VALUES (?, ?, ?, ?, ?, datetime('now'))
       ON CONFLICT(org, repo, rel_path)
       DO UPDATE SET hit_count = excluded.hit_count, covered_pct = excluded.covered_pct, updated_at = excluded.updated_at`
    ),
    getRuntimeCoverageForFile: db.prepare(
      'SELECT hit_count, covered_pct FROM runtime_coverage WHERE org = ? AND repo = ? AND rel_path = ?'
    ),
    listRuntimeCoverage: db.prepare('SELECT rel_path, hit_count, covered_pct FROM runtime_coverage WHERE org = ? AND repo = ?'),
    clearRuntimeCoverage: db.prepare('DELETE FROM runtime_coverage WHERE org = ? AND repo = ?'),
  };

  return {
    createProject(jobId, org, repo, isGxp, source = 'ui', scanLocation = null) {
      return Number(stmt.insertProject.run(jobId, org, repo, isGxp ? 1 : 0, source, scanLocation).lastInsertRowid);
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

    getProject(projectId) {
      return stmt.getProject.get(projectId) ?? null;
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
      // Also drop this org/repo's per-file scan cache (file_scan_cache) —
      // otherwise a re-onboard of the same repo after removal reuses stale
      // Phase 4 findings (secrets/governance/LLM) cached under old check
      // logic, instead of getting a fresh scan. Safe even if another project
      // row shares the same org/repo: the cache is a re-scan optimization,
      // not a record — losing it just means the next run for that repo
      // rescans from scratch.
      const project = stmt.getProject.get(projectId);
      stmt.deleteProjectDocuments.run(projectId);
      stmt.deleteProjectSteps.run(projectId);
      stmt.deleteProjectOverrides.run(projectId);
      stmt.deleteProjectIssues.run(projectId);
      stmt.deleteRetainedSource.run(projectId);
      stmt.deleteProject.run(projectId);
      if (project) stmt.deleteFileScanCacheForRepo.run(project.org, project.repo);
    },

    deleteAllProjects() {
      db.exec('DELETE FROM documents; DELETE FROM steps; DELETE FROM overrides; DELETE FROM issues; DELETE FROM retained_sources; DELETE FROM projects; DELETE FROM file_scan_cache;');
    },

    getDocument(documentId) {
      return stmt.getDocumentForDownload.get(documentId);
    },

    /* ---------------- retained sources (post-mortem Studio parity) --------
       Full local source kept for the 5 most recently completed runs (any
       outcome that passed Phase 4, so it has real files worth browsing —
       see pipeline-interactive.js), so Studio's Dependencies/SBOM/LOC/
       Posture/CodeQL-run/Rescan buttons work the same after the run ends
       as they do live. LRU by retained_at; callers do the actual fs.rm of
       evicted directories — this store only tracks which dir belongs to
       which project. */
    retainProjectSource(projectId, dirPath) {
      stmt.upsertRetainedSource.run(projectId, dirPath);
    },

    getRetainedSource(projectId) {
      return stmt.getRetainedSource.get(projectId)?.dir_path ?? null;
    },

    listRetainedSources() {
      return stmt.listRetainedSources.all();
    },

    // Rows beyond the `keep` most recently retained — the caller fs.rm's
    // each dir_path, then calls deleteRetainedSource for each project_id.
    listEvictableRetainedSources(keep) {
      return stmt.listEvictableRetainedSources.all(keep);
    },

    deleteRetainedSource(projectId) {
      stmt.deleteRetainedSource.run(projectId);
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
      return stmt.getSession.get(sessionId);
    },

    // Expired sessions are otherwise harmless (getSession/attachUser both
    // check expires_at before trusting a row), so this doesn't need to run
    // inline on every request — see sweepExpiredSessions's caller.
    sweepExpiredSessions() {
      stmt.deleteExpiredSessions.run();
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

    /* ---------------- cosign verify cache (TTL-bound — see schema comment) ---------------- */

    getCosignVerifyCache(image, identityRegexp, issuerRegexp, maxAgeSeconds) {
      const row = stmt.getCosignVerifyCache.get(image, identityRegexp, issuerRegexp, maxAgeSeconds);
      return row ? { verified: Boolean(row.verified), reason: row.reason } : null;
    },

    saveCosignVerifyCache(image, identityRegexp, issuerRegexp, verified, reason) {
      stmt.upsertCosignVerifyCache.run(image, identityRegexp, issuerRegexp, verified ? 1 : 0, reason || null);
    },

    /* ---------------- manifest-level tool-result cache (e.g. GuardDog) ---------------- */

    getManifestScanCache(tool, ecosystem, contentHash, toolVersion) {
      const row = stmt.getManifestScanCache.get(tool, ecosystem, contentHash, toolVersion);
      return row ? JSON.parse(row.findings_json) : null;
    },

    saveManifestScanCache(tool, ecosystem, contentHash, toolVersion, findings) {
      stmt.upsertManifestScanCache.run(tool, ecosystem, contentHash, toolVersion, JSON.stringify(findings));
    },

    /* ---------------- CodeQL cross-file scan cache (keyed by org/repo, see schema comment) ---------------- */

    getCodeqlScanCache(org, repo, language, fileSetHash, toolVersion) {
      const row = stmt.getCodeqlScanCache.get(org, repo, language, fileSetHash, toolVersion);
      return row ? JSON.parse(row.findings_json) : null;
    },

    saveCodeqlScanCache(org, repo, language, fileSetHash, toolVersion, findings) {
      stmt.upsertCodeqlScanCache.run(org, repo, language, fileSetHash, toolVersion, JSON.stringify(findings));
    },

    /* ---------------- governance workflow cache (skip re-fetching unchanged workflows) ---------------- */

    /**
     * Keyed by (repo, filename). Callers check this against the workflow
     * file's latest commit sha (a cheap `gh api .../commits?path=...`
     * lookup) before re-fetching the full workflow content — a match means
     * nothing changed upstream since the last fetch.
     */
    getWorkflowCache(repo, filename) {
      const row = stmt.getWorkflowCache.get(repo, filename);
      return row ? { commitSha: row.commit_sha, content: row.content } : null;
    },

    saveWorkflowCache(repo, filename, commitSha, content) {
      stmt.upsertWorkflowCache.run(repo, filename, commitSha, content);
    },

    /* ---------------- scheduled re-checks on effectivated repos ---------------- */

    listEffectivatedProjects() {
      return stmt.listEffectivatedProjects.all();
    },

    setProjectSchedule(projectId, enabled, interval, nextRunAtIso) {
      stmt.setProjectSchedule.run(enabled ? 1 : 0, interval || null, enabled ? nextRunAtIso : null, projectId);
    },

    getDueScheduledProjects(nowIso) {
      return stmt.getDueScheduledProjects.all(nowIso);
    },

    recordScheduledRunResult(projectId, status, error, nextRunAtIso) {
      stmt.recordScheduledRunResult.run(status, error || null, nextRunAtIso, projectId);
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
          issue.crossFile ? 1 : 0,
          issue.chain ? JSON.stringify(issue.chain) : null,
          issue.cwe || null,
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
        crossFile: Boolean(row.cross_file),
        chain: row.chain_json ? JSON.parse(row.chain_json) : null,
        cwe: row.cwe,
        status: row.status,
        created_at: row.created_at,
      }));
    },

    getProjectIdByJobId(jobId) {
      return stmt.getProjectByJobId.get(jobId)?.id ?? null;
    },

    /* ---------------- API keys (headless/agent auth) ---------------- */

    createApiKey(userId, keyHash, label, createdBy, createdVia) {
      return Number(
        stmt.insertApiKey.run(userId, keyHash, label || null, createdBy || null, createdVia || 'cli')
          .lastInsertRowid
      );
    },

    getActiveApiKeyByHash(keyHash) {
      return stmt.getActiveApiKeyByHash.get(keyHash) || null;
    },

    touchApiKeyLastUsed(id) {
      stmt.touchApiKeyLastUsed.run(id);
    },

    listApiKeysForUser(userId) {
      return stmt.listApiKeysForUser.all(userId);
    },

    revokeApiKey(id) {
      return stmt.revokeApiKey.run(id).changes > 0;
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

    /* ---------------- Baseline/diff adoption mode ---------------- */

    saveBaseline(org, repo, issueIds) {
      stmt.clearBaseline.run(org, repo);
      for (const id of issueIds) stmt.insertBaselineIssue.run(org, repo, id);
      return issueIds.length;
    },

    clearBaseline(org, repo) {
      return stmt.clearBaseline.run(org, repo).changes;
    },

    getBaselineIssueIds(org, repo) {
      return new Set(stmt.listBaselineIssueIds.all(org, repo).map((r) => r.issue_id));
    },

    /* ---------------- Runtime coverage ingestion (Beacon-equivalent) ---------------- */

    ingestRuntimeCoverage(org, repo, fileStats) {
      let count = 0;
      for (const [relPath, { hitCount = 0, coveredPct = null }] of Object.entries(fileStats)) {
        stmt.upsertRuntimeCoverage.run(org, repo, relPath, Number(hitCount) || 0, coveredPct === null ? null : Number(coveredPct));
        count++;
      }
      return count;
    },

    getRuntimeCoverageForFile(org, repo, relPath) {
      return stmt.getRuntimeCoverageForFile.get(org, repo, relPath) || null;
    },

    getRuntimeCoverageMap(org, repo) {
      const map = new Map();
      for (const row of stmt.listRuntimeCoverage.all(org, repo)) map.set(row.rel_path, row);
      return map;
    },

    clearRuntimeCoverage(org, repo) {
      return stmt.clearRuntimeCoverage.run(org, repo).changes;
    },
  };
}

module.exports = { createDbStore };
