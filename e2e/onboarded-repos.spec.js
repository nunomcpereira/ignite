'use strict';

/**
 * End-to-end proof for the "Onboarded Repos" nav view: one row per distinct
 * (org, repo) Ignite has onboarded, showing the latest run's license-problem
 * and open-findings counts, every acknowledgment recorded for that repo
 * (downloadable), and every PR Ignite has opened for it (onboarding PR +
 * fix-PRs), linkable straight to GitHub.
 *
 * Unlike the other e2e specs in this directory, this one runs against an
 * isolated database (IGNITE_DB_PATH into a throwaway temp dir) rather than
 * the repo-root ignite.db — that file is this developer's real, live
 * onboarding history (including this very repo's own dogfooded pre-push
 * scans), and this spec seeds synthetic rows directly via the sqlite3 CLI
 * rather than driving a real GitHub onboarding flow (too slow, and would
 * require real GitHub credentials) — polluting the real db with fake
 * "acme/widgets" rows would be a real regression, not just untidy.
 */

const { test, expect } = require('@playwright/test');
const { spawn, execFileSync } = require('child_process');
const fsp = require('fs/promises');
const path = require('path');
const os = require('os');

const PORT = 3913;
const BASE = `http://localhost:${PORT}`;

let serverProc;
let workDir;
let dbPath;

async function waitForServer(url, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`Server at ${url} did not come up within ${timeoutMs}ms`);
}

test.beforeAll(async () => {
  workDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'ignite-e2e-onboarded-repos-'));
  dbPath = path.join(workDir, 'ignite.db');

  serverProc = spawn(path.resolve(__dirname, '../rust/target/release/ignite-server'), [], {
    cwd: path.resolve(__dirname, '..'),
    env: { ...process.env, PORT: String(PORT), IGNITE_DB_PATH: dbPath },
    stdio: 'ignore',
  });
  await waitForServer(BASE);

  // Seed two repos directly against the schema the server just created on
  // first connection: one with real findings/acknowledgments/PRs to exercise
  // every table cell, one clean to prove a repo with nothing still renders
  // (zero counts, "—" placeholders) instead of breaking the row.
  const seedSql = `
    INSERT INTO projects (id, job_id, org, repo, status, repo_url, pr_url, created_at, finished_at)
    VALUES (1, 'seed-job-1', 'acme', 'widgets', 'success', 'https://github.com/acme/widgets', 'https://github.com/acme/widgets/pull/1', '2026-01-01 10:00:00', '2026-01-01 10:05:00');
    INSERT INTO pull_requests (project_id, kind, url, created_at)
    VALUES (1, 'onboarding', 'https://github.com/acme/widgets/pull/1', '2026-01-01 10:05:00');
    INSERT INTO issues (project_id, issue_id, category, severity, summary, file, line, status)
    VALUES
      (1, 'license-compliance::pom.xml::1', 'license-compliance', 'error', 'Commercial dependency (aspose-cells)', 'pom.xml', 1, 'open'),
      (1, 'secret::app.py::4', 'secret', 'error', 'Hardcoded API key', 'app.py', 4, 'open');
    INSERT INTO overrides (project_id, job_id, phase, issue_id, category, severity, summary, file, line, justification, actor_email, actor_name, email_sent, created_at)
    VALUES (1, 'seed-job-1', 3, 'license-compliance::pom.xml::1', 'license-compliance', 'error', 'Commercial dependency (aspose-cells)', 'pom.xml', 1, 'Reviewed and approved by legal for internal use only.', 'dev@acme.example', 'Dev Person', 1, '2026-01-01 10:03:00');
    INSERT INTO pull_requests (project_id, kind, url, branch, files_changed, created_at)
    VALUES (1, 'fix-pr', 'https://github.com/acme/widgets/pull/2', 'ignite/fix-issues/seed-job-1', 2, '2026-01-01 10:10:00');

    INSERT INTO projects (id, job_id, org, repo, status, repo_url, pr_url, created_at, finished_at)
    VALUES (2, 'seed-job-2', 'acme', 'clean-service', 'success', 'https://github.com/acme/clean-service', 'https://github.com/acme/clean-service/pull/1', '2026-01-02 09:00:00', '2026-01-02 09:05:00');
    INSERT INTO pull_requests (project_id, kind, url, created_at)
    VALUES (2, 'onboarding', 'https://github.com/acme/clean-service/pull/1', '2026-01-02 09:05:00');
  `;
  execFileSync('sqlite3', [dbPath], { input: seedSql });
});

test.afterAll(async () => {
  if (serverProc) serverProc.kill();
  if (workDir) await fsp.rm(workDir, { recursive: true, force: true }).catch(() => {});
});

test('nav switch shows the table with every seeded column populated', async ({ page }) => {
  await page.goto(BASE);
  await expect(page.locator('#dashboardView')).toBeVisible();
  await expect(page.locator('#onboardedReposView')).toBeHidden();

  await page.click('#onboardedReposNavBtn');
  await expect(page.locator('#onboardedReposView')).toBeVisible();
  await expect(page.locator('#dashboardView')).toBeHidden();
  await expect(page.locator('#onboardedReposNavBtn')).toHaveClass(/bg-brand-50/);
  await expect(page.locator('#dashboardNavBtn')).not.toHaveClass(/bg-brand-50/);

  const rows = page.locator('#onboardedReposTableBody tr');
  await expect(rows).toHaveCount(2);

  // acme/widgets — the repo with real data, most recent scan so it sorts first.
  const widgetsRow = rows.filter({ hasText: 'widgets' });
  await expect(widgetsRow).toContainText('acme');
  await expect(widgetsRow.locator('td').nth(2)).toContainText('1'); // license problems
  await expect(widgetsRow.locator('td').nth(3)).toContainText('2'); // total findings
  await expect(widgetsRow.locator('a[href="https://github.com/acme/widgets"]')).toBeVisible();
  await expect(widgetsRow.locator('a[href="https://github.com/acme/widgets/pull/1"]')).toContainText('#1');
  await expect(widgetsRow.locator('a[href="https://github.com/acme/widgets/pull/2"]')).toContainText('#2');
  await expect(widgetsRow.locator('.onboarded-repo-download-acks')).toContainText('1');

  // acme/clean-service — nothing flagged, no fix-PR: zero counts, "—" for acknowledgments.
  const cleanRow = rows.filter({ hasText: 'clean-service' });
  await expect(cleanRow.locator('td').nth(2)).toContainText('0');
  await expect(cleanRow.locator('td').nth(3)).toContainText('0');
  await expect(cleanRow.locator('.onboarded-repo-download-acks')).toHaveCount(0);
  await expect(cleanRow.locator('a[href="https://github.com/acme/clean-service/pull/1"]')).toBeVisible();

  await page.click('#dashboardNavBtn');
  await expect(page.locator('#dashboardView')).toBeVisible();
  await expect(page.locator('#onboardedReposView')).toBeHidden();
});

test('downloading acknowledgments produces a file naming the real justification', async ({ page }) => {
  await page.goto(BASE);
  await page.click('#onboardedReposNavBtn');
  const widgetsRow = page.locator('#onboardedReposTableBody tr').filter({ hasText: 'widgets' });

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    widgetsRow.locator('.onboarded-repo-download-acks').click(),
  ]);
  expect(download.suggestedFilename()).toBe('acme-widgets-acknowledgments.md');
  const filePath = await download.path();
  const content = await fsp.readFile(filePath, 'utf8');
  expect(content).toContain('acme/widgets');
  expect(content).toContain('Reviewed and approved by legal for internal use only.');
  expect(content).toContain('license-compliance::pom.xml::1');
});
