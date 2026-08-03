'use strict';

/**
 * End-to-end proof that license compliance runs automatically as part of the
 * pipeline (Phase 3) and its findings surface as regular, file-level issues:
 *  - the final review gate lists license-compliance issues alongside
 *    secret/AI-governance ones, with no extra button click;
 *  - Ignite Studio's file tree badges the manifests (pom.xml, package.json…)
 *    and LICENSE files that carry the findings;
 *  - opening such a file shows its license issues in the issue panel.
 *
 * Uses the vulnerable-app-multilang fixture, which ships commercial
 * dependencies (aspose-cells, ag-grid-enterprise, gurobipy, noxtls, unipdf)
 * and per-module commercial LICENSE files with a "Licensee:" field. The
 * fixture also has raw .env files, which makes Phase 3 FAIL — deliberately
 * kept, to prove license findings survive a phase-3 failure (they're
 * collected before the throwing checks).
 */

const { test, expect } = require('@playwright/test');
const { spawn, execFileSync } = require('child_process');
const fsp = require('fs/promises');
const path = require('path');
const os = require('os');

const PORT = 3911;
const BASE = `http://localhost:${PORT}`;
const FIXTURE = path.resolve(__dirname, '../../aigovernancedevops/vulnerable-app-multilang');

let serverProc;
let workDir;
let zipPath;

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
  workDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'ignite-e2e-'));
  zipPath = path.join(workDir, 'fixture.zip');
  execFileSync('zip', ['-r', zipPath, '.', '-x', '.DS_Store', '-x', '*/.DS_Store'], {
    cwd: FIXTURE,
    stdio: 'ignore',
  });

  serverProc = spawn('node', ['server.js'], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(PORT),
      // Point the LLM deep-scan at a dead port so it soft-skips — this test
      // is about license compliance, not the LLM review, and skipping keeps
      // the run fast and deterministic.
      LLM_SCAN_URL: 'http://127.0.0.1:9',
      LLM_SCAN_TRUSTED_ORIGINS: 'http://127.0.0.1:9',
      // This test doesn't need the MCP HTTP server, and spawning one would
      // otherwise fight over the same default port with any other Ignite
      // instance (or e2e run) already using it.
      MCP_AUTOSTART: 'false',
    },
    stdio: 'ignore',
  });
  await waitForServer(BASE);
});

test.afterAll(async () => {
  if (serverProc) serverProc.kill();
  if (workDir) await fsp.rm(workDir, { recursive: true, force: true }).catch(() => {});
});

test('license findings appear automatically in review gate and Studio file tree', async ({ page }) => {
  await page.goto(BASE);

  // --- Upload the fixture ZIP and start a dry run ---
  await page.locator('#fileInput').setInputFiles(zipPath);
  await page.locator('#orgInput').fill('e2e-org');
  await page.locator('#repoInput').fill('e2e-license-check');
  await expect(page.locator('#dryRunInput')).toBeChecked();
  await expect(page.locator('#startBtn')).toBeEnabled();
  await page.locator('#startBtn').click();

  // --- The run pauses at the final review gate with license issues listed,
  // without any Dependencies-button click ---
  const reviewModal = page.locator('#reviewModal');
  await expect(reviewModal).toBeVisible({ timeout: 180_000 });
  await expect(reviewModal).toContainText('license-compliance');
  await expect(reviewModal).toContainText('aspose-cells');
  await expect(reviewModal).toContainText('Commercial license agreement');

  // --- Open Ignite Studio from the review gate ---
  await page.locator('#reviewStudioBtn').click();
  await expect(page.locator('#studioView')).toBeVisible();

  // Summary bar counts license-compliance as a first-class category.
  await expect(page.locator('#studioSummaryBar')).toContainText('license-compliance');

  // --- File-level: manifests and LICENSE files carry issue badges in the tree ---
  const treeBtn = (relPath) => page.locator(`.studio-file-btn[data-path="${relPath}"]`);
  for (const flagged of ['java/pom.xml', 'node/package.json', 'go/go.mod', 'java/LICENSE']) {
    await expect(treeBtn(flagged).locator('span.bg-rose-100'), `${flagged} should show an issue badge`).toBeVisible();
  }

  // --- Opening pom.xml lists its license issues in the issue panel. The
  // directly-declared aspose-cells dependency resolves to its actual
  // declaration line (no "line ?") and the editor highlights that line —
  // transitive dependencies ORT also reports (not literally in pom.xml) are
  // expected to keep "line ?", so the assertion is scoped to that one card
  // rather than the whole panel. ---
  await treeBtn('java/pom.xml').click();
  const issuePanel = page.locator('#studioIssuePanel');
  await expect(issuePanel).toContainText('aspose-cells');
  await expect(issuePanel).not.toContainText('No flagged issues');
  const asposeCard = page.locator('.studio-issue-pick', { hasText: 'aspose-cells' });
  await expect(asposeCard).not.toContainText('line ?');
  await expect(asposeCard).toContainText(/line \d+/);
  const highlightedRows = page.locator('#studioCodeWrap .bg-rose-50, #studioCodeWrap .bg-rose-100');
  await expect(highlightedRows.first()).toBeVisible();
  await expect(page.locator('#studioCodeWrap .bg-rose-50, #studioCodeWrap .bg-rose-100', { hasText: 'aspose-cells' }).first()).toBeVisible();

  // --- Opening a commercial LICENSE file shows the Licensee-based finding ---
  await treeBtn('java/LICENSE').click();
  await expect(issuePanel).toContainText('Commercial license agreement');
  await expect(issuePanel).toContainText('Licensee');
});
