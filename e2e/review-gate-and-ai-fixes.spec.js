'use strict';

/**
 * End-to-end proof for three fixes made together (see MIGRATION_STATUS.md /
 * session history around 2026-09-04):
 *
 *  1. The review-gate modal's Esc/✕/"Stop pipeline" path no longer requires
 *     an authenticated session for a bare decline (`proceed:false`, no
 *     overrides) — previously this always 401'd once a session had
 *     expired, permanently trapping the modal open with no way out.
 *  2. "Generate suggested fix" in Ignite Studio's issue panel no longer
 *     400s with "A code snippet is required to suggest a fix." for
 *     license-compliance / dependency-vulnerability findings (and several
 *     Phase 4 categories) that never had a snippet attached in the first
 *     place.
 *  3. `aiAutoJustify` actually runs when configured: an eligible finding
 *     shows up in Studio's issue panel already overridden, badged
 *     "✨ AI-justified", with the model's own justification text.
 *
 * This suite never authenticates (matches the real bug: a caller with no
 * session at all) and points ignite-server's LLM config at a fake local
 * "local"-provider HTTP stub (helpers.js's startFakeLocalLlm) instead of a
 * real LLM, so it's deterministic and needs nothing installed.
 */

const { test, expect } = require('@playwright/test');
const { spawn, execFileSync } = require('child_process');
const fsp = require('fs/promises');
const path = require('path');
const os = require('os');
const { startFakeLocalLlm } = require('./helpers');

const PORT = 3912;
const BASE = `http://localhost:${PORT}`;
const FIXTURE = path.resolve(__dirname, '../../aigovernancedevops/vulnerable-app-multilang');

let serverProc;
let llmServer;
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
  workDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'ignite-e2e-review-gate-'));
  zipPath = path.join(workDir, 'fixture.zip');
  execFileSync('zip', ['-r', zipPath, '.', '-x', '.DS_Store', '-x', '*/.DS_Store'], {
    cwd: FIXTURE,
    stdio: 'ignore',
  });

  llmServer = await startFakeLocalLlm();
  const llmPort = llmServer.address().port;

  serverProc = spawn(path.resolve(__dirname, '../rust/target/release/ignite-server'), [], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(PORT),
      LLM_PROVIDER: 'local',
      LLM_SCAN_URL: `http://127.0.0.1:${llmPort}`,
      LLM_SCAN_TRUSTED_ORIGINS: `http://127.0.0.1:${llmPort}`,
      AI_AUTO_JUSTIFY_ENABLED: 'true',
      AI_AUTO_JUSTIFY_CATEGORIES: 'license-compliance',
    },
    stdio: 'ignore',
  });
  await waitForServer(BASE);
});

test.afterAll(async () => {
  if (serverProc) serverProc.kill();
  if (llmServer) await new Promise((r) => llmServer.close(r));
  if (workDir) await fsp.rm(workDir, { recursive: true, force: true }).catch(() => {});
});

test('review gate: Esc closes the modal and the pipeline finishes, fully unauthenticated', async ({ page }) => {
  await page.goto(BASE);

  await page.locator('#fileInput').setInputFiles(zipPath);
  await page.locator('#orgInput').fill('e2e-org');
  await page.locator('#repoInput').fill(`e2e-review-gate-esc-${Date.now()}`);
  await expect(page.locator('#dryRunInput')).toBeChecked();
  await expect(page.locator('#startBtn')).toBeEnabled();
  await page.locator('#startBtn').click();

  const reviewModal = page.locator('#reviewModal');
  await expect(reviewModal).toBeVisible({ timeout: 180_000 });

  // Esc used to send the exact same decline request Stop/✕ send, which the
  // server unconditionally 401'd once unauthenticated — leaving this modal
  // open forever with only an "Authentication required." error and no way
  // out. It must now actually close.
  await page.keyboard.press('Escape');
  await expect(reviewModal).toBeHidden({ timeout: 15_000 });
  await expect(page.locator('#reviewError')).not.toContainText('Authentication required');

  // The pipeline must have actually resolved (declined), not just hidden
  // the modal client-side while the server still thinks it's paused.
  await expect(page.locator('#startBtn')).toBeEnabled({ timeout: 30_000 });
});

test('Studio: suggested fix has no snippet error, and an aiAutoJustify finding shows its AI justification', async ({ page }) => {
  await page.goto(BASE);

  // A unique repo name per run matters here: `get_carry_forward_overrides`
  // matches on exact (org, repo, issueId) against the persistent
  // ignite.db, so reusing a repo name across repeated local/CI runs would
  // have this finding read as "↻ Carried forward from a previous scan"
  // (still correctly overridden, just a different actor label) instead of
  // the fresh "✨ AI-justified" this test is actually proving.
  await page.locator('#fileInput').setInputFiles(zipPath);
  await page.locator('#orgInput').fill('e2e-org');
  await page.locator('#repoInput').fill(`e2e-review-gate-studio-${Date.now()}`);
  await page.locator('#startBtn').click();

  const reviewModal = page.locator('#reviewModal');
  await expect(reviewModal).toBeVisible({ timeout: 180_000 });
  await expect(reviewModal).toContainText('aspose-cells');

  // Open Ignite Studio directly on the aspose-cells license-compliance
  // finding (a manifest-line finding — pom.xml:<line> — of the exact kind
  // that never carried a snippet before the phase4-orchestrator fix).
  const asposeCard = page.locator('div.border.border-slate-200.rounded-lg.p-3', { hasText: 'aspose-cells' }).first();
  await asposeCard.locator('.open-studio-btn').click();

  const issuePanel = page.locator('#studioIssuePanel');
  await expect(page.locator('#studioView')).toBeVisible();
  await expect(issuePanel).toContainText('aspose-cells');

  // --- Proof 1: aiAutoJustify actually ran and is visible in Studio ---
  // license-compliance is the one configured eligible category, and the
  // fake LLM justifies every eligible finding it's offered — so this
  // finding must already read as overridden, attributed to the AI actor,
  // with the model's own justification text.
  await expect(issuePanel).toContainText('AI-justified');
  await expect(issuePanel).toContainText('Fake-LLM (e2e)');
  await page.screenshot({ path: 'e2e/screenshots/ai-auto-justify.png', fullPage: true });

  // --- Proof 2: "Generate suggested fix" no longer 400s on this finding ---
  await page.getByRole('button', { name: 'Generate suggested fix' }).click();
  await expect(issuePanel).not.toContainText('A code snippet is required', { timeout: 15_000 });
  await expect(issuePanel).toContainText('Fake-LLM (e2e) test fix', { timeout: 15_000 });
  await page.screenshot({ path: 'e2e/screenshots/suggested-fix.png', fullPage: true });
});
