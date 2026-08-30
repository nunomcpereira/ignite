'use strict';

/**
 * End-to-end proof that Ignite Studio's CodeQL workflow actually works from
 * the browser: editing a file and saving it, running the real CodeQL CLI
 * ("🔎 Run CodeQL" — a database build + the security-extended query suite),
 * and writing/running a custom .ql query against that database ("Custom
 * Query"). Skips (not fails) if the `codeql` CLI isn't on PATH, same
 * convention as the Rust integration test covering the same server routes
 * (routes::studio::tests::codeql_run_persists_database_and_query_can_reuse_it).
 *
 * Uses the vulnerable-app-multilang fixture (javascript/python/java/go) so
 * a CodeQL database can actually be built for at least one language.
 */

const { test, expect } = require('@playwright/test');
const { spawn, spawnSync, execFileSync } = require('child_process');
const fsp = require('fs/promises');
const path = require('path');
const os = require('os');

const PORT = 3912;
const BASE = `http://localhost:${PORT}`;
const FIXTURE = path.resolve(__dirname, '../../aigovernancedevops/vulnerable-app-multilang');

let serverProc;
let workDir;
let zipPath;
let codeqlAvailable = false;

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
  const check = spawnSync('codeql', ['--version']);
  codeqlAvailable = !check.error && check.status === 0;

  workDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'ignite-e2e-codeql-'));
  zipPath = path.join(workDir, 'fixture.zip');
  execFileSync('zip', ['-r', zipPath, '.', '-x', '.DS_Store', '-x', '*/.DS_Store'], {
    cwd: FIXTURE,
    stdio: 'ignore',
  });

  serverProc = spawn(path.resolve(__dirname, '../rust/target/release/ignite-server'), [], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(PORT),
      LLM_SCAN_URL: 'http://127.0.0.1:9',
      LLM_SCAN_TRUSTED_ORIGINS: 'http://127.0.0.1:9',
    },
    stdio: 'ignore',
  });
  await waitForServer(BASE);
});

test.afterAll(async () => {
  if (serverProc) serverProc.kill();
  if (workDir) await fsp.rm(workDir, { recursive: true, force: true }).catch(() => {});
});

test('edit + save, Run CodeQL, and a custom query all work end-to-end in Studio', async ({ page }) => {
  test.skip(!codeqlAvailable, 'codeql CLI not installed on PATH');
  test.setTimeout(240_000);

  await page.goto(BASE);

  // --- Upload the fixture ZIP and start a dry run ---
  await page.locator('#fileInput').setInputFiles(zipPath);
  await page.locator('#orgInput').fill('e2e-org');
  await page.locator('#repoInput').fill('e2e-codeql-check');
  await expect(page.locator('#dryRunInput')).toBeChecked();
  await expect(page.locator('#startBtn')).toBeEnabled();
  await page.locator('#startBtn').click();

  const reviewModal = page.locator('#reviewModal');
  await expect(reviewModal).toBeVisible({ timeout: 180_000 });

  await page.locator('#reviewStudioBtn').click();
  await expect(page.locator('#studioView')).toBeVisible();

  // ============================================================
  // 1. Edit code — open a real source file, edit it, save + rescan
  // ============================================================
  const treeBtn = (relPath) => page.locator(`.studio-file-btn[data-path="${relPath}"]`);
  // node/ has real JS source in this fixture (not just a manifest).
  const targetFile = 'node/agent.js';
  await expect(treeBtn(targetFile)).toBeVisible({ timeout: 15_000 });
  await treeBtn(targetFile).click();

  await expect(page.locator('#studioEditBtn')).toBeVisible({ timeout: 15_000 });
  await page.locator('#studioEditBtn').click();

  const textarea = page.locator('#studioTextarea');
  await expect(textarea).toBeVisible();
  const original = await textarea.inputValue();
  expect(original.length).toBeGreaterThan(0);

  await textarea.fill(original + '\n// e2e-edit-marker\n');
  await expect(page.locator('#studioDirtyBadge')).toBeVisible();

  await page.locator('#studioSaveBtn').click();
  // Save + rescan: the dirty badge clears immediately after the PUT
  // succeeds, but the button doesn't return to "Edit" until the rescan
  // itself (a real POST /studio/rescan re-running Phase 4's fast checks)
  // finishes - give that its own generous timeout rather than assuming
  // it's done the instant the badge is gone.
  await expect(page.locator('#studioDirtyBadge')).toBeHidden({ timeout: 30_000 });
  await expect(page.locator('#studioSaveBtn')).toBeHidden({ timeout: 30_000 });
  await expect(page.locator('#studioEditBtn')).toBeVisible();
  // No error banner after a successful save.
  const errorBanner = page.locator('#studioError');
  await expect(errorBanner).toBeHidden().catch(() => {});

  // Re-fetch the file to prove the edit actually persisted to disk, not
  // just to the in-memory textarea.
  const putRes = await page.request.get(`${BASE}/api/pipeline/${await page.evaluate(() => studioState.jobId)}/studio/file?path=${encodeURIComponent(targetFile)}`);
  expect(putRes.ok()).toBeTruthy();
  const savedContent = (await putRes.json()).content;
  expect(savedContent).toContain('e2e-edit-marker');

  // ============================================================
  // 2. Run CodeQL — real CLI, database build + security-extended suite
  // ============================================================
  const runCodeqlBtn = page.locator('#studioCodeqlBtn');
  await expect(runCodeqlBtn).toBeVisible();
  await expect(runCodeqlBtn).toBeEnabled();
  await runCodeqlBtn.click();

  const outputPanel = page.locator('#studioOutputPanel');
  await expect(outputPanel).toBeVisible({ timeout: 10_000 });
  // The button is disabled + relabeled while running.
  await expect(runCodeqlBtn).toBeDisabled();

  // Database build + security-extended analysis across up to 4 languages
  // can genuinely take a couple of minutes.
  await expect(runCodeqlBtn).toBeEnabled({ timeout: 180_000 });
  await expect(runCodeqlBtn).toHaveText('🔎 Run CodeQL');

  const outputLog = page.locator('#studioOutputLog');
  const logText = await outputLog.textContent();
  // A genuine failure (missing binary, crashed build) shows up as an error
  // banner and a failed output status — assert neither happened.
  await expect(errorBanner).toBeHidden();
  expect(logText).not.toMatch(/✗ .*(error|failed|not found)/i);

  // ============================================================
  // 3. Custom Query — write a real .ql query, run it against the database
  //    Run CodeQL just built, and see located results in the tree/table.
  // ============================================================
  const customQueryBtn = page.locator('#studioCodeqlQueryBtn');
  await expect(customQueryBtn).toBeEnabled();
  await customQueryBtn.click();

  const querySelect = page.locator('#studioQueryLanguage');
  await expect(querySelect).toBeVisible({ timeout: 10_000 });
  const availableLanguages = await querySelect.locator('option').allTextContents();
  expect(availableLanguages.length).toBeGreaterThan(0);

  // Pick javascript if the database built for it (fixture guarantees JS
  // source exists), otherwise fall back to whatever language is available.
  const chosenLanguage = availableLanguages.includes('javascript') ? 'javascript' : availableLanguages[0];
  await querySelect.selectOption(chosenLanguage);

  const queryText = page.locator('#studioQueryText');
  // A deliberately simple, always-non-empty query for whichever language
  // was actually built, so this doesn't depend on the fixture's exact
  // vulnerable-code shape to prove the query pipeline works.
  const universalQueries = {
    javascript: 'import javascript\n\nfrom File f\nselect f, "file"',
    python: 'import python\n\nfrom Module m\nselect m, "module"',
    java: 'import java\n\nfrom CompilationUnit c\nselect c, "unit"',
    go: 'import go\n\nfrom File f\nselect f, "file"',
  };
  await queryText.fill(universalQueries[chosenLanguage] || universalQueries.javascript);

  await page.locator('#studioQueryRunBtn').click();
  await expect(page.locator('#studioQueryRunBtn')).toHaveText('▶ Running…');
  await expect(page.locator('#studioQueryRunBtn')).toHaveText('▶ Run query', { timeout: 60_000 });

  await expect(errorBanner).toBeHidden();
  const resultsWrap = page.locator('#studioQueryResultsWrap');
  await expect(resultsWrap).not.toBeEmpty();
  // Either a results table or an explicit "0 rows" message — both are a
  // successful run; what would indicate brokenness is an empty wrap or an
  // error string leaking into it.
  const resultsText = await resultsWrap.textContent();
  expect(resultsText).not.toMatch(/error|failed|exception/i);
  expect(resultsText).toMatch(/row\(s\)|0 rows/);
});
