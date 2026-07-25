'use strict';

/**
 * Proves the ORT + licensee integrations end-to-end in the UI: the server is
 * spawned with fake `ort` and `licensee` CLIs prepended to PATH (see
 * test/helpers.js's makeFakeLicenseTools), so Ignite Studio's Dependencies
 * view must report the ORT engine, show licensee's project-license verdict,
 * and classify the ORT-declared commercial package — proving the real
 * tool-invocation and parsing paths, not the built-in fallback.
 */

const { test, expect } = require('@playwright/test');
const { spawn, execFileSync } = require('child_process');
const fsp = require('fs/promises');
const path = require('path');
const os = require('os');

const { makeFakeLicenseTools } = require('../test/helpers');

const PORT = 3912;
const BASE = `http://localhost:${PORT}`;
const FIXTURE = path.resolve(__dirname, '../../aigovernancedevops/vulnerable-app-multilang');

let serverProc;
let workDir;
let zipPath;
let fakeBinDir;

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
  workDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'ignite-e2e-ort-'));
  zipPath = path.join(workDir, 'fixture.zip');
  execFileSync('zip', ['-r', zipPath, '.', '-x', '.DS_Store', '-x', '*/.DS_Store'], {
    cwd: FIXTURE,
    stdio: 'ignore',
  });

  fakeBinDir = await makeFakeLicenseTools({
    ortPackages: [
      { package: { id: 'NPM::ag-grid-enterprise:31.3.2', declared_licenses: ['Commercial'] } },
      { package: { id: 'Maven:com.aspose:aspose-cells:25.3', declared_licenses: ['LicenseRef-Proprietary'] } },
      { package: { id: 'NPM::express:4.21.2', declared_licenses: ['MIT'] } },
    ],
    licenseeJson: { licenses: [{ spdx_id: 'MIT', similarity: 99 }] },
  });

  serverProc = spawn('node', ['server.js'], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...process.env,
      PATH: `${fakeBinDir}:${process.env.PATH}`,
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
  for (const dir of [workDir, fakeBinDir]) {
    if (dir) await fsp.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
});

test('Studio Dependencies view reports the ORT engine and licensee project license', async ({ page }) => {
  await page.goto(BASE);

  await page.locator('#fileInput').setInputFiles(zipPath);
  await page.locator('#orgInput').fill('e2e-org');
  await page.locator('#repoInput').fill('e2e-ort-licensee');
  await expect(page.locator('#startBtn')).toBeEnabled();
  await page.locator('#startBtn').click();

  const reviewModal = page.locator('#reviewModal');
  await expect(reviewModal).toBeVisible({ timeout: 180_000 });
  // ORT-derived findings gate the run like any other issue.
  await expect(reviewModal).toContainText('license-compliance');
  await expect(reviewModal).toContainText('ag-grid-enterprise');

  await page.locator('#reviewStudioBtn').click();
  await expect(page.locator('#studioView')).toBeVisible();

  await page.locator('#studioDepsBtn').click();
  const codeWrap = page.locator('#studioCodeWrap');

  // Engine line proves ORT ran (not the built-in fallback)…
  await expect(codeWrap).toContainText('ORT (OSS Review Toolkit)', { timeout: 30_000 });
  // …the project-license block proves licensee ran…
  await expect(codeWrap).toContainText("This project's own declared license");
  await expect(codeWrap).toContainText('MIT');
  // …and ORT's declared licenses drive the classification chips.
  await expect(codeWrap).toContainText('ag-grid-enterprise');
  await expect(codeWrap.locator('text=COMMERCIAL/RISK').first()).toBeVisible();
  await expect(codeWrap).toContainText('express');
  await expect(codeWrap.locator('text=OPEN SOURCE').first()).toBeVisible();
});
