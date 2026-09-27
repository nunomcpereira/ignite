'use strict';
const { test, expect } = require('@playwright/test');
const fs = require('node:fs/promises');
const path = require('node:path');

async function setup(page, snapshot, updateStatus = 202) {
  const requests = [];
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.pathname.startsWith('/api/')) {
      if (route.request().method() === 'POST' && url.pathname.startsWith('/api/tools/')) {
        requests.push(url.pathname);
        if (updateStatus !== 202) return route.fulfill({ status: updateStatus, json: { error: 'Wait for active pipeline runs to finish before updating tools' } });
        if (url.pathname.endsWith('/check')) snapshot.checking = true;
        else snapshot.tools.jscpd.updating = true;
        return route.fulfill({ status: 202, body: '' });
      }
      if (url.pathname === '/api/tools/updates') return route.fulfill({ json: snapshot });
      return route.fulfill({ json: {} });
    }
    if (url.hostname !== 'tools.test') return route.fulfill({ body: 'window.tailwind = {};', contentType: 'application/javascript' });
    const name = url.pathname === '/' ? 'index.html' : path.basename(url.pathname);
    try { return route.fulfill({ body: await fs.readFile(path.join(__dirname, '../public', name)), contentType: name.endsWith('.js') ? 'application/javascript' : 'text/html' }); }
    catch { return route.fulfill({ status: 404, body: '' }); }
  });
  await page.goto('http://tools.test/');
  await page.evaluate(async () => {
    await loadToolUpdates();
    renderToolsBar(Object.fromEntries(Object.keys(TOOLS_META).map(key => [key, { ok: true, enabled: true }])));
    document.getElementById('accountMenu').classList.remove('hidden');
  });
  await page.locator('#toolsBarToggle').click();
  return requests;
}
const available = () => ({ checking: false, checkedAt: '2026-09-26T10:00:00Z', tools: {
  jscpd: { installedVersion: '1.9.0', latestVersion: '1.10.0', updateAvailable: true, canUpdate: true, manager: 'npm' },
  codeql: { installedVersion: '2.20.0', latestVersion: '2.21.0', updateAvailable: true, canUpdate: false, releaseUrl: 'https://github.com/github/codeql-cli-binaries/releases/latest' },
  trivy: { installedVersion: '0.60.0', latestVersion: '0.60.0', updateAvailable: false },
} });

test('updates managed tools, shows manual releases, and refreshes completion', async ({ page }) => {
  const snapshot = available();
  const requests = await setup(page, snapshot);
  await expect(page.locator('[data-tool-update="jscpd"]')).toHaveCount(1);
  await expect(page.locator('[data-tool-update="trivy"]')).toHaveCount(0);
  await expect(page.locator('#toolsBarList a')).toHaveAttribute('href', snapshot.tools.codeql.releaseUrl);
  await page.locator('[data-tool-update="jscpd"]').click();
  await expect(page.locator('#toolsBarList')).toContainText('Updating…');
  expect(requests).toEqual(['/api/tools/jscpd/update']);
  snapshot.tools.jscpd = { installedVersion: '1.10.0', latestVersion: '1.10.0', updateAvailable: false, updating: false };
  await page.evaluate(() => loadToolUpdates());
  await expect(page.locator('[data-tool-update="jscpd"]')).toHaveCount(0);
  await expect(page.locator('#toolsBarList')).toContainText('1.10.0');
  await expect(page.locator('#toolsBarList')).toHaveClass(/flex/);
});

test('disabled startup state permits an explicit check without installing anything', async ({ page }) => {
  const requests = await setup(page, { checking: false, checkedAt: null, tools: {} });
  await expect(page.locator('#toolsBarList')).toContainText('Updates have not been checked');
  expect(requests).toEqual([]);
  await page.locator('#toolsCheckUpdatesBtn').click();
  await expect(page.locator('#toolsCheckUpdatesBtn')).toHaveText('Checking for updates…');
  await expect(page.locator('#toolsCheckUpdatesBtn')).toBeDisabled();
  expect(requests).toEqual(['/api/tools/updates/check']);
});

test('failed update displays the server error and can be retried', async ({ page }) => {
  await setup(page, available(), 409);
  await page.locator('[data-tool-update="jscpd"]').click();
  await expect(page.locator('#toolsBarList [role="alert"]')).toContainText('Wait for active pipeline runs');
  await expect(page.locator('[data-tool-update="jscpd"]')).toBeEnabled();
});
