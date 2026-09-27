'use strict';

const { test, expect } = require('@playwright/test');
const fs = require('node:fs/promises');
const path = require('node:path');

const snippet = (line, text) => ({ startLine: line, highlightLine: line, highlightEndLine: line + 1,
  lines: [{ number: line, text }, { number: line + 1, text: 'associated context' }] });
const issues = [
  { id: 'dup', category: 'code-duplication', severity: 'warning', file: 'notes.md', line: 10,
    summary: 'Repeated interview questions', snippet: snippet(10, 'Original duplicate questions'),
    duplicateRef: { file: 'other.md', line: 20, endLine: 21, snippet: snippet(20, 'Matching duplicate questions') } },
  { id: 'warning', category: 'security', severity: 'warning', file: 'notes.md', line: 30,
    summary: 'Warning finding', snippet: snippet(30, 'Warning source code') },
  { id: 'error', category: 'secret', severity: 'error', file: 'notes.md', line: 40,
    summary: 'Error finding', snippet: snippet(40, 'Error source code') },
];

test.beforeEach(async ({ page }) => {
  // Serve the actual UI with deterministic API responses; no shared DB or pipeline required.
  await page.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.startsWith('/api/')) {
      const body = url.pathname.endsWith('/issues') ? { issues }
        : url.pathname.includes('/studio/file') ? { content: Array.from({ length: 45 }, (_, i) =>
          ({ 10: 'Original duplicate questions', 20: 'Matching duplicate questions', 30: 'Warning source code', 40: 'Error source code' }[i + 1] || 'context')).join('\n') }
        : { documents: [] };
      return route.fulfill({ json: body });
    }
    if (url.hostname !== 'studio.test') return route.fulfill({ body: 'window.tailwind = {};', contentType: 'application/javascript' });
    const filename = url.pathname === '/' ? 'index.html' : path.basename(url.pathname);
    try {
      return route.fulfill({ body: await fs.readFile(path.join(__dirname, '../public', filename)),
        contentType: filename.endsWith('.js') ? 'application/javascript' : 'text/html' });
    } catch { return route.fulfill({ status: 404, body: '' }); }
  });
  await page.goto('http://studio.test/');
  await page.evaluate(async () => { await openHistoricalStudio('fixture', 'test', 'snippets'); await openStudioFile('notes.md'); });
});

async function assertAllSeverities(page) {
  const pane = page.locator('#studioCodeWrap');
  for (const [line, text, color, label] of [
    [10, 'Original duplicate questions', 'emerald', 'NICE TO HAVE'],
    [30, 'Warning source code', 'amber', 'WARNING'],
    [40, 'Error source code', 'rose', 'ERROR'],
  ]) {
    await expect(pane.locator(`[data-line="${line}"].bg-${color}-50`)).toContainText(text);
    await expect(page.locator('.studio-issue-pick', { hasText: label })).toHaveCount(1);
  }
  await page.locator('.studio-issue-pick', { hasText: 'Warning finding' }).click();
  await expect(pane).toContainText('Warning source code');
  await expect(page.locator('#studioIssuePanel')).toContainText('Warning finding');
  await page.evaluate(() => selectStudioIssue(studioState.issues.find(i => i.id === 'error')));
  await expect(pane).toContainText('Error source code');
  await expect(page.locator('#studioIssuePanel')).toContainText('Error finding');
}

test('historical nice-to-have, warnings and errors retain their code and details', async ({ page }) => {
  await assertAllSeverities(page);
  await page.evaluate(() => studioNavigateToDuplicateRef(studioState.issues[0].duplicateRef));
  await expect(page.locator('#studioCodeWrap [data-line="20"]')).toContainText('Matching duplicate questions');
  await expect(page.locator('#studioIssuePanel')).toContainText('20-21');
  await page.evaluate(() => openStudioFile('notes.md'));
  await assertAllSeverities(page);
});

test('legacy duplicate navigation preserves captured snippets and explains missing code', async ({ page }) => {
  await page.evaluate(async () => {
    studioState.originalContent = 'stale content from a previous live project';
    await studioNavigateToDuplicateRef({ file: 'notes.md', line: 220, end_line: 230 });
  });
  await expect(page.locator('#studioCodeWrap')).toContainText('matching duplicate block was not captured');
  await expect(page.locator('#studioCodeWrap')).not.toContainText('stale content');
  await expect(page.locator('#studioIssuePanel')).toContainText('220-230');
  await assertAllSeverities(page);
});

test('live nice-to-have, warnings and errors still render their associated code', async ({ page }) => {
  await page.evaluate(async () => { studioState.historical = false; studioState.jobId = 'live'; await openStudioFile('notes.md'); });
  await assertAllSeverities(page);
  await page.evaluate(() => studioNavigateToDuplicateRef(studioState.issues[0].duplicateRef));
  await expect(page.locator('#studioCodeWrap [data-line="20"].bg-indigo-50')).toContainText('Matching duplicate questions');
});
