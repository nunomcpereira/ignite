import { test } from 'node:test';
import assert from 'node:assert/strict';
import { defaultPdfName, planForPick, summarizeReports, type DailyReportResult } from './dailyReport';

const base = { org: 'acme', repos: 3, unjustifiedFindings: 8, sent: false };

test('planForPick maps each quick-pick to server channels and a PDF download', () => {
  assert.deepEqual(planForPick('webhook'), { serverChannels: ['webhook'], downloadPdf: false });
  assert.deepEqual(planForPick('azure_blob'), { serverChannels: ['azure_blob'], downloadPdf: false });
  assert.deepEqual(planForPick('email'), { serverChannels: ['email'], downloadPdf: false });
  assert.deepEqual(planForPick('pdf'), { serverChannels: null, downloadPdf: true });
  assert.deepEqual(planForPick('all'), { serverChannels: [], downloadPdf: true });
});

test('summarizeReports reports delivered channels', () => {
  const result: DailyReportResult = { date: '2026-09-19', dryRun: false, channels: ['webhook'], reports: [{ ...base, sent: true, webhookSent: true }] };
  const s = summarizeReports(result);
  assert.equal(s.hasFailures, false);
  assert.match(s.message, /delivered: 1 org\(s\), 3 repo\(s\), 8 unjustified finding\(s\)/);
  assert.ok(s.lines.includes('  sentinel/webhook: ok'));
});

test('summarizeReports flags a failing channel even when another succeeded', () => {
  const result: DailyReportResult = { date: 'd', dryRun: false, channels: [], reports: [{ ...base, sent: true, webhookSent: true, azureBlobError: 'Azure Blob answered HTTP 403' }] };
  const s = summarizeReports(result);
  assert.equal(s.hasFailures, true);
  assert.match(s.message, /some channels failed/);
  assert.ok(s.lines.some((l) => l.includes('azure blob: FAILED — Azure Blob answered HTTP 403')));
});

test('summarizeReports treats "nothing delivered" as a problem and dry runs as previews', () => {
  const none: DailyReportResult = { date: 'd', dryRun: false, channels: [], reports: [{ ...base, reason: 'notifications disabled' }] };
  const s = summarizeReports(none);
  assert.equal(s.hasFailures, true);
  assert.match(s.message, /nothing was delivered/);
  assert.ok(s.lines.some((l) => l.includes('email: skipped — notifications disabled')));
  const dry = summarizeReports({ ...none, dryRun: true });
  assert.match(dry.message, /preview \(nothing sent\)/);
  assert.equal(summarizeReports({ date: 'd', dryRun: false, channels: [], reports: [] }).hasFailures, false);
});

test('a missing PDF renderer is only a failure when PDF was requested', () => {
  const quiet = summarizeReports({ date: 'd', dryRun: false, channels: ['azure_blob'], reports: [{ ...base, sent: true, azureBlobSent: true, pdfError: 'no Chrome' }] });
  assert.equal(quiet.hasFailures, false);
  const asked = summarizeReports({ date: 'd', dryRun: false, channels: ['pdf'], reports: [{ ...base, pdfError: 'no Chrome' }] });
  assert.equal(asked.hasFailures, true);
});

test('defaultPdfName sanitizes the org and stamps the date', () => {
  assert.equal(defaultPdfName('acme-corp', new Date('2026-09-19T10:00:00Z')), 'ignite-report-acme-corp-2026-09-19.pdf');
  assert.equal(defaultPdfName('../evil org', new Date('2026-09-19T10:00:00Z')), 'ignite-report-..evilorg-2026-09-19.pdf');
});
