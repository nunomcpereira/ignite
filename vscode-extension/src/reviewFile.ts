import * as fs from 'fs/promises';
import * as path from 'path';
import type { IgniteIssue, OverrideSubmission } from './api';

// Same header and canonical form `ignite_acknowledgments` (the pre-push
// hook / `ignite check`) writes, so the two writers never churn each other's
// output: one entry per ID, sorted by ID, no running numbers.
const HEADER = [
  '# Ignite pre-push acknowledgments - meant to be committed: a filled-in',
  '# justification is a real audit record, reviewable like code.',
  '#',
  '# Fill in a justification after "Acknowledge:" for any issue below you want',
  '# to override, save, commit, then `git push` again. Blank = stays blocking.',
  '# Entries are sorted by ID, one per finding. The file is only rewritten when',
  '# a new finding needs an entry - then entries for findings that are no',
  '# longer reported are dropped.',
  "# A `# Code:` line, when present, is the flagged source line's own text -",
  '# it lets this justification keep matching after an unrelated edit',
  '# elsewhere in the file shifts its line number. Do not hand-edit it.',
  '',
].join('\n');

const CARRY_NOTE = / \(auto-carried-forward from [^()]* - pure line-number drift, flagged code unchanged\)/g;

/** A justification without the carry-forward notes older versions appended on every line move. */
export function cleanJustification(justification: string): string {
  return justification.replace(CARRY_NOTE, '').trim();
}

/** An entry's text in the current format: no "# Issue #N" line, no carry-forward notes. */
function normalizeBlock(raw: string): string {
  return raw
    .replace(/^(ID: [^\n]*)\n# Issue #\d+\n/, '$1\n')
    .trimEnd()
    .split('\n')
    .map((l) => {
      if (!l.startsWith('Acknowledge:')) return l;
      const j = cleanJustification(l.slice('Acknowledge:'.length));
      return j ? `Acknowledge: ${j}` : 'Acknowledge: ';
    })
    .join('\n');
}

function blockId(block: string): string {
  return /^ID:\s*([^\n]+)/.exec(block)?.[1]?.trim() ?? '';
}

/** Final file body: entries sorted by ID, separated by a blank line. */
function renderBlocks(blocks: string[]): string {
  return [...blocks].sort((a, b) => (blockId(a) < blockId(b) ? -1 : blockId(a) > blockId(b) ? 1 : 0)).join('\n\n');
}

interface ParsedEntry {
  id: string;
  category: string;
  file: string | null;
  code: string | null;
  justification: string;
  raw: string;
  superseded: boolean;
}

/** Ports hooks/pre-push's id/`# Code:`/Acknowledge: block format 1:1 — the CLI hook and this
 *  extension must produce byte-compatible entries so either one can edit the same file. */
function parseBlocks(text: string): ParsedEntry[] {
  const entries: ParsedEntry[] = [];
  for (const block of text.split(/\n(?=ID: )/)) {
    const idMatch = block.match(/^ID:\s*(.+)$/m);
    if (!idMatch) continue;
    const id = idMatch[1].trim();
    const locMatch = block.match(/^#\s+(\S+?)(?::(\d+))?$/m);
    const codeMatch = block.match(/^# Code:\s*(.*)$/m);
    const ackMatch = block.match(/^Acknowledge:\s*(.*)$/m);
    entries.push({
      id,
      category: id.split('::')[0],
      file: locMatch ? locMatch[1] : null,
      code: codeMatch ? codeMatch[1].trim() : null,
      justification: (ackMatch ? ackMatch[1] : '').trim(),
      raw: block.replace(/\n+$/, ''),
      superseded: false,
    });
  }
  return entries;
}

export function igniteDir(repoRoot: string): string {
  return path.join(repoRoot, '.ignite');
}

export function reviewFilePath(repoRoot: string): string {
  return path.join(igniteDir(repoRoot), 'acknowledgments.md');
}

async function readFileSafe(p: string): Promise<string> {
  try {
    return await fs.readFile(p, 'utf8');
  } catch {
    return '';
  }
}

/**
 * One entry per finding (same `ID:` = same category + file + line), keeping
 * the latest supplied justification: newer entries are appended after older
 * ones, so the last non-blank justification wins and a later blank entry
 * never erases a filled-in one. The survivor keeps the id's first position.
 * Mirrors `ignite_acknowledgments::dedupe_latest` on the server/CLI side.
 */
export function dedupeLatest<T extends { id: string; justification: string }>(entries: T[]): T[] {
  const order: string[] = [];
  const chosen = new Map<string, T>();
  for (const entry of entries) {
    const current = chosen.get(entry.id);
    if (!current) {
      order.push(entry.id);
      chosen.set(entry.id, entry);
    } else if (entry.justification) {
      chosen.set(entry.id, entry);
    }
  }
  return order.map((id) => chosen.get(id) as T);
}

/** Justified entries, as the `overrides` array validate-all's body expects. */
export async function loadOverrides(repoRoot: string): Promise<OverrideSubmission[]> {
  const entries = dedupeLatest(parseBlocks(await readFileSafe(reviewFilePath(repoRoot))));
  return entries
    .filter((e) => e.justification)
    .map((e) => ({ issueId: e.id, justification: e.justification }));
}

/** id -> justification, for filtering "already acknowledged" issues out of Diagnostics. */
export async function loadAcknowledgedIds(repoRoot: string): Promise<Set<string>> {
  const entries = dedupeLatest(parseBlocks(await readFileSafe(reviewFilePath(repoRoot))));
  return new Set(entries.filter((e) => e.justification).map((e) => e.id));
}

/**
 * Collapses embedded newlines/carriage-returns to spaces before a value is
 * interpolated into a single markdown line of acknowledgments.md. Fields
 * like `issue.summary`/`issue.category` and a matched code snippet can echo
 * scanned-repo content (a semgrep/bearer rule message, a matched source
 * fragment, a package name) — an untrusted repo crafting one of those with
 * an embedded `\nID: ...\nAcknowledge: ...\n` could otherwise forge a fake
 * entry that parseBlocks() reads back as a legitimately-justified override
 * for an unrelated issue id.
 */
function sanitizeLine(value: string): string {
  return value.replace(/[\r\n]+/g, ' ');
}

function codeForIssue(issue: IgniteIssue): string | null {
  const snippet = issue.snippet;
  if (!snippet || !Array.isArray(snippet.lines)) return null;
  const hit = snippet.lines.find((l) => l.number === snippet.highlightLine);
  return hit ? hit.text.trim() : null;
}

/**
 * Appends a blank stanza for every unresolved issue not already present,
 * carrying forward justifications whose flagged line drifted (same
 * category+file+`# Code:` text) exactly as hooks/pre-push does. Returns the
 * number of newly-appended (still-blank) stanzas.
 */
export async function appendUnresolvedIssues(repoRoot: string, issues: IgniteIssue[]): Promise<number> {
  const filePath = reviewFilePath(repoRoot);
  const existing = dedupeLatest(parseBlocks(await readFileSafe(filePath)));
  const existingIds = new Set(existing.map((e) => e.id));

  const newBlocks: string[] = [];
  for (const issue of issues) {
    if (existingIds.has(issue.id)) continue;
    const loc = issue.file ? issue.file + (issue.line ? ':' + issue.line : '') : '(no file)';
    const code = codeForIssue(issue);
    const match = code
      ? existing.find((e) => !e.superseded && e.justification && e.category === issue.category && e.file === issue.file && e.code === code)
      : undefined;
    if (match) match.superseded = true;
    const ackLine = match
      ? `Acknowledge: ${sanitizeLine(cleanJustification(match.justification))}`
      : 'Acknowledge: ';
    newBlocks.push(
      [
        `ID: ${sanitizeLine(issue.id)}`,
        `# [${(issue.severity || '').toUpperCase()}] ${sanitizeLine(issue.category)} - ${sanitizeLine(issue.summary)}`,
        `#   ${sanitizeLine(loc)}`,
        ...(code ? [`# Code: ${sanitizeLine(code)}`] : []),
        ackLine,
      ].join('\n')
    );
  }
  // Nothing new to add: leave the file exactly as it is (no reshuffling).
  if (newBlocks.length === 0) return 0;
  const remainingExisting = existing.filter((e) => !e.superseded).map((e) => normalizeBlock(e.raw));
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, HEADER + renderBlocks([...remainingExisting, ...newBlocks]) + '\n');
  return newBlocks.filter((b) => b.endsWith('Acknowledge: ')).length;
}

/** Filesystem-safe timestamp (no colons) for a scan snapshot folder name. */
function scanTimestamp(date: Date): string {
  return date.toISOString().replace(/:/g, '-').replace(/\.\d+Z$/, 'Z');
}

export function scanSnapshotPath(repoRoot: string, date: Date = new Date()): string {
  return path.join(igniteDir(repoRoot), 'scans', scanTimestamp(date), 'findings.md');
}

/**
 * Snapshots every finding from one scan run as markdown, one file per
 * datetime under .ignite/scans/<timestamp>/findings.md - a point-in-time
 * record, unlike the append-only, carry-forward acknowledgments.md.
 */
export async function writeScanSnapshot(repoRoot: string, issues: IgniteIssue[], date: Date = new Date()): Promise<string> {
  const filePath = scanSnapshotPath(repoRoot, date);
  const lines: string[] = [`# Ignite scan findings — ${date.toISOString()}`, ''];
  if (issues.length === 0) {
    lines.push('No findings.');
  } else {
    issues.forEach((issue, i) => {
      const loc = issue.file ? issue.file + (issue.line ? ':' + issue.line : '') : '(no file)';
      lines.push(`## ${i + 1}. [${(issue.severity || '').toUpperCase()}] ${issue.category} - ${issue.summary}`);
      lines.push('');
      lines.push(`- ID: \`${issue.id}\``);
      lines.push(`- Location: ${loc}`);
      lines.push(`- Score: ${issue.score}`);
      if (issue.status) lines.push(`- Status: ${issue.status}`);
      if (issue.cwe) lines.push(`- CWE: ${issue.cwe}`);
      if (issue.owasp) lines.push(`- OWASP: ${issue.owasp}`);
      const hit = issue.snippet?.lines?.find((l) => l.number === issue.snippet?.highlightLine);
      if (hit) {
        lines.push('');
        lines.push('```');
        lines.push(hit.text);
        lines.push('```');
      }
      lines.push('');
    });
  }
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, lines.join('\n'));
  return filePath;
}

/**
 * Bulk-acknowledges a batch of issues with one shared justification —
 * backs the findings tree's multi-select "Acknowledge Selected" command,
 * so grouping several occurrences of the same finding no longer means
 * opening the review file and typing the same justification N times.
 * An issue already present gets its Acknowledge: line overwritten
 * in place (same one-justification-per-id invariant appendUnresolvedIssues
 * relies on); a new one gets a fresh, already-filled-in stanza appended.
 */
export async function acknowledgeIssues(repoRoot: string, issues: IgniteIssue[], justification: string): Promise<void> {
  const filePath = reviewFilePath(repoRoot);
  const existing = dedupeLatest(parseBlocks(await readFileSafe(filePath)));
  const byId = new Map(existing.map((e) => [e.id, e]));

  const newBlocks: string[] = [];
  for (const issue of issues) {
    const match = byId.get(issue.id);
    if (match) {
      match.raw = match.raw.replace(/^Acknowledge:.*$/m, `Acknowledge: ${sanitizeLine(justification)}`);
      if (!/^Acknowledge:/m.test(match.raw)) match.raw += `\nAcknowledge: ${sanitizeLine(justification)}`;
      continue;
    }
    const loc = issue.file ? issue.file + (issue.line ? ':' + issue.line : '') : '(no file)';
    const code = codeForIssue(issue);
    newBlocks.push(
      [
        `ID: ${sanitizeLine(issue.id)}`,
        `# [${(issue.severity || '').toUpperCase()}] ${sanitizeLine(issue.category)} - ${sanitizeLine(issue.summary)}`,
        `#   ${sanitizeLine(loc)}`,
        ...(code ? [`# Code: ${sanitizeLine(code)}`] : []),
        `Acknowledge: ${sanitizeLine(justification)}`,
      ].join('\n')
    );
  }
  const all = [...existing.filter((e) => !e.superseded).map((e) => normalizeBlock(e.raw)), ...newBlocks];
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, HEADER + renderBlocks(all) + '\n');
}

/** Byte offset of a given issue id's `Acknowledge:` line, for jumping the editor there. */
export async function findAcknowledgeLineNumber(repoRoot: string, issueId: string): Promise<number | null> {
  const text = await readFileSafe(reviewFilePath(repoRoot));
  const lines = text.split('\n');
  let inBlock = false;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith('ID: ')) {
      inBlock = lines[i].slice(4).trim() === issueId;
    } else if (inBlock && lines[i].startsWith('Acknowledge:')) {
      return i;
    }
  }
  return null;
}
