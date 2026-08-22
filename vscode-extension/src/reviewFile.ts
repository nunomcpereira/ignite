import * as fs from 'fs/promises';
import * as path from 'path';
import type { IgniteIssue, OverrideSubmission } from './api';

const HEADER = [
  '# Ignite pre-push acknowledgments - meant to be committed: a filled-in',
  '# justification is a real audit record, reviewable like code.',
  '#',
  '# Fill in a justification after "Acknowledge:" for any issue below you want',
  '# to override, save, then `git push` again (or rerun "Ignite: Scan Workspace").',
  '# Blank = stays blocking.',
  '# Append-only: once written, an entry (and its justification) stays here',
  '# permanently, resubmitted as an override on every future run, even',
  '# after the id it names stops being reported - delete an entry yourself',
  '# if you want to stop carrying it forward.',
  '# A `# Code:` line, when present, is the flagged source line own text -',
  '# used to auto-carry-forward this justification if an unrelated edit',
  '# elsewhere in the file later shifts its line number. Do not hand-edit it.',
  '',
].join('\n');

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

/** Justified entries, as the `overrides` array validate-all's body expects. */
export async function loadOverrides(repoRoot: string): Promise<OverrideSubmission[]> {
  const entries = parseBlocks(await readFileSafe(reviewFilePath(repoRoot)));
  return entries
    .filter((e) => e.justification)
    .map((e) => ({ issueId: e.id, justification: e.justification }));
}

/** id -> justification, for filtering "already acknowledged" issues out of Diagnostics. */
export async function loadAcknowledgedIds(repoRoot: string): Promise<Set<string>> {
  const entries = parseBlocks(await readFileSafe(reviewFilePath(repoRoot)));
  return new Set(entries.filter((e) => e.justification).map((e) => e.id));
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
  const existing = parseBlocks(await readFileSafe(filePath));
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
      ? `Acknowledge: ${match.justification} (auto-carried-forward from ${match.id} - pure line-number drift, flagged code unchanged)`
      : 'Acknowledge: ';
    newBlocks.push(
      [
        `ID: ${issue.id}`,
        `# [${(issue.severity || '').toUpperCase()}] ${issue.category} - ${issue.summary}`,
        `#   ${loc}`,
        ...(code ? [`# Code: ${code}`] : []),
        ackLine,
      ].join('\n')
    );
  }
  const remainingExisting = existing.filter((e) => !e.superseded).map((e) => e.raw);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, HEADER + [...remainingExisting, ...newBlocks].join('\n\n') + '\n');
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
    for (const issue of issues) {
      const loc = issue.file ? issue.file + (issue.line ? ':' + issue.line : '') : '(no file)';
      lines.push(`## [${(issue.severity || '').toUpperCase()}] ${issue.category} - ${issue.summary}`);
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
    }
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
  const existing = parseBlocks(await readFileSafe(filePath));
  const byId = new Map(existing.map((e) => [e.id, e]));

  const newBlocks: string[] = [];
  for (const issue of issues) {
    const match = byId.get(issue.id);
    if (match) {
      match.raw = match.raw.replace(/^Acknowledge:.*$/m, `Acknowledge: ${justification}`);
      if (!/^Acknowledge:/m.test(match.raw)) match.raw += `\nAcknowledge: ${justification}`;
      continue;
    }
    const loc = issue.file ? issue.file + (issue.line ? ':' + issue.line : '') : '(no file)';
    const code = codeForIssue(issue);
    newBlocks.push(
      [
        `ID: ${issue.id}`,
        `# [${(issue.severity || '').toUpperCase()}] ${issue.category} - ${issue.summary}`,
        `#   ${loc}`,
        ...(code ? [`# Code: ${code}`] : []),
        `Acknowledge: ${justification}`,
      ].join('\n')
    );
  }
  const all = [...existing.filter((e) => !e.superseded).map((e) => e.raw), ...newBlocks];
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, HEADER + all.join('\n\n') + '\n');
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
