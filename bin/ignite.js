#!/usr/bin/env node
'use strict';

/**
 * `ignite scan [path]` — CLI wrapper around POST /api/pipeline/validate-all,
 * for agents/CI that want a plain command + exit code instead of driving
 * the HTTP API themselves. Always dry-run by design (validate-all never
 * ships/pushes) — this is a pre-commit/pre-push check, not a fourth way to
 * onboard a repo; use the MCP `onboard_project` tool for a real push.
 *
 * Requires a running Ignite server (`npm start`) reachable at
 * IGNITE_BASE_URL (default http://localhost:51337) — same requirement as
 * every other agent-facing entrypoint (mcp-server.js's proxyToIgnite).
 *
 * Usage:
 *   ignite scan [path] [--changed-files a.js,b.py] [--json] [--base-url URL]
 *
 * Exit codes: 0 = passed, 1 = blocking issues / validation failure,
 * 2 = couldn't reach the Ignite server or bad usage.
 */

const path = require('path');

function parseArgs(argv) {
  const args = { command: null, projectPath: null, changedFiles: null, json: false, baseUrl: null };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    // eslint-disable-next-line security/detect-object-injection -- i is a bounded numeric loop index, not user-controlled
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a === '--changed-files') args.changedFiles = String(argv[++i] || '').split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--base-url') args.baseUrl = argv[++i];
    else rest.push(a);
  }
  args.command = rest[0] || null;
  args.projectPath = rest[1] || null;
  return args;
}

function printHumanSummary(result) {
  const errorCount = (result.issues || []).filter((i) => i.severity === 'error' && i.status !== 'overridden').length;
  const warningCount = (result.issues || []).filter((i) => i.severity === 'warning').length;
  console.log(`\nIgnite scan: ${result.ok ? 'PASSED' : 'FAILED'}${result.failedPhase ? ` (phase ${result.failedPhase})` : ''}`);
  if (!result.ok) console.log(`  ${result.error}`);
  console.log(`  ${errorCount} blocking issue(s), ${warningCount} warning(s)${result.filteredByChangedFiles ? ` (of ${result.totalIssueCount} total — filtered to changed files)` : ''}`);
  for (const issue of (result.issues || []).slice(0, 50)) {
    const loc = issue.file ? `${issue.file}${issue.line ? ':' + issue.line : ''}` : '(project-wide)';
    const tag = issue.status === 'overridden' ? 'overridden' : issue.severity;
    console.log(`  [${tag}] ${loc} — ${issue.summary}`);
  }
  if ((result.issues || []).length > 50) console.log(`  ... and ${result.issues.length - 50} more`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.command !== 'scan') {
    console.error('Usage: ignite scan [path] [--changed-files a.js,b.py] [--json] [--base-url URL]');
    process.exit(2);
  }

  const baseUrl = (args.baseUrl || process.env.IGNITE_BASE_URL || 'http://localhost:51337').replace(/\/+$/, '');
  const projectPath = path.resolve(args.projectPath || process.cwd());

  let response;
  try {
    response = await fetch(`${baseUrl}/api/pipeline/validate-all`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Ignite-Client': 'cli',
        ...(process.env.IGNITE_API_KEY ? { Authorization: `Bearer ${process.env.IGNITE_API_KEY}` } : {}),
      },
      body: JSON.stringify({
        projectPath,
        ...(args.changedFiles ? { changedFiles: args.changedFiles } : {}),
      }),
    });
  } catch (err) {
    console.error(`Could not reach Ignite server at ${baseUrl}: ${err.message}. Is it running ("npm start")?`);
    process.exit(2);
  }

  const result = await response.json().catch(() => null);
  if (!result) {
    console.error(`Ignite server returned a non-JSON response (HTTP ${response.status}).`);
    process.exit(2);
  }

  if (args.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printHumanSummary(result);
  }

  process.exit(result.ok ? 0 : 1);
}

main();
