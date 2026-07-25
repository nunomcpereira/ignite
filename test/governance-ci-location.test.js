'use strict';

/**
 * The org governance CI workflow (Phase 5, run via `act`) only ever reports
 * a failing file in its raw text output ("... matched in: ./server.js"),
 * never a line — it's effectively a `grep -l` report. resolveGovernanceCiLocation
 * re-scans that file with the same secret pattern Phase 4's own scan uses so
 * the finding is still file:line-addressable instead of showing "unknown".
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs/promises');

const { withServerEnv, makeTempProject } = require('./helpers');

test('resolveGovernanceCiLocation: finds the file + line behind a "matched in: ./x" failure line', async () => {
  await withServerEnv({}, async (mod) => {
    const dir = await makeTempProject({
      'server.js': [
        'const express = require("express");',
        'const dbPassword = "hunter2reallylongsecretvalue";',
        'console.log("hi");',
      ].join('\n'),
    });
    const result = await mod.resolveGovernanceCiLocation(
      dir,
      '[security-and-compliance/Global Security and Performance Governance/universal-audit] | ❌ CRITICAL SECURITY ERROR: Unencrypted credential leak matched in: ./server.js'
    );
    assert.equal(result.file, 'server.js');
    assert.equal(result.line, 2);
    assert.ok(result.code && result.code.lines.some((l) => l.number === 2));
    await fs.rm(dir, { recursive: true, force: true });
  })();
});

test('resolveGovernanceCiLocation: file resolves but no secret-shaped line found', async () => {
  await withServerEnv({}, async (mod) => {
    const dir = await makeTempProject({ 'clean.js': 'console.log("nothing secret here");\n' });
    const result = await mod.resolveGovernanceCiLocation(
      dir,
      'Unencrypted credential leak matched in: ./clean.js'
    );
    assert.equal(result.file, 'clean.js');
    assert.equal(result.line, null);
    await fs.rm(dir, { recursive: true, force: true });
  })();
});

test('resolveGovernanceCiLocation: no parseable file reference, or file outside the project root', async () => {
  await withServerEnv({}, async (mod) => {
    const dir = await makeTempProject({ 'a.js': 'x' });
    const noFile = await mod.resolveGovernanceCiLocation(dir, "Error: Job 'validate-go' failed");
    assert.equal(noFile.file, null);
    assert.equal(noFile.line, null);

    const traversal = await mod.resolveGovernanceCiLocation(dir, 'matched in: ../../etc/passwd');
    assert.equal(traversal.file, null);
    assert.equal(traversal.line, null);
    await fs.rm(dir, { recursive: true, force: true });
  })();
});
