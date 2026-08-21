'use strict';

/**
 * lib/issue-filter.js's filterIssuesByChangedFiles — backs validate-all's
 * `changedFiles` param (an agent fix-verify loop's "did the files I just
 * touched get flagged" view; see routes/pipeline-validate.js). The gating
 * behavior itself (must still override every blocking issue project-wide)
 * lives inline in the route and isn't re-tested here — this covers only
 * the pure filtering function.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { filterIssuesByChangedFiles } = require('../lib/issue-filter');

function issues() {
  return [
    { id: 'a', file: 'src/app.js', summary: 'x' },
    { id: 'b', file: 'src/util.js', summary: 'y' },
    { id: 'c', file: null, summary: 'project-wide, no file' },
  ];
}

test('filterIssuesByChangedFiles: null/undefined changedFiles returns the list unchanged', () => {
  assert.deepEqual(filterIssuesByChangedFiles(issues(), null), issues());
  assert.deepEqual(filterIssuesByChangedFiles(issues(), undefined), issues());
});

test('filterIssuesByChangedFiles: keeps only issues whose file is in the set', () => {
  const result = filterIssuesByChangedFiles(issues(), ['src/app.js']);
  assert.deepEqual(result.map((i) => i.id), ['a']);
});

test('filterIssuesByChangedFiles: accepts an array or a Set interchangeably', () => {
  const viaArray = filterIssuesByChangedFiles(issues(), ['src/app.js', 'src/util.js']);
  const viaSet = filterIssuesByChangedFiles(issues(), new Set(['src/app.js', 'src/util.js']));
  assert.deepEqual(viaArray.map((i) => i.id), viaSet.map((i) => i.id));
  assert.deepEqual(viaArray.map((i) => i.id), ['a', 'b']);
});

test('filterIssuesByChangedFiles: project-wide issues (no file) are always dropped when filtering', () => {
  const result = filterIssuesByChangedFiles(issues(), ['src/app.js', 'src/util.js']);
  assert.ok(!result.some((i) => i.id === 'c'));
});

test('filterIssuesByChangedFiles: a changedFiles set matching nothing returns an empty list', () => {
  const result = filterIssuesByChangedFiles(issues(), ['no/such/file.js']);
  assert.deepEqual(result, []);
});

test('filterIssuesByChangedFiles: whitespace/empty entries in the input array are ignored, not matched', () => {
  const result = filterIssuesByChangedFiles(issues(), ['src/app.js', '', '  ']);
  assert.deepEqual(result.map((i) => i.id), ['a']);
});
