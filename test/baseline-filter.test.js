'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { filterIssuesByBaseline } = require('../lib/baseline-filter');

test('filterIssuesByBaseline: null baseline returns issues unchanged', () => {
  const issues = [{ id: 'a' }, { id: 'b' }];
  assert.equal(filterIssuesByBaseline(issues, null), issues);
});

test('filterIssuesByBaseline: empty baseline returns issues unchanged', () => {
  const issues = [{ id: 'a' }, { id: 'b' }];
  assert.equal(filterIssuesByBaseline(issues, new Set()), issues);
});

test('filterIssuesByBaseline: drops issues whose id is in the baseline set', () => {
  const issues = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
  const result = filterIssuesByBaseline(issues, new Set(['a', 'c']));
  assert.deepEqual(result, [{ id: 'b' }]);
});
