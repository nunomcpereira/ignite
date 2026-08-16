'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { checkContent } = require('../guidelines/checks');

function idsFor(content, relPath) {
  return checkContent(content, { path: relPath }).map((v) => v.guidelineId);
}

test('noSqlInjection: flags string-built queries, not parameterized ones', () => {
  assert.ok(idsFor(
    'const q = `SELECT * FROM users WHERE id = ${id}`;\n',
    'db.js'
  ).includes('no-sql-injection'));
  assert.ok(idsFor(
    "query = f\"SELECT * FROM users WHERE id = {user_id}\"\n",
    'db.py'
  ).includes('no-sql-injection'));
  assert.ok(idsFor(
    "sql = \"SELECT * FROM users WHERE id = \" + id\n",
    'db.py'
  ).includes('no-sql-injection'));
  assert.ok(!idsFor(
    "db.query('SELECT * FROM users WHERE id = ?', [id]);\n",
    'db.js'
  ).includes('no-sql-injection'), 'parameterized queries must not be flagged');
});

test('noXssSinks: flags raw-HTML sinks, not text-content assignment', () => {
  assert.ok(idsFor(
    'el.innerHTML = userInput;\n',
    'view.js'
  ).includes('no-xss-sinks'));
  assert.ok(idsFor(
    'return <div dangerouslySetInnerHTML={{ __html: comment }} />;\n',
    'Comment.tsx' // extension not in appliesTo — see next assertion for the covered case
  ).length === 0);
  assert.ok(idsFor(
    'const el = <div dangerouslySetInnerHTML={{ __html: comment }} />;\n',
    'Comment.js'
  ).includes('no-xss-sinks'));
  assert.ok(!idsFor(
    'el.textContent = userInput;\n',
    'view.js'
  ).includes('no-xss-sinks'), 'textContent is safe and must not be flagged');
});

test('noWeakCrypto: flags MD5/SHA-1/DES, not modern algorithms', () => {
  assert.ok(idsFor(
    "const h = crypto.createHash('md5').update(pw).digest('hex');\n",
    'auth.js'
  ).includes('no-weak-crypto'));
  assert.ok(idsFor(
    'digest = hashlib.sha1(password.encode()).hexdigest()\n',
    'auth.py'
  ).includes('no-weak-crypto'));
  assert.ok(!idsFor(
    "const h = crypto.createHash('sha256').update(pw).digest('hex');\n",
    'auth.js'
  ).includes('no-weak-crypto'), 'sha256 must not be flagged');
  assert.ok(!idsFor(
    'const token = Math.random().toString(36);\n',
    'util.js'
  ).includes('no-weak-crypto'), 'Math.random() is legitimate outside security contexts and must not be flagged');
});

test('noSsrfSinks: flags request-derived outbound URLs, not literal ones', () => {
  assert.ok(idsFor(
    'const res = await fetch(req.query.url);\n',
    'proxy.js'
  ).includes('no-ssrf-sinks'));
  assert.ok(idsFor(
    "resp = requests.get(request.args.get('url'))\n",
    'proxy.py'
  ).includes('no-ssrf-sinks'));
  assert.ok(!idsFor(
    "const res = await fetch('https://api.example.com/status');\n",
    'proxy.js'
  ).includes('no-ssrf-sinks'), 'a literal URL must not be flagged');
});

test('noCsrfDisabled: flags explicit CSRF opt-outs', () => {
  assert.ok(idsFor(
    '@csrf_exempt\ndef webhook(request):\n    pass\n',
    'views.py'
  ).includes('no-csrf-disabled'));
  assert.ok(idsFor(
    'skip_before_action :verify_authenticity_token\n',
    'controller.rb'
  ).includes('no-csrf-disabled'));
  assert.ok(idsFor(
    'app.use(csrf({ csrf: false }));\n',
    'app.js'
  ).includes('no-csrf-disabled'));
  assert.ok(!idsFor(
    'app.use(csurf());\n',
    'app.js'
  ).includes('no-csrf-disabled'), 'enabling CSRF protection must not be flagged');
});

test('noUnpinnedGhaAction: flags mutable-ref actions in workflow files only', () => {
  assert.ok(idsFor(
    'steps:\n  - uses: some-org/some-action@main\n',
    '.github/workflows/ci.yml'
  ).includes('no-unpinned-gha-action'));
  assert.ok(idsFor(
    'steps:\n  - uses: some-org/some-action@v4\n',
    '.github/workflows/ci.yml'
  ).includes('no-unpinned-gha-action'));
  assert.ok(!idsFor(
    'steps:\n  - uses: some-org/some-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n',
    '.github/workflows/ci.yml'
  ).includes('no-unpinned-gha-action'), 'a SHA-pinned action must not be flagged');
  assert.ok(!idsFor(
    'steps:\n  - uses: actions/checkout@v4\n',
    '.github/workflows/ci.yml'
  ).includes('no-unpinned-gha-action'), 'first-party actions/* is excluded by design');
  assert.ok(!idsFor(
    'steps:\n  - uses: some-org/some-action@main\n',
    'k8s/deployment.yaml'
  ).includes('no-unpinned-gha-action'), 'only .github/workflows/*.yml is scanned');
});
