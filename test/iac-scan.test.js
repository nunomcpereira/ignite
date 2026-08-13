'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');

const { withServerEnv, makeTempProject, makeFakeTrivy, makeFakeCheckov, makeFakeHadolint } = require('./helpers');

const noopLog = () => {};

function hasRealTrivy() {
  return new Promise((resolve) => {
    execFile('trivy', ['--version'], (err) => resolve(!err));
  });
}

function hasRealCheckov() {
  return new Promise((resolve) => {
    execFile('checkov', ['--version'], (err) => resolve(!err));
  });
}

function hasRealHadolint() {
  return new Promise((resolve) => {
    execFile('hadolint', ['--version'], (err) => resolve(!err));
  });
}

test('checkIacSecurity: trivy disabled by default is not the case — enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.security.trivy.enabled, true);
  assert.equal(cfg.security.trivy.binary, 'trivy');
}));

test('checkIacSecurity: TRIVY_* env vars are wired into CONFIG.security.trivy', withServerEnv(
  { TRIVY_ENABLED: 'false', TRIVY_BINARY: '/opt/bin/trivy' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.security.trivy.enabled, false);
    assert.equal(cfg.security.trivy.binary, '/opt/bin/trivy');
  }
));

test('checkIacSecurity: falls back to the built-in Dockerfile heuristic scan when trivy is disabled', withServerEnv(
  { TRIVY_ENABLED: 'false', HADOLINT_ENABLED: 'false', CHECKOV_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({
      Dockerfile: 'FROM ubuntu:latest\nCOPY . /app\nCMD ["./run.sh"]\n',
    });
    const { findings, engine } = await mod.checkIacSecurity(dir, noopLog);
    assert.equal(engine, 'fallback');
    const kinds = findings.map((f) => f.kind).sort();
    assert.deepEqual(kinds, ['container-runs-as-root', 'unpinned-base-image']);
  }
));

test('checkIacSecurity: fallback scan is clean on a pinned, non-root Dockerfile', withServerEnv(
  { TRIVY_ENABLED: 'false', HADOLINT_ENABLED: 'false', CHECKOV_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({
      Dockerfile: 'FROM ubuntu:22.04\nCOPY . /app\nUSER 1000\nCMD ["./run.sh"]\n',
    });
    const { findings, engine } = await mod.checkIacSecurity(dir, noopLog);
    assert.equal(engine, 'fallback');
    assert.deepEqual(findings, []);
  }
));

test('checkIacSecurity: trivy enabled but binary missing — soft-fails back to the fallback scan', withServerEnv(
  { TRIVY_ENABLED: 'true', TRIVY_BINARY: '/nonexistent/trivy-binary-xyz', HADOLINT_ENABLED: 'false', CHECKOV_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({
      Dockerfile: 'FROM ubuntu:latest\n',
    });
    const logs = [];
    const { findings, engine } = await mod.checkIacSecurity(dir, (m) => logs.push(m));
    assert.equal(engine, 'fallback');
    assert.deepEqual(findings.map((f) => f.kind).sort(), ['container-runs-as-root', 'unpinned-base-image']);
    assert.ok(logs.some((l) => l.includes('trivy')), 'failure is logged, not thrown');
  }
));

test('checkIacSecurity: parses fake trivy JSON output into findings', async () => {
  const trivyBinary = await makeFakeTrivy([
    {
      Target: 'Dockerfile',
      Misconfigurations: [
        {
          ID: 'DS002',
          Title: "Image user should not be 'root'",
          Severity: 'HIGH',
          CauseMetadata: { StartLine: 1 },
        },
      ],
    },
  ]);
  await withServerEnv({ TRIVY_ENABLED: 'true', TRIVY_BINARY: trivyBinary, HADOLINT_ENABLED: 'false', CHECKOV_ENABLED: 'false' }, async (mod) => {
    const dir = await makeTempProject({ Dockerfile: 'FROM ubuntu:22.04\n' });
    const { findings, engine } = await mod.checkIacSecurity(dir, noopLog);
    assert.equal(engine, 'trivy');
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, 'Dockerfile');
    assert.equal(findings[0].line, 1);
    assert.equal(findings[0].severity, 'high');
    assert.equal(findings[0].tool, 'trivy');
  })();
});

test('checkIacSecurity: real trivy binary end-to-end (skipped if trivy is not installed)', async (t) => {
  if (!(await hasRealTrivy())) {
    t.skip('trivy not installed on PATH — install with `brew install trivy` to run this test');
    return;
  }
  await withServerEnv({ TRIVY_ENABLED: 'true', TRIVY_BINARY: 'trivy', HADOLINT_ENABLED: 'false', CHECKOV_ENABLED: 'false' }, async (mod) => {
    const dir = await makeTempProject({
      Dockerfile: 'FROM ubuntu:latest\nRUN apt-get update && apt-get install -y curl\nCOPY . /app\nCMD ["./run.sh"]\n',
    });
    const { findings, engine } = await mod.checkIacSecurity(dir, noopLog);
    assert.equal(engine, 'trivy');
    assert.ok(findings.length >= 2, 'real trivy should flag at least the unpinned tag + root user');
    assert.ok(findings.every((f) => f.tool === 'trivy'));
  })();
});

test('checkIacSecurity: checkov is enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.security.checkov.enabled, true);
  assert.equal(cfg.security.checkov.binary, 'checkov');
}));

test('checkIacSecurity: checkov explicitly disabled — trivy findings only, engine has no "+checkov" suffix', async () => {
  const trivyBinary = await makeFakeTrivy([{
    Target: 'Dockerfile',
    Misconfigurations: [{ ID: 'DS002', Title: "Image user should not be 'root'", Severity: 'HIGH', CauseMetadata: { StartLine: 1 } }],
  }]);
  await withServerEnv({ TRIVY_ENABLED: 'true', TRIVY_BINARY: trivyBinary, HADOLINT_ENABLED: 'false', CHECKOV_ENABLED: 'false' }, async (mod) => {
    const dir = await makeTempProject({ Dockerfile: 'FROM ubuntu:22.04\n' });
    const { findings, engine } = await mod.checkIacSecurity(dir, noopLog);
    assert.equal(engine, 'trivy');
    assert.equal(findings.length, 1);
  })();
});

test('checkIacSecurity: checkov enabled — supplements trivy findings, merged and tagged distinctly', async () => {
  const trivyBinary = await makeFakeTrivy([{
    Target: 'Dockerfile',
    Misconfigurations: [{ ID: 'DS002', Title: "Image user should not be 'root'", Severity: 'HIGH', CauseMetadata: { StartLine: 1 } }],
  }]);
  const checkovBinary = await makeFakeCheckov({
    check_type: 'dockerfile',
    results: {
      failed_checks: [{
        check_id: 'CKV_DOCKER_7',
        check_name: 'Ensure the base image uses a non latest version tag',
        severity: 'MEDIUM',
        file_path: '/Dockerfile',
        repo_file_path: '/Dockerfile',
        file_line_range: [1, 1],
      }],
    },
  });
  await withServerEnv(
    { TRIVY_ENABLED: 'true', TRIVY_BINARY: trivyBinary, CHECKOV_ENABLED: 'true', CHECKOV_BINARY: checkovBinary, HADOLINT_ENABLED: 'false' },
    async (mod) => {
      const dir = await makeTempProject({ Dockerfile: 'FROM ubuntu:latest\n' });
      const { findings, engine } = await mod.checkIacSecurity(dir, noopLog);
      assert.equal(engine, 'trivy+checkov');
      assert.equal(findings.length, 2);
      assert.deepEqual(findings.map((f) => f.tool).sort(), ['checkov', 'trivy']);
    }
  )();
});

test('checkIacSecurity: checkov enabled but binary missing — soft-skips, trivy findings unaffected', async () => {
  const trivyBinary = await makeFakeTrivy([{
    Target: 'Dockerfile',
    Misconfigurations: [{ ID: 'DS002', Title: "Image user should not be 'root'", Severity: 'HIGH', CauseMetadata: { StartLine: 1 } }],
  }]);
  await withServerEnv(
    { TRIVY_ENABLED: 'true', TRIVY_BINARY: trivyBinary, CHECKOV_ENABLED: 'true', CHECKOV_BINARY: '/nonexistent/checkov-xyz', HADOLINT_ENABLED: 'false' },
    async (mod) => {
      const dir = await makeTempProject({ Dockerfile: 'FROM ubuntu:latest\n' });
      const logs = [];
      const { findings, engine } = await mod.checkIacSecurity(dir, (m) => logs.push(m));
      assert.equal(engine, 'trivy');
      assert.equal(findings.length, 1);
      assert.ok(logs.some((l) => l.includes('checkov')), 'failure is logged, not thrown');
    }
  )();
});

test('checkIacSecurity: real checkov binary end-to-end (skipped if checkov is not installed)', async (t) => {
  if (!(await hasRealCheckov())) {
    t.skip('checkov not installed on PATH — install with `brew install checkov` to run this test');
    return;
  }
  await withServerEnv({ TRIVY_ENABLED: 'false', CHECKOV_ENABLED: 'true', CHECKOV_BINARY: 'checkov', HADOLINT_ENABLED: 'false' }, async (mod) => {
    const dir = await makeTempProject({
      'main.tf': [
        'resource "aws_security_group" "sg" {',
        '  name = "wide-open"',
        '  ingress {',
        '    from_port   = 22',
        '    to_port     = 22',
        '    protocol    = "tcp"',
        '    cidr_blocks = ["0.0.0.0/0"]',
        '  }',
        '}',
        '',
      ].join('\n'),
    });
    const { findings, engine } = await mod.checkIacSecurity(dir, noopLog);
    assert.equal(engine, 'fallback+checkov');
    assert.ok(findings.some((f) => f.tool === 'checkov'), 'real checkov should flag the open ingress rule');
  })();
});

test('checkIacSecurity: hadolint is enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.security.hadolint.enabled, true);
  assert.equal(cfg.security.hadolint.binary, 'hadolint');
}));

test('checkIacSecurity: hadolint enabled — supplements trivy/fallback findings, merged and tagged distinctly', async () => {
  const hadolintBinary = await makeFakeHadolint([
    { code: 'DL3007', level: 'warning', line: 1, file: 'Dockerfile', message: "Using latest is prone to errors" },
  ]);
  await withServerEnv(
    { TRIVY_ENABLED: 'false', CHECKOV_ENABLED: 'false', HADOLINT_ENABLED: 'true', HADOLINT_BINARY: hadolintBinary },
    async (mod) => {
      const dir = await makeTempProject({ Dockerfile: 'FROM ubuntu:latest\nUSER 1000\n' });
      const { findings, engine } = await mod.checkIacSecurity(dir, noopLog);
      assert.equal(engine, 'fallback+hadolint');
      const kinds = findings.map((f) => `${f.tool}:${f.kind}`).sort();
      assert.deepEqual(kinds, ['hadolint:dl3007', 'ignite-fallback:unpinned-base-image']);
    }
  )();
});

test('checkIacSecurity: hadolint enabled but binary missing — soft-skips, other findings unaffected', async () => {
  await withServerEnv(
    { TRIVY_ENABLED: 'false', CHECKOV_ENABLED: 'false', HADOLINT_ENABLED: 'true', HADOLINT_BINARY: '/nonexistent/hadolint-xyz' },
    async (mod) => {
      const dir = await makeTempProject({ Dockerfile: 'FROM ubuntu:latest\nUSER 1000\n' });
      const logs = [];
      const { findings, engine } = await mod.checkIacSecurity(dir, (m) => logs.push(m));
      assert.equal(engine, 'fallback');
      assert.equal(findings.length, 1);
      assert.ok(logs.some((l) => l.includes('hadolint')), 'failure is logged, not thrown');
    }
  )();
});

test('checkIacSecurity: hadolint disabled — no [format json] invocation, no "+hadolint" suffix', async () => {
  await withServerEnv({ TRIVY_ENABLED: 'false', CHECKOV_ENABLED: 'false', HADOLINT_ENABLED: 'false' }, async (mod) => {
    const dir = await makeTempProject({ Dockerfile: 'FROM ubuntu:latest\nUSER 1000\n' });
    const { engine } = await mod.checkIacSecurity(dir, noopLog);
    assert.equal(engine, 'fallback');
  })();
});

test('checkIacSecurity: real hadolint binary end-to-end (skipped if hadolint is not installed)', async (t) => {
  if (!(await hasRealHadolint())) {
    t.skip('hadolint not installed on PATH — install with `brew install hadolint` to run this test');
    return;
  }
  await withServerEnv({ TRIVY_ENABLED: 'false', CHECKOV_ENABLED: 'false', HADOLINT_ENABLED: 'true', HADOLINT_BINARY: 'hadolint' }, async (mod) => {
    const dir = await makeTempProject({
      Dockerfile: 'FROM ubuntu:latest\nRUN apt-get update && apt-get install -y curl\nUSER 1000\n',
    });
    const { findings, engine } = await mod.checkIacSecurity(dir, noopLog);
    assert.equal(engine, 'fallback+hadolint');
    assert.ok(findings.some((f) => f.tool === 'hadolint'), 'real hadolint should flag at least the unpinned-tag / apt-get rules');
  })();
});
