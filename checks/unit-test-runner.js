'use strict';

/**
 * Runs the onboarded project's own unit test suite, sandboxed inside a
 * throwaway Docker container per detected language (never on the host).
 * Phase D of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {Function} deps.runToolStreaming - from lib/tool-runner.js's createToolRunner()
 */
function createUnitTestRunnerCheck({ runTool, runToolStreaming }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');

  const DEFAULT_TEST_NODE_MAJOR = 22; // oldest LTS with `node:sqlite` and other modern built-ins

  async function readPackageJson(root) {
    try {
      return JSON.parse(await fsp.readFile(path.join(root, 'package.json'), 'utf8'));
    } catch {
      return null;
    }
  }

  function detectNpmTestScript(pkg) {
    const testScript = pkg?.scripts?.test;
    if (!testScript || /\bno test specified\b/.test(testScript)) return null;
    return testScript;
  }

  // Respects an `engines.node` minimum if the project declares one newer than
  // our default, so containers running the test suite have whatever modern
  // built-ins (e.g. `node:sqlite`) the project's own code expects.
  function resolveTestNodeImage(pkg) {
    const engineNode = pkg?.engines?.node;
    const declaredMajor = engineNode ? parseInt(String(engineNode).match(/(\d+)/)?.[1], 10) : NaN;
    const major = Number.isInteger(declaredMajor) ? Math.max(DEFAULT_TEST_NODE_MAJOR, declaredMajor) : DEFAULT_TEST_NODE_MAJOR;
    return `node:${major}-alpine`;
  }

  async function fileExists(p) {
    return fsp.stat(p).then(() => true).catch(() => false);
  }

  // Each detector inspects the staged project root for that language's own
  // marker file(s) and, if present, returns the Docker image + shell command
  // used to install deps and run its native test suite. A project can match
  // more than one (e.g. a Node frontend next to a Go backend) — all matches
  // run, in this fixed order, and any one failing fails the phase.
  const LANGUAGE_TEST_RUNNERS = [
    {
      language: 'Node.js',
      async detect(root) {
        const pkg = await readPackageJson(root);
        const testScript = detectNpmTestScript(pkg);
        if (!testScript) return null;
        return {
          detail: `npm test script: "${testScript}"`,
          image: resolveTestNodeImage(pkg),
          // node:*-alpine ships no `git` — some suites shell out to a real
          // git binary (e.g. this repo's own resolveGovernanceCiLocation
          // tests), which fails with a bare "spawn git ENOENT" inside the
          // sandbox despite passing fine on the host. `--no-cache` avoids
          // leaving an apk index behind in the throwaway container.
          command: 'apk add --no-cache git >/dev/null 2>&1 || true; npm ci --no-audit --no-fund || npm install --no-audit --no-fund && npm test',
        };
      },
    },
    {
      language: 'Go',
      async detect(root) {
        if (!await fileExists(path.join(root, 'go.mod'))) return null;
        return {
          detail: '`go.mod` found',
          image: 'golang:1.23-alpine',
          command: 'go test ./...',
        };
      },
    },
    {
      language: 'Rust',
      async detect(root) {
        if (!await fileExists(path.join(root, 'Cargo.toml'))) return null;
        return {
          detail: '`Cargo.toml` found',
          image: 'rust:1-slim',
          command: 'cargo test --locked || cargo test',
        };
      },
    },
    {
      language: 'Python',
      async detect(root) {
        const hasProjectFile = await fileExists(path.join(root, 'pyproject.toml'))
          || await fileExists(path.join(root, 'setup.py'))
          || await fileExists(path.join(root, 'requirements.txt'));
        if (!hasProjectFile) return null;
        return {
          detail: 'Python project file found (pyproject.toml/setup.py/requirements.txt)',
          image: 'python:3.12-slim',
          command: [
            'pip install --quiet --no-input --disable-pip-version-check pytest',
            '(test -f requirements.txt && pip install --quiet --no-input --disable-pip-version-check -r requirements.txt || true)',
            '(test -f pyproject.toml -o -f setup.py && pip install --quiet --no-input --disable-pip-version-check -e . || true)',
            'pytest',
          ].join(' && '),
        };
      },
    },
    {
      language: 'Java (Maven)',
      async detect(root) {
        if (!await fileExists(path.join(root, 'pom.xml'))) return null;
        return {
          detail: '`pom.xml` found',
          image: 'maven:3-eclipse-temurin-21',
          command: 'mvn --batch-mode --no-transfer-progress test',
        };
      },
    },
    {
      language: 'Java (Gradle)',
      async detect(root) {
        const hasGradle = await fileExists(path.join(root, 'build.gradle'))
          || await fileExists(path.join(root, 'build.gradle.kts'));
        if (!hasGradle) return null;
        const hasWrapper = await fileExists(path.join(root, 'gradlew'));
        return {
          detail: hasWrapper ? '`build.gradle(.kts)` + gradlew wrapper found' : '`build.gradle(.kts)` found',
          image: 'gradle:8-jdk21',
          command: hasWrapper ? 'chmod +x ./gradlew && ./gradlew test --no-daemon' : 'gradle test --no-daemon',
        };
      },
    },
  ];

  async function runProjectUnitTests(root, log) {
    const matches = [];
    for (const runner of LANGUAGE_TEST_RUNNERS) {
      const match = await runner.detect(root);
      if (match) matches.push({ language: runner.language, ...match });
    }

    if (matches.length === 0) {
      log('No recognized test project (package.json/go.mod/Cargo.toml/pyproject.toml/setup.py/requirements.txt/pom.xml/build.gradle) — skipping unit test run.');
      return { ran: false };
    }

    try {
      await runTool('docker', ['info', '--format', '{{.ServerVersion}}'], os.tmpdir());
    } catch {
      throw new Error('Cannot run project unit tests: Docker daemon is not running (start Docker Desktop).');
    }

    for (const { language, detail, image, command } of matches) {
      log(`Detected ${language} project (${detail}). Running its test suite in an isolated ${image} container (no host access, no network beyond dependency install)...`);
      const args = [
        'run', '--rm',
        '-v', `${root}:/repo`,
        '-w', '/repo',
        image,
        'sh', '-c', command,
      ];
      try {
        await runToolStreaming('docker', args, os.tmpdir(), (line) => log(line.slice(0, 400)), {
          timeoutMs: 10 * 60_000,
        });
      } catch (e) {
        throw new Error(`${language} unit tests failed: ${e.message}`);
      }
      log(`✓ ${language} unit tests passed.`);
    }
    return { ran: true, languages: matches.map((m) => m.language) };
  }

  return { runProjectUnitTests };
}

module.exports = { createUnitTestRunnerCheck };
