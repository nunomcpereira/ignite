'use strict';

/**
 * Built-in complexity/maintainability health scan — closes the "no
 * complexity/maintainability scoring" gap against fallow.tools (see project
 * memory). No external tool: a regex/bracket-depth pass per JS/TS/Python/
 * Go/Java/etc. source file (language-agnostic on decision-keyword
 * counting, the same tradeoff checks/feature-posture.js's fallback engine
 * makes for cross-language coverage) computing, per file:
 *
 *  - Cyclomatic complexity: 1 + count of branching constructs (if/else if/
 *    for/while/case/catch/&&/||/??/ternary).
 *  - Cognitive complexity: same decision points, weighted by nesting depth
 *    at the point they occur (Sonar's model — nesting compounds
 *    comprehension cost, not just path count).
 *  - Maintainability Index: Ignite's own JS/TS-friendly adaptation (we have
 *    no Halstead Volume without a real parser) —
 *    MI = 100 - 5.2*ln(complexityDensity+1) - 0.23*cyclomatic - 16.2*ln(loc+1),
 *    clamped to [0,100]. complexityDensity = cyclomatic / loc.
 *  - CRAP score: cyclomatic² * (1 - coverage/100)³ + cyclomatic, using
 *    per-file runtime coverage from lib/runtime-coverage.js when a project
 *    has ingested any (see gap 6 / Beacon-equivalent); coverage defaults to
 *    0 (worst case) when none has been ingested, so CRAP without coverage
 *    data is intentionally conservative rather than silently optimistic.
 *  - Hotspot score: normalized git churn (commit count touching the file,
 *    when `root` has real history) × normalized complexity — the
 *    intersection where defects concentrate. Falls back to complexity-only
 *    ranking when there's no git history to churn against (the common case
 *    for a freshly-uploaded ZIP/folder before Ignite's own `git init`).
 *
 * Always advisory (`severity: 'warning'`) — a health *signal* to prioritize
 * refactoring, never a hard gate, matching LOC metrics/posture's precedent
 * for descriptive-not-blocking Phase 4 checks.
 */

const fsp = require('fs/promises');
const path = require('path');

const CODE_EXT_RE = /\.(js|jsx|ts|tsx|mjs|cjs|py|go|rb|php|java|kt|cs|c|cpp|h|hpp|swift|rs|scala)$/i;
const DECISION_RE = /\b(if|else\s+if|for|while|case|catch|elif|except)\b|&&|\|\||\?\?|\?(?!\.)/g;
const OPEN_BRACE = /[{(]/g;
const CLOSE_BRACE = /[})]/g;

function cyclomaticAndCognitive(content) {
  const lines = content.split(/\r?\n/);
  let cyclomatic = 1;
  let cognitive = 0;
  let depth = 0;
  for (const line of lines) {
    const decisions = line.match(DECISION_RE);
    if (decisions) {
      cyclomatic += decisions.length;
      cognitive += decisions.length * (1 + depth);
    }
    const opens = (line.match(OPEN_BRACE) || []).length;
    const closes = (line.match(CLOSE_BRACE) || []).length;
    depth = Math.max(0, depth + opens - closes);
  }
  return { cyclomatic, cognitive };
}

// Calibrated (not the textbook SEI formula, which needs Halstead Volume we
// don't compute without a real parser): coefficients picked so a small,
// low-branching file scores in the 80s-90s and a large, branch-heavy file
// (e.g. a 1000-line file with cyclomatic complexity 100) scores in the
// teens — checked against a spread of file sizes, see checks/complexity-
// health.test.js.
function maintainabilityIndex(cyclomatic, loc) {
  const raw = 100 - 8 * Math.log(cyclomatic + 1) - 6 * Math.log(loc + 1);
  return Math.max(0, Math.min(100, Math.round(raw)));
}

function crapScore(cyclomatic, coveragePct) {
  const cov = Math.max(0, Math.min(100, coveragePct || 0)) / 100;
  return Math.round((cyclomatic * cyclomatic) * Math.pow(1 - cov, 3) + cyclomatic);
}

function createComplexityHealthCheck({ runTool, fsUtils, config }) {
  const { walkFiles, looksBinary, buildSnippet } = fsUtils;
  const ENABLED = config.enabled !== false;
  const CYCLOMATIC_WARN = Number(config.cyclomaticWarnThreshold) || 20; // classic "hard to test exhaustively" line, applied as a whole-file total below
  const MI_WARN = Number(config.maintainabilityWarnThreshold) || 40;
  // cyclomatic is summed per *file*, not per function (no real parser to
  // find function boundaries) — a raw >=20 total makes almost any
  // non-trivial file "too complex". Density (decision points per line of
  // code) normalizes for file size instead; 0.3 was picked empirically
  // against Ignite's own codebase (flags genuinely branch-heavy files —
  // server.js, override-engine.js — without flagging every file that
  // merely has more than ~65 lines and one branch).
  const DENSITY_WARN = Number(config.complexityDensityWarnThreshold) || 0.3;
  const TOP_N_HOTSPOTS = Number(config.topHotspots) || 10;

  async function gitChurn(root, relFiles) {
    if (!runTool) return new Map();
    const churn = new Map();
    try {
      const { stdout } = await runTool('git', ['log', '--name-only', '--pretty=format:', '--', '.'], root, { allowedExitCodes: [0, 1, 128] });
      for (const line of stdout.split('\n')) {
        const f = line.trim();
        if (!f) continue;
        churn.set(f, (churn.get(f) || 0) + 1);
      }
    } catch { /* no git history in this staging dir — churn stays empty, hotspots fall back to complexity-only */ }
    return churn;
  }

  async function checkComplexityHealth(root, log, { getCoverageForFile } = {}) {
    if (!ENABLED) {
      log?.('Complexity/health scan is disabled (health.enabled=false).');
      return { findings: [], engine: 'disabled', metrics: null };
    }

    const perFile = [];
    for await (const file of walkFiles(root)) {
      if (!CODE_EXT_RE.test(file)) continue;
      const buffer = await fsp.readFile(file).catch(() => null);
      if (!buffer || looksBinary(buffer)) continue;
      const content = buffer.toString('utf8');
      const loc = content.split(/\r?\n/).filter((l) => l.trim()).length;
      if (loc === 0) continue;
      const { cyclomatic, cognitive } = cyclomaticAndCognitive(content);
      const mi = maintainabilityIndex(cyclomatic, loc);
      const rel = path.relative(root, file);
      const coverage = getCoverageForFile ? await getCoverageForFile(rel) : null;
      const crap = crapScore(cyclomatic, coverage ?? 0);
      perFile.push({ file: rel, loc, cyclomatic, cognitive, mi, crap, coverage: coverage ?? null, content });
    }

    const churn = await gitChurn(root, perFile.map((f) => f.file));
    const maxComplexity = Math.max(1, ...perFile.map((f) => f.cyclomatic));
    const maxChurn = Math.max(1, ...perFile.map((f) => churn.get(f.file) || 0));
    for (const f of perFile) {
      const normComplexity = f.cyclomatic / maxComplexity;
      const normChurn = (churn.get(f.file) || 0) / maxChurn;
      // No real churn signal at all (fresh checkout) → rank on complexity
      // alone rather than letting an all-zero churn column zero out every
      // hotspot score.
      f.hotspot = maxChurn > 1 || churn.size > 0 ? Math.round(normComplexity * normChurn * 100) : Math.round(normComplexity * 100);
      f.churnCount = churn.get(f.file) || 0;
    }

    const findings = [];
    for (const f of perFile) {
      const density = f.cyclomatic / f.loc;
      if (f.cyclomatic >= CYCLOMATIC_WARN && density >= DENSITY_WARN) {
        findings.push({
          file: f.file, line: 1, kind: 'high-complexity', tool: 'ignite-built-in', severity: 'warning',
          message: `Cyclomatic complexity ${f.cyclomatic} (cognitive ${f.cognitive}) — over the ${CYCLOMATIC_WARN} threshold past which functions become difficult to test exhaustively. CRAP score ${f.crap}${f.coverage === null ? ' (no coverage data ingested — treated as 0% for CRAP)' : ` at ${f.coverage}% coverage`}.`,
          code: buildSnippet(f.content, 1),
        });
      } else if (f.mi < MI_WARN) {
        findings.push({
          file: f.file, line: 1, kind: 'low-maintainability', tool: 'ignite-built-in', severity: 'warning',
          message: `Maintainability Index ${f.mi}/100 — below the ${MI_WARN} threshold (complexity ${f.cyclomatic} over ${f.loc} lines of code).`,
          code: buildSnippet(f.content, 1),
        });
      }
    }

    const hotspots = [...perFile].sort((a, b) => b.hotspot - a.hotspot).slice(0, TOP_N_HOTSPOTS)
      .map((f) => ({ file: f.file, hotspot: f.hotspot, cyclomatic: f.cyclomatic, cognitive: f.cognitive, mi: f.mi, crap: f.crap, churnCount: f.churnCount }));

    const refactorTargets = [...perFile]
      .filter((f) => f.cyclomatic >= CYCLOMATIC_WARN || f.mi < MI_WARN || f.crap > 30)
      .sort((a, b) => (b.crap + (100 - b.mi)) - (a.crap + (100 - a.mi)))
      .slice(0, TOP_N_HOTSPOTS)
      .map((f) => ({
        file: f.file,
        reason: f.crap > 30 ? 'untested-complexity' : f.cyclomatic >= CYCLOMATIC_WARN ? 'extract-complex-function' : 'reduce-coupling',
        crap: f.crap, cyclomatic: f.cyclomatic, mi: f.mi,
      }));

    log?.(`Analyzed ${perFile.length} source file(s); ${findings.length} over threshold; churn signal: ${churn.size > 0 ? 'git history' : 'none (complexity-only ranking)'}.`);

    return {
      findings,
      engine: 'built-in',
      metrics: {
        fileCount: perFile.length,
        averageCyclomatic: perFile.length ? Math.round(perFile.reduce((s, f) => s + f.cyclomatic, 0) / perFile.length) : 0,
        averageMaintainability: perFile.length ? Math.round(perFile.reduce((s, f) => s + f.mi, 0) / perFile.length) : 0,
        hotspots,
        refactorTargets,
      },
    };
  }

  return { checkComplexityHealth };
}

module.exports = { createComplexityHealthCheck, cyclomaticAndCognitive, maintainabilityIndex, crapScore };
