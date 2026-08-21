'use strict';

/**
 * Reshapes Ignite's flat issue list (collectPhase4Issues' output, as
 * persisted in the `issues` table / returned by store.getProjectIssues)
 * into SARIF 2.1.0 — see routes/sarif.js for the endpoint and rationale.
 * Pulled out to its own module so the mapping (severity→level, stable
 * id→partialFingerprints, etc.) is unit-testable without booting a server.
 */

const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

// error → blocking; anything else Ignite calls "warning" maps to SARIF
// warning; a fully-overridden issue is downgraded to "note" — it was a
// real finding, but a human already justified it, so it shouldn't read as
// an open blocker to a SARIF consumer either.
function sarifLevel(issue) {
  if (issue.status === 'overridden') return 'note';
  return issue.severity === 'error' ? 'error' : 'warning';
}

function ruleIdFor(issue) {
  return String(issue.category || 'ignite-finding').replace(/[^a-zA-Z0-9._-]/g, '-');
}

function toSarifResult(issue) {
  const result = {
    ruleId: ruleIdFor(issue),
    level: sarifLevel(issue),
    message: { text: issue.summary || '(no summary)' },
    // Stable across reruns of the same project — collectPhase4Issues'
    // `<category>::<file>::<line>` id — so a SARIF consumer's own
    // dedup/baseline logic can track one finding across runs.
    partialFingerprints: { igniteIssueId: issue.id },
    properties: {
      status: issue.status,
      ...(typeof issue.score === 'number' ? { igniteScore: issue.score } : {}),
      ...(issue.crossFile ? { crossFile: true } : {}),
      ...(issue.chain ? { chain: issue.chain } : {}),
      ...(issue.cwe ? { cwe: issue.cwe } : {}),
    },
  };
  if (issue.file) {
    result.locations = [{
      physicalLocation: {
        artifactLocation: { uri: issue.file },
        ...(Number.isInteger(issue.line) && issue.line > 0
          ? { region: { startLine: issue.line } }
          : {}),
      },
    }];
  }
  return result;
}

function buildSarif(issues) {
  const rules = new Map();
  for (const issue of issues) {
    const id = ruleIdFor(issue);
    if (!rules.has(id)) {
      rules.set(id, {
        id,
        shortDescription: { text: issue.category },
        defaultConfiguration: { level: issue.severity === 'error' ? 'error' : 'warning' },
      });
    }
  }
  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Ignite',
          informationUri: 'https://github.com/nunomcpereira/ignite',
          rules: [...rules.values()],
        },
      },
      results: issues.map(toSarifResult),
    }],
  };
}

module.exports = { buildSarif, sarifLevel, ruleIdFor };
