'use strict';

/**
 * EU AI Act doc-presence scan — the process/governance obligations that
 * dominate the Act (risk-management system, Annex IV technical
 * documentation, fundamental rights impact assessment, GPAI training-data
 * summary, post-market monitoring plan) are org-process artifacts, not
 * code, so there's no call-site/import signature to detect the way
 * checks/feature-posture.js does for the three code-detectable Art. 5/12/13
 * signals. This check answers a much weaker question — "does an expected
 * document exist anywhere in the repo?" — by filename/path pattern only.
 *
 * Deliberately never produces issues and never blocks a run: absence in
 * this one repo's tree is not evidence the document doesn't exist
 * elsewhere in the org (a wiki, a GRC tool, a separate compliance repo),
 * so DETECTED/MISSING here is advisory context for a human, exactly like
 * checkFeaturePosture's report and the SBOM/LOC-metrics documents.
 *
 * @param {object} deps
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles, relativeToRoot)
 * @param {object} deps.config - { enabled }
 */
function createComplianceDocumentsCheck({ fsUtils, config }) {
  const path = require('path');
  const { walkFiles, relativeToRoot } = fsUtils;

  const ENABLED = Boolean(config.enabled);

  const DOCUMENT_CATEGORIES = [
    'risk-management-system', // Art. 9
    'technical-documentation', // Art. 11 / Annex IV
    'fria', // Art. 27 — fundamental rights impact assessment
    'training-data-summary', // Art. 53 — GPAI providers
    'post-market-monitoring', // Art. 72
  ];

  // Filename/path patterns only — deliberately not content-sniffed the way
  // ignite-posture-rules.yaml's rules are, since these are prose documents
  // (any format: .md/.pdf/.docx) with no reliable code-level signature.
  const DOCUMENT_PATTERNS = {
    'risk-management-system': /risk[-_ ]?management([-_ ]?system)?|\brms\b/i,
    'technical-documentation': /annex[-_ ]?iv|technical[-_ ]?documentation|tech[-_ ]?docs?/i,
    'fria': /\bfria\b|fundamental[-_ ]?rights[-_ ]?impact/i,
    'training-data-summary': /training[-_ ]?data[-_ ]?summary|dataset[-_ ]?summary|model[-_ ]?card/i,
    'post-market-monitoring': /post[-_ ]?market[-_ ]?monitoring|\bpmms\b/i,
  };

  function emptyDocumentsReport() {
    const documents = {};
    for (const cat of DOCUMENT_CATEGORIES) documents[cat] = { status: 'MISSING', matches: [] };
    return documents;
  }

  async function checkComplianceDocuments(root, log) {
    const documents = emptyDocumentsReport();
    if (!ENABLED) {
      log?.('✓ Check skipped — EU AI Act document-presence scan disabled (compliance.euAiActDocuments.enabled=false).');
      return { engine: 'disabled', documents };
    }

    log?.('Engine: Ignite Built-In Document-Presence Scanner (filename/path match only)');
    for await (const file of walkFiles(root)) {
      const base = path.basename(file);
      const rel = await relativeToRoot(root, file);
      for (const category of DOCUMENT_CATEGORIES) {
        if (DOCUMENT_PATTERNS[category].test(base) || DOCUMENT_PATTERNS[category].test(rel)) {
          documents[category].matches.push({ file: rel });
        }
      }
    }
    for (const category of DOCUMENT_CATEGORIES) {
      documents[category].status = documents[category].matches.length > 0 ? 'DETECTED' : 'MISSING';
    }
    return { engine: 'built-in', documents };
  }

  return { checkComplianceDocuments, DOCUMENT_CATEGORIES };
}

module.exports = { createComplianceDocumentsCheck };
