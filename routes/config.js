'use strict';

/**
 * GET /api/config — safe subset of config for the frontend. Phase F of the
 * server.js module split (see /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {object} deps.config - CONFIG
 * @param {Function} deps.llmAvailableCached - lib/llm-client.js's createLlmClient() result
 * @param {Array} deps.defaultPhaseMeta - DEFAULT_PHASE_META
 * @param {Array} deps.phaseMeta - PHASE_META
 * @param {string} deps.igniteVersion - IGNITE_VERSION
 */
function mountConfigRoutes(app, { config, llmAvailableCached, defaultPhaseMeta, phaseMeta, igniteVersion }) {
  /* Safe subset of config for the frontend. `orgs` accepts a comma-separated
     string or an array; first entry is the default proposal. */
  app.get('/api/config', async (req, res) => {
    const raw = config.github.orgs;
    const orgs = (Array.isArray(raw) ? raw : String(raw).split(','))
      .map((s) => String(s).trim())
      .filter(Boolean);
    // Phase 4 still runs everything else (secrets/AI-governance/IaC/SAST/
    // etc.) with no LLM configured or reachable — only its LLM deep-scan
    // sub-check is skipped — so its displayed name shouldn't claim an "AI"
    // check ran when it didn't. Only swaps the *unmodified* default title;
    // an org that already customized phase 4's title via config.json's
    // `phases` override is left alone.
    const aiAvailable = await llmAvailableCached();
    const defaultPhase4Title = defaultPhaseMeta.find((d) => d.id === 4)?.title;
    const phases = phaseMeta.map((p) => {
      if (p.id !== 4 || aiAvailable || p.title !== defaultPhase4Title) return p;
      return { ...p, title: 'Security & Compliance Scan' };
    });
    res.json({ orgs, phases, version: igniteVersion });
  });
}

module.exports = { mountConfigRoutes };
