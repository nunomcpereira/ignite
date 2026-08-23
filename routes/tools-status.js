'use strict';

/**
 * GET /api/tools/status — informational connected/disconnected status for
 * every optional external tool Ignite integrates with. Never gates
 * anything itself. Phase F of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {object} deps.toolings - { ortTooling, licenseeTooling, gitleaksTooling, trivyTooling, trivyImageTooling, checkovTooling, hadolintTooling, syftTooling, cosignTooling, semgrepTooling, bearerTooling, jscpdTooling, goclocTooling, spectralTooling, guarddogTooling, codeqlTooling, picklescanTooling, oasdiffTooling }
 * @param {object} deps.enabled - { gitleaksEnabled, trivyEnabled, trivyImageEnabled, checkovEnabled, hadolintEnabled, syftEnabled, cosignEnabled, semgrepEnabled, bearerEnabled, jscpdEnabled, goclocEnabled, spectralEnabled, guarddogEnabled, codeqlEnabled, picklescanEnabled, oasdiffEnabled }
 */
function mountToolsStatusRoutes(app, { toolings, enabled }) {
  const {
    ortTooling, licenseeTooling, gitleaksTooling, trivyTooling, trivyImageTooling,
    checkovTooling, hadolintTooling, syftTooling, cosignTooling, semgrepTooling,
    bearerTooling, jscpdTooling, goclocTooling, spectralTooling, guarddogTooling, codeqlTooling,
    picklescanTooling, oasdiffTooling,
  } = toolings;
  const {
    gitleaksEnabled, trivyEnabled, trivyImageEnabled, checkovEnabled, hadolintEnabled,
    syftEnabled, cosignEnabled, semgrepEnabled, bearerEnabled, jscpdEnabled,
    goclocEnabled, spectralEnabled, guarddogEnabled, codeqlEnabled, picklescanEnabled, oasdiffEnabled,
  } = enabled;

  app.get('/api/tools/status', async (req, res) => {
    const [ort, licensee, gitleaks, trivy, trivyImage, checkov, hadolint, syft, cosign, semgrep, bearer, jscpd, gocloc, spectral, guarddog, codeql, picklescan, oasdiff] = await Promise.all([
      ortTooling(), licenseeTooling(), gitleaksTooling(), trivyTooling(), trivyImageTooling(), checkovTooling(), hadolintTooling(), syftTooling(), cosignTooling(), semgrepTooling(), bearerTooling(), jscpdTooling(), goclocTooling(), spectralTooling(), guarddogTooling(), codeqlTooling(), picklescanTooling(), oasdiffTooling(),
    ]);
    res.json({
      ort: { ...ort, enabled: true },
      licensee: { ...licensee, enabled: true },
      gitleaks: { ...gitleaks, enabled: gitleaksEnabled },
      trivy: { ...trivy, enabled: trivyEnabled },
      trivyImage: { ...trivyImage, enabled: trivyImageEnabled },
      checkov: { ...checkov, enabled: checkovEnabled },
      hadolint: { ...hadolint, enabled: hadolintEnabled },
      syft: { ...syft, enabled: syftEnabled },
      cosign: { ...cosign, enabled: cosignEnabled },
      semgrep: { ...semgrep, enabled: semgrepEnabled },
      bearer: { ...bearer, enabled: bearerEnabled },
      jscpd: { ...jscpd, enabled: jscpdEnabled },
      gocloc: { ...gocloc, enabled: goclocEnabled },
      spectral: { ...spectral, enabled: spectralEnabled },
      guarddog: { ...guarddog, enabled: guarddogEnabled },
      codeql: { ...codeql, enabled: codeqlEnabled },
      picklescan: { ...picklescan, enabled: picklescanEnabled },
      oasdiff: { ...oasdiff, enabled: oasdiffEnabled },
    });
  });
}

module.exports = { mountToolsStatusRoutes };
