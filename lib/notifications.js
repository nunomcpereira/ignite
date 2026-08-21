'use strict';

/**
 * Email notifications — pipeline failures and override audit trail.
 * Phase E of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {object} deps.config - CONFIG.notifications ({ enabled, to, from, smtp: { host, port, secure, user, pass } })
 * @param {object} deps.phaseTitles - PHASE_TITLES (id -> title), for the phase-status table in each email
 */
function createNotifications({ config, phaseTitles }) {
  const nodemailer = require('nodemailer');

  function buildMailTransport() {
    const { smtp } = config;
    if (smtp.host && smtp.user && smtp.pass) {
      return nodemailer.createTransport({
        host: smtp.host,
        port: smtp.port,
        secure: smtp.secure,
        auth: { user: smtp.user, pass: smtp.pass },
      });
    }
    // No SMTP credentials configured — fall back to the local sendmail binary.
    return nodemailer.createTransport({ sendmail: true });
  }

  function escapeHtmlMail(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function buildFailureEmail({ jobId, org, repo, error, failedPhase, record, insight }) {
    const rows = Object.keys(phaseTitles)
      .map((id) => {
        // eslint-disable-next-line security/detect-object-injection -- id comes from Object.keys(phaseTitles) itself, always a fixed known phase number
        const ph = record[id] || { state: 'pending', logs: [] };
        const color =
          ph.state === 'success' ? '#059669' :
          ph.state === 'failed' ? '#e11d48' :
          ph.state === 'running' ? '#2563eb' : '#94a3b8';
        // eslint-disable-next-line security/detect-object-injection -- id comes from Object.keys(phaseTitles) itself, always a fixed known phase number
        const title = phaseTitles[id];
        return `<tr>
          <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;">Phase ${id}</td>
          <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;">${title}</td>
          <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;color:${color};font-weight:600;text-transform:uppercase;">${ph.state}</td>
        </tr>`;
      })
      .join('');

    const failedSections = Object.keys(record)
      // eslint-disable-next-line security/detect-object-injection -- id comes from Object.keys(record) itself, always a fixed known phase number
      .filter((id) => record[id].state === 'failed' && record[id].logs.length > 0)
      .map((id) => {
        // eslint-disable-next-line security/detect-object-injection -- same fixed phaseTitles/record-key domain as above
        const title = phaseTitles[id];
        // eslint-disable-next-line security/detect-object-injection -- same fixed phaseTitles/record-key domain as above
        const logs = escapeHtmlMail(record[id].logs.join('\n'));
        return `
        <h3 style="margin:24px 0 8px;color:#0f172a;">Phase ${id} — ${title} logs</h3>
        <pre style="background:#0f172a;color:#e2e8f0;padding:14px;border-radius:8px;font-size:12px;line-height:1.6;overflow-x:auto;white-space:pre-wrap;">${logs}</pre>`;
      })
      .join('');

    // eslint-disable-next-line security/detect-object-injection -- failedPhase is always a fixed known phase number, never user input
    const failedPhaseTitle = phaseTitles[failedPhase] || 'Unknown';
    const subject = `[Ignite] ❌ Onboarding failed at Phase ${failedPhase} — ${org}/${repo}`;
    const html = `
    <div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:720px;margin:0 auto;color:#334155;">
      <h2 style="color:#e11d48;">Ignite onboarding pipeline failed</h2>
      <p><strong>Target:</strong> ${escapeHtmlMail(org)}/${escapeHtmlMail(repo)} (private)<br/>
         <strong>Job:</strong> ${jobId}<br/>
         <strong>Failed at:</strong> Phase ${failedPhase} — ${failedPhaseTitle}<br/>
         <strong>Error:</strong> ${escapeHtmlMail(error)}</p>
      <table style="border-collapse:collapse;width:100%;font-size:14px;">
        <tr style="background:#f1f5f9;">
          <th style="padding:6px 12px;text-align:left;">#</th>
          <th style="padding:6px 12px;text-align:left;">Phase</th>
          <th style="padding:6px 12px;text-align:left;">Status</th>
        </tr>
        ${rows}
      </table>
      ${insight ? `
      <h3 style="margin:24px 0 8px;color:#0f172a;">🤖 AI insight</h3>
      <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:14px;font-size:14px;line-height:1.6;white-space:pre-wrap;">${escapeHtmlMail(insight)}</div>` : ''}
      ${failedSections}
      <p style="color:#94a3b8;font-size:12px;margin-top:24px;">Sent by Ignite — staging files were cleaned up. Fix the violations and re-run the pipeline.</p>
    </div>`;

    return { subject, html };
  }

  async function sendFailureNotification(details) {
    const { enabled, to, from } = config;
    if (!enabled || !to) return { sent: false, reason: 'notifications disabled or no recipient configured' };
    const transport = buildMailTransport();
    const { subject, html } = buildFailureEmail(details);
    await transport.sendMail({ from, to, subject, html });
    return { sent: true, to };
  }

  /* A developer chose to bypass one or more flagged guideline violations.
     Always notify — this is the whole point of the override audit trail. */
  function buildOverrideEmail({ jobId, org, repo, phase, actor, applied }) {
    const rows = applied
      .map(
        ({ issue, justification }) => `
        <tr>
          <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;text-transform:uppercase;font-weight:600;color:${issue.severity === 'error' ? '#e11d48' : '#b45309'};">${escapeHtmlMail(issue.severity)}</td>
          <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;">${escapeHtmlMail(issue.category)}</td>
          <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;font-family:monospace;">${escapeHtmlMail(issue.file || '')}${issue.line ? ':' + issue.line : ''}</td>
          <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;">${escapeHtmlMail(issue.summary)}</td>
          <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;">${escapeHtmlMail(justification)}</td>
        </tr>`
      )
      .join('');

    const errorCount = applied.filter((a) => a.issue.severity === 'error').length;
    // eslint-disable-next-line security/detect-object-injection -- phase is always a fixed known phase number, never user input
    const phaseTitle = phaseTitles[phase] || 'Unknown';
    const subject = `[Ignite] ⚠ ${applied.length} guideline override(s) at Phase ${phase} — ${org}/${repo}`;
    const html = `
    <div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:760px;margin:0 auto;color:#334155;">
      <h2 style="color:#b45309;">A developer overrode flagged guideline check(s)</h2>
      <p><strong>Target:</strong> ${escapeHtmlMail(org)}/${escapeHtmlMail(repo)}<br/>
         <strong>Job:</strong> ${jobId}<br/>
         <strong>Phase:</strong> ${phase} — ${phaseTitle}<br/>
         <strong>Overridden by:</strong> ${escapeHtmlMail(actor.name || actor.email)} (${escapeHtmlMail(actor.email)})<br/>
         <strong>Blocking findings bypassed:</strong> ${errorCount} of ${applied.length}</p>
      <table style="border-collapse:collapse;width:100%;font-size:13px;">
        <tr style="background:#f1f5f9;">
          <th style="padding:6px 12px;text-align:left;">Severity</th>
          <th style="padding:6px 12px;text-align:left;">Category</th>
          <th style="padding:6px 12px;text-align:left;">Location</th>
          <th style="padding:6px 12px;text-align:left;">Finding</th>
          <th style="padding:6px 12px;text-align:left;">Justification</th>
        </tr>
        ${rows}
      </table>
      <p style="color:#94a3b8;font-size:12px;margin-top:24px;">Sent by Ignite — this override is recorded in the project's audit log.</p>
    </div>`;

    return { subject, html };
  }

  async function sendOverrideNotification(details) {
    const { enabled, to, from } = config;
    if (!enabled || !to) return { sent: false, reason: 'notifications disabled or no recipient configured' };
    const transport = buildMailTransport();
    const { subject, html } = buildOverrideEmail(details);
    await transport.sendMail({ from, to, subject, html });
    return { sent: true, to };
  }

  /* A headless API key was minted for an account. Notified to the key's
     owner (not the admin `to` list an override notification goes to) —
     that's the account being granted the ability to act as, so silent
     minting is exactly the impersonation vector this guards against. */
  function buildApiKeyCreatedEmail({ ownerEmail, ownerName, label, createdBy, createdVia }) {
    const subject = `[Ignite] A new API key was created for your account`;
    const html = `
    <div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:640px;margin:0 auto;color:#334155;">
      <h2 style="color:#b45309;">A new API key was created for your Ignite account</h2>
      <p><strong>Account:</strong> ${escapeHtmlMail(ownerName || ownerEmail)} (${escapeHtmlMail(ownerEmail)})<br/>
         <strong>Label:</strong> ${escapeHtmlMail(label || '(none)')}<br/>
         <strong>Created via:</strong> ${escapeHtmlMail(createdVia || 'cli')}<br/>
         <strong>Created by:</strong> ${escapeHtmlMail(createdBy || 'unknown')}</p>
      <p>This key can authenticate as you against the Ignite API without a browser
         login. If you did not request this, revoke it immediately and notify
         an administrator.</p>
      <p style="color:#94a3b8;font-size:12px;margin-top:24px;">Sent by Ignite — this event is recorded in the account's key audit log.</p>
    </div>`;
    return { subject, html };
  }

  /* Best-effort: a flaky SMTP endpoint must not fail key creation, but the
     event must always be knowable after the fact — see created_by/created_via
     columns on api_keys for the non-email half of this audit trail. */
  async function sendApiKeyCreatedNotification(details) {
    const { enabled, from } = config;
    if (!enabled || !details.ownerEmail) {
      return { sent: false, reason: 'notifications disabled or no owner email' };
    }
    const transport = buildMailTransport();
    const { subject, html } = buildApiKeyCreatedEmail(details);
    await transport.sendMail({ from, to: details.ownerEmail, subject, html });
    return { sent: true, to: details.ownerEmail };
  }

  return {
    buildMailTransport,
    escapeHtmlMail,
    buildFailureEmail,
    sendFailureNotification,
    buildOverrideEmail,
    sendOverrideNotification,
    buildApiKeyCreatedEmail,
    sendApiKeyCreatedNotification,
  };
}

module.exports = { createNotifications };
