/**
 * Pure (vscode-free) helpers for the org daily-report command — kept apart from
 * extension.ts/api.ts so `node --test` can exercise them without a VS Code host.
 */

export type ReportChannel = 'email' | 'webhook' | 'azure_blob' | 'pdf';

/** One org's outcome from `POST /api/reports/daily/run` (only the fields the extension reads). */
export interface DailyReportOutcome {
  org: string;
  repos: number;
  unjustifiedFindings: number;
  sent: boolean;
  reason?: string | null;
  error?: string | null;
  emailSent?: boolean;
  emailError?: string | null;
  webhookSent?: boolean;
  webhookError?: string | null;
  azureBlobSent?: boolean;
  azureBlobError?: string | null;
  pdfGenerated?: boolean;
  pdfError?: string | null;
  markdown?: string;
  webhookPayload?: { sentinelIncident?: { severity?: string } } | null;
}

export interface DailyReportResult {
  date: string;
  dryRun: boolean;
  channels: string[];
  reports: DailyReportOutcome[];
}

export interface DailyReportOptions {
  org?: string;
  /** Empty/omitted = every channel the server has configured. */
  channels?: ReportChannel[];
  dryRun?: boolean;
  webhookUrl?: string;
  to?: string;
}

export type ChannelPick = 'webhook' | 'azure_blob' | 'email' | 'pdf' | 'all';

export interface PlannedReport {
  /** Channels for the server-side run (`[]` = all configured). Omitted when only the PDF was asked for. */
  serverChannels: ReportChannel[] | null;
  /** Whether to also download the org's PDF to disk. */
  downloadPdf: boolean;
}

export function planForPick(pick: ChannelPick): PlannedReport {
  switch (pick) {
    case 'webhook': return { serverChannels: ['webhook'], downloadPdf: false };
    case 'azure_blob': return { serverChannels: ['azure_blob'], downloadPdf: false };
    case 'email': return { serverChannels: ['email'], downloadPdf: false };
    case 'pdf': return { serverChannels: null, downloadPdf: true };
    case 'all': return { serverChannels: [], downloadPdf: true };
  }
}

export interface ReportSummary {
  /** Headline for the notification. */
  message: string;
  /** True when any channel reported an error. */
  hasFailures: boolean;
  /** One line per org/channel outcome, for the Output channel. */
  lines: string[];
}

export function summarizeReports(result: DailyReportResult): ReportSummary {
  const lines: string[] = [];
  let hasFailures = false;
  let repos = 0;
  let findings = 0;
  let delivered = 0;
  for (const r of result.reports) {
    repos += r.repos;
    findings += r.unjustifiedFindings;
    lines.push(`${r.org}: ${r.repos} repo(s), ${r.unjustifiedFindings} unjustified finding(s)`);
    const channelLines: [string, boolean | undefined, string | null | undefined][] = [
      ['email', r.emailSent, r.emailError],
      ['sentinel/webhook', r.webhookSent, r.webhookError],
      ['azure blob', r.azureBlobSent, r.azureBlobError],
      ['pdf', r.pdfGenerated, r.pdfError],
    ];
    for (const [name, ok, err] of channelLines) {
      if (ok) {
        lines.push(`  ${name}: ok`);
      } else if (err) {
        // A PDF that couldn't be rendered only matters if PDF was asked for.
        if (name === 'pdf' && !result.channels.includes('pdf')) continue;
        hasFailures = true;
        lines.push(`  ${name}: FAILED — ${err}`);
      }
    }
    if (!r.emailSent && !r.emailError && r.reason && !result.dryRun) lines.push(`  email: skipped — ${r.reason}`);
    if (r.sent) delivered++;
  }
  if (result.reports.length === 0) {
    return { message: 'Ignite: no scanned repositories — nothing to report.', hasFailures: false, lines };
  }
  const counts = `${result.reports.length} org(s), ${repos} repo(s), ${findings} unjustified finding(s)`;
  if (result.dryRun) return { message: `Ignite report preview (nothing sent): ${counts}.`, hasFailures, lines };
  const message = hasFailures
    ? `Ignite report: some channels failed — ${counts}. See the Output panel.`
    : delivered > 0
      ? `Ignite report delivered: ${counts}.`
      : `Ignite report: nothing was delivered (no channel configured/enabled) — ${counts}.`;
  return { message, hasFailures: hasFailures || delivered === 0, lines };
}

/** `ignite-report-<org>-<yyyy-mm-dd>.pdf`, with the org sanitized for a filename. */
export function defaultPdfName(org: string, date: Date = new Date()): string {
  const safeOrg = org.replace(/[^A-Za-z0-9._-]/g, '');
  return `ignite-report-${safeOrg}-${date.toISOString().slice(0, 10)}.pdf`;
}
