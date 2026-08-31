import * as vscode from 'vscode';
import { encode } from 'he';

function escapeHtml(s: unknown): string {
  return encode(String(s ?? ''), { useNamedReferences: true });
}

const SHARED_STYLE = `
  :root { color-scheme: light dark; }
  body {
    font-family: var(--vscode-font-family, sans-serif);
    font-size: var(--vscode-font-size, 13px);
    padding: 0 1.25rem 2rem;
    color: var(--vscode-foreground);
  }
  h1 { font-size: 1.1rem; font-weight: 600; margin: 1.25rem 0 0.25rem; }
  .subtitle { color: var(--vscode-descriptionForeground); margin-bottom: 1rem; }
  .summary { display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1.25rem; }
  .stat {
    border: 1px solid var(--vscode-panel-border, #4443);
    border-radius: 6px;
    padding: 0.4rem 0.75rem;
    font-size: 0.85rem;
  }
  .stat b { font-size: 1rem; display: block; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }
  th, td {
    text-align: left;
    padding: 0.35rem 0.6rem;
    border-bottom: 1px solid var(--vscode-panel-border, #4443);
    vertical-align: top;
  }
  th {
    position: sticky; top: 0;
    background: var(--vscode-editor-background);
    font-weight: 600;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.02em;
    color: var(--vscode-descriptionForeground);
  }
  tr:hover td { background: var(--vscode-list-hoverBackground); }
  code {
    font-family: var(--vscode-editor-font-family, monospace);
    font-size: 0.9em;
    background: var(--vscode-textCodeBlock-background, #8882);
    padding: 0.05rem 0.3rem;
    border-radius: 3px;
  }
  .badge {
    display: inline-block;
    border-radius: 3px;
    padding: 0.05rem 0.45rem;
    font-size: 0.78rem;
    font-weight: 600;
    text-transform: uppercase;
  }
  .badge-green { background: #2ea04333; color: #3fb950; }
  .badge-yellow { background: #d2992233; color: #e3b341; }
  .badge-red { background: #f8514933; color: #f85149; }
  .badge-blue { background: #58a6ff33; color: #58a6ff; }
  .badge-grey { background: #8b949e33; color: #8b949e; }
  details.group { margin-bottom: 0.75rem; }
  details.group > summary {
    cursor: pointer;
    font-weight: 600;
    padding: 0.3rem 0;
    list-style: none;
  }
  details.group > summary::-webkit-details-marker { display: none; }
  details.group > summary::before { content: '▸ '; }
  details.group[open] > summary::before { content: '▾ '; }
  .empty { color: var(--vscode-descriptionForeground); font-style: italic; padding: 1rem 0; }
`;

function page(title: string, subtitle: string, body: string): string {
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>${SHARED_STYLE}</style>
</head>
<body>
<h1>${escapeHtml(title)}</h1>
<div class="subtitle">${escapeHtml(subtitle)}</div>
${body}
</body>
</html>`;
}

function tierBadge(tier: unknown): string {
  const t = String(tier || '').toLowerCase();
  const cls = t === 'green' ? 'badge-green' : t === 'yellow' ? 'badge-yellow' : t === 'red' ? 'badge-red'
    : t === 'internal' ? 'badge-blue' : 'badge-grey';
  return `<span class="badge ${cls}">${escapeHtml(tier || 'unknown')}</span>`;
}

function postureBadge(status: unknown): string {
  const s = String(status || '').toUpperCase();
  const cls = s === 'DETECTED' ? 'badge-green' : s === 'PARTIAL' ? 'badge-yellow' : 'badge-red';
  return `<span class="badge ${cls}">${escapeHtml(s || 'UNKNOWN')}</span>`;
}

function stat(label: string, value: string | number): string {
  return `<div class="stat"><b>${escapeHtml(value)}</b>${escapeHtml(label)}</div>`;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function renderLicense(data: Record<string, unknown>): string {
  const manifests = Array.isArray(data.manifests) ? data.manifests : [];
  let total = 0;
  const counts: Record<string, number> = { green: 0, yellow: 0, red: 0, internal: 0 };
  const rows: string[] = [];
  for (const m of manifests) {
    if (!isPlainObject(m)) continue;
    const deps = Array.isArray(m.dependencies) ? m.dependencies : [];
    if (deps.length === 0) continue;
    const depRows = deps.map((d) => {
      if (!isPlainObject(d)) return '';
      total++;
      const tier = String(d.tier || 'unknown').toLowerCase();
      if (counts[tier] !== undefined) counts[tier]++;
      const licenses = Array.isArray(d.licenses) ? d.licenses.join(', ') : (d.license ?? '');
      return `<tr>
        <td><code>${escapeHtml(d.name)}</code></td>
        <td>${escapeHtml(d.version ?? d.versionRange ?? '')}</td>
        <td>${escapeHtml(licenses)}</td>
        <td>${tierBadge(d.tier)}</td>
        <td>${escapeHtml(d.reason ?? '')}</td>
      </tr>`;
    }).join('');
    rows.push(`<details class="group" open>
      <summary>${escapeHtml(m.ecosystem || m.file || 'manifest')} — ${escapeHtml(m.file || '')} (${deps.length})</summary>
      <table>
        <thead><tr><th>Package</th><th>Version</th><th>License(s)</th><th>Tier</th><th>Reason</th></tr></thead>
        <tbody>${depRows}</tbody>
      </table>
    </details>`);
  }
  const summary = `<div class="summary">
    ${stat('total dependencies', total)}
    ${stat('green', counts.green)}
    ${stat('yellow', counts.yellow)}
    ${stat('red', counts.red)}
    ${stat('internal', counts.internal)}
  </div>`;
  return summary + (rows.length ? rows.join('') : '<div class="empty">No manifest dependencies found.</div>');
}

function renderSbom(data: Record<string, unknown>): string {
  const sbom = isPlainObject(data.sbom) ? data.sbom : {};
  const components = Array.isArray(sbom.components) ? sbom.components : [];
  const rows = components.map((c) => {
    if (!isPlainObject(c)) return '';
    const licenses = Array.isArray(c.licenses)
      ? c.licenses.map((l) => (isPlainObject(l) ? (l.license as Record<string, unknown> | undefined)?.id ?? (l.expression ?? '') : l)).join(', ')
      : '';
    return `<tr>
      <td><code>${escapeHtml(c.name)}</code></td>
      <td>${escapeHtml(c.version ?? '')}</td>
      <td>${escapeHtml(c.type ?? c.ecosystem ?? '')}</td>
      <td>${escapeHtml(licenses)}</td>
      <td><code>${escapeHtml(c.purl ?? '')}</code></td>
    </tr>`;
  }).join('');
  const summary = `<div class="summary">
    ${stat('components', components.length)}
    ${stat('engine', String(data.engine ?? 'unknown'))}
    ${stat('format', String(sbom.bomFormat ?? 'CycloneDX'))}
  </div>`;
  const table = components.length
    ? `<table><thead><tr><th>Component</th><th>Version</th><th>Type</th><th>License(s)</th><th>PURL</th></tr></thead><tbody>${rows}</tbody></table>`
    : '<div class="empty">No components found.</div>';
  return summary + table;
}

function renderLocMetrics(data: Record<string, unknown>): string {
  const metrics = isPlainObject(data.metrics) ? data.metrics : {};
  const languages = Array.isArray(metrics.languages) ? [...metrics.languages] : [];
  languages.sort((a, b) => (isPlainObject(b) && isPlainObject(a) ? (Number(b.code) || 0) - (Number(a.code) || 0) : 0));
  const total = isPlainObject(metrics.total) ? metrics.total : {};
  const rows = languages.map((l) => {
    if (!isPlainObject(l)) return '';
    return `<tr>
      <td>${escapeHtml(l.name)}</td>
      <td>${escapeHtml(l.files)}</td>
      <td>${escapeHtml(l.code)}</td>
      <td>${escapeHtml(l.comment)}</td>
      <td>${escapeHtml(l.blank)}</td>
    </tr>`;
  }).join('');
  const summary = `<div class="summary">
    ${stat('languages', languages.length)}
    ${stat('files', String(total.files ?? ''))}
    ${stat('lines of code', String(total.code ?? ''))}
    ${stat('comments', String(total.comment ?? ''))}
    ${stat('blank', String(total.blank ?? ''))}
  </div>`;
  const table = languages.length
    ? `<table><thead><tr><th>Language</th><th>Files</th><th>Code</th><th>Comments</th><th>Blank</th></tr></thead><tbody>${rows}</tbody></table>`
    : '<div class="empty">No LOC metrics available.</div>';
  return summary + table;
}

function renderPosture(data: Record<string, unknown>): string {
  const posture = isPlainObject(data.posture) ? data.posture : {};
  const entries = Object.entries(posture).filter(([, v]) => isPlainObject(v));
  const counts: Record<string, number> = { DETECTED: 0, PARTIAL: 0, MISSING: 0 };
  const cards = entries.map(([category, value]) => {
    const v = value as Record<string, unknown>;
    const status = String(v.status ?? 'MISSING').toUpperCase();
    if (counts[status] !== undefined) counts[status]++;
    const matches = Array.isArray(v.matches) ? v.matches : [];
    const matchRows = matches.map((m) => {
      if (!isPlainObject(m)) return '';
      return `<tr>
        <td><code>${escapeHtml(m.file)}:${escapeHtml(m.line)}</code></td>
        <td>${escapeHtml(m.tier ?? '')}</td>
        <td>${escapeHtml(m.message ?? '')}</td>
      </tr>`;
    }).join('');
    const table = matches.length
      ? `<table><thead><tr><th>Location</th><th>Tier</th><th>Signal</th></tr></thead><tbody>${matchRows}</tbody></table>`
      : '<div class="empty">No signals found for this category.</div>';
    return `<details class="group">
      <summary>${postureBadge(status)} ${escapeHtml(category)}</summary>
      ${table}
    </details>`;
  }).join('');
  const summary = `<div class="summary">
    ${stat('detected', counts.DETECTED)}
    ${stat('partial', counts.PARTIAL)}
    ${stat('missing', counts.MISSING)}
  </div>`;
  return summary + (cards || '<div class="empty">No posture categories reported.</div>');
}

const RENDERERS: Record<string, (data: Record<string, unknown>) => string> = {
  license: renderLicense,
  sbom: renderSbom,
  'loc-metrics': renderLocMetrics,
  posture: renderPosture,
};

/**
 * Renders a Phase 4 report (license compliance / SBOM / LOC metrics /
 * posture) as a themed HTML table view instead of raw JSON — v1 shipped a
 * `<pre>` of pretty-printed JSON for every report kind, which was fine for
 * machine consumption but unreadable for a human skimming a 200-dependency
 * license report. Each known report `id` gets a dedicated table/summary
 * renderer; anything else (or a shape a renderer can't make sense of) falls
 * back to the original pretty-printed JSON so no report kind is ever a dead
 * end. One panel per report kind, reused across re-renders instead of
 * stacking a new tab per refresh.
 */
const panels = new Map<string, vscode.WebviewPanel>();

export function showReport(id: string, title: string, data: unknown): void {
  let panel = panels.get(id);
  if (panel) {
    panel.reveal(vscode.ViewColumn.Beside);
  } else {
    panel = vscode.window.createWebviewPanel(`ignite.report.${id}`, title, vscode.ViewColumn.Beside, {
      enableScripts: false,
    });
    panel.onDidDispose(() => panels.delete(id));
    panels.set(id, panel);
  }
  panel.title = title;

  const renderer = RENDERERS[id];
  let body: string;
  let subtitle = isPlainObject(data) ? String((data as Record<string, unknown>).projectPath ?? '') : '';
  try {
    if (renderer && isPlainObject(data)) {
      body = renderer(data);
    } else {
      throw new Error('no renderer for this report shape');
    }
  } catch {
    subtitle = 'Raw JSON (no table view available for this report)';
    body = `<pre style="white-space:pre-wrap;word-break:break-word;">${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
  }

  panel.webview.html = page(title, subtitle, body);
}
