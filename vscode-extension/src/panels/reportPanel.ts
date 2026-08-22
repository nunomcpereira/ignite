import * as vscode from 'vscode';

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
}

/**
 * Renders an arbitrary JSON report (license compliance / SBOM / LOC metrics
 * / posture — all shapes returned as-is by their respective server
 * endpoints) as a read-only webview: a `<pre>` of pretty-printed JSON is
 * enough for v1 — these are inspect-and-export reports the web UI already
 * renders in full, not something the extension needs a bespoke table
 * layout for. One panel per report kind, reused across re-renders instead
 * of stacking a new tab per refresh.
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
  const json = escapeHtml(JSON.stringify(data, null, 2));
  panel.webview.html = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  body { font-family: var(--vscode-editor-font-family, monospace); padding: 0 1rem; }
  pre { white-space: pre-wrap; word-break: break-word; font-size: var(--vscode-editor-font-size, 13px); }
</style>
</head>
<body>
<pre>${json}</pre>
</body>
</html>`;
}
