import * as vscode from 'vscode';
import * as path from 'path';
import type { IgniteIssue } from './api';

export const DIAGNOSTIC_SOURCE = 'ignite';

function severityOf(issue: IgniteIssue): vscode.DiagnosticSeverity {
  return issue.severity === 'error' ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning;
}

export function issueDiagnostic(issue: IgniteIssue): vscode.Diagnostic {
  const line = Math.max(0, (issue.line ?? 1) - 1);
  const range = new vscode.Range(line, 0, line, 10_000);
  const diag = new vscode.Diagnostic(range, `[${issue.category}] ${issue.summary}`, severityOf(issue));
  diag.source = DIAGNOSTIC_SOURCE;
  diag.code = issue.id;
  if (issue.status === 'overridden') {
    diag.tags = [vscode.DiagnosticTag.Unnecessary];
  }
  return diag;
}

/**
 * Publishes one Diagnostic per file-addressable issue. Issues already
 * acknowledged in .ignite-review.md are dropped unless showOverridden is
 * set, mirroring the web UI's OVERRIDDEN badge — an acknowledged finding
 * is a resolved audit record, not something to keep nagging about.
 */
export function publishDiagnostics(
  collection: vscode.DiagnosticCollection,
  workspaceRoot: string,
  issues: IgniteIssue[],
  showOverridden: boolean
): void {
  collection.clear();
  const byFile = new Map<string, vscode.Diagnostic[]>();
  for (const issue of issues) {
    if (!issue.file) continue;
    if (issue.status === 'overridden' && !showOverridden) continue;
    const abs = path.isAbsolute(issue.file) ? issue.file : path.join(workspaceRoot, issue.file);
    const list = byFile.get(abs) ?? [];
    list.push(issueDiagnostic(issue));
    byFile.set(abs, list);
  }
  for (const [file, diags] of byFile) {
    collection.set(vscode.Uri.file(file), diags);
  }
}
