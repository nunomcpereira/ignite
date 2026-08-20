import * as vscode from 'vscode';
import * as path from 'path';
import type { IgnitePhase, IgniteIssue } from '../api';

type Node = PhaseNode | IssueNode;

class PhaseNode {
  readonly kind = 'phase';
  constructor(public phase: IgnitePhase, public issues: IgniteIssue[]) {}
}

class IssueNode {
  readonly kind = 'issue';
  constructor(public issue: IgniteIssue) {}
}

const STATE_ICON: Record<string, vscode.ThemeIcon> = {
  success: new vscode.ThemeIcon('pass', new vscode.ThemeColor('testing.iconPassed')),
  failed: new vscode.ThemeIcon('error', new vscode.ThemeColor('testing.iconFailed')),
  skipped: new vscode.ThemeIcon('circle-slash'),
  running: new vscode.ThemeIcon('sync~spin'),
  pending: new vscode.ThemeIcon('circle-outline'),
};

/** Explorer-sidebar replacement for the web UI's phase cards + issue list. */
export class FindingsTreeProvider implements vscode.TreeDataProvider<Node> {
  private _onDidChangeTreeData = new vscode.EventEmitter<Node | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private phases: IgnitePhase[] = [];
  private issues: IgniteIssue[] = [];
  private workspaceRoot = '';

  setResult(phases: IgnitePhase[], issues: IgniteIssue[], workspaceRoot: string): void {
    this.phases = phases;
    this.issues = issues;
    this.workspaceRoot = workspaceRoot;
    this._onDidChangeTreeData.fire(undefined);
  }

  clear(): void {
    this.setResult([], [], '');
  }

  getTreeItem(node: Node): vscode.TreeItem {
    if (node.kind === 'phase') {
      const item = new vscode.TreeItem(
        `Phase ${node.phase.phase} — ${node.phase.title}`,
        node.issues.length > 0 ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None
      );
      item.iconPath = STATE_ICON[node.phase.state] ?? STATE_ICON.pending;
      item.description = node.issues.length > 0 ? `${node.issues.length} issue(s)` : node.phase.state;
      return item;
    }
    const issue = node.issue;
    const loc = issue.file ? `${path.basename(issue.file)}${issue.line ? ':' + issue.line : ''}` : '';
    const item = new vscode.TreeItem(`${loc ? loc + ' — ' : ''}${issue.summary}`, vscode.TreeItemCollapsibleState.None);
    item.description = issue.category;
    item.iconPath = new vscode.ThemeIcon(
      issue.status === 'overridden' ? 'check' : issue.severity === 'error' ? 'error' : 'warning',
      new vscode.ThemeColor(
        issue.status === 'overridden'
          ? 'disabledForeground'
          : issue.severity === 'error'
          ? 'testing.iconFailed'
          : 'notificationsWarningIcon.foreground'
      )
    );
    if (issue.file) {
      const abs = path.isAbsolute(issue.file) ? issue.file : path.join(this.workspaceRoot, issue.file);
      item.command = {
        command: 'vscode.open',
        title: 'Open',
        arguments: [vscode.Uri.file(abs), { selection: new vscode.Range((issue.line ?? 1) - 1, 0, (issue.line ?? 1) - 1, 0) }],
      };
    }
    item.contextValue = issue.severity === 'error' && issue.status !== 'overridden' ? 'igniteUnresolvedIssue' : 'igniteIssue';
    return item;
  }

  getChildren(node?: Node): Node[] {
    if (!node) return this.phases.map((p) => new PhaseNode(p, this.issues.filter((i) => this.issueBelongsToPhase(i, p))));
    if (node.kind === 'phase') return node.issues.map((i) => new IssueNode(i));
    return [];
  }

  // validate-all's issues[] carries no per-issue phase number — license/
  // dependency-vulnerability findings (logged under Phase 3's log stream)
  // and Phase 4's own findings are returned as one flat list. Grouping them
  // all under the Phase 4 node is a cosmetic simplification for v1; the
  // Problems panel (diagnostics.ts) remains the source of truth for file/
  // line accuracy regardless of which phase node an issue is nested under.
  private issueBelongsToPhase(_issue: IgniteIssue, phase: IgnitePhase): boolean {
    return phase.phase === 4;
  }
}
