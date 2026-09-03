import * as vscode from 'vscode';
import * as path from 'path';
import type { IgnitePhase, IgniteIssue } from '../api';

export type Node = PhaseNode | FindingGroupNode | IssueNode;

class PhaseNode {
  readonly kind = 'phase';
  constructor(public phase: IgnitePhase, public issues: IgniteIssue[]) {}
}

/**
 * One row per distinct finding (same category + summary text, e.g. "same
 * secret-detection rule fired") — the different files/lines it occurred at
 * nest underneath as IssueNodes. Lets a multi-selection ("Acknowledge
 * Selected") target every occurrence of one finding, or the whole group at
 * once via the group node's own "Acknowledge Group" command, instead of
 * clicking through each occurrence individually.
 */
class FindingGroupNode {
  readonly kind = 'group';
  constructor(public key: string, public category: string, public summary: string, public issues: IgniteIssue[]) {}
}

class IssueNode {
  readonly kind = 'issue';
  constructor(public issue: IgniteIssue) {}
}

/** category + summary — same fingerprint used to group occurrences of "the same finding". */
function findingKey(issue: IgniteIssue): string {
  return `${issue.category}::${issue.summary}`;
}

/**
 * Flattens a multi-selection from the tree (a mix of FindingGroupNodes and
 * IssueNodes — VS Code hands back whatever the user ctrl/cmd-clicked, not
 * just leaves) into the unique, still-unresolved issues it covers. Backs
 * "Acknowledge Selected"/"Acknowledge Group" so either a whole group or an
 * arbitrary multi-select of individual occurrences works the same way.
 */
export function unresolvedIssuesFromSelection(nodes: Node[]): IgniteIssue[] {
  const seen = new Set<string>();
  const result: IgniteIssue[] = [];
  const consider = (issue: IgniteIssue) => {
    if (issue.severity !== 'error' || issue.status === 'overridden') return;
    if (seen.has(issue.id)) return;
    seen.add(issue.id);
    result.push(issue);
  };
  for (const node of nodes) {
    if (node.kind === 'issue') consider(node.issue);
    else if (node.kind === 'group') node.issues.forEach(consider);
  }
  return result;
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
  /** 'phase' matches the web UI's phase cards; 'finding' groups occurrences of the same finding together. */
  private groupBy: 'phase' | 'finding' = 'finding';

  setResult(phases: IgnitePhase[], issues: IgniteIssue[], workspaceRoot: string): void {
    this.phases = phases;
    this.issues = issues;
    this.workspaceRoot = workspaceRoot;
    this._onDidChangeTreeData.fire(undefined);
  }

  clear(): void {
    this.setResult([], [], '');
  }

  setGroupBy(mode: 'phase' | 'finding'): void {
    this.groupBy = mode;
    this._onDidChangeTreeData.fire(undefined);
  }

  getGroupBy(): 'phase' | 'finding' {
    return this.groupBy;
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
    if (node.kind === 'group') {
      const unresolvedCount = node.issues.filter((i) => i.severity === 'error' && i.status !== 'overridden').length;
      const item = new vscode.TreeItem(node.summary, vscode.TreeItemCollapsibleState.Collapsed);
      item.description = `${node.category} · ${node.issues.length} occurrence(s)`;
      item.iconPath = new vscode.ThemeIcon(
        unresolvedCount > 0 ? 'error' : 'check',
        new vscode.ThemeColor(unresolvedCount > 0 ? 'testing.iconFailed' : 'disabledForeground')
      );
      item.contextValue = unresolvedCount > 0 ? 'igniteFindingGroup' : 'igniteFindingGroupResolved';
      return item;
    }
    const issue = node.issue;
    const loc = issue.file ? `${path.basename(issue.file)}${issue.line ? ':' + issue.line : ''}` : '';
    const item = new vscode.TreeItem(`${loc ? loc + ' — ' : ''}${issue.summary}`, vscode.TreeItemCollapsibleState.None);
    const refs = [issue.cwe, issue.owasp].filter(Boolean).join(' · ');
    item.description = refs ? `${issue.category} · ${refs}` : issue.category;
    item.tooltip = new vscode.MarkdownString(
      [
        `**${issue.summary}**`,
        '',
        `Category: ${issue.category}`,
        issue.cwe ? `CWE: [${issue.cwe}](https://cwe.mitre.org/data/definitions/${issue.cwe.match(/\d+/)?.[0] ?? ''}.html)` : '',
        issue.owasp ? `OWASP: ${issue.owasp}` : '',
      ]
        .filter(Boolean)
        .join('  \n')
    );
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
    if (!node) {
      if (this.groupBy === 'finding') return this.findingGroups(this.issues);
      return this.phases.map((p) => new PhaseNode(p, this.issues.filter((i) => this.issueBelongsToPhase(i, p))));
    }
    if (node.kind === 'phase') return node.issues.map((i) => new IssueNode(i));
    if (node.kind === 'group') return node.issues.map((i) => new IssueNode(i));
    return [];
  }

  /** Groups the flat issue list by (category, summary), unresolved findings surfaced first. */
  private findingGroups(issues: IgniteIssue[]): FindingGroupNode[] {
    const byKey = new Map<string, IgniteIssue[]>();
    for (const issue of issues) {
      const key = findingKey(issue);
      const list = byKey.get(key) ?? [];
      list.push(issue);
      byKey.set(key, list);
    }
    const groups = [...byKey.entries()].map(
      ([key, group]) => new FindingGroupNode(key, group[0].category, group[0].summary, group)
    );
    groups.sort((a, b) => {
      const aUnresolved = a.issues.some((i) => i.severity === 'error' && i.status !== 'overridden');
      const bUnresolved = b.issues.some((i) => i.severity === 'error' && i.status !== 'overridden');
      if (aUnresolved !== bUnresolved) return aUnresolved ? -1 : 1;
      return b.issues.length - a.issues.length;
    });
    return groups;
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
