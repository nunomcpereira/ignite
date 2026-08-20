import * as vscode from 'vscode';
import { validateAll, checkReachable, IgniteUnreachableError, type IgniteIssue } from './api';
import { publishDiagnostics, DIAGNOSTIC_SOURCE } from './diagnostics';
import { getActor, getOriginOrgRepo, getRepoRoot } from './git';
import { loadOverrides, appendUnresolvedIssues, reviewFilePath, findAcknowledgeLineNumber } from './reviewFile';
import { installPrePushHook } from './prePushHook';
import { FindingsTreeProvider } from './panels/findingsTree';
import { ToolsStatusTreeProvider } from './panels/toolsStatusTree';

let outputChannel: vscode.OutputChannel;
let diagnostics: vscode.DiagnosticCollection;
let findingsTree: FindingsTreeProvider;
let toolsStatusTree: ToolsStatusTreeProvider;
let statusBarItem: vscode.StatusBarItem;
let lastResultIssues: IgniteIssue[] = [];

function activeWorkspaceFolder(): vscode.WorkspaceFolder | undefined {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) return undefined;
  return folders[0]; // single-root for v1 — see plan
}

function setStatusBar(state: 'idle' | 'running' | 'ok' | 'errors', detail?: string): void {
  switch (state) {
    case 'running':
      statusBarItem.text = '$(sync~spin) Ignite: scanning…';
      break;
    case 'ok':
      statusBarItem.text = '$(shield) Ignite: passed';
      break;
    case 'errors':
      statusBarItem.text = `$(shield) Ignite: ${detail ?? 'issues found'}`;
      break;
    default:
      statusBarItem.text = '$(shield) Ignite';
  }
  statusBarItem.tooltip = 'Run Ignite: Scan Workspace';
  statusBarItem.command = 'ignite.scanWorkspace';
  statusBarItem.show();
}

function logPhases(phases: { phase: number; title: string; state: string; logs: string[] }[]): void {
  for (const p of phases) {
    if (p.logs.length === 0) continue;
    outputChannel.appendLine(`\n── Phase ${p.phase} — ${p.title} [${p.state}] ──`);
    p.logs.forEach((l) => outputChannel.appendLine(l));
  }
}

async function scanWorkspace(context: vscode.ExtensionContext): Promise<void> {
  const folder = activeWorkspaceFolder();
  if (!folder) {
    vscode.window.showWarningMessage('Ignite: open a folder first — there is no workspace to scan.');
    return;
  }
  const workspaceRoot = folder.uri.fsPath;

  if (!(await checkReachable())) {
    const baseUrl = vscode.workspace.getConfiguration('ignite').get<string>('baseUrl');
    const choice = await vscode.window.showErrorMessage(
      `Ignite isn't reachable at ${baseUrl}. Start it with 'npm start' in the ignite repo, or set "ignite.baseUrl".`,
      'Open Settings'
    );
    if (choice === 'Open Settings') vscode.commands.executeCommand('workbench.action.openSettings', 'ignite.baseUrl');
    return;
  }

  outputChannel.clear();
  outputChannel.show(true);
  setStatusBar('running');

  const config = vscode.workspace.getConfiguration('ignite');
  const runLocalCi = config.get<boolean>('runLocalCi', false);
  const showOverridden = config.get<boolean>('showOverriddenIssues', false);

  const repoRoot = (await getRepoRoot(workspaceRoot)) ?? workspaceRoot;
  const [overrides, actor, { org, repo }] = await Promise.all([
    loadOverrides(repoRoot),
    getActor(repoRoot),
    getOriginOrgRepo(repoRoot),
  ]);

  try {
    const result = await validateAll(workspaceRoot, {
      runLocalCi,
      org: org || undefined,
      repo: repo || undefined,
      overrides,
      actor: actor ?? undefined,
    });

    logPhases(result.phases ?? []);

    const issues = result.issues ?? [];
    lastResultIssues = issues;
    publishDiagnostics(diagnostics, workspaceRoot, issues, showOverridden);
    findingsTree.setResult(result.phases ?? [], issues, workspaceRoot);

    const unresolvedErrors = issues.filter((i) => i.severity === 'error' && i.status !== 'overridden');
    if (result.ok) {
      setStatusBar('ok');
      outputChannel.appendLine('\n✓ Ignite checks passed.');
      if (issues.length > 0) {
        vscode.window.setStatusBarMessage(`Ignite: passed (${issues.length} non-blocking finding(s))`, 5000);
      }
    } else if (unresolvedErrors.length > 0) {
      await appendUnresolvedIssues(repoRoot, unresolvedErrors);
      setStatusBar('errors', `${unresolvedErrors.length} blocking`);
      outputChannel.appendLine(`\n✗ ${unresolvedErrors.length} blocking finding(s) need a justification or a source fix.`);
      outputChannel.appendLine(`  Edit ${reviewFilePath(repoRoot)}, fill in "Acknowledge:" for whichever you want to override, then rescan.`);
      const choice = await vscode.window.showErrorMessage(
        `Ignite: ${unresolvedErrors.length} blocking finding(s). See the Problems panel or the review file.`,
        'Open Review File',
        'Show Problems'
      );
      if (choice === 'Open Review File') vscode.commands.executeCommand('ignite.openReviewFile');
      if (choice === 'Show Problems') vscode.commands.executeCommand('workbench.actions.view.problems');
    } else {
      // Failure not tied to overridable issues (e.g. a failing unit test, raw .env file).
      setStatusBar('errors', result.error ?? 'failed');
      outputChannel.appendLine(`\n✗ ${result.error ?? 'Ignite checks failed.'}`);
      outputChannel.appendLine("  This failure isn't something a justification can override — fix it in the source and rescan.");
      vscode.window.showErrorMessage(`Ignite: ${result.error ?? 'checks failed'} — see Output › Ignite.`);
    }
  } catch (e) {
    setStatusBar('idle');
    const message = e instanceof IgniteUnreachableError || e instanceof Error ? e.message : String(e);
    outputChannel.appendLine(`\n✗ ${message}`);
    vscode.window.showErrorMessage(`Ignite: ${message}`);
  }
}

export function activate(context: vscode.ExtensionContext): void {
  outputChannel = vscode.window.createOutputChannel('Ignite');
  diagnostics = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);
  findingsTree = new FindingsTreeProvider();
  toolsStatusTree = new ToolsStatusTreeProvider();
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  setStatusBar('idle');

  context.subscriptions.push(
    outputChannel,
    diagnostics,
    statusBarItem,
    vscode.window.registerTreeDataProvider('igniteFindings', findingsTree),
    vscode.window.registerTreeDataProvider('igniteToolsStatus', toolsStatusTree),
    vscode.commands.registerCommand('ignite.scanWorkspace', () => scanWorkspace(context)),
    vscode.commands.registerCommand('ignite.showOutput', () => outputChannel.show()),
    vscode.commands.registerCommand('ignite.refreshToolsStatus', () => toolsStatusTree.refresh()),
    vscode.commands.registerCommand('ignite.openReviewFile', async () => {
      const folder = activeWorkspaceFolder();
      if (!folder) return;
      const repoRoot = (await getRepoRoot(folder.uri.fsPath)) ?? folder.uri.fsPath;
      const filePath = reviewFilePath(repoRoot);
      const uri = vscode.Uri.file(filePath);
      try {
        await vscode.workspace.fs.stat(uri);
      } catch {
        vscode.window.showInformationMessage('No .ignite-review.md yet — run a scan with unresolved findings first.');
        return;
      }
      await vscode.window.showTextDocument(uri);
    }),
    vscode.commands.registerCommand('ignite.acknowledgeIssue', async (issueId: string) => {
      const folder = activeWorkspaceFolder();
      if (!folder) return;
      const repoRoot = (await getRepoRoot(folder.uri.fsPath)) ?? folder.uri.fsPath;
      const unresolved = lastResultIssues.filter((i) => i.severity === 'error' && i.status !== 'overridden');
      await appendUnresolvedIssues(repoRoot, unresolved);
      const uri = vscode.Uri.file(reviewFilePath(repoRoot));
      const doc = await vscode.window.showTextDocument(uri);
      const lineNo = await findAcknowledgeLineNumber(repoRoot, issueId);
      if (lineNo !== null) {
        const pos = new vscode.Position(lineNo, 'Acknowledge: '.length);
        doc.selection = new vscode.Selection(pos, pos);
        doc.revealRange(new vscode.Range(pos, pos));
      }
    }),
    vscode.commands.registerCommand('ignite.installPrePushHook', async () => {
      const folder = activeWorkspaceFolder();
      if (!folder) {
        vscode.window.showWarningMessage('Ignite: open a folder first.');
        return;
      }
      const repoRoot = await getRepoRoot(folder.uri.fsPath);
      if (!repoRoot) {
        vscode.window.showWarningMessage('Ignite: the open folder is not a git repository.');
        return;
      }
      await installPrePushHook(context, repoRoot);
    })
  );

  toolsStatusTree.refresh();
}

export function deactivate(): void {
  diagnostics?.dispose();
}
