import * as vscode from 'vscode';
import * as path from 'path';
import * as os from 'os';
import {
  validateAll, checkReachable, IgniteUnreachableError, type IgniteIssue,
  getLicenseCompliance, getSbom, getLocMetrics, getPosture,
  previewFixPr, applyFixPr, type FixCandidate,
  explainIssue, suggestFix,
  runDailyReport, downloadDailyReportPdf,
  probeServer, setStoredApiKey, effectiveApiKey, baseUrl, mintApiKeyWithPassword,
} from './api';
import { normalizeBaseUrl, cleanApiKey, maskApiKey, DEFAULT_BASE_URL } from './serverUrl';
import { UiStateStore } from './uiState';
import { ControlPanelProvider, updateSetting, type ControlPanelHost } from './panels/controlPanel';
import { planForPick, summarizeReports, defaultPdfName, type ChannelPick } from './dailyReport';
import { publishDiagnostics, DIAGNOSTIC_SOURCE } from './diagnostics';
import { getActor, getOriginOrgRepo, getRepoRoot, getChangedFiles } from './git';
import {
  loadOverrides, appendUnresolvedIssues, reviewFilePath, findAcknowledgeLineNumber,
  writeScanSnapshot, acknowledgeIssues,
} from './reviewFile';
import { installPrePushHook } from './prePushHook';
import { FindingsTreeProvider, unresolvedIssuesFromSelection, type Node as FindingsNode } from './panels/findingsTree';
import { ToolsStatusTreeProvider } from './panels/toolsStatusTree';
import { LiveLogPrinter, ScanProgressPoller } from './progress';
import { showReport } from './panels/reportPanel';

let outputChannel: vscode.OutputChannel;
let diagnostics: vscode.DiagnosticCollection;
let findingsTree: FindingsTreeProvider;
let toolsStatusTree: ToolsStatusTreeProvider;
let statusBarItem: vscode.StatusBarItem;
let findingsView: vscode.TreeView<FindingsNode>;
let uiState: UiStateStore;
let controlPanel: ControlPanelProvider;
/** Name of the SecretStorage (OS keychain) entry holding the API key — an identifier, not the key. */
const KEYCHAIN_ENTRY_NAME = 'ignite.apiKey';
let lastResultIssues: IgniteIssue[] = [];
/** jobId from the most recent scan — the fix-PR endpoints are scoped to one job's stored issues. */
let lastJobId: string | undefined;
/** Guards against a second "Ignite: Scan Workspace" firing while one is already in flight. */
let scanInProgress = false;

function activeWorkspaceFolder(): vscode.WorkspaceFolder | undefined {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) return undefined;
  return folders[0]; // single-root for v1 — see plan
}

function setStatusBar(state: 'idle' | 'running' | 'ok' | 'errors', detail?: string): void {
  const offline = uiState?.current.connection.status === 'disconnected';
  statusBarItem.backgroundColor = undefined;
  switch (state) {
    case 'running':
      statusBarItem.text = `$(sync~spin) Ignite: ${detail ?? 'scanning…'}`;
      break;
    case 'ok':
      statusBarItem.text = '$(pass-filled) Ignite: passed';
      break;
    case 'errors':
      statusBarItem.text = `$(error) Ignite: ${detail ?? 'issues found'}`;
      statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
      break;
    default:
      statusBarItem.text = offline ? '$(debug-disconnect) Ignite: offline' : '$(shield) Ignite';
      if (offline) statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
  }
  const tooltip = new vscode.MarkdownString(undefined, true);
  tooltip.isTrusted = { enabledCommands: ['ignite.scanWorkspace', 'ignite.configureServer', 'ignite.showOutput'] };
  tooltip.appendMarkdown(`**Ignite** — ${offline ? 'server unreachable' : 'server'} \`${baseUrl()}\`\n\n`);
  tooltip.appendMarkdown('[$(shield) Scan workspace](command:ignite.scanWorkspace) · [$(plug) Server…](command:ignite.configureServer) · [$(output) Output](command:ignite.showOutput)');
  statusBarItem.tooltip = tooltip;
  statusBarItem.command = state === 'running' ? 'ignite.showOutput' : offline && state === 'idle' ? 'ignite.configureServer' : 'ignite.scanWorkspace';
  statusBarItem.show();
}

/** Re-probes the configured server and publishes the result to the sidebar + status bar. */
async function refreshConnection(): Promise<void> {
  const url = baseUrl();
  uiState.update({ connection: { status: 'checking', url } });
  const probe = await probeServer();
  // A newer refresh (URL changed mid-probe) already superseded this one.
  if (baseUrl() !== url) return;
  uiState.update({ connection: { status: probe.ok ? 'connected' : 'disconnected', ...probe } });
  if (uiState.current.scan.status !== 'running' && !['passed', 'blocked', 'failed'].includes(uiState.current.scan.status)) setStatusBar('idle');
}

function publishApiKeyState(): void {
  const { key, source } = effectiveApiKey();
  uiState.update({ apiKey: { source, masked: maskApiKey(key) } });
}

async function refreshTools(): Promise<void> {
  await toolsStatusTree.refresh();
  uiState.update({ tools: toolsStatusTree.summary() });
}

function createControlPanelHost(context: vscode.ExtensionContext): ControlPanelHost {
  return {
    baseUrl,
    async testBaseUrl(input) {
      const normalized = normalizeBaseUrl(input);
      if (!normalized.ok) return { ok: false, error: normalized.error };
      const probe = await probeServer(normalized.url);
      return { ok: probe.ok, probe, error: probe.error };
    },
    async saveBaseUrl(input) {
      const normalized = normalizeBaseUrl(input);
      if (!normalized.ok) return { ok: false, error: normalized.error };
      const probe = await probeServer(normalized.url);
      // Saved regardless of the probe — the server may simply not be started yet.
      // onDidChangeConfiguration then re-probes and refreshes everything else.
      await updateSetting('baseUrl', normalized.url === DEFAULT_BASE_URL ? undefined : normalized.url);
      return { ok: probe.ok, probe, error: probe.error };
    },
    async resetBaseUrl() {
      await updateSetting('baseUrl', undefined);
    },
    async saveApiKey(input) {
      const key = cleanApiKey(input);
      if (!key) return { ok: false, error: 'Paste an API key first.' };
      await context.secrets.store(KEYCHAIN_ENTRY_NAME, key);
      return { ok: true };
    },
    async clearApiKey() {
      await context.secrets.delete(KEYCHAIN_ENTRY_NAME);
    },
    log: (line) => outputChannel.appendLine(line),
    async mintApiKey(email, password) {
      try {
        const minted = await mintApiKeyWithPassword(email.trim(), password, `VS Code — ${os.hostname()}`);
        await context.secrets.store(KEYCHAIN_ENTRY_NAME, minted.key);
        return { ok: true, email: minted.user?.email ?? email };
      } catch (e) {
        return { ok: false, error: e instanceof Error ? e.message : String(e) };
      }
    },
    reconnect: async () => {
      await Promise.all([refreshConnection(), refreshTools()]);
    },
  };
}

/** "Ignite: Configure Server…" — palette/status-bar entry point to the same URL field the sidebar has. */
async function configureServer(): Promise<void> {
  const value = await vscode.window.showInputBox({
    title: 'Ignite server URL',
    prompt: 'Where is ignite-server running?',
    value: baseUrl(),
    ignoreFocusOut: true,
    validateInput: (v) => {
      const n = normalizeBaseUrl(v);
      return n.ok ? null : n.error;
    },
  });
  if (value === undefined) return;
  const normalized = normalizeBaseUrl(value);
  if (!normalized.ok) return;
  const probe = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `Ignite: connecting to ${normalized.url}…` },
    () => probeServer(normalized.url)
  );
  await updateSetting('baseUrl', normalized.url === DEFAULT_BASE_URL ? undefined : normalized.url);
  if (probe.ok) {
    vscode.window.showInformationMessage(`Ignite: connected to ${normalized.url} (${probe.latencyMs} ms).`);
  } else {
    vscode.window.showWarningMessage(`Ignite: saved ${normalized.url}, but it isn't reachable — ${probe.error}`);
  }
}

async function setApiKeyCommand(context: vscode.ExtensionContext): Promise<void> {
  const value = await vscode.window.showInputBox({
    title: 'Ignite API key',
    prompt: 'Paste an ignite_… key (kept in your OS keychain; empty removes it). No key? Use "Sign in & create key" in the Ignite Overview panel, or the web UI\'s API keys page.',
    placeHolder: 'ignite_…',
    password: true,
    ignoreFocusOut: true,
  });
  if (value === undefined) return;
  const key = cleanApiKey(value);
  if (key) await context.secrets.store(KEYCHAIN_ENTRY_NAME, key);
  else await context.secrets.delete(KEYCHAIN_ENTRY_NAME);
}

async function scanWorkspace(context: vscode.ExtensionContext, changedOnly = false): Promise<void> {
  if (scanInProgress) {
    vscode.window.showWarningMessage('Ignite: a scan is already running — wait for it to finish before starting another.');
    outputChannel.show(true);
    return;
  }
  const folder = activeWorkspaceFolder();
  if (!folder) {
    vscode.window.showWarningMessage('Ignite: open a folder first — there is no workspace to scan.');
    return;
  }
  await runGuarded(context, folder.uri.fsPath, changedOnly);
}

/**
 * "Ignite: Scan Selected Folder" — an explorer context-menu command scoped
 * to one folder instead of the whole workspace root. `uri` is the
 * right-clicked folder (VS Code passes it as the first arg for an
 * `explorer/context` `when: explorerResourceIsFolder` command).
 */
async function scanFolder(context: vscode.ExtensionContext, uri?: vscode.Uri): Promise<void> {
  if (scanInProgress) {
    vscode.window.showWarningMessage('Ignite: a scan is already running — wait for it to finish before starting another.');
    outputChannel.show(true);
    return;
  }
  const target = uri ?? (await pickFolderFallback());
  if (!target) return;
  await runGuarded(context, target.fsPath, false);
}

/** Command-palette invocation of "Scan Selected Folder" carries no URI — ask. */
async function pickFolderFallback(): Promise<vscode.Uri | undefined> {
  const picked = await vscode.window.showOpenDialog({
    canSelectFiles: false,
    canSelectFolders: true,
    canSelectMany: false,
    openLabel: 'Scan this folder',
    defaultUri: activeWorkspaceFolder()?.uri,
  });
  return picked?.[0];
}

async function runGuarded(context: vscode.ExtensionContext, scanRoot: string, changedOnly: boolean): Promise<void> {
  // Set before any await — checkReachable() below is the first suspension
  // point, and two near-simultaneous invocations (e.g. double-click on the
  // status bar item) would otherwise both pass the scanInProgress check
  // above before either one flips the flag.
  scanInProgress = true;
  try {
    outputChannel.appendLine(`Checking reachability of the Ignite server...`);
    const reachable = await checkReachable((line) => outputChannel.appendLine(line));
    if (!reachable) {
      const url = baseUrl();
      void refreshConnection();
      outputChannel.appendLine(`✗ Ignite isn't reachable at ${url} after 3 probes — see the lines above for the actual cause per attempt.`);
      outputChannel.show(true);
      const choice = await vscode.window.showErrorMessage(
        `Ignite isn't reachable at ${url}. Start ignite-server, or point the extension at a running server. See Output › Ignite for per-attempt detail.`,
        'Change Server URL',
        'Show Output'
      );
      if (choice === 'Show Output') outputChannel.show();
      if (choice === 'Change Server URL') void controlPanel.focusServerSettings();
      return;
    }
    if (uiState.current.connection.status !== 'connected') void refreshConnection();
    await runScan(context, scanRoot, changedOnly);
  } finally {
    scanInProgress = false;
  }
}

function updateFindingsBadge(blocking: number, total: number): void {
  findingsView.badge = blocking > 0 ? { value: blocking, tooltip: `${blocking} blocking finding(s)` } : undefined;
  findingsView.description = total > 0 ? `${total} finding(s)` : undefined;
  findingsView.message = total === 0 ? 'No findings — the last scan came back clean.' : undefined;
  void vscode.commands.executeCommand('setContext', 'ignite.hasScanResult', true);
}

async function runScan(context: vscode.ExtensionContext, workspaceRoot: string, changedOnly: boolean): Promise<void> {
  outputChannel.clear();
  outputChannel.show(true);
  setStatusBar('running');
  const startedAt = Date.now();
  const target = path.basename(workspaceRoot) + (changedOnly ? ' (changed files)' : '');
  uiState.updateScan({ status: 'running', target, detail: 'Starting…', startedAt, finishedAt: undefined });
  findingsView.message = undefined;

  const config = vscode.workspace.getConfiguration('ignite');
  const runLocalCi = config.get<boolean>('runLocalCi', false);
  const showOverridden = config.get<boolean>('showOverriddenIssues', false);

  const repoRoot = (await getRepoRoot(workspaceRoot)) ?? workspaceRoot;
  const [overrides, actor, { org, repo }] = await Promise.all([
    loadOverrides(repoRoot),
    getActor(repoRoot),
    getOriginOrgRepo(repoRoot),
  ]);

  let changedFiles: string[] | undefined;
  if (changedOnly) {
    changedFiles = await getChangedFiles(workspaceRoot);
    if (changedFiles.length === 0) {
      outputChannel.appendLine('No uncommitted changes in this workspace — nothing to scan.');
      vscode.window.showInformationMessage('Ignite: no uncommitted changes to scan.');
      setStatusBar('idle');
      uiState.updateScan({ status: 'idle' });
      return;
    }
    outputChannel.appendLine(`Scanning ${changedFiles.length} changed file(s): ${changedFiles.join(', ')}`);
  }

  const printer = new LiveLogPrinter(outputChannel);
  let progressReport: ((message: string) => void) | undefined;
  // validate-all is one synchronous request with no NDJSON streaming, but
  // each phase's logs land in the DB live as the server-side run progresses
  // (see api.ts's listProjects/getProjectDetails doc comment) — polling
  // those two endpoints is how "Phase 4 — Security & AI Compliance Scan"
  // ends up next to the spinner instead of a static "scanning…" for
  // however many minutes Bearer/CodeQL/GuardDog take on a real project.
  const poller = new ScanProgressPoller(org, repo, printer, (phase, title, elapsedSeconds) => {
    setStatusBar('running', `Phase ${phase} — ${title} (${elapsedSeconds}s)`);
    progressReport?.(`Phase ${phase} — ${title}`);
    uiState.updateScan({ detail: `Phase ${phase} — ${title}` });
  });

  try {
    const result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `Ignite: scanning ${target}`,
        cancellable: false,
      },
      async (progress) => {
        progressReport = (message: string) => progress.report({ message });
        poller.start();
        try {
          return await validateAll(workspaceRoot, {
            runLocalCi,
            org: org || undefined,
            repo: repo || undefined,
            overrides,
            actor: actor ?? undefined,
            changedFiles,
          });
        } finally {
          poller.stop();
          progressReport = undefined;
        }
      }
    );

    // Final reconciliation pass: authoritative and complete, but the printer
    // only emits what the poller hasn't already shown, so nothing duplicates.
    for (const p of result.phases ?? []) {
      printer.appendPhase(p.phase, p.title, p.state, p.logs ?? []);
    }

    const issues = result.issues ?? [];
    lastResultIssues = issues;
    lastJobId = result.jobId;
    if (result.filteredByChangedFiles) {
      outputChannel.appendLine(`  Showing ${issues.length} of ${result.totalIssueCount ?? issues.length} total finding(s) — restricted to changed files.`);
    }
    publishDiagnostics(diagnostics, workspaceRoot, issues, showOverridden);
    findingsTree.setResult(result.phases ?? [], issues, workspaceRoot);
    const blocking = issues.filter((i) => i.severity === 'error' && i.status !== 'overridden').length;
    const counts = {
      blocking,
      warnings: issues.filter((i) => i.severity !== 'error' && i.status !== 'overridden').length,
      acknowledged: issues.filter((i) => i.status === 'overridden').length,
      total: issues.length,
      finishedAt: Date.now(),
    };
    updateFindingsBadge(counts.blocking, issues.length);
    uiState.updateScan({
      ...counts,
      status: result.ok ? 'passed' : blocking > 0 ? 'blocked' : 'failed',
      detail: result.ok ? undefined : blocking > 0 ? undefined : result.error ?? 'Checks failed',
    });
    const snapshotPath = await writeScanSnapshot(repoRoot, issues);
    outputChannel.appendLine(`  Findings snapshot: ${snapshotPath}`);

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
    uiState.updateScan({ status: 'error', detail: message, finishedAt: Date.now() });
    if (e instanceof IgniteUnreachableError) void refreshConnection();
    outputChannel.appendLine(`\n✗ ${message}`);
    vscode.window.showErrorMessage(`Ignite: ${message}`);
  }
}

/**
 * Shared driver for the four on-demand report commands (license/SBOM/LOC/
 * posture) — each just supplies its fetch function and a panel title; this
 * handles the "no workspace open" guard, a progress notification (these
 * reuse Phase 4's own tool binaries and can take a while on a cold run),
 * and routing failures through the same message the scan path uses.
 */
async function runReport<T>(id: string, title: string, fetchReport: (projectPath: string) => Promise<T>): Promise<void> {
  const folder = activeWorkspaceFolder();
  if (!folder) {
    vscode.window.showWarningMessage('Ignite: open a folder first — there is no workspace to report on.');
    return;
  }
  try {
    const data = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: `${title} — generating…`, cancellable: false },
      () => fetchReport(folder.uri.fsPath)
    );
    showReport(id, title, data);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    vscode.window.showErrorMessage(`${title}: ${message}`);
  }
}

/**
 * Drives the scan-wide "generate a PR that fixes every finding" feature:
 * preview the LLM-proposed diffs for the last scan's open issues, let the
 * user drop any they don't want via a multi-select QuickPick, confirm (this
 * pushes a branch and opens a real PR — not reversible from here), then
 * apply. Scoped to `lastJobId`, so a scan must have run first.
 */
/**
 * Delivers the org's daily findings report. The org comes from the workspace's git
 * `origin` remote, or a prompt when there isn't one; a QuickPick then chooses the
 * channels (Sentinel/webhook, Azure Blob, email, PDF download, or everything).
 */
async function runOrgDailyReport(): Promise<void> {
  const folder = activeWorkspaceFolder();
  let org = '';
  if (folder) {
    const repoRoot = (await getRepoRoot(folder.uri.fsPath)) ?? folder.uri.fsPath;
    org = (await getOriginOrgRepo(repoRoot)).org;
  }
  if (!org) {
    const typed = await vscode.window.showInputBox({
      title: 'Ignite: Org Daily Report',
      prompt: 'GitHub org to report on (no git remote found in this workspace)',
      placeHolder: 'my-org',
      ignoreFocusOut: true,
      validateInput: (v) => (/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(v.trim()) ? null : 'Enter a valid GitHub org name'),
    });
    if (!typed) return;
    org = typed.trim();
  }

  type Item = vscode.QuickPickItem & { pick: ChannelPick };
  const items: Item[] = [
    { label: '$(cloud-upload) Sentinel / Webhook', description: 'POST the report + Sentinel incident payload', pick: 'webhook' },
    { label: '$(database) Azure Blob Storage', description: 'upload the .json (and .pdf) report to the configured container', pick: 'azure_blob' },
    { label: '$(mail) Email', description: 'send the HTML digest', pick: 'email' },
    { label: '$(file-pdf) Download PDF', description: 'save the report as a PDF file', pick: 'pdf' },
    { label: '$(rocket) All channels', description: 'every configured channel, plus a PDF download', pick: 'all' },
  ];
  const chosen = await vscode.window.showQuickPick(items, { title: `Ignite: deliver ${org}'s daily security report`, placeHolder: 'Choose a delivery channel', ignoreFocusOut: true });
  if (!chosen) return;
  const plan = planForPick(chosen.pick);

  outputChannel.appendLine(`\n=== Org daily report: ${org} ===`);
  let failed = false;
  let headline = '';
  await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: `Ignite: delivering ${org}'s report…`, cancellable: false }, async () => {
    if (plan.serverChannels !== null) {
      try {
        const result = await runDailyReport({ org, channels: plan.serverChannels });
        const summary = summarizeReports(result);
        summary.lines.forEach((l) => outputChannel.appendLine(l));
        headline = summary.message;
        failed = failed || summary.hasFailures;
      } catch (e) {
        failed = true;
        headline = `Ignite: report failed — ${e instanceof Error ? e.message : String(e)}`;
        outputChannel.appendLine(headline);
      }
    }
  });

  let pdfUri: vscode.Uri | undefined;
  if (plan.downloadPdf) {
    const target = await vscode.window.showSaveDialog({
      title: 'Save the Ignite report PDF',
      defaultUri: vscode.Uri.file(path.join(folder?.uri.fsPath ?? os.homedir(), defaultPdfName(org))),
      filters: { PDF: ['pdf'] },
    });
    if (target) {
      try {
        const bytes = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Ignite: rendering PDF…', cancellable: false }, () => downloadDailyReportPdf(org));
        await vscode.workspace.fs.writeFile(target, bytes);
        pdfUri = target;
        outputChannel.appendLine(`pdf saved: ${target.fsPath}`);
        headline = headline ? `${headline} PDF saved.` : `Ignite: PDF report saved to ${target.fsPath}.`;
      } catch (e) {
        failed = true;
        const message = `Ignite: PDF export failed — ${e instanceof Error ? e.message : String(e)}`;
        outputChannel.appendLine(message);
        headline = headline ? `${headline} ${message}` : message;
      }
    } else if (!headline) {
      return; // cancelled the save dialog, nothing else ran
    }
  }

  const actions = ['Open Output', ...(pdfUri ? ['Open PDF'] : [])];
  const action = failed ? await vscode.window.showWarningMessage(headline, ...actions) : await vscode.window.showInformationMessage(headline, ...actions);
  if (action === 'Open Output') outputChannel.show(true);
  else if (action === 'Open PDF' && pdfUri) await vscode.env.openExternal(pdfUri);
}

async function generateFixPr(): Promise<void> {
  if (!lastJobId) {
    vscode.window.showWarningMessage('Ignite: run a scan first — Generate Fix PR works off the most recent scan\'s findings.');
    return;
  }
  const jobId = lastJobId;

  let preview: Awaited<ReturnType<typeof previewFixPr>>;
  try {
    preview = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: 'Ignite: generating fix suggestions…', cancellable: false },
      () => previewFixPr(jobId)
    );
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    vscode.window.showErrorMessage(`Ignite: fix-PR preview failed — ${message}`);
    return;
  }

  if (preview.candidates.length === 0) {
    vscode.window.showInformationMessage(
      preview.reason ? `Ignite: no fix suggestions — ${preview.reason}` : 'Ignite: no fixable open findings from the last scan.'
    );
    return;
  }

  type Pick = vscode.QuickPickItem & { candidate: FixCandidate };
  const items: Pick[] = preview.candidates.map((c) => ({
    label: `${path.basename(c.file)}:${c.startLine} — ${c.summary}`,
    description: c.category,
    detail: c.explanation,
    picked: true,
    candidate: c,
  }));
  const selected = await vscode.window.showQuickPick(items, {
    canPickMany: true,
    ignoreFocusOut: true,
    title: `Ignite: ${items.length} proposed fix(es) — uncheck any to exclude, then confirm`,
    placeHolder: 'Select the fixes to include in the PR',
  });
  if (!selected || selected.length === 0) return;

  const confirm = await vscode.window.showWarningMessage(
    `Open a PR with ${selected.length} fix(es)? This pushes a new branch and opens a real pull request on GitHub.`,
    { modal: true },
    'Open PR'
  );
  if (confirm !== 'Open PR') return;

  try {
    const result = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: 'Ignite: opening fix PR…', cancellable: false },
      () => applyFixPr(jobId, selected.map((s) => s.candidate))
    );
    if (result.alreadyOpen) {
      vscode.window.showInformationMessage(`Ignite: a fix PR is already open on branch ${result.branch}.`);
      return;
    }
    if (!result.ok || !result.prUrl) {
      vscode.window.showErrorMessage(`Ignite: fix-PR failed — ${result.error ?? 'unknown error'}`);
      return;
    }
    const choice = await vscode.window.showInformationMessage(`Ignite: opened fix PR (${result.filesChanged?.length ?? 0} file(s) changed).`, 'Open PR');
    if (choice === 'Open PR') vscode.env.openExternal(vscode.Uri.parse(result.prUrl));
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    vscode.window.showErrorMessage(`Ignite: fix-PR failed — ${message}`);
  }
}

function issueFromNode(node: FindingsNode | undefined): IgniteIssue | undefined {
  return node && node.kind === 'issue' ? node.issue : undefined;
}

/** "Ignite: Explain Finding" — plain-language explanation of one finding, from the findings tree's context menu. */
async function explainFinding(node: FindingsNode | undefined): Promise<void> {
  const issue = issueFromNode(node);
  if (!issue) return;
  try {
    const result = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: 'Ignite: explaining finding…', cancellable: false },
      () => explainIssue(issue)
    );
    if (!result.explanation) {
      vscode.window.showInformationMessage(`Ignite: ${result.reason ?? result.error ?? 'no explanation available.'}`);
      return;
    }
    await vscode.window.showInformationMessage(issue.summary, { modal: true, detail: result.explanation });
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    vscode.window.showErrorMessage(`Ignite: explain failed — ${message}`);
  }
}

/**
 * "Ignite: Suggest Fix" — one-off LLM diff for a single finding (the
 * per-issue counterpart to the scan-wide "Generate Fix PR"). Offers to
 * apply the proposed replacement directly to the open file instead of
 * opening a PR — for a fix a developer wants to review and commit
 * themselves rather than ship through a bot-authored branch.
 */
async function suggestFixForFinding(node: FindingsNode | undefined, workspaceRoot: string): Promise<void> {
  const issue = issueFromNode(node);
  if (!issue) return;
  if (!issue.file || !issue.snippet) {
    vscode.window.showWarningMessage('Ignite: this finding has no stored code snippet — cannot suggest a fix.');
    return;
  }
  try {
    const result = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: 'Ignite: suggesting a fix…', cancellable: false },
      () => suggestFix(issue)
    );
    if (!result.suggestion || !result.suggestion.replacement) {
      vscode.window.showInformationMessage(`Ignite: ${result.reason ?? result.suggestion?.explanation ?? 'no fix suggestion available.'}`);
      return;
    }
    const { explanation, replacement, startLine, endLine } = result.suggestion;
    const choice = await vscode.window.showInformationMessage(
      `Ignite: proposed fix for "${issue.summary}"`,
      { modal: true, detail: `${explanation}\n\n${replacement}` },
      'Apply to File'
    );
    if (choice !== 'Apply to File') return;

    const abs = path.isAbsolute(issue.file) ? issue.file : path.join(workspaceRoot, issue.file);
    const uri = vscode.Uri.file(abs);
    const doc = await vscode.workspace.openTextDocument(uri);
    const startIdx = Math.max(0, startLine - 1);
    const endIdx = Math.min(doc.lineCount - 1, endLine - 1);
    const range = new vscode.Range(startIdx, 0, endIdx, doc.lineAt(endIdx).text.length);

    // The LLM call between scan and "Apply to File" can take a while — if the
    // file was edited in the meantime, startLine/endLine may no longer point
    // at the code the fix was generated against. Compare against the snippet
    // captured at scan time before blindly overwriting those lines.
    const originalText = issue.snippet.lines
      .filter((l) => l.number >= startLine && l.number <= endLine)
      .map((l) => l.text)
      .join('\n');
    if (originalText && doc.getText(range).trim() !== originalText.trim()) {
      const proceed = await vscode.window.showWarningMessage(
        `Ignite: ${path.basename(issue.file)} has changed since this finding was scanned — the proposed fix may no longer target the right lines.`,
        { modal: true },
        'Apply Anyway'
      );
      if (proceed !== 'Apply Anyway') return;
    }

    const edit = new vscode.WorkspaceEdit();
    edit.replace(uri, range, replacement);
    if (!(await vscode.workspace.applyEdit(edit))) {
      vscode.window.showErrorMessage('Ignite: could not apply the fix — the file may have changed since the scan.');
      return;
    }
    await vscode.window.showTextDocument(doc, { selection: range });
    vscode.window.showInformationMessage('Ignite: fix applied — review and save before committing.');
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    vscode.window.showErrorMessage(`Ignite: suggest fix failed — ${message}`);
  }
}

export function activate(context: vscode.ExtensionContext): void {
  outputChannel = vscode.window.createOutputChannel('Ignite');
  diagnostics = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);
  findingsTree = new FindingsTreeProvider();
  toolsStatusTree = new ToolsStatusTreeProvider();
  uiState = new UiStateStore();
  controlPanel = new ControlPanelProvider(uiState, createControlPanelHost(context));
  statusBarItem = vscode.window.createStatusBarItem('ignite.status', vscode.StatusBarAlignment.Left, 100);
  statusBarItem.name = 'Ignite';
  findingsView = vscode.window.createTreeView('igniteFindings', { treeDataProvider: findingsTree, canSelectMany: true, showCollapseAll: true });
  const toolsView = vscode.window.createTreeView('igniteToolsStatus', { treeDataProvider: toolsStatusTree });
  setStatusBar('idle');
  publishApiKeyState();

  uiState.onDidChange((s) => {
    toolsView.description = s.tools && !s.tools.error ? `${s.tools.installed}/${s.tools.total} installed` : undefined;
  });

  context.subscriptions.push(
    outputChannel,
    diagnostics,
    statusBarItem,
    uiState,
    findingsView,
    toolsView,
    vscode.window.registerWebviewViewProvider(ControlPanelProvider.viewId, controlPanel),
    context.secrets.onDidChange(async (e) => {
      if (e.key !== KEYCHAIN_ENTRY_NAME) return;
      setStoredApiKey(await context.secrets.get(KEYCHAIN_ENTRY_NAME));
      publishApiKeyState();
      void refreshConnection();
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (!e.affectsConfiguration('ignite')) return;
      if (e.affectsConfiguration('ignite.baseUrl') || e.affectsConfiguration('ignite.apiKey')) {
        publishApiKeyState();
        void refreshConnection();
        void refreshTools();
      }
      controlPanel.refresh();
    }),
    vscode.workspace.onDidChangeWorkspaceFolders(() => controlPanel.refresh()),
    vscode.commands.registerCommand('ignite.configureServer', () => configureServer()),
    vscode.commands.registerCommand('ignite.setApiKey', () => setApiKeyCommand(context)),
    vscode.commands.registerCommand('ignite.getApiKey', () => controlPanel.focusApiKey()),
    vscode.commands.registerCommand('ignite.reconnect', () => Promise.all([refreshConnection(), refreshTools()])),
    vscode.commands.registerCommand('ignite.scanWorkspace', () => scanWorkspace(context)),
    vscode.commands.registerCommand('ignite.scanChangedFiles', () => scanWorkspace(context, true)),
    vscode.commands.registerCommand('ignite.scanFolder', (uri?: vscode.Uri) => scanFolder(context, uri)),
    vscode.commands.registerCommand('ignite.showOutput', () => outputChannel.show()),
    vscode.commands.registerCommand('ignite.refreshToolsStatus', () => refreshTools()),
    vscode.commands.registerCommand('ignite.openReviewFile', async () => {
      const folder = activeWorkspaceFolder();
      if (!folder) return;
      const repoRoot = (await getRepoRoot(folder.uri.fsPath)) ?? folder.uri.fsPath;
      const filePath = reviewFilePath(repoRoot);
      const uri = vscode.Uri.file(filePath);
      try {
        await vscode.workspace.fs.stat(uri);
      } catch {
        vscode.window.showInformationMessage('No .ignite/acknowledgments.md yet — run a scan with unresolved findings first.');
        return;
      }
      await vscode.window.showTextDocument(uri);
    }),
    vscode.commands.registerCommand('ignite.acknowledgeIssue', async (node: FindingsNode) => {
      const issue = issueFromNode(node);
      if (!issue) return;
      const folder = activeWorkspaceFolder();
      if (!folder) return;
      const repoRoot = (await getRepoRoot(folder.uri.fsPath)) ?? folder.uri.fsPath;
      await appendUnresolvedIssues(repoRoot, [issue]);
      const uri = vscode.Uri.file(reviewFilePath(repoRoot));
      const doc = await vscode.window.showTextDocument(uri);
      const lineNo = await findAcknowledgeLineNumber(repoRoot, issue.id);
      if (lineNo !== null) {
        const pos = new vscode.Position(lineNo, 'Acknowledge: '.length);
        doc.selection = new vscode.Selection(pos, pos);
        doc.revealRange(new vscode.Range(pos, pos));
      }
    }),
    vscode.commands.registerCommand('ignite.acknowledgeSelected', async (_node: FindingsNode, allSelected?: FindingsNode[]) => {
      const folder = activeWorkspaceFolder();
      if (!folder) return;
      const nodes = allSelected && allSelected.length > 0 ? allSelected : _node ? [_node] : [];
      const issues = unresolvedIssuesFromSelection(nodes);
      if (issues.length === 0) {
        vscode.window.showInformationMessage('Ignite: nothing unresolved in that selection to acknowledge.');
        return;
      }
      const justification = await vscode.window.showInputBox({
        prompt: `Justification for overriding ${issues.length} finding(s) — applied to all of them`,
        placeHolder: 'e.g. reviewed, false positive in test fixture data',
        ignoreFocusOut: true,
      });
      if (!justification) return;
      const repoRoot = (await getRepoRoot(folder.uri.fsPath)) ?? folder.uri.fsPath;
      await acknowledgeIssues(repoRoot, issues, justification);
      vscode.window.showInformationMessage(`Ignite: acknowledged ${issues.length} finding(s) in ${reviewFilePath(repoRoot)}. Rescan to apply.`);
    }),
    vscode.commands.registerCommand('ignite.toggleFindingGrouping', () => {
      findingsTree.setGroupBy(findingsTree.getGroupBy() === 'finding' ? 'phase' : 'finding');
    }),
    vscode.commands.registerCommand('ignite.showLicenseCompliance', async () => {
      await runReport('license', 'Ignite: License Compliance', getLicenseCompliance);
    }),
    vscode.commands.registerCommand('ignite.showSbom', async () => {
      await runReport('sbom', 'Ignite: SBOM', getSbom);
    }),
    vscode.commands.registerCommand('ignite.showLocMetrics', async () => {
      await runReport('loc-metrics', 'Ignite: LOC Metrics', getLocMetrics);
    }),
    vscode.commands.registerCommand('ignite.showPosture', async () => {
      await runReport('posture', 'Ignite: Compliance & Feature Posture', getPosture);
    }),
    vscode.commands.registerCommand('ignite.generateFixPr', () => generateFixPr()),
    vscode.commands.registerCommand('ignite.runDailyReport', () => runOrgDailyReport()),
    // Alias (not in the palette): the name the feature was first specced under.
    vscode.commands.registerCommand('ignite.runOrgDailyReport', () => runOrgDailyReport()),
    vscode.commands.registerCommand('ignite.explainIssue', (node: FindingsNode) => explainFinding(node)),
    vscode.commands.registerCommand('ignite.suggestFixForIssue', (node: FindingsNode) => {
      const workspaceRoot = activeWorkspaceFolder()?.uri.fsPath;
      if (!workspaceRoot) return;
      return suggestFixForFinding(node, workspaceRoot);
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

  void context.secrets.get(KEYCHAIN_ENTRY_NAME).then((key) => {
    setStoredApiKey(key);
    publishApiKeyState();
    void refreshConnection();
    void refreshTools();
  });
}

export function deactivate(): void {
  diagnostics?.dispose();
}
