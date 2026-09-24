import * as vscode from 'vscode';
import * as crypto from 'crypto';
import type { UiStateStore, UiState } from '../uiState';
import type { ServerProbe } from '../api';
import { MINT_API_KEY_COMMAND } from '../serverUrl';
import { resolveScanMode, type ScanMode } from '../upload';

/** Everything the panel can ask the extension to do — implemented in extension.ts. */
export interface ControlPanelHost {
  baseUrl(): string;
  saveBaseUrl(input: string): Promise<{ ok: boolean; error?: string; probe?: ServerProbe }>;
  testBaseUrl(input: string): Promise<{ ok: boolean; error?: string; probe?: ServerProbe }>;
  resetBaseUrl(): Promise<void>;
  saveApiKey(key: string): Promise<{ ok: boolean; error?: string }>;
  clearApiKey(): Promise<void>;
  reconnect(): Promise<void>;
  log(line: string): void;
  mintApiKey(email: string, password: string): Promise<{ ok: boolean; error?: string; email?: string }>;
}

/** Commands the webview may trigger — anything else it posts is ignored. */
const ALLOWED_COMMANDS = new Set([
  'ignite.scanWorkspace',
  'ignite.scanChangedFiles',
  'ignite.scanFolder',
  'ignite.generateFixPr',
  'ignite.openReviewFile',
  'ignite.showLicenseCompliance',
  'ignite.showSbom',
  'ignite.showLocMetrics',
  'ignite.showPosture',
  'ignite.runDailyReport',
  'ignite.installPrePushHook',
  'ignite.showOutput',
  'igniteToolsStatus.focus',
  'igniteFindings.focus',
  'workbench.actions.view.problems',
]);

const OPTION_KEYS = new Set(['runLocalCi', 'showOverriddenIssues']);

type Inbound =
  | { type: 'ready' }
  | { type: 'saveUrl' | 'testUrl'; url: string }
  | { type: 'resetUrl' }
  | { type: 'reconnect' }
  | { type: 'saveKey'; key: string }
  | { type: 'clearKey' }
  | { type: 'run'; command: string }
  | { type: 'setOption'; key: string; value: boolean }
  | { type: 'openWebUi' }
  | { type: 'openSettings' }
  | { type: 'copy'; text: string }
  | { type: 'mintKey'; email: string; password: string }
  | { type: 'openKeysPage' };

/**
 * The "Server" view at the top of the Ignite sidebar: connection status,
 * server URL + API key editing (no settings.json round-trip), scan options,
 * the last scan's summary, and one-click access to every Ignite command.
 */
export class ControlPanelProvider implements vscode.WebviewViewProvider {
  static readonly viewId = 'igniteControl';
  private view: vscode.WebviewView | undefined;

  constructor(private readonly store: UiStateStore, private readonly host: ControlPanelHost) {
    store.onDidChange((s) => this.postState(s));
  }

  resolveWebviewView(view: vscode.WebviewView): void {
    this.host.log('[overview] resolving webview view');
    this.view = view;
    view.webview.options = { enableScripts: true, enableCommandUris: false, localResourceRoots: [] };
    view.webview.html = this.html(view.webview);
    view.webview.onDidReceiveMessage((m: Inbound) => void this.handle(m));
    view.onDidChangeVisibility(() => {
      if (view.visible) this.postState(this.store.current);
    });
    view.onDidDispose(() => {
      if (this.view === view) this.view = undefined;
    });
  }

  /** Re-sends settings-derived values (options, URL) after a configuration change. */
  refresh(): void {
    this.postState(this.store.current);
  }

  /** Opens the server section at the "Get a key" form — backs "Ignite: Get API Key…". */
  async focusApiKey(): Promise<void> {
    await vscode.commands.executeCommand(`${ControlPanelProvider.viewId}.focus`);
    this.view?.webview.postMessage({ type: 'focusKey' });
  }

  /** Opens the server section with the URL field focused — backs "Ignite: Configure Server". */
  async focusServerSettings(): Promise<void> {
    await vscode.commands.executeCommand(`${ControlPanelProvider.viewId}.focus`);
    this.view?.webview.postMessage({ type: 'focusUrl' });
  }

  private postState(state: UiState): void {
    if (!this.view) return;
    const config = vscode.workspace.getConfiguration('ignite');
    this.view.webview.postMessage({
      type: 'state',
      state,
      baseUrl: this.host.baseUrl(),
      options: {
        runLocalCi: config.get<boolean>('runLocalCi', false),
        showOverriddenIssues: config.get<boolean>('showOverriddenIssues', false),
      },
      hasWorkspace: (vscode.workspace.workspaceFolders?.length ?? 0) > 0,
      scanMode: resolveScanMode(config.get<ScanMode>('scanMode', 'auto'), this.host.baseUrl()),
    });
  }

  private reply(message: Record<string, unknown>): void {
    this.view?.webview.postMessage(message);
  }

  private async handle(m: Inbound): Promise<void> {
    switch (m.type) {
      case 'ready':
        this.host.log('[overview] webview script loaded');
        this.postState(this.store.current);
        return;
      case 'saveUrl':
        this.reply({ type: 'urlResult', action: 'save', ...(await this.host.saveBaseUrl(String(m.url ?? ''))) });
        return;
      case 'testUrl':
        this.reply({ type: 'urlResult', action: 'test', ...(await this.host.testBaseUrl(String(m.url ?? ''))) });
        return;
      case 'resetUrl':
        await this.host.resetBaseUrl();
        return;
      case 'reconnect':
        await this.host.reconnect();
        return;
      case 'saveKey':
        this.reply({ type: 'keyResult', ...(await this.host.saveApiKey(String(m.key ?? ''))) });
        return;
      case 'clearKey':
        await this.host.clearApiKey();
        this.reply({ type: 'keyResult', ok: true });
        return;
      case 'run':
        if (ALLOWED_COMMANDS.has(m.command)) await vscode.commands.executeCommand(m.command);
        return;
      case 'setOption':
        if (OPTION_KEYS.has(m.key)) await updateSetting(m.key, Boolean(m.value));
        return;
      case 'openWebUi':
        await vscode.env.openExternal(vscode.Uri.parse(this.host.baseUrl()));
        return;
      case 'mintKey':
        this.reply({ type: 'mintResult', ...(await this.host.mintApiKey(String(m.email ?? ''), String(m.password ?? ''))) });
        return;
      case 'openKeysPage':
        await vscode.env.openExternal(vscode.Uri.parse(`${this.host.baseUrl()}/#api-keys`));
        return;
      case 'copy':
        await vscode.env.clipboard.writeText(String(m.text ?? ''));
        vscode.window.setStatusBarMessage('$(check) Copied', 2000);
        return;
      case 'openSettings':
        await vscode.commands.executeCommand('workbench.action.openSettings', '@ext:ignite.ignite-vscode');
        return;
    }
  }

  private html(webview: vscode.Webview): string {
    const nonce = crypto.randomBytes(16).toString('base64');
    const csp = [
      "default-src 'none'",
      `style-src ${webview.cspSource} 'unsafe-inline'`,
      `script-src 'nonce-${nonce}'`,
    ].join('; ');
    return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>${STYLE}</style>
</head>
<body>
<div id="app">
  <section class="conn" id="conn">
    <div class="conn-row">
      <span class="dot" id="connDot"></span>
      <div class="conn-text">
        <div class="conn-title" id="connTitle">Checking server…</div>
        <div class="conn-sub" id="connSub"></div>
      </div>
      <button class="icon-btn" id="reconnectBtn" title="Re-check connection" aria-label="Re-check connection">${ICON_REFRESH}</button>
    </div>
    <div class="conn-error" id="connError" hidden></div>
  </section>

  <details class="card" id="serverDetails">
    <summary><span>Server</span><span class="summary-hint" id="serverHint"></span></summary>
    <label class="field-label" for="urlInput">Ignite server URL</label>
    <div class="input-row">
      <input id="urlInput" type="text" spellcheck="false" autocomplete="off" placeholder="http://localhost:51337">
    </div>
    <div class="btn-row">
      <button id="saveUrlBtn">Save &amp; connect</button>
      <button class="secondary" id="testUrlBtn">Test</button>
      <button class="link" id="resetUrlBtn">Reset to default</button>
    </div>
    <div class="feedback" id="urlFeedback" hidden></div>

    <label class="field-label" for="keyInput">API key <span class="muted">(optional)</span></label>
    <div class="input-row">
      <input id="keyInput" type="password" spellcheck="false" autocomplete="off" placeholder="ignite_…">
    </div>
    <div class="btn-row">
      <button class="secondary" id="saveKeyBtn">Save key</button>
      <button class="link" id="clearKeyBtn" hidden>Remove key</button>
    </div>
    <div class="hint" id="keyHint"></div>
    <button class="link" id="showGetKeyBtn" hidden>No key? Sign in to create one</button>
    <div class="getkey" id="getKey">
      <div class="getkey-title">Get a key</div>
      <div id="getKeyPassword">
        <input id="mintEmail" type="text" spellcheck="false" autocomplete="username" placeholder="you@example.com">
        <input id="mintPassword" type="password" autocomplete="current-password" placeholder="Ignite password">
        <button class="wide" id="mintBtn">Sign in &amp; create key</button>
        <div class="hint">Creates a key for this machine and stores it in your keychain. Your password is only used for this sign-in and is not saved.</div>
      </div>
      <div id="getKeySso" hidden>
        <button class="wide secondary" id="openKeysPageBtn">Create a key in the web UI ↗</button>
        <div class="hint">Sign in there with <span id="ssoMode">SSO</span>, create a key, then paste it above.</div>
      </div>
      <div class="feedback" id="mintFeedback" hidden></div>
      <details class="mint">
        <summary>No account, or admin on the server?</summary>
        <div class="hint">Mint one for any existing user from the ignite repo root on the server host:</div>
        <div class="copy-row"><code id="mintCmd">${escapeAttr(MINT_API_KEY_COMMAND)}</code><button class="icon-btn" id="copyMintBtn" title="Copy command" aria-label="Copy command">${ICON_COPY}</button></div>
      </details>
    </div>
    <div class="btn-row">
      <button class="link" id="openWebUiBtn">Open web UI ↗</button>
      <button class="link" id="openSettingsBtn">All settings</button>
    </div>
  </details>

  <section class="card">
    <div class="card-title">Scan</div>
    <button class="primary wide" id="scanBtn" data-run="ignite.scanWorkspace">${ICON_SHIELD}<span>Scan workspace</span></button>
    <div class="btn-row split">
      <button class="secondary" data-run="ignite.scanChangedFiles">Changed files</button>
      <button class="secondary" data-run="ignite.scanFolder">Folder…</button>
    </div>
    <div class="hint" id="scanModeHint"></div>
    <label class="check"><input type="checkbox" id="optCi"> Run org governance CI <span class="muted">(act + Docker, slow)</span></label>
    <label class="check"><input type="checkbox" id="optOverridden"> Show acknowledged findings</label>
  </section>

  <section class="card result" id="resultCard" hidden>
    <div class="result-head">
      <span class="badge" id="resultBadge"></span>
      <span class="muted" id="resultWhen"></span>
    </div>
    <div class="result-detail" id="resultDetail"></div>
    <div class="counters" id="counters">
      <button class="counter danger" data-run="igniteFindings.focus"><b id="cBlocking">0</b><span>blocking</span></button>
      <button class="counter warn" data-run="igniteFindings.focus"><b id="cWarnings">0</b><span>warnings</span></button>
      <button class="counter ok" data-run="igniteFindings.focus"><b id="cAck">0</b><span>acknowledged</span></button>
    </div>
    <div class="btn-row" id="resultActions">
      <button class="secondary" data-run="ignite.openReviewFile" id="reviewBtn">Review file</button>
      <button class="secondary" data-run="ignite.generateFixPr" id="fixPrBtn">Generate fix PR</button>
      <button class="link" data-run="ignite.showOutput">Output</button>
    </div>
  </section>

  <section class="card">
    <div class="card-title">Reports</div>
    <div class="list">
      <button class="row" data-run="ignite.showLicenseCompliance"><span>License compliance</span><span class="chev">›</span></button>
      <button class="row" data-run="ignite.showSbom"><span>SBOM</span><span class="chev">›</span></button>
      <button class="row" data-run="ignite.showLocMetrics"><span>LOC metrics</span><span class="chev">›</span></button>
      <button class="row" data-run="ignite.showPosture"><span>Compliance posture</span><span class="chev">›</span></button>
      <button class="row" data-run="ignite.runDailyReport"><span>Org daily report…</span><span class="chev">›</span></button>
    </div>
  </section>

  <section class="card">
    <div class="card-title">Workspace</div>
    <div class="list">
      <button class="row" data-run="ignite.installPrePushHook"><span>Install pre-push hook</span><span class="chev">›</span></button>
      <button class="row" data-run="ignite.openReviewFile"><span>Open acknowledgments file</span><span class="chev">›</span></button>
      <button class="row" data-run="igniteToolsStatus.focus"><span>Scanner tools</span><span class="muted" id="toolsSummary"></span></button>
    </div>
  </section>
</div>
<script nonce="${nonce}">${SCRIPT}</script>
</body>
</html>`;
  }
}

/** Writes to wherever the value currently lives (workspace wins if it's set there), else user settings. */
export async function updateSetting(key: string, value: unknown): Promise<void> {
  const config = vscode.workspace.getConfiguration('ignite');
  const inspected = config.inspect(key);
  const target = inspected?.workspaceFolderValue !== undefined
    ? vscode.ConfigurationTarget.WorkspaceFolder
    : inspected?.workspaceValue !== undefined
    ? vscode.ConfigurationTarget.Workspace
    : vscode.ConfigurationTarget.Global;
  await config.update(key, value, target);
}

function escapeAttr(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
}

const ICON_COPY = '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M4 4V2.5A1.5 1.5 0 0 1 5.5 1h7A1.5 1.5 0 0 1 14 2.5v7a1.5 1.5 0 0 1-1.5 1.5H11v1.5A1.5 1.5 0 0 1 9.5 14h-7A1.5 1.5 0 0 1 1 12.5v-7A1.5 1.5 0 0 1 2.5 4H4zm1 0h4.5A1.5 1.5 0 0 1 11 5.5V10h1.5a.5.5 0 0 0 .5-.5v-7a.5.5 0 0 0-.5-.5h-7a.5.5 0 0 0-.5.5V4zM2.5 5a.5.5 0 0 0-.5.5v7a.5.5 0 0 0 .5.5h7a.5.5 0 0 0 .5-.5v-7a.5.5 0 0 0-.5-.5h-7z"/></svg>';
const ICON_REFRESH = '<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path fill="currentColor" d="M13.45 5.17A6 6 0 1 0 14 8h-1.5a4.5 4.5 0 1 1-.9-2.7L9.5 7.5H14V3l-1.55 2.17z"/></svg>';
const ICON_SHIELD = '<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path fill="currentColor" d="M8 1 2.5 3.2v4c0 3.3 2.3 6.1 5.5 7.3 3.2-1.2 5.5-4 5.5-7.3v-4L8 1zm0 1.6 4 1.6v3c0 2.5-1.6 4.7-4 5.8-2.4-1.1-4-3.3-4-5.8v-3l4-1.6z"/></svg>';

const STYLE = /* css */ `
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 10px 12px 16px;
    font-family: var(--vscode-font-family); font-size: var(--vscode-font-size);
    color: var(--vscode-foreground); background: transparent;
  }
  [hidden] { display: none !important; }
  .muted { color: var(--vscode-descriptionForeground); font-weight: normal; }
  .card {
    border: 1px solid var(--vscode-widget-border, var(--vscode-panel-border, rgba(128,128,128,.25)));
    border-radius: 6px; padding: 10px; margin-bottom: 10px;
    background: var(--vscode-sideBar-background);
  }
  .card-title, summary {
    font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .04em;
    color: var(--vscode-descriptionForeground); margin-bottom: 8px;
  }
  details.card > summary { cursor: pointer; list-style: none; display: flex; justify-content: space-between; margin-bottom: 0; }
  details.card > summary::-webkit-details-marker { display: none; }
  details.card > summary::before { content: '›'; display: inline-block; margin-right: 6px; transition: transform .1s; }
  details.card[open] > summary::before { transform: rotate(90deg); }
  details.card[open] > summary { margin-bottom: 8px; }
  details.card > summary > span:first-child { flex: 1; }
  .summary-hint { text-transform: none; letter-spacing: 0; font-weight: normal; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 60%; }

  .conn { margin-bottom: 10px; padding: 8px 10px; border-radius: 6px; background: var(--vscode-textBlockQuote-background, rgba(128,128,128,.08)); }
  .conn-row { display: flex; align-items: center; gap: 8px; }
  .conn-text { flex: 1; min-width: 0; }
  .conn-title { font-weight: 600; }
  .conn-sub { color: var(--vscode-descriptionForeground); font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .conn-error { margin-top: 6px; font-size: 12px; color: var(--vscode-errorForeground); line-height: 1.4; }
  .conn-error code { font-family: var(--vscode-editor-font-family); font-size: 11px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; flex: none; background: var(--vscode-disabledForeground); }
  .dot.connected { background: var(--vscode-testing-iconPassed, #3fb950); box-shadow: 0 0 0 3px color-mix(in srgb, var(--vscode-testing-iconPassed, #3fb950) 25%, transparent); }
  .dot.disconnected { background: var(--vscode-testing-iconFailed, #f85149); }
  .dot.checking { background: var(--vscode-progressBar-background, #0e70c0); animation: pulse 1s infinite ease-in-out; }
  @keyframes pulse { 50% { opacity: .35; } }

  .field-label { display: block; font-size: 12px; margin: 8px 0 4px; }
  .field-label:first-of-type { margin-top: 0; }
  input[type=text], input[type=password] {
    width: 100%; padding: 4px 6px; border-radius: 2px;
    font-family: var(--vscode-editor-font-family); font-size: 12px;
    color: var(--vscode-input-foreground); background: var(--vscode-input-background);
    border: 1px solid var(--vscode-input-border, transparent); outline: none;
  }
  input:focus { border-color: var(--vscode-focusBorder); }
  input.invalid { border-color: var(--vscode-inputValidation-errorBorder); }

  button {
    font: inherit; cursor: pointer; border: 1px solid var(--vscode-button-border, transparent);
    border-radius: 2px; padding: 4px 10px;
    color: var(--vscode-button-foreground); background: var(--vscode-button-background);
  }
  button:hover { background: var(--vscode-button-hoverBackground); }
  button:focus-visible { outline: 1px solid var(--vscode-focusBorder); outline-offset: 2px; }
  button:disabled { opacity: .5; cursor: default; }
  button.secondary { color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); }
  button.secondary:hover { background: var(--vscode-button-secondaryHoverBackground); }
  button.link { background: none; border: none; padding: 4px 2px; color: var(--vscode-textLink-foreground); }
  button.link:hover { color: var(--vscode-textLink-activeForeground); text-decoration: underline; background: none; }
  button.wide { width: 100%; display: flex; align-items: center; justify-content: center; gap: 6px; padding: 6px 10px; }
  .icon-btn { background: none; border: none; padding: 3px; color: var(--vscode-icon-foreground); border-radius: 4px; display: flex; }
  .icon-btn:hover { background: var(--vscode-toolbar-hoverBackground); }
  .icon-btn.spin svg { animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .btn-row { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; margin-top: 6px; }
  .btn-row.split > button { flex: 1; }

  .feedback { margin-top: 6px; font-size: 12px; line-height: 1.4; }
  .feedback.ok { color: var(--vscode-testing-iconPassed, #3fb950); }
  .feedback.err { color: var(--vscode-errorForeground); }
  .hint { margin-top: 4px; font-size: 12px; color: var(--vscode-descriptionForeground); line-height: 1.4; }
  .hint.warn { color: var(--vscode-editorWarning-foreground); }

  .getkey { margin-top: 10px; padding: 8px; border-radius: 4px; background: var(--vscode-textBlockQuote-background, rgba(128,128,128,.08)); }
  .getkey-title { font-size: 12px; font-weight: 600; margin-bottom: 6px; }
  .getkey input { margin-bottom: 6px; }
  details.mint { margin-top: 6px; font-size: 12px; }
  details.mint > summary { cursor: pointer; color: var(--vscode-textLink-foreground); text-transform: none; letter-spacing: 0; font-weight: normal; font-size: 12px; margin: 0; }
  details.mint ol { margin: 6px 0 0; padding-left: 18px; line-height: 1.5; color: var(--vscode-descriptionForeground); }
  details.mint code { font-family: var(--vscode-editor-font-family); font-size: 11px; word-break: break-all; color: var(--vscode-textPreformat-foreground); }
  .copy-row { display: flex; align-items: flex-start; gap: 4px; margin: 4px 0; padding: 4px 6px; border-radius: 3px; background: var(--vscode-textCodeBlock-background, rgba(128,128,128,.12)); }
  .copy-row code { flex: 1; }
  .check { display: flex; align-items: center; gap: 6px; margin-top: 8px; font-size: 12px; cursor: pointer; }
  .check input { margin: 0; accent-color: var(--vscode-button-background); }

  .result { border-left-width: 3px; }
  .result.passed { border-left-color: var(--vscode-testing-iconPassed, #3fb950); }
  .result.blocked, .result.failed, .result.error { border-left-color: var(--vscode-testing-iconFailed, #f85149); }
  .result.running { border-left-color: var(--vscode-progressBar-background, #0e70c0); }
  .result-head { display: flex; align-items: center; justify-content: space-between; gap: 6px; font-size: 12px; }
  .badge { font-weight: 600; font-size: 12px; display: inline-flex; align-items: center; gap: 6px; }
  .badge .spinner { width: 10px; height: 10px; border: 2px solid currentColor; border-right-color: transparent; border-radius: 50%; animation: spin .8s linear infinite; }
  .result-detail { font-size: 12px; margin: 6px 0 2px; color: var(--vscode-descriptionForeground); line-height: 1.4; word-break: break-word; }
  .counters { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; margin: 8px 0 2px; }
  .counter {
    display: flex; flex-direction: column; align-items: center; padding: 6px 2px;
    background: var(--vscode-textBlockQuote-background, rgba(128,128,128,.08)); color: var(--vscode-foreground);
    border: 1px solid transparent; border-radius: 4px;
  }
  .counter:hover { background: var(--vscode-list-hoverBackground); }
  .counter b { font-size: 18px; line-height: 1.2; font-variant-numeric: tabular-nums; }
  .counter span { font-size: 11px; color: var(--vscode-descriptionForeground); }
  .counter.danger.nonzero b { color: var(--vscode-testing-iconFailed, #f85149); }
  .counter.warn.nonzero b { color: var(--vscode-editorWarning-foreground, #d29922); }

  .list { display: flex; flex-direction: column; margin: 0 -4px; }
  .row {
    display: flex; justify-content: space-between; align-items: center; gap: 8px;
    background: none; border: none; color: var(--vscode-foreground); text-align: left; padding: 5px 4px; border-radius: 3px;
  }
  .row:hover { background: var(--vscode-list-hoverBackground); }
  .chev { color: var(--vscode-descriptionForeground); }
`;

const SCRIPT = /* js */ `
(function () {
  const vscode = acquireVsCodeApi();
  const $ = (id) => document.getElementById(id);
  let latest = null;
  let urlDirty = false;
  let ticker = null;

  document.querySelectorAll('[data-run]').forEach((el) =>
    el.addEventListener('click', () => vscode.postMessage({ type: 'run', command: el.dataset.run }))
  );

  const urlInput = $('urlInput');
  const keyInput = $('keyInput');
  urlInput.addEventListener('input', () => { urlDirty = true; urlInput.classList.remove('invalid'); hide('urlFeedback'); });
  urlInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') saveUrl(); if (e.key === 'Escape') resetUrlField(); });
  keyInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') saveKey(); });

  $('saveUrlBtn').addEventListener('click', saveUrl);
  $('testUrlBtn').addEventListener('click', () => {
    busy('testUrlBtn', true, 'Testing…');
    vscode.postMessage({ type: 'testUrl', url: urlInput.value });
  });
  $('resetUrlBtn').addEventListener('click', () => { urlDirty = false; vscode.postMessage({ type: 'resetUrl' }); });
  $('reconnectBtn').addEventListener('click', () => vscode.postMessage({ type: 'reconnect' }));
  $('saveKeyBtn').addEventListener('click', saveKey);
  $('clearKeyBtn').addEventListener('click', () => vscode.postMessage({ type: 'clearKey' }));
  let getKeyExpanded = false;
  $('showGetKeyBtn').addEventListener('click', () => { getKeyExpanded = true; if (latest) render(latest); $('mintEmail').focus(); });
  $('mintBtn').addEventListener('click', mint);
  $('mintPassword').addEventListener('keydown', (e) => { if (e.key === 'Enter') mint(); });
  $('openKeysPageBtn').addEventListener('click', () => vscode.postMessage({ type: 'openKeysPage' }));
  function mint() {
    const email = $('mintEmail').value.trim();
    const password = $('mintPassword').value;
    if (!email || !password) { mintFeedback(false, 'Enter your Ignite email and password.'); return; }
    busy('mintBtn', true, 'Signing in…');
    hide('mintFeedback');
    vscode.postMessage({ type: 'mintKey', email, password });
  }
  function mintFeedback(ok, text) {
    const el = $('mintFeedback');
    el.textContent = text;
    el.className = 'feedback ' + (ok ? 'ok' : 'err');
    el.hidden = false;
  }
  $('copyMintBtn').addEventListener('click', () => vscode.postMessage({ type: 'copy', text: $('mintCmd').textContent }));
  $('openWebUiBtn').addEventListener('click', () => vscode.postMessage({ type: 'openWebUi' }));
  $('openSettingsBtn').addEventListener('click', () => vscode.postMessage({ type: 'openSettings' }));
  $('optCi').addEventListener('change', (e) => vscode.postMessage({ type: 'setOption', key: 'runLocalCi', value: e.target.checked }));
  $('optOverridden').addEventListener('change', (e) => vscode.postMessage({ type: 'setOption', key: 'showOverriddenIssues', value: e.target.checked }));

  function saveUrl() {
    busy('saveUrlBtn', true, 'Connecting…');
    vscode.postMessage({ type: 'saveUrl', url: urlInput.value });
  }
  function saveKey() {
    if (!keyInput.value.trim()) return;
    busy('saveKeyBtn', true, 'Saving…');
    vscode.postMessage({ type: 'saveKey', key: keyInput.value });
  }
  function resetUrlField() {
    urlDirty = false;
    if (latest) urlInput.value = latest.baseUrl;
    urlInput.classList.remove('invalid');
    hide('urlFeedback');
  }
  function busy(id, on, label) {
    const b = $(id);
    if (on) { b.dataset.label = b.textContent; b.textContent = label; b.disabled = true; }
    else if (b.dataset.label) { b.textContent = b.dataset.label; b.disabled = false; }
  }
  function show(id) { $(id).hidden = false; }
  function hide(id) { $(id).hidden = true; }
  function feedback(ok, text) {
    const el = $('urlFeedback');
    el.textContent = text;
    el.className = 'feedback ' + (ok ? 'ok' : 'err');
    el.hidden = false;
  }
  function hostOf(url) { try { return new URL(url).host + new URL(url).pathname.replace(/\\/$/, ''); } catch { return url; } }
  function probeLine(p) {
    const bits = [];
    if (typeof p.latencyMs === 'number') bits.push(p.latencyMs + ' ms');
    if (p.authMode) bits.push(p.authMode + ' auth');
    return bits.join(' · ');
  }
  function ago(ts) {
    const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
    if (s < 60) return 'just now';
    const m = Math.round(s / 60); if (m < 60) return m + ' min ago';
    const h = Math.round(m / 60); if (h < 24) return h + ' h ago';
    return new Date(ts).toLocaleString();
  }
  function dur(ms) {
    const s = Math.round(ms / 1000);
    return s < 60 ? s + 's' : Math.floor(s / 60) + 'm ' + (s % 60) + 's';
  }

  window.addEventListener('message', (event) => {
    const m = event.data;
    if (m.type === 'state') render(m);
    else if (m.type === 'focusKey') {
      $('serverDetails').open = true;
      getKeyExpanded = true;
      if (latest) render(latest);
      const target = !$('getKey').hidden && !$('getKeyPassword').hidden ? $('mintEmail') : keyInput;
      target.scrollIntoView({ block: 'center' });
      target.focus();
    }
    else if (m.type === 'focusUrl') { $('serverDetails').open = true; urlInput.focus(); urlInput.select(); }
    else if (m.type === 'urlResult') {
      busy('saveUrlBtn', false); busy('testUrlBtn', false);
      if (!m.ok && !m.probe) { urlInput.classList.add('invalid'); feedback(false, m.error); return; }
      if (m.probe && m.probe.ok) {
        const who = m.probe.user && m.probe.user.email ? ' — signed in as ' + m.probe.user.email : '';
        feedback(true, (m.action === 'save' ? 'Saved. ' : '') + 'Ignite answered in ' + m.probe.latencyMs + ' ms' + who + '.');
        if (m.action === 'save') urlDirty = false;
      } else if (m.probe) {
        feedback(false, (m.action === 'save' ? 'Saved, but ' : '') + (m.probe.error || 'not reachable') );
        if (m.action === 'save') urlDirty = false;
      }
    } else if (m.type === 'mintResult') {
      busy('mintBtn', false);
      $('mintPassword').value = '';
      if (m.ok) mintFeedback(true, 'Key created for ' + (m.email || 'your account') + ' and saved to your keychain.');
      else mintFeedback(false, m.error || 'Could not create a key.');
    } else if (m.type === 'keyResult') {
      busy('saveKeyBtn', false);
      if (m.ok) keyInput.value = '';
      else { const h = $('keyHint'); h.textContent = m.error; h.className = 'hint warn'; }
    }
  });

  function render(m) {
    latest = m;
    const { state } = m;
    const c = state.connection;

    if (!urlDirty && document.activeElement !== urlInput) urlInput.value = m.baseUrl;
    $('serverHint').textContent = hostOf(m.baseUrl);

    const dot = $('connDot');
    dot.className = 'dot ' + (c.status === 'unknown' ? 'checking' : c.status);
    $('reconnectBtn').classList.toggle('spin', c.status === 'checking');
    const err = $('connError');
    if (c.status === 'connected') {
      $('connTitle').textContent = 'Connected';
      const who = c.user && c.user.email ? ' · ' + c.user.email : '';
      $('connSub').textContent = hostOf(c.url) + (probeLine(c) ? ' · ' + probeLine(c) : '') + who;
      $('connSub').title = c.url;
      if (c.keyRejected) {
        err.textContent = 'The API key was not accepted by this server — requests run unauthenticated.';
        err.hidden = false;
      } else err.hidden = true;
    } else if (c.status === 'disconnected') {
      $('connTitle').textContent = 'Not connected';
      $('connSub').textContent = hostOf(c.url);
      err.innerHTML = '';
      err.append(document.createTextNode((c.error || 'Unreachable.') + ' Start the server (e.g. '));
      const code = document.createElement('code'); code.textContent = 'ignite-server'; err.append(code);
      err.append(document.createTextNode(') or point the URL below at a running one.'));
      err.hidden = false;
      $('serverDetails').open = true;
    } else {
      $('connTitle').textContent = 'Checking server…';
      $('connSub').textContent = c.url ? hostOf(c.url) : '';
      err.hidden = true;
    }

    const src = state.apiKey.source;
    const hint = $('keyHint');
    keyInput.placeholder = state.apiKey.masked || 'ignite_…';
    $('clearKeyBtn').hidden = src !== 'secret';
    if (src === 'secret') { hint.textContent = 'Stored in your OS keychain. Paste a new key to replace it.'; hint.className = 'hint'; }
    else if (src === 'settings') { hint.textContent = 'Using the plaintext "ignite.apiKey" setting. Save it here to move it to the keychain.'; hint.className = 'hint warn'; }
    else { hint.textContent = 'Optional unless the server requires sign-in. Also used to open fix PRs under your own GitHub account.'; hint.className = 'hint'; }
    // "Get a key" shows while there's no working key; password sign-in only for standalone auth.
    // Only push for a key when the server actually demanded one (a 401) or rejected ours —
    // a server allowing unauthenticated simulation works fine without.
    const keyDemanded = !!(state.tools && state.tools.error === 'needs API key');
    const needsKey = (src === 'none' && keyDemanded) || (c.status === 'connected' && c.keyRejected);
    const connected = c.status === 'connected';
    $('getKey').hidden = !connected || !(needsKey || (src === 'none' && getKeyExpanded));
    $('showGetKeyBtn').hidden = !connected || src !== 'none' || !$('getKey').hidden;
    const sso = c.status === 'connected' && c.authMode && c.authMode !== 'standalone';
    $('getKeyPassword').hidden = !!sso;
    $('getKeySso').hidden = !sso;
    if (sso) $('ssoMode').textContent = c.authMode === 'github' ? 'GitHub' : 'your company SSO';
    if (needsKey && state.tools && state.tools.error === 'needs API key') $('serverDetails').open = true;

    $('optCi').checked = m.options.runLocalCi;
    $('scanModeHint').textContent = m.scanMode === 'upload'
      ? 'Remote server: scans upload the folder (respecting .gitignore) as a simulation run.'
      : 'Local server: scans send the folder path; the server reads it from disk.';
    $('optCi').closest('label').hidden = m.scanMode === 'upload';
    $('optOverridden').checked = m.options.showOverriddenIssues;

    const offline = c.status === 'disconnected';
    const running = state.scan.status === 'running';
    const scanBtn = $('scanBtn');
    scanBtn.disabled = running || !m.hasWorkspace;
    scanBtn.querySelector('span').textContent = running ? 'Scanning…' : 'Scan workspace';
    scanBtn.title = !m.hasWorkspace ? 'Open a folder to scan it' : offline ? 'The server looks offline — the scan will re-check first' : '';
    document.querySelectorAll('.btn-row.split button').forEach((b) => {
      // "Folder…" opens a picker, so it works with no workspace open; "Changed files" needs one.
      b.disabled = running || (!m.hasWorkspace && b.dataset.run !== 'ignite.scanFolder');
    });

    renderScan(state.scan);

    const t = state.tools;
    $('toolsSummary').textContent = !t ? '' : t.error ? t.error : t.installed + ' / ' + t.total + ' installed';
  }

  function renderScan(s) {
    const card = $('resultCard');
    if (ticker) { clearInterval(ticker); ticker = null; }
    if (s.status === 'idle') { card.hidden = true; return; }
    card.hidden = false;
    card.className = 'card result ' + s.status;
    const badge = $('resultBadge');
    const labels = { running: 'Scanning', passed: 'Passed', blocked: 'Blocked', failed: 'Failed', error: 'Scan error' };
    badge.innerHTML = '';
    if (s.status === 'running') { const sp = document.createElement('span'); sp.className = 'spinner'; badge.append(sp); }
    badge.append(document.createTextNode(labels[s.status] || s.status));
    const when = $('resultWhen');
    const tick = () => {
      if (s.status === 'running' && s.startedAt) when.textContent = dur(Date.now() - s.startedAt);
      else if (s.finishedAt) when.textContent = ago(s.finishedAt) + (s.startedAt ? ' · took ' + dur(s.finishedAt - s.startedAt) : '');
    };
    tick();
    ticker = setInterval(tick, s.status === 'running' ? 1000 : 30000);

    const parts = [];
    if (s.target) parts.push(s.target);
    if (s.detail) parts.push(s.detail);
    $('resultDetail').textContent = parts.join(' — ');
    $('resultDetail').hidden = parts.length === 0;

    const done = s.status !== 'running';
    $('counters').hidden = !done || s.status === 'error';
    $('resultActions').hidden = !done;
    $('cBlocking').textContent = s.blocking;
    $('cWarnings').textContent = s.warnings;
    $('cAck').textContent = s.acknowledged;
    $('cBlocking').parentElement.classList.toggle('nonzero', s.blocking > 0);
    $('cWarnings').parentElement.classList.toggle('nonzero', s.warnings > 0);
    $('reviewBtn').hidden = s.blocking === 0;
    $('fixPrBtn').hidden = s.total === 0;
  }

  vscode.postMessage({ type: 'ready' });
})();
`;
