import * as vscode from 'vscode';
import { toolsStatus, IgniteAuthError, type ToolStatus } from '../api';
import type { ToolsSummary } from '../uiState';
import { MINT_API_KEY_COMMAND } from '../serverUrl';

type Node = { kind: 'tool'; tool: ToolStatus } | { kind: 'error'; message: string; auth: boolean };

/** Sidebar replacement for the web UI's TOOLS_META panel (the soft-dep scanner tools). */
export class ToolsStatusTreeProvider implements vscode.TreeDataProvider<Node> {
  private _onDidChangeTreeData = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private tools: ToolStatus[] = [];
  private error: string | null = null;
  private authError = false;
  private loaded = false;

  async refresh(): Promise<void> {
    try {
      // Installed first, then alphabetical — what's missing is easy to scan at the bottom.
      this.tools = (await toolsStatus()).sort(
        (a, b) => Number(b.installed) - Number(a.installed) || a.name.localeCompare(b.name)
      );
      this.error = null;
      this.authError = false;
    } catch (e) {
      this.tools = [];
      this.authError = e instanceof IgniteAuthError;
      this.error = e instanceof Error ? e.message : String(e);
    }
    this.loaded = true;
    this._onDidChangeTreeData.fire();
  }

  summary(): ToolsSummary | null {
    if (!this.loaded) return null;
    if (this.error) return { installed: 0, total: 0, error: this.authError ? 'needs API key' : 'unavailable' };
    return { installed: this.tools.filter((t) => t.installed).length, total: this.tools.length };
  }

  getTreeItem(node: Node): vscode.TreeItem {
    if (node.kind === 'error' && node.auth) {
      const item = new vscode.TreeItem('API key required');
      item.iconPath = new vscode.ThemeIcon('key', new vscode.ThemeColor('notificationsWarningIcon.foreground'));
      item.description = 'click to set one';
      const tip = new vscode.MarkdownString(
        `${node.message}\n\n**Click here** to sign in from the Overview panel — it creates a key and saves it to your keychain. ` +
          'SSO users create one in the web UI (account bar → **API keys**).\n\nServer admins can also mint one from the ignite repo root:\n'
      );
      tip.appendCodeblock(MINT_API_KEY_COMMAND, 'sh');
      item.tooltip = tip;
      item.command = { command: 'ignite.getApiKey', title: 'Get API Key' };
      return item;
    }
    if (node.kind === 'error') {
      const item = new vscode.TreeItem("Can't reach the Ignite server");
      item.iconPath = new vscode.ThemeIcon('debug-disconnect', new vscode.ThemeColor('testing.iconFailed'));
      item.description = 'click to change server';
      item.tooltip = node.message;
      item.command = { command: 'ignite.configureServer', title: 'Configure Server' };
      return item;
    }
    const tool = node.tool;
    const item = new vscode.TreeItem(tool.name);
    if (tool.installed && tool.enabled) {
      item.iconPath = new vscode.ThemeIcon('pass-filled', new vscode.ThemeColor('testing.iconPassed'));
      item.description = 'ready';
    } else if (tool.installed) {
      item.iconPath = new vscode.ThemeIcon('circle-large-outline', new vscode.ThemeColor('disabledForeground'));
      item.description = 'installed · disabled in config';
    } else {
      item.iconPath = new vscode.ThemeIcon('circle-slash', new vscode.ThemeColor('disabledForeground'));
      item.description = 'not installed · built-in fallback';
    }
    item.tooltip = new vscode.MarkdownString(
      `**${tool.name}**  \n${tool.installed ? (tool.enabled ? 'Installed and enabled.' : 'Installed, but disabled in config.json.') : 'Not installed — the check soft-skips to its built-in fallback.'}${tool.detail ? `\n\n${tool.detail}` : ''}`
    );
    return item;
  }

  getChildren(): Node[] {
    if (this.error) return [{ kind: 'error', message: this.error, auth: this.authError }];
    return this.tools.map((tool) => ({ kind: 'tool', tool }));
  }
}
