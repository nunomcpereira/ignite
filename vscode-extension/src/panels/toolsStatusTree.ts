import * as vscode from 'vscode';
import { toolsStatus, type ToolStatus } from '../api';

/** Sidebar replacement for the web UI's TOOLS_META panel (13 soft-dep tools). */
export class ToolsStatusTreeProvider implements vscode.TreeDataProvider<ToolStatus> {
  private _onDidChangeTreeData = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private tools: ToolStatus[] = [];
  private error: string | null = null;

  async refresh(): Promise<void> {
    try {
      this.tools = (await toolsStatus()).sort((a, b) => a.name.localeCompare(b.name));
      this.error = null;
    } catch (e) {
      this.tools = [];
      this.error = e instanceof Error ? e.message : String(e);
    }
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(tool: ToolStatus): vscode.TreeItem {
    const item = new vscode.TreeItem(tool.name);
    if (tool.installed) {
      item.iconPath = new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'));
      item.description = tool.enabled ? 'installed' : 'installed (disabled)';
    } else {
      item.iconPath = new vscode.ThemeIcon('circle-slash', new vscode.ThemeColor('disabledForeground'));
      item.description = 'not installed — soft-skips to a fallback';
    }
    if (tool.detail) item.tooltip = tool.detail;
    return item;
  }

  getChildren(): vscode.ProviderResult<ToolStatus[]> {
    if (this.error) {
      const item: ToolStatus = { name: this.error, installed: false, enabled: false };
      return [item];
    }
    return this.tools;
  }
}
