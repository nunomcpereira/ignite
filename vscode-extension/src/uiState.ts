import * as vscode from 'vscode';
import type { ServerProbe, ApiKeySource } from './api';

export type ConnectionState =
  | { status: 'unknown' }
  | { status: 'checking'; url: string }
  | ({ status: 'connected' | 'disconnected' } & ServerProbe);

export interface ScanSummary {
  status: 'idle' | 'running' | 'passed' | 'blocked' | 'failed' | 'error';
  /** e.g. "Phase 4 — Security & AI Compliance Scan" while running; the error text on failure. */
  detail?: string;
  target?: string;
  blocking: number;
  warnings: number;
  acknowledged: number;
  total: number;
  startedAt?: number;
  finishedAt?: number;
}

export interface ToolsSummary {
  installed: number;
  total: number;
  error?: string;
}

export interface UiState {
  connection: ConnectionState;
  apiKey: { source: ApiKeySource; masked: string };
  scan: ScanSummary;
  tools: ToolsSummary | null;
}

/**
 * The one place the sidebar panel, status bar and tree views read "how are
 * things right now" from — extension.ts writes, everything else subscribes.
 */
export class UiStateStore {
  private readonly emitter = new vscode.EventEmitter<UiState>();
  readonly onDidChange = this.emitter.event;

  private state: UiState = {
    connection: { status: 'unknown' },
    apiKey: { source: 'none', masked: '' },
    scan: { status: 'idle', blocking: 0, warnings: 0, acknowledged: 0, total: 0 },
    tools: null,
  };

  get current(): UiState {
    return this.state;
  }

  update(patch: Partial<UiState>): void {
    this.state = { ...this.state, ...patch };
    this.emitter.fire(this.state);
  }

  updateScan(patch: Partial<ScanSummary>): void {
    this.update({ scan: { ...this.state.scan, ...patch } });
  }

  dispose(): void {
    this.emitter.dispose();
  }
}
