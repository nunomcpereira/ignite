import * as vscode from 'vscode';
import { listProjects, getProjectDetails, type ProjectStep } from './api';

const POLL_INTERVAL_MS = 1500;

/**
 * Prints each phase's log lines to the output channel exactly once,
 * appending only what's new since the last call — shared between the live
 * poller (partial logs, phase still running) and the final validate-all
 * response (complete logs), so nothing gets duplicated when the poller's
 * last partial view and the authoritative final result overlap.
 */
export class LiveLogPrinter {
  private printedCount = new Map<number, number>();
  private headerPrinted = new Set<number>();

  constructor(private out: vscode.OutputChannel) {}

  appendPhase(phase: number, title: string, state: string, lines: string[]): void {
    if (lines.length === 0) return;
    if (!this.headerPrinted.has(phase)) {
      this.out.appendLine(`\n── Phase ${phase} — ${title} ──`);
      this.headerPrinted.add(phase);
    }
    const already = this.printedCount.get(phase) ?? 0;
    for (let i = already; i < lines.length; i++) this.out.appendLine(lines[i]);
    this.printedCount.set(phase, lines.length);
  }
}

/**
 * Polls GET /api/projects + /api/projects/:id (live step logs, persisted
 * as validate-all's own run progresses server-side) so the user sees
 * something moving instead of a bare "scanning…" status bar for however
 * long Phase 4's tools take. Best-effort: any failure to find/poll the
 * project just means no live updates, never a fatal error for the scan
 * itself — the final validate-all response still carries the full result.
 */
export class ScanProgressPoller {
  private timer: ReturnType<typeof setInterval> | undefined;
  private projectId: number | null = null;
  private readonly startedAt = Date.now();

  constructor(
    private org: string,
    private repo: string,
    private printer: LiveLogPrinter,
    private onPhase: (phase: number, title: string, elapsedSeconds: number) => void
  ) {}

  start(): void {
    this.timer = setInterval(() => void this.tick(), POLL_INTERVAL_MS);
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  private async tick(): Promise<void> {
    try {
      if (this.projectId === null) {
        const projects = await listProjects();
        const match = projects.find(
          (p) => p.org === this.org && p.repo === this.repo && p.status === 'running'
        );
        if (!match) return;
        this.projectId = match.id;
      }
      const details = await getProjectDetails(this.projectId);
      if (!details) return;
      for (const step of details.steps as ProjectStep[]) {
        if (!step.logs) continue;
        const lines = step.logs.split('\n').filter(Boolean);
        this.printer.appendPhase(step.phase, step.title, step.state, lines);
        if (step.state === 'running') this.onPhase(step.phase, step.title, this.elapsedSeconds());
      }
    } catch {
      // Best-effort — a poll failure (e.g. the server restarted mid-scan)
      // just means the next tick tries again, or the final response wins.
    }
  }

  private elapsedSeconds(): number {
    return Math.round((Date.now() - this.startedAt) / 1000);
  }
}
