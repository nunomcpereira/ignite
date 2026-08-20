import * as vscode from 'vscode';
import * as fs from 'fs/promises';
import * as fsSync from 'fs';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

/**
 * Installs Ignite's own hooks/pre-push script (from the ignite repo this
 * extension ships alongside) rather than reimplementing its 269-line
 * carry-forward/delta-skip logic in TypeScript — see the plan's rationale.
 * Looks for it at <this extension's install dir>/resources/pre-push first
 * (bundled copy), falling back to asking the user to locate an ignite
 * checkout if that's missing.
 */
export async function installPrePushHook(context: vscode.ExtensionContext, repoRoot: string): Promise<void> {
  const bundled = path.join(context.extensionPath, 'resources', 'pre-push');
  let sourceScript = bundled;
  if (!fsSync.existsSync(bundled)) {
    const picked = await vscode.window.showOpenDialog({
      title: 'Locate ignite/hooks/pre-push',
      canSelectFiles: true,
      canSelectFolders: false,
      canSelectMany: false,
    });
    if (!picked || picked.length === 0) return;
    sourceScript = picked[0].fsPath;
  }

  let hooksDir: string;
  try {
    const { stdout } = await execFileAsync('git', ['config', '--get', 'core.hooksPath'], { cwd: repoRoot });
    hooksDir = stdout.trim() ? path.resolve(repoRoot, stdout.trim()) : path.join(repoRoot, '.git', 'hooks');
  } catch {
    hooksDir = path.join(repoRoot, '.git', 'hooks');
  }

  const dest = path.join(hooksDir, 'pre-push');
  if (fsSync.existsSync(dest)) {
    const existing = await fs.readFile(dest, 'utf8').catch(() => '');
    if (!existing.includes('Ignite pre-push hook')) {
      const choice = await vscode.window.showWarningMessage(
        `${dest} already exists and isn't an Ignite hook. Overwrite it?`,
        { modal: true },
        'Overwrite'
      );
      if (choice !== 'Overwrite') return;
    }
  }

  await fs.mkdir(hooksDir, { recursive: true });
  await fs.copyFile(sourceScript, dest);
  await fs.chmod(dest, 0o755);
  vscode.window.showInformationMessage(`Ignite pre-push hook installed at ${dest}.`);
}
