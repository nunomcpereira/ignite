/**
 * Pure helpers for the "Server URL" field in the Ignite sidebar — no vscode
 * import, so node:test can cover them directly.
 */

export const DEFAULT_BASE_URL = 'http://localhost:51337';

/**
 * Mints a key on the server host. Run from the ignite repo root: create-api-key
 * opens `ignite.db` relative to the cwd (or IGNITE_DB_PATH), which must be the
 * same database the server uses — and the email must already have an account.
 */
export const MINT_API_KEY_COMMAND = 'cargo run --manifest-path rust/Cargo.toml --bin create-api-key -- you@example.com vscode';

export type NormalizedUrl = { ok: true; url: string } | { ok: false; error: string };

/**
 * Turns whatever the user typed into the base URL every api.ts call prefixes
 * its `/api/...` paths with. Tolerates a missing scheme (`localhost:51337`)
 * and trailing slashes; keeps a path prefix (an Ignite behind a reverse proxy
 * at `/ignite`); rejects anything that isn't plain http(s) or that carries a
 * query/fragment, since those would silently end up in the middle of every
 * request URL.
 */
export function normalizeBaseUrl(input: string): NormalizedUrl {
  const raw = input.trim();
  if (!raw) return { ok: false, error: 'Enter the URL of a running Ignite server.' };
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    return { ok: false, error: `"${raw}" isn't a valid URL.` };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, error: 'Only http:// and https:// URLs are supported.' };
  }
  if (parsed.search || parsed.hash) {
    return { ok: false, error: 'Leave out any ?query or #fragment — just the server address.' };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, error: 'Don\'t put credentials in the URL — use the API key field instead.' };
  }
  const pathPart = parsed.pathname.replace(/\/+$/, '');
  return { ok: true, url: `${parsed.protocol}//${parsed.host}${pathPart}` };
}

/** Strips a pasted "Bearer " prefix; empty string means "no key". */
export function cleanApiKey(input: string): string {
  return input.trim().replace(/^Bearer\s+/i, '').trim();
}

/** "ignite_abcd…wxyz" — enough to recognise which key is stored, never the whole secret. */
export function maskApiKey(key: string): string {
  if (!key) return '';
  if (key.length <= 12) return '•'.repeat(key.length);
  return `${key.slice(0, 7)}…${key.slice(-4)}`;
}
