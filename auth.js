'use strict';

/**
 * Pluggable authentication: AUTH_MODE = 'standalone' (local email/password
 * accounts), 'oidc' (delegate to a company IdP — Okta/Entra/Auth0/any
 * standards-compliant OIDC provider), or 'github' (sign in with a GitHub
 * account via github.oauth — also connects that account for push in the
 * same step). All modes converge on the same session-cookie + `req.user`
 * shape, which is what audit-log attribution (who overrode a flagged
 * guideline) relies on downstream.
 */

const crypto = require('crypto');
const { promisify } = require('util');

const scrypt = promisify(crypto.scrypt);

const SESSION_COOKIE = 'ignite_sid';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h

const API_KEY_PREFIX = 'ignite_';

// API keys are high-entropy random secrets (not user-chosen passwords), so
// there's no offline-guessing risk to slow down with scrypt — a plain
// SHA-256 lookup hash is standard practice for this class of token (same
// approach GitHub/Stripe use for PATs) and keeps every authenticated
// request from paying scrypt's ~100ms cost.
function hashApiKey(rawKey) {
  return crypto.createHash('sha256').update(rawKey, 'utf8').digest('hex');
}

function generateApiKey() {
  return `${API_KEY_PREFIX}${crypto.randomBytes(32).toString('hex')}`;
}

// __proto__/constructor/prototype can never be real cookie names we care
// about (SESSION_COOKIE is 'ignite_sid') - rejecting them outright means
// `out[key] = val` below is never a property-name-from-user-input write
// onto anything but this fresh plain object, regardless of what a client
// sends as a cookie name.
const UNSAFE_COOKIE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function parseCookies(header) {
  const out = {};
  String(header || '')
    .split(';')
    .forEach((pair) => {
      const idx = pair.indexOf('=');
      if (idx === -1) return;
      const key = pair.slice(0, idx).trim();
      const val = pair.slice(idx + 1).trim();
      // eslint-disable-next-line security/detect-object-injection -- key is guarded above (UNSAFE_COOKIE_KEYS), see codeql-sast::auth.js::52 in .ignite/acknowledgments.md
      if (key && !UNSAFE_COOKIE_KEYS.has(key)) out[key] = decodeURIComponent(val);
    });
  return out;
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = await scrypt(password, salt, 64);
  return `${salt}:${derived.toString('hex')}`;
}

async function verifyPassword(password, stored) {
  const [salt, hashHex] = String(stored || '').split(':');
  if (!salt || !hashHex) return false;
  const derived = await scrypt(password, salt, 64);
  const expected = Buffer.from(hashHex, 'hex');
  return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
}

function isValidEmail(email) {
  const str = String(email || '');
  // RFC 5321's own length cap - also bounds the regex below to trivial
  // input sizes, so its worst-case backtracking cost never grows large
  // enough to matter regardless of crafted input shape.
  if (!str || str.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(str);
}

// A fixed, valid-shaped hash to verify against when the account doesn't
// exist (or isn't a local-password account) - hashPassword() is async and
// per-call-random-salted, so this is computed once, lazily, on first use.
// Verifying against it costs the same one scrypt derivation as a real
// wrong-password attempt does, so a login response's timing doesn't
// distinguish "no such account" from "wrong password" (CWE-208/CWE-203).
let dummyHashPromise = null;
function dummyHash() {
  if (!dummyHashPromise) dummyHashPromise = hashPassword(crypto.randomBytes(24).toString('hex'));
  return dummyHashPromise;
}

// Minimal fixed-window limiter, in-memory (single-process - matches how
// sessions/pendingStates are already kept here). Swept on a timer, not
// just pruned lazily on the next request, so a flood of requests against
// an endpoint that never succeeds can't grow this unboundedly either.
function createRateLimiter({ windowMs, max }) {
  const hits = new Map(); // key -> { count, resetAt }
  setInterval(() => {
    const now = Date.now();
    for (const [key, v] of hits) if (v.resetAt <= now) hits.delete(key);
  }, windowMs).unref();
  return {
    check(key) {
      const now = Date.now();
      let entry = hits.get(key);
      if (!entry || entry.resetAt <= now) {
        entry = { count: 0, resetAt: now + windowMs };
        hits.set(key, entry);
      }
      entry.count++;
      return entry.count <= max;
    },
    reset(key) {
      hits.delete(key);
    },
  };
}
const loginLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 8 }); // per email
const registerLimiter = createRateLimiter({ windowMs: 60 * 60 * 1000, max: 8 }); // per IP

/**
 * @param {object} store - createDbStore() instance
 * @param {object} authConfig - CONFIG.auth: { mode, allowSelfRegistration, oidc: {...} }
 * @param {object} githubConfig - CONFIG.github: { orgs, bootstrapBranch, oauth: {...} }
 */
function createAuth(store, authConfig = {}, githubConfig = {}) {
  const mode = ['oidc', 'github'].includes(authConfig.mode) ? authConfig.mode : 'standalone';
  const allowSelfRegistration = authConfig.allowSelfRegistration !== false;
  const secureCookies = process.env.NODE_ENV === 'production';

  function setSessionCookie(res, sessionId) {
    const parts = [
      `${SESSION_COOKIE}=${encodeURIComponent(sessionId)}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Lax',
      `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
    ];
    if (secureCookies) parts.push('Secure');
    res.setHeader('Set-Cookie', parts.join('; '));
  }

  function clearSessionCookie(res) {
    res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; Max-Age=0`);
  }

  function issueSession(res, userId) {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
    store.createSession(sessionId, userId, expiresAt);
    setSessionCookie(res, sessionId);
  }

  /* Attaches req.user (or null) from the session cookie, or — for headless
     agent/CLI callers with no browser to hold a cookie jar — from an
     `Authorization: Bearer ignite_<key>` API key minted by
     scripts/create-api-key.js. Session cookie wins if both are present.
     Never blocks. */
  function attachUser(req, res, next) {
    const cookies = parseCookies(req.headers.cookie);
    // eslint-disable-next-line security/detect-object-injection -- SESSION_COOKIE is a fixed constant, not user input
    const sessionId = cookies[SESSION_COOKIE];
    req.user = null;
    if (sessionId) {
      const session = store.getSession(sessionId);
      if (session && new Date(session.expires_at).getTime() > Date.now()) {
        req.user = { id: session.user_id, email: session.email, name: session.name, provider: session.provider };
      }
    }
    if (!req.user) {
      const authHeader = String(req.headers.authorization || '');
      const [scheme, token] = authHeader.split(' ');
      if (scheme === 'Bearer' && token && token.startsWith(API_KEY_PREFIX)) {
        const row = store.getActiveApiKeyByHash(hashApiKey(token));
        if (row) {
          req.user = { id: row.user_id, email: row.email, name: row.name, provider: row.provider };
          store.touchApiKeyLastUsed(row.id);
        }
      }
    }
    next();
  }

  /* Blocks with 401 unless a session is attached. Use on routes that need attribution. */
  function requireAuth(req, res, next) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required.' });
    next();
  }

  const router = require('express').Router();

  router.get('/api/auth/config', (req, res) => {
    res.json({ mode, allowSelfRegistration: mode === 'standalone' && allowSelfRegistration });
  });

  router.get('/api/auth/me', (req, res) => {
    res.json({ user: req.user });
  });

  router.post('/api/auth/logout', (req, res) => {
    const cookies = parseCookies(req.headers.cookie);
    // eslint-disable-next-line security/detect-object-injection -- SESSION_COOKIE is a fixed constant, not user input
    const sessionId = cookies[SESSION_COOKIE];
    if (sessionId) store.deleteSession(sessionId);
    clearSessionCookie(res);
    res.json({ ok: true });
  });

  if (mode === 'standalone') {
    router.post('/api/auth/register', async (req, res) => {
      if (!allowSelfRegistration) {
        return res.status(403).json({ error: 'Self-registration is disabled. Ask an admin to create your account.' });
      }
      if (!registerLimiter.check(req.socket.remoteAddress || 'unknown')) {
        return res.status(429).json({ error: 'Too many registration attempts. Try again later.' });
      }
      const email = String(req.body?.email || '').trim().toLowerCase();
      const name = String(req.body?.name || '').trim();
      const password = String(req.body?.password || '');
      if (!isValidEmail(email)) return res.status(400).json({ error: 'A valid email is required.' });
      if (password.length < 10) return res.status(400).json({ error: 'Password must be at least 10 characters.' });
      if (store.getUserByEmail(email)) return res.status(409).json({ error: 'An account with this email already exists.' });

      const passwordHash = await hashPassword(password);
      const userId = store.createLocalUser(email, name, passwordHash);
      issueSession(res, userId);
      res.status(201).json({ user: { id: userId, email, name } });
    });

    router.post('/api/auth/login', async (req, res) => {
      const email = String(req.body?.email || '').trim().toLowerCase();
      const password = String(req.body?.password || '');
      if (!loginLimiter.check(email || req.socket.remoteAddress || 'unknown')) {
        return res.status(429).json({ error: 'Too many attempts. Try again later.' });
      }
      const user = store.getUserByEmail(email);
      // Always run one scrypt derivation either way - verifying against a
      // fixed dummy hash when there's no real local account to check
      // against - so a nonexistent/non-local email doesn't respond
      // measurably faster than a wrong password on a real account.
      const passwordOk = user && user.provider === 'local'
        ? await verifyPassword(password, user.password_hash)
        : await verifyPassword(password, await dummyHash());
      if (!user || user.provider !== 'local' || !passwordOk) {
        return res.status(401).json({ error: 'Invalid email or password.' });
      }
      loginLimiter.reset(email);
      issueSession(res, user.id);
      res.json({ user: { id: user.id, email: user.email, name: user.name } });
    });
  }

  if (mode === 'oidc') {
    // Lazy-init: openid-client's discovery call is async and network-bound;
    // don't block server boot on the IdP being reachable.
    let clientPromise = null;
    const pendingStates = new Map(); // state -> { nonce, createdAt }

    function getClient() {
      if (!clientPromise) {
        const { issuer: issuerUrl, clientId, clientSecret, redirectUri } = authConfig.oidc || {};
        if (!issuerUrl || !clientId || !redirectUri) {
          throw new Error('OIDC is not configured: set auth.oidc.issuer, clientId, and redirectUri.');
        }
        const { Issuer } = require('openid-client');
        clientPromise = Issuer.discover(issuerUrl).then(
          (issuer) =>
            new issuer.Client({
              client_id: clientId,
              client_secret: clientSecret,
              redirect_uris: [redirectUri],
              response_types: ['code'],
            })
        );
      }
      return clientPromise;
    }

    router.get('/api/auth/oidc/login', async (req, res) => {
      try {
        const { generators } = require('openid-client');
        const client = await getClient();
        const state = generators.state();
        const nonce = generators.nonce();
        pendingStates.set(state, { nonce, createdAt: Date.now() });
        // Prune anything older than 10 minutes — an abandoned login attempt.
        for (const [s, v] of pendingStates) if (Date.now() - v.createdAt > 10 * 60_000) pendingStates.delete(s);

        const url = client.authorizationUrl({
          scope: authConfig.oidc?.scope || 'openid email profile',
          state,
          nonce,
        });
        res.redirect(url);
      } catch (err) {
        res.status(503).json({ error: `OIDC login unavailable: ${err.message}` });
      }
    });

    router.get('/api/auth/oidc/callback', async (req, res) => {
      try {
        const client = await getClient();
        const params = client.callbackParams(req);
        const pending = pendingStates.get(params.state);
        if (!pending) throw new Error('Unknown or expired OIDC state.');
        pendingStates.delete(params.state);

        const tokenSet = await client.callback(authConfig.oidc.redirectUri, params, {
          state: params.state,
          nonce: pending.nonce,
        });
        const claims = tokenSet.claims();
        if (!claims.email) throw new Error('IdP did not return an email claim.');

        const user = store.upsertOidcUser(claims.email, claims.name || claims.email, claims.sub);
        issueSession(res, user.id);
        res.redirect('/');
      } catch (err) {
        // err.message is HTML-escaped below before it ever reaches the
        // response body — an IdP/library error can't inject markup here.
        res.status(401).send(`OIDC login failed: ${escapeHtml(err.message)}`);
      }
    });
  }

  /*
   * GitHub account connection — independent of how the user logged into
   * Ignite (standalone or OIDC). Provisioning (Phase 6: repo creation +
   * push) must run as the actual person who submitted the project, not a
   * shared `gh auth login` session on the server host, so each Ignite user
   * connects their own GitHub account once via OAuth and we hold their
   * access token for that purpose.
   */
  const githubOauth = githubConfig.oauth || {};
  const pendingGithubStates = new Map(); // state -> { userId, isLogin, createdAt }

  router.get('/api/auth/github/status', (req, res) => {
    if (!req.user) return res.json({ connected: false });
    const conn = store.getGithubConnection(req.user.id);
    res.json({ connected: !!conn, login: conn?.github_login || null });
  });

  function startGithubOauth(req, res, { isLogin }) {
    if (!githubOauth.clientId || !githubOauth.redirectUri) {
      return res.status(503).json({ error: 'GitHub OAuth is not configured: set github.oauth.clientId, clientSecret, and redirectUri.' });
    }
    const state = crypto.randomBytes(24).toString('hex');
    pendingGithubStates.set(state, { userId: isLogin ? null : req.user.id, isLogin, createdAt: Date.now() });
    for (const [s, v] of pendingGithubStates) if (Date.now() - v.createdAt > 10 * 60_000) pendingGithubStates.delete(s);

    const url = new URL('https://github.com/login/oauth/authorize');
    url.searchParams.set('client_id', githubOauth.clientId);
    url.searchParams.set('redirect_uri', githubOauth.redirectUri);
    // Signing in (identity) additionally needs the account's email; connecting
    // an already-signed-in user to push on their behalf only needs 'repo'.
    url.searchParams.set('scope', isLogin ? `${githubOauth.scope || 'repo'} user:email` : githubOauth.scope || 'repo');
    url.searchParams.set('state', state);
    res.redirect(url.toString());
  }

  // Sign in to Ignite itself via GitHub identity — only meaningful when
  // auth.mode === 'github' (the standalone/OIDC modes have their own login).
  if (mode === 'github') {
    router.get('/api/auth/github/login', (req, res) => startGithubOauth(req, res, { isLogin: true }));
  }

  router.get('/api/auth/github/connect', requireAuth, (req, res) => startGithubOauth(req, res, { isLogin: false }));

  router.get('/api/auth/github/callback', async (req, res) => {
    try {
      const { code, state } = req.query;
      const pending = state && pendingGithubStates.get(String(state));
      if (!pending) throw new Error('Unknown or expired GitHub OAuth state.');
      pendingGithubStates.delete(String(state));
      if (!pending.isLogin && (!req.user || req.user.id !== pending.userId)) {
        throw new Error('GitHub connection must be completed in the same session that started it.');
      }

      const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({
          client_id: githubOauth.clientId,
          client_secret: githubOauth.clientSecret,
          code,
          redirect_uri: githubOauth.redirectUri,
        }),
      });
      const tokenData = await tokenRes.json();
      if (!tokenData.access_token) {
        throw new Error(tokenData.error_description || tokenData.error || 'GitHub did not return an access token.');
      }

      const authHeaders = {
        Authorization: `Bearer ${tokenData.access_token}`,
        'User-Agent': 'ignite-onboarding-gatekeeper',
      };
      const userRes = await fetch('https://api.github.com/user', { headers: authHeaders });
      const ghUser = await userRes.json();
      if (!ghUser.login) throw new Error('Could not read the GitHub account login.');

      if (pending.isLogin) {
        let email = ghUser.email;
        if (!email) {
          const emailsRes = await fetch('https://api.github.com/user/emails', { headers: authHeaders });
          const emails = await emailsRes.json();
          const primary = Array.isArray(emails) && (emails.find((e) => e.primary && e.verified) || emails.find((e) => e.verified));
          email = primary?.email || `${ghUser.login}@users.noreply.github.com`;
        }
        const user = store.upsertGithubUser(email, ghUser.name || ghUser.login, String(ghUser.id));
        issueSession(res, user.id);
        store.upsertGithubConnection(user.id, ghUser.login, tokenData.access_token, tokenData.scope || '');
      } else {
        store.upsertGithubConnection(req.user.id, ghUser.login, tokenData.access_token, tokenData.scope || '');
      }
      res.redirect('/');
    } catch (err) {
      res.status(401).send(`GitHub authentication failed: ${escapeHtml(err.message)}`);
    }
  });

  router.post('/api/auth/github/disconnect', requireAuth, (req, res) => {
    store.deleteGithubConnection(req.user.id);
    res.json({ ok: true });
  });

  /* Resolves the GitHub access token to use for provisioning/pushing this
     request's project — the connected user's own token, never a fallback
     to any ambient host-level `gh auth login` session. */
  function resolveGithubToken(req) {
    if (!req.user) return null;
    return store.getGithubConnection(req.user.id)?.access_token || null;
  }

  return { router, attachUser, requireAuth, resolveGithubToken, mode, generateApiKey, hashApiKey };
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

module.exports = { createAuth, hashPassword, verifyPassword, isValidEmail, generateApiKey, hashApiKey };
