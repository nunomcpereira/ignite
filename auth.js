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

function parseCookies(header) {
  const out = {};
  String(header || '')
    .split(';')
    .forEach((pair) => {
      const idx = pair.indexOf('=');
      if (idx === -1) return;
      const key = pair.slice(0, idx).trim();
      const val = pair.slice(idx + 1).trim();
      if (key) out[key] = decodeURIComponent(val);
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
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || ''));
}

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

  /* Attaches req.user (or null) from the session cookie. Never blocks. */
  function attachUser(req, res, next) {
    const cookies = parseCookies(req.headers.cookie);
    const sessionId = cookies[SESSION_COOKIE];
    req.user = null;
    if (sessionId) {
      const session = store.getSession(sessionId);
      if (session && new Date(session.expires_at).getTime() > Date.now()) {
        req.user = { id: session.user_id, email: session.email, name: session.name, provider: session.provider };
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
      const user = store.getUserByEmail(email);
      if (!user || user.provider !== 'local' || !(await verifyPassword(password, user.password_hash))) {
        return res.status(401).json({ error: 'Invalid email or password.' });
      }
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

  return { router, attachUser, requireAuth, resolveGithubToken, mode };
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

module.exports = { createAuth, hashPassword, verifyPassword, isValidEmail };
