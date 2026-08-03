'use strict';

/**
 * REST API exposing the same company AI validation guidelines as
 * mcp-server.js, for callers that want plain HTTP instead of MCP
 * (CI steps, pre-commit hooks, dashboards, etc.).
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const { listGuidelines, getGuideline, listCategories } = require('./guidelines/catalog');
const { checkContent, checkProject } = require('./guidelines/checks');

const app = express();
app.use(express.json({ limit: '2mb' }));

// /check-project resolves and reads arbitrary paths on the host filesystem
// by design — this is a local dev/CI tool for scanning your own checkouts,
// not a multi-tenant service, so there is no per-path allowlist to enforce.
// The real boundary is that nothing here should ever be reachable except
// from the same machine. Binding app.listen() to 127.0.0.1 (below) is the
// primary control; this middleware is defense in depth for that same
// invariant — enforced per-request, independent of how/where the process
// ends up bound (e.g. an operator accidentally setting GUIDELINES_API_HOST,
// or a reverse proxy forwarding connections from elsewhere) — so a request
// that somehow arrives from a non-loopback peer is rejected before it ever
// reaches a route handler, regardless of the path it asks for.
const LOOPBACK_ADDRESSES = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
function isLoopbackAddress(remoteAddress) {
  return LOOPBACK_ADDRESSES.has(remoteAddress);
}
app.use((req, res, next) => {
  if (!isLoopbackAddress(req.socket.remoteAddress)) {
    return res.status(403).json({ error: 'This API only accepts connections from localhost.' });
  }
  next();
});

app.get('/health', (req, res) => {
  res.json({ ok: true });
});

app.get('/guidelines', (req, res) => {
  const { category, severity } = req.query;
  if (severity && !['error', 'warning'].includes(severity)) {
    return res.status(400).json({ error: 'severity must be "error" or "warning"' });
  }
  res.json({ guidelines: listGuidelines({ category, severity }), categories: listCategories() });
});

app.get('/guidelines/:id', (req, res) => {
  const guideline = getGuideline(req.params.id);
  if (!guideline) return res.status(404).json({ error: `No guideline with id "${req.params.id}".` });
  res.json(guideline);
});

app.post('/check', (req, res) => {
  const { content, path: relPath } = req.body || {};
  if (typeof content !== 'string' || !content.length) {
    return res.status(400).json({ error: '"content" (string) is required.' });
  }
  const violations = checkContent(content, { path: typeof relPath === 'string' ? relPath : undefined });
  res.json({ violations, hasBlockingViolations: violations.some((v) => v.severity === 'error') });
});

// projectPath is intentionally unrestricted (no allowlist) — see the
// loopback-only middleware above for why that's safe here.
app.post('/check-project', async (req, res) => {
  const { projectPath } = req.body || {};
  if (typeof projectPath !== 'string' || !projectPath.length) {
    return res.status(400).json({ error: '"projectPath" (string, absolute path) is required.' });
  }
  const root = path.resolve(projectPath);
  let stat;
  try {
    stat = await fs.promises.stat(root);
  } catch {
    return res.status(400).json({ error: `Path does not exist: ${root}` });
  }
  if (!stat.isDirectory()) {
    return res.status(400).json({ error: `Path is not a directory: ${root}` });
  }
  const { violations, scanned } = await checkProject(root);
  res.json({ scanned, violations, hasBlockingViolations: violations.some((v) => v.severity === 'error') });
});

app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error(err);
  res.status(500).json({ error: 'Internal error' });
});

if (require.main === module) {
  const port = Number(process.env.GUIDELINES_API_PORT || 8090);
  // /check-project reads arbitrary paths on the host filesystem, so this API
  // is meant for local dev/CI use only — bind to loopback unless overridden.
  const host = process.env.GUIDELINES_API_HOST || '127.0.0.1';
  app.listen(port, host, () => {
    console.log(`AI validation guidelines API listening on ${host}:${port}`);
  });
}

module.exports = app;
module.exports.isLoopbackAddress = isLoopbackAddress;
