#!/usr/bin/env node
'use strict';

/**
 * MCP server exposing the company AI validation guidelines so they can be
 * applied during development (from an editor/agent), not just at Ignite
 * onboarding time. Tools: list_guidelines, get_guideline, check_guidelines,
 * check_project.
 */

const path = require('path');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { z } = require('zod');
const { listGuidelines, getGuideline, listCategories } = require('./guidelines/catalog');
const { checkContent, checkProject } = require('./guidelines/checks');

// Base URL of a running Ignite server (`npm start`), used by onboard_project
// to reach POST /api/pipeline/onboard.
const IGNITE_BASE_URL = (process.env.IGNITE_BASE_URL || 'http://localhost:51337').replace(/\/+$/, '');

// Headless auth for endpoints that need req.user (real pushes, overrides
// attribution) — a key minted via `node scripts/create-api-key.js <email>`.
// Optional: tools that only need dryRun/read-only behavior work without it.
const IGNITE_API_KEY = process.env.IGNITE_API_KEY || null;

// Factory so each HTTP session can get its own McpServer instance: a single
// McpServer can only be bound to one transport at a time, but stateful
// Streamable HTTP opens one transport per session.
function buildServer() {
const server = new McpServer({
  name: 'ai-validation-guidelines',
  version: '1.0.0',
});

server.registerTool(
  'list_guidelines',
  {
    title: 'List AI validation guidelines',
    description:
      'List the company AI/security validation guidelines, optionally filtered by category or severity.',
    inputSchema: {
      category: z.string().optional().describe(`Filter by category. One of: ${listCategories().join(', ')}`),
      severity: z.enum(['error', 'warning']).optional(),
    },
  },
  async ({ category, severity }) => {
    console.error('[mcp] list_guidelines called', { category, severity });
    const results = listGuidelines({ category, severity });
    return {
      content: [{ type: 'text', text: JSON.stringify(results, null, 2) }],
    };
  }
);

server.registerTool(
  'get_guideline',
  {
    title: 'Retrieve a single guideline',
    description: 'Retrieve the full detail (description, rationale, remediation) of one guideline by id.',
    inputSchema: {
      id: z.string().describe('Guideline id, e.g. "no-hardcoded-secrets"'),
    },
  },
  async ({ id }) => {
    console.error('[mcp] get_guideline called', { id });
    const guideline = getGuideline(id);
    if (!guideline) {
      return {
        content: [{ type: 'text', text: `No guideline with id "${id}".` }],
        isError: true,
      };
    }
    return { content: [{ type: 'text', text: JSON.stringify(guideline, null, 2) }] };
  }
);

server.registerTool(
  'check_guidelines',
  {
    title: 'Check code against guidelines',
    description:
      'Check a code snippet or file content against the automated guidelines and return any violations.',
    inputSchema: {
      content: z.string().describe('The source code to check'),
      path: z
        .string()
        .optional()
        .describe('File path or name (used to infer language/extension), e.g. "src/agent.py"'),
    },
  },
  async ({ content, path: relPath }) => {
    console.error('[mcp] check_guidelines called', { path: relPath, contentLength: content.length });
    const violations = checkContent(content, { path: relPath });
    const summary = violations.length
      ? `${violations.length} violation(s) found.`
      : 'No violations found.';
    return {
      content: [{ type: 'text', text: `${summary}\n${JSON.stringify(violations, null, 2)}` }],
      isError: violations.some((v) => v.severity === 'error'),
    };
  }
);

server.registerTool(
  'check_project',
  {
    title: 'Check a project directory against guidelines',
    description:
      'Walk a project directory on disk and check every source file against the automated guidelines.',
    inputSchema: {
      projectPath: z.string().describe('Absolute path to the project root to scan'),
    },
  },
  async ({ projectPath }) => {
    console.error('[mcp] check_project called', { projectPath });
    const root = path.resolve(projectPath);
    const { violations, scanned } = await checkProject(root);
    const summary = `Scanned ${scanned} file(s). ${violations.length} violation(s) found.`;
    return {
      content: [{ type: 'text', text: `${summary}\n${JSON.stringify(violations, null, 2)}` }],
      isError: violations.some((v) => v.severity === 'error'),
    };
  }
);

// Shared by both dependency-scan tools below — same "thin proxy to a running
// Ignite server" pattern as onboard_project, so the MCP process itself never
// needs server.js's manifest parsers/deps.dev client loaded directly.
async function proxyToIgnite(endpoint, body) {
  let response;
  try {
    response = await fetch(`${IGNITE_BASE_URL}${endpoint}`, {
      method: 'POST',
      // Lets Ignite's onboarded-projects history annotate this run as
      // having come through MCP, distinct from a direct API call hitting
      // the same endpoint.
      headers: {
        'Content-Type': 'application/json',
        'X-Ignite-Client': 'mcp',
        ...(IGNITE_API_KEY ? { Authorization: `Bearer ${IGNITE_API_KEY}` } : {}),
      },
      body: JSON.stringify(body),
    });
  } catch (err) {
    return {
      content: [{ type: 'text', text: `Could not reach Ignite server at ${IGNITE_BASE_URL}: ${err.message}. Is it running ("npm start")?` }],
      isError: true,
    };
  }
  const result = await response.json().catch(() => null);
  if (!result) {
    return {
      content: [{ type: 'text', text: `Ignite server returned a non-JSON response (HTTP ${response.status}).` }],
      isError: true,
    };
  }
  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    isError: !result.ok,
  };
}

server.registerTool(
  'check_dependency_licenses',
  {
    title: 'Check dependency + LICENSE-file license compliance',
    description:
      'Scan a local project directory\'s dependency manifests (package.json, Cargo.toml, requirements.txt, go.mod, pom.xml) and every LICENSE/LICENCE file in the tree for commercial/proprietary/copyleft licensing risk. ' +
      'Uses ORT (OSS Review Toolkit) if installed for real per-dependency license resolution, otherwise falls back to deps.dev lookups; the project\'s own declared license is detected via `licensee` if installed. ' +
      'Same scan Ignite\'s onboarding pipeline runs automatically in Phase 3 — this lets you run it standalone, outside of onboarding. Requires a running Ignite server (`npm start`) reachable at IGNITE_BASE_URL.',
    inputSchema: {
      projectPath: z.string().describe('Absolute path to the project root to scan.'),
    },
  },
  async ({ projectPath }) => {
    console.error('[mcp] check_dependency_licenses called', { projectPath });
    return proxyToIgnite('/api/dependencies/check', { projectPath });
  }
);

server.registerTool(
  'check_dependency_vulnerabilities',
  {
    title: 'Check dependencies for known security vulnerabilities',
    description:
      'Scan a local project directory\'s dependency manifests (package.json, Cargo.toml, requirements.txt, go.mod, pom.xml) for known CVE/GHSA vulnerabilities in the resolved dependency versions, via deps.dev\'s aggregated OSV advisory data. ' +
      'Reports each vulnerability\'s id, title, CVSS v3 score, and severity (score >= 7 is "error"/blocking, lower is advisory). Only reports real, known advisories — no static/heuristic "risky package" guessing. ' +
      'Requires a running Ignite server (`npm start`) reachable at IGNITE_BASE_URL.',
    inputSchema: {
      projectPath: z.string().describe('Absolute path to the project root to scan.'),
    },
  },
  async ({ projectPath }) => {
    console.error('[mcp] check_dependency_vulnerabilities called', { projectPath });
    return proxyToIgnite('/api/dependencies/vulnerabilities', { projectPath });
  }
);

server.registerTool(
  'onboard_project',
  {
    title: 'Run the full onboarding pipeline (checks + push)',
    description:
      'Run all Ignite onboarding checks (secrets, AI governance, LLM deep-scan, org governance CI) against a local project directory, and — if every check passes — provision a private GitHub repo and push the code. ' +
      'Requires a running Ignite server (`npm start`) reachable at IGNITE_BASE_URL (default http://localhost:51337) with `gh` authenticated on that host. ' +
      'Set dryRun=true to run every check without pushing — use that first to see what would fail before committing to a real push.',
    inputSchema: {
      projectPath: z.string().describe('Absolute path to the project root to onboard.'),
      org: z.string().describe('GitHub organization to create the repository in.'),
      repo: z.string().describe('Repository name to create.'),
      dryRun: z.boolean().optional().describe('If true, run all checks but skip repo provisioning and push. Default false.'),
      gxp: z.boolean().optional().describe('Whether this is a GxP-regulated process requiring validation documents. Default false.'),
      gxpLinks: z
        .array(z.object({ name: z.string().optional(), url: z.string() }))
        .optional()
        .describe('Required when gxp=true: links to validation documents.'),
      runLocalCi: z.boolean().optional().describe('Run phase 5 org governance workflows locally via act. Default true.'),
      warningDecision: z.enum(['continue', 'fail']).optional().describe('How to treat unoverridden LLM warnings. Default "continue".'),
      overrides: z
        .array(z.object({ issueId: z.string(), justification: z.string() }))
        .optional()
        .describe('Pre-authorized overrides for flagged issues, keyed by issue id.'),
      actor: z
        .object({ email: z.string(), name: z.string().optional() })
        .optional()
        .describe('Required if overrides are submitted and the Ignite server has no logged-in session.'),
    },
  },
  async ({ projectPath, org, repo, dryRun, gxp, gxpLinks, runLocalCi, warningDecision, overrides, actor }) => {
    console.error('[mcp] onboard_project called', { projectPath, org, repo, dryRun, gxp });
    return proxyToIgnite('/api/pipeline/onboard', {
      projectPath, org, repo, dryRun, gxp, gxpLinks, runLocalCi, warningDecision, overrides, actor,
    });
  }
);

server.registerTool(
  'resolve_review_decision',
  {
    title: 'Resolve a paused interactive onboarding run',
    description:
      'Continue or stop a pipeline run that paused waiting for review (POST /api/pipeline/:jobId/review-decision) — a run started via the browser-driven /api/pipeline endpoint that hit an overridable issue. ' +
      'Not needed for onboard_project calls, which resolve overrides inline in the same request. Use this only to resume a run someone else (or a prior agent turn) already started interactively. ' +
      'Requires a running Ignite server reachable at IGNITE_BASE_URL.',
    inputSchema: {
      jobId: z.string().describe('The paused job id (from the SSE stream\'s review_required event).'),
      proceed: z.boolean().describe('true to continue past the pause (after justifying any overrides below), false to stop the run.'),
      overrides: z
        .array(z.object({ issueId: z.string(), justification: z.string() }))
        .optional()
        .describe('Overrides to apply for blocking issues raised at the pause, keyed by issue id.'),
      actor: z
        .object({ email: z.string(), name: z.string().optional() })
        .optional()
        .describe('Required if overrides are submitted and the Ignite server has no logged-in session or API key.'),
    },
  },
  async ({ jobId, proceed, overrides, actor }) => {
    console.error('[mcp] resolve_review_decision called', { jobId, proceed });
    return proxyToIgnite(`/api/pipeline/${encodeURIComponent(jobId)}/review-decision`, { proceed, overrides, actor });
  }
);

server.registerTool(
  'effectivate_project',
  {
    title: 'Turn a completed dry-run simulation into a real push',
    description:
      'Provision + push the exact snapshot already validated by a prior onboard_project(dryRun: true) call (POST /api/projects/:projectId/effectivate), without re-running phases 1-5. ' +
      'Use this for the "check first, ship later" agent loop: run onboard_project with dryRun=true, inspect the returned issues, then call this once satisfied (with overrides for anything still open). ' +
      'Requires a running Ignite server with `gh` authenticated, and the caller\'s GitHub account connected (session or API key mapped to a user with a connected GitHub token).',
    inputSchema: {
      projectId: z.number().int().describe('The numeric project id returned by the earlier onboard_project(dryRun: true) call.'),
      overrides: z
        .array(z.object({ issueId: z.string(), justification: z.string() }))
        .optional()
        .describe('Overrides for any blocking issue still open since the simulation, keyed by issue id.'),
      actor: z
        .object({ email: z.string(), name: z.string().optional() })
        .optional()
        .describe('Required if overrides are submitted and the Ignite server has no logged-in session or API key.'),
    },
  },
  async ({ projectId, overrides, actor }) => {
    console.error('[mcp] effectivate_project called', { projectId });
    return proxyToIgnite(`/api/projects/${encodeURIComponent(projectId)}/effectivate`, { overrides, actor });
  }
);

return server;
}

// MCP_TRANSPORT=stdio (default) spawns one server per client, as a child
// process of the connecting editor/agent — no visible logs in any terminal
// you control (see mcp-logs-* under ~/Library/Caches/claude-cli-nodejs).
// MCP_TRANSPORT=http runs one long-lived server all clients connect to over
// Streamable HTTP (POST+GET /mcp, SSE-capable per the current spec), so
// every tool call is logged right here in this terminal.
async function main() {
  const mode = (process.env.MCP_TRANSPORT || 'stdio').toLowerCase();

  if (mode === 'stdio') {
    const server = buildServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    return;
  }

  if (mode === 'http') {
    const express = require('express');
    const { randomUUID } = require('crypto');
    const port = Number(process.env.MCP_HTTP_PORT || 51338);
    const app = express();
    app.use(express.json());

    // Stateful mode: one transport per session (keyed by the mcp-session-id
    // header the SDK issues on initialize). Required for clients that
    // reconnect or hold a standalone GET SSE stream open — stateless mode
    // (sessionIdGenerator: undefined) can't distinguish those and 500s.
    const transports = new Map();

    app.all('/mcp', async (req, res) => {
      const sessionId = req.headers['mcp-session-id'];
      let transport = sessionId && transports.get(sessionId);

      if (!transport) {
        if (req.method !== 'POST') {
          res.status(400).send('No session; send an initialize POST first.');
          return;
        }
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (id) => {
            transports.set(id, transport);
            console.error(`[mcp] http session initialized (${id})`);
          },
        });
        transport.onclose = () => {
          if (transport.sessionId) transports.delete(transport.sessionId);
        };
        const server = buildServer();
        await server.connect(transport);
      }

      transport.handleRequest(req, res, req.body).catch((err) => {
        console.error('[mcp] error handling request:', err);
        if (!res.headersSent) res.status(500).end();
      });
    });

    app.listen(port, () => {
      console.error(`[mcp] ai-validation-guidelines listening on http://localhost:${port}/mcp (Streamable HTTP)`);
    });
    return;
  }

  throw new Error(`Unknown MCP_TRANSPORT "${mode}". Use "stdio" or "http".`);
}

// Guarded so tests can `require('../mcp-server')` for buildServer() alone
// without also starting a stdio/HTTP transport as a side effect.
if (require.main === module) {
  main().catch((err) => {
    console.error('Fatal error starting MCP server:', err);
    process.exit(1);
  });
}

module.exports = { buildServer };
