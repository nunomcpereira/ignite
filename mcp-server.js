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
const IGNITE_BASE_URL = (process.env.IGNITE_BASE_URL || 'http://localhost:3000').replace(/\/+$/, '');

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

server.registerTool(
  'onboard_project',
  {
    title: 'Run the full onboarding pipeline (checks + push)',
    description:
      'Run all Ignite onboarding checks (secrets, AI governance, LLM deep-scan, org governance CI) against a local project directory, and — if every check passes — provision a private GitHub repo and push the code. ' +
      'Requires a running Ignite server (`npm start`) reachable at IGNITE_BASE_URL (default http://localhost:3000) with `gh` authenticated on that host. ' +
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
    let response;
    try {
      response = await fetch(`${IGNITE_BASE_URL}/api/pipeline/onboard`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectPath, org, repo, dryRun, gxp, gxpLinks, runLocalCi, warningDecision, overrides, actor,
        }),
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
    const port = Number(process.env.MCP_HTTP_PORT || 3001);
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

main().catch((err) => {
  console.error('Fatal error starting MCP server:', err);
  process.exit(1);
});
