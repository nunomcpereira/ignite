---
title: MCP server
sidebar_position: 4
---

# Also an MCP server — bring these checks into your editor

Beyond the web app, Ignite ships an [MCP](https://modelcontextprotocol.io)
server (`mcp-server.js`) exposing the same guideline/security checks as
tools an AI coding agent can call *during development* — not just at
onboarding time. Point Claude Code, Claude Desktop, or any other MCP client
at it (stdio, or Streamable HTTP — auto-started alongside `npm start` on
`:51338/mcp`) to get:

- `check_guidelines` / `check_project` — run the same regex/AST guideline checks against a snippet or a whole project directory, live, as you write code.
- `check_dependency_licenses` / `check_dependency_vulnerabilities` — the same license-compliance and CVE/GHSA scans Phase 3 runs automatically, on demand.
- `onboard_project` — trigger a full (or `dryRun`) pipeline run against a running Ignite server, so an agent can "see what would fail" before ever pushing.

This means an agent working on your codebase can catch a hardcoded secret,
an ungoverned AI call, or a risky dependency *before* it's ever committed —
the same gate that blocks onboarding, available as a tool call mid-session.

## Acknowledging findings via MCP

`onboard_project` already accepts `overrides: [{issueId, justification}]`
and `actor: {email, name}`, and a failed run's response carries the exact
unresolved `issues` (id, category, severity, summary, file, line) needed to
build them — the same shape the [pre-push hook's CLI acknowledgment](./pre-push-hook)
works from. An agent can call `onboard_project`, read back which findings
are still blocking, call it again with justified overrides for the ones it
(or you, via the agent) decides to accept, and only what's genuinely
unresolved keeps blocking — no browser involved at any point.

See [MCP server](https://github.com/nunomcpereira/ignite#mcp-server) in the README for setup.
