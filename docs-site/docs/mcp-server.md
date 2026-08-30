---
title: MCP server
sidebar_position: 5
---

# Also an MCP server — bring these checks into your editor

Beyond the web app, Ignite ships an [MCP](https://modelcontextprotocol.io)
server (the `mcp-server` Rust binary, `rust/crates/mcp-server`) exposing the
same guideline/security checks as tools an AI coding agent can call *during
development* — not just at onboarding time. Point Claude Code, Claude
Desktop, or any other MCP client at it (stdio, or Streamable HTTP — run with
`MCP_TRANSPORT=http` on `:51338/mcp`) to get:

- `list_guidelines` / `get_guideline` — browse the AI-governance/security/process guideline catalog itself, optionally filtered by category or severity.
- `check_guidelines` / `check_project` — run the same regex/AST guideline checks against a snippet or a whole project directory, live, as you write code.
- `check_dependency_licenses` / `check_dependency_vulnerabilities` — the same license-compliance and CVE/GHSA scans Phase 3 runs automatically, on demand.
- `onboard_project` — trigger a full (or `dryRun`) pipeline run against a running Ignite server, so an agent can "see what would fail" before ever pushing.
- `resolve_review_decision` — resume a run paused mid-flight on the *interactive* web-UI pipeline (e.g. one a human started and handed off to an agent, or the reverse).
- `effectivate_project` — the "check first, ship later" loop: call `onboard_project` with `dryRun: true`, inspect issues over one or more turns, then call this once satisfied to provision + push the exact already-validated snapshot without re-running the checks.

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

## Headless / CI auth

An agent calling these tools against a real (non-`dryRun`) `onboard_project`
or `effectivate_project` needs an authenticated user behind it — the same
attribution requirement the web UI's review gate has. Since no unattended
agent can complete a browser login, mint a headless
[API key](https://github.com/nunomcpereira/ignite#api-keys-headlessagent-auth)
once (`./target/release/create-api-key you@example.com "ci-agent"`) and set
`IGNITE_API_KEY` — the `mcp-server` binary picks it up automatically and
attaches it as a `Bearer` token on every proxied call.

There's also a plain CLI (`ignite scan`) and a `hooks/pre-push` git hook
for agents/CI that would rather not speak MCP at all — see the
[README](https://github.com/nunomcpereira/ignite#cli-ignite-scan) for both.

See [MCP server](https://github.com/nunomcpereira/ignite#mcp-server) in the README for setup.
