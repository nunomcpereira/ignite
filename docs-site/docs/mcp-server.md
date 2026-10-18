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

## Guideline catalog

`list_guidelines` returns the full text of each guideline (rationale and remediation). Every
guideline with a mechanical check runs in `check_guidelines`/`check_project`; the
ones marked *advice* have no reliable regex shape and are there for agents to
follow while writing code. Many were added because they're the findings Ignite's
Phase 3/4 engines report most often across real scans (license, credentials in
URLs, `actions/checkout` credential persistence, Dockerfile HEALTHCHECK/USER/
package pinning, OpenAPI security, Terraform exposure, ...).

| Category | Guidelines |
|---|---|
| ai-governance | `ai-recursion-limit` |
| security — secrets | `no-hardcoded-secrets`, `no-committed-env-files`, `no-committed-private-keys`, `no-credentials-in-urls`, `no-sensitive-data-in-logs` |
| security — injection | `no-injection-sinks`, `no-sql-injection`, `no-xss-sinks`, `no-ssrf-sinks`, `no-path-traversal-sinks`, `no-insecure-deserialization`, `no-unsafe-xml-parsing` (defusedxml), `no-dynamic-urllib-open`, `no-template-var-in-href`, `no-handrolled-html-sanitization`, `no-log-injection` *(advice)* |
| security — crypto/transport/auth | `no-weak-crypto`, `no-insecure-randomness`, `no-tls-verification-disabled` (incl. Ansible `validate_certs`, `curl -k`), `no-jwt-verification-disabled`, `no-plaintext-http-egress`, `no-csrf-disabled`, `no-permissive-cors`, `no-substring-url-validation`, `no-sensitive-data-in-browser-storage`, `no-debug-mode-enabled` |
| security — GitHub Actions | `no-unpinned-gha-action` (full commit SHA), `gha-script-injection`, `gha-pwn-request`, `gha-write-all-permissions`, `gha-permissions-not-declared`, `gha-checkout-persist-credentials` |
| container | `docker-runs-as-root`, `docker-non-numeric-user`, `docker-unpinned-base-image`, `docker-unpinned-packages`, `docker-secret-build-arg`, `docker-remote-script-execution`, `docker-missing-healthcheck`, `docker-exec-form-cmd`, `docker-pipefail`, `docker-signed-base-image` *(advice)*, `compose-runs-as-root`, `compose-privileged-container` |
| iac | `iac-public-exposure`, `iac-encryption-disabled`, `iac-aws-baseline` *(advice)* |
| api | `openapi-security-defined`, `openapi-operation-metadata` *(advice)*, `api-rate-limiting` *(advice)* |
| supply-chain | `python-unpinned-requirements`, `lockfile-committed`, `keep-dependencies-patched` *(advice)* |
| licensing | `project-license-declared` |
| quality | `avoid-duplicated-code`, `maintainable-complexity`, `remove-dead-code`, `document-env-vars` *(all advice)* |
| process | `ai-governance-workflow-required`, `llm-deep-scan-required` *(advice)* |

`project-license-declared` and `lockfile-committed` look at the whole tree, so
only `check_project` runs them. Test files are skipped where test fixtures would
otherwise trip the check (TLS, JWT, logging, randomness, browser storage).
These are fast regex checks for use while coding; the onboarding pipeline goes
further (e.g. Phase 4's zizmor parses workflow expressions properly).

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

Limit what the key can do with `create-api-key --scopes scan,override,publish`
(default: unrestricted). `onboard_project` also takes an optional
`idempotency_key` — re-sending the same request with the same key returns the
run it already started instead of scanning or pushing again — and runs
asynchronously under the hood (start, then poll), so a single long request
isn't held open between the MCP server and Ignite. Set `IGNITE_MCP_ASYNC=0`
to fall back to one blocking request.

There's also a plain CLI (`ignite scan`) and a `hooks/pre-push` git hook
for agents/CI that would rather not speak MCP at all — see the
[README](https://github.com/nunomcpereira/ignite#cli-ignite-scan) for both.

See [MCP server](https://github.com/nunomcpereira/ignite#mcp-server) in the README for setup.
