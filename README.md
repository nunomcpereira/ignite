# Ignite — Onboarding Gatekeeper

A single-page web app that acts as a compliance gate for onboarding code into a GitHub organization. Users upload a project as a ZIP; the server scans it locally for security and AI-framework violations, and only if **every** check passes does it provision a private GitHub repository and push the code.

## System Architecture

```
┌──────────────┐  multipart POST   ┌─────────────────────────────────────────┐
│   Browser    │ ───────────────▶  │  Express server (server.js)             │
│  (index.html)│                   │                                         │
│              │ ◀───────────────  │  1. multer buffers ZIP →                │
│  NDJSON      │  streamed events  │     $TMPDIR/gatekeeper-uploads/<rand>   │
│  pipeline UI │  (log / status /  │  2. safe-extract (zip-slip + bomb       │
└──────────────┘   done)           │     guards) →                           │
                                   │     $TMPDIR/gatekeeper-staging/<uuid>/  │
                                   │  3. Check 1: deny .env* files           │
                                   │  4. Check 2: secret regex scan          │
                                   │  5. Check 4: AI governance audit        │
                                   │  6. Phase 4 (only if all green):        │
                                   │     git init/add/commit,                │
                                   │     gh repo create --private,           │
                                   │     git remote add + push               │
                                   │  7. finally: rm -rf staging dir AND     │
                                   │     uploaded ZIP — success or failure   │
                                   └─────────────────────────────────────────┘
```

**File lifecycle:** upload → temp ZIP (multer) → extracted staging directory (per-job UUID, isolated under the OS temp dir) → scanned in place → pushed from staging → **forcefully deleted in a `finally` block**, so no user code lingers on disk regardless of outcome.

**Progress transport:** the pipeline endpoint keeps the POST response open and streams newline-delimited JSON events (`log`, `status`, `done`). The frontend consumes the stream with `fetch` + `ReadableStream` and re-renders the stepper in real time — no WebSocket or polling needed.

## Pipeline Checks

| Phase | Check | Failure condition |
|---|---|---|
| 2 | Structure audit | Any file named `.env` or `.env.*` anywhere in the tree |
| 3 | Secret leakage | Line matches `/(password\|aws_secret\|api_key\|token\|private_key)\s*[:=]\s*['" \t]*[a-zA-Z0-9_\-.~]{10,}/i` in any text file (binaries, `node_modules`, `.git`, etc. excluded). Optionally supplemented by [gitleaks](https://github.com/gitleaks/gitleaks) — see below. |
| 3 | AI governance | A `.py`/`.js`/`.ts` file calls `.invoke(` / `.stream(` / `.ainvoke(` / `.astream(` but never mentions `recursion_limit` |
| 3 | LLM deep-scan (always on) | A local LLM reports critical/high vulnerabilities **and** `LLM_SCAN_MODE=block`; otherwise findings are advisory (amber). Skipped softly if the endpoint is down. |
| 4 | Org governance CI (act) | Any job of the central `ai-guardrails-orchestrator.yml` fails when executed locally in Docker. Soft-skipped if `act`/Docker are unavailable. |
| 5 | Shipping | Any `git`/`gh` command exits non-zero |

### Phase 4 — running the org's GitHub Actions locally

Instead of replicating the logic of the centrally defined governance workflows, Phase 4 executes the **real** workflow files with [`act`](https://github.com/nektos/act):

1. The orchestrator (`ai-guardrails-orchestrator.yml`) is fetched fresh from `ai-governance-poc-2026/devops-governance@main` via `gh api` and cached outside the project tree (never committed/pushed).
2. `act pull_request -W <orchestrator>` runs it against the staged project in Docker (`catthehacker/ubuntu:act-latest` runner image). The reusable sub-workflows it `uses:` (node/python/java/rust/go/ai-agent/security pipelines) are resolved from GitHub at run time — exactly as they would be in a real PR, so local results match the remote gate.
3. Any failing job halts the pipeline before anything reaches GitHub.

Requires `brew install act` and a running Docker daemon; if either is missing the phase soft-skips with a warning (the workflows still gate the repo remotely). Configure with `GOVERNANCE_REPO`, `GOVERNANCE_WORKFLOW`, `ACT_EVENT`, `ACT_TIMEOUT_MIN`.

A failed check halts the pipeline, reports offending file paths and line numbers in the phase's terminal widget, marks downstream phases **Skipped**, and cleans up staging.

### Optional gitleaks-powered secret scan

The regex secret scan always runs. If [gitleaks](https://github.com/gitleaks/gitleaks) is installed and enabled in config, it runs as an additional pass over the same staging tree and its findings (tagged `tool: "gitleaks"`) are merged in — deduped against anything the regex already caught at the same file/line. Disabled by default; if it's enabled but the binary isn't found, the scan soft-fails back to regex-only results (a warning is logged, nothing blocks the pipeline).

```jsonc
"security": {
  "gitleaks": {
    "enabled": false,       // env: GITLEAKS_ENABLED=true
    "binary": "gitleaks",   // env: GITLEAKS_BINARY (path or name on $PATH)
    "configPath": ""        // env: GITLEAKS_CONFIG_PATH — optional gitleaks.toml
  }
}
```

## Hardening notes

- **Zip-slip:** every archive entry's resolved path must stay inside the staging root, or extraction aborts.
- **Zip bombs:** total extracted size is capped at 1 GB; uploads capped at 250 MB.
- **Symlinks:** symlink archive entries are skipped; the directory walker never follows symlinks.
- **Command injection:** all `git`/`gh` invocations use `execFile` with argument arrays (no shell), and org/repo names are validated against GitHub's naming rules before use.

## Configuration — `config.json`

All settings live in `config.json` next to `server.js` (environment variables override it):

```jsonc
{
  "port": 3000,
  "llm": {                       // local llama.cpp deep-scan connection
    "url": "http://localhost:8050",
    "model": "default",
    "mode": "warn",              // "warn" | "block"
    "maxFiles": 40
  },
  "github": {
    // Optional. Comma-separated list (or JSON array) of GitHub orgs.
    // One entry: prefills the org field. Two or more: the org field
    // becomes a dropdown, first entry selected by default.
    "orgs": "ai-governance-poc-2026",
    // Branch the compliant code is pushed to before PRing into the
    // repo's default branch (env override: BOOTSTRAP_BRANCH).
    "bootstrapBranch": "ignite"
  },
  "governance": {                // central org workflows run locally via act
    "repo": "ai-governance-poc-2026/devops-governance",
    "workflow": "ai-guardrails-orchestrator.yml",
    "event": "pull_request",
    "timeoutMinutes": 30
  },
  "notifications": {             // failure emails
    "enabled": true,
    "to": "nunocpereira@gmail.com",
    "from": "Ignite Gatekeeper <nunocpereira@gmail.com>",
    "smtp": {
      "host": "smtp.gmail.com",
      "port": 587,
      "secure": false,
      "user": "nunocpereira@gmail.com",
      "pass": ""                 // Gmail app password — see below
    }
  },
  "security": {
    "gitleaks": {                // optional supplemental secret scan
      "enabled": false,
      "binary": "gitleaks",
      "configPath": ""
    }
  }
}
```

### Failure emails

When any phase fails, Ignite emails a detailed report to `notifications.to`: target repo, failed phase, a status table of all five phases, and the full terminal logs of every failed phase.

- **With SMTP credentials** (`smtp.host`+`user`+`pass` set): sends through that server. For Gmail, create an [app password](https://myaccount.google.com/apppasswords) and paste it into `pass` — your normal account password will not work.
- **Without credentials**: falls back to the local `sendmail` binary. The message is handed to the OS mail system, but delivery to external addresses (Gmail) is unreliable without a configured relay — set the app password for dependable delivery.

## Prerequisites

1. **Node.js ≥ 18**
2. **git** available on `PATH`
3. **GitHub CLI (`gh`)** installed and authenticated *before* starting the server:
   ```bash
   gh auth login
   gh auth status   # verify — must show a logged-in account with repo scope
   ```
   The authenticated account needs permission to create repositories in the target organization.

## Local LLM deep-scan (always on)

On top of the deterministic checks, the pipeline submits source files to a **local** LLM served by llama.cpp (OpenAI-compatible `/v1/chat/completions` endpoint) that hunts for real vulnerabilities — injection, path traversal, SSRF, unsafe eval, weak crypto, etc. Code never leaves the machine. If the endpoint is unreachable, the scan is skipped with a warning rather than failing the run.

Configure via environment variables (all optional):

| Variable | Default | Meaning |
|---|---|---|
| `LLM_SCAN_URL` | `http://localhost:8050` | llama.cpp / OpenAI-compatible base URL |
| `LLM_SCAN_MODEL` | `default` | Model name (llama.cpp serves its loaded model regardless) |
| `LLM_SCAN_MODE` | `warn` | `warn` = findings are advisory; `block` = critical/high findings halt the pipeline |
| `LLM_MAX_FILES` | `40` | Cap on source files sent to the model |

Files are batched into ~24 KB chunks with numbered lines, and the model must answer in strict JSON (`{"findings":[{file,line,severity,issue}]}`); malformed responses skip that chunk only.

## Setup & Run

```bash
npm install
npm start
# → http://localhost:3000
```

Then in the browser:

1. Drag a `.zip` **or a whole project folder** onto the drop zone (or use the Choose ZIP / Choose Folder buttons). Folder uploads skip `node_modules`, `.git`, and build output automatically — no repacking needed between iterations.
2. Enter the GitHub organization name; the repository name is auto-proposed from the ZIP/folder name (editable).
3. Click **Initiate Onboarding Pipeline** and watch the four phases stream their logs. Click any phase card to expand/collapse its terminal output.
4. On success, the final banner shows the live repository URL as a clickable link.

> **Security note:** this server executes `git`/`gh` with the host machine's credentials. Run it locally or behind authentication — never expose it unauthenticated to a network.

## Simulation mode (`dryRun`) — check without pushing

`POST /api/pipeline` (the same multipart endpoint the browser UI uses) accepts
an optional `dryRun` form field (`"true"`/`"false"`, default `"false"`). When
set, phases 1-5 run exactly as normal (structure audit, secret scan, AI
governance, LLM deep-scan, local CI via `act`) but phase 6 — repo
provisioning and `git push` — is skipped; the job is recorded as a success
with no `repoUrl`/`prUrl`. This is the mode to reach for when driving the
pipeline from an agent/MCP client that just wants to surface errors without
committing to a real onboarding: run the checks, inspect the streamed NDJSON
events, and only re-run with `dryRun` unset (or omitted) once everything is
green.

`POST /api/pipeline/validate-all` (below) is already dry-run-only — it never
ships — but it takes a `projectPath` on the local filesystem rather than an
upload, and only accepts GxP document *links*, not uploaded files. Prefer
`dryRun` on `/api/pipeline` when you need parity with the real upload-driven
pipeline (GxP doc uploads, folder/zip upload) minus the push.

## Headless validation API (agent loop)

Use this endpoint to run all validation phases via API (without the UI stream):

- `POST /api/pipeline/validate-all`
- Content type: `application/json`
- Runs phases 1-5 and always skips phase 6 (shipping).

Example:

```bash
curl -sS -X POST http://localhost:3000/api/pipeline/validate-all \
  -H 'Content-Type: application/json' \
  -d '{
    "projectPath": "/Users/nuno/tests/ignite",
    "org": "ai-governance-poc-2026",
    "repo": "ignite",
    "gxp": false,
    "runLocalCi": true,
    "warningDecision": "continue"
  }' | jq
```

Request fields:

- `projectPath` (string, absolute path): local folder to validate.
- `org` (string, optional): metadata context for validation logs.
- `repo` (string, optional): metadata context for validation logs.
- `gxp` (boolean, optional, default `false`): whether to enforce GxP document checks.
- `gxpLinks` (array, optional): required when `gxp=true`; each item `{ "name": "...", "url": "https://..." }`.
- `runLocalCi` (boolean, optional, default `true`): run phase 5 local governance workflows via `act`.
- `warningDecision` (string, optional, default `continue`): `continue` or `fail` when LLM warnings exist.

Response shape:

- `ok`: `true`/`false`
- `failedPhase`: phase number when `ok=false`
- `phases`: array of `{ phase, title, state, logs[] }`
- `events`: full event list (`status` + `log`) for machine-driven loops

## AI validation guidelines — MCP server & API

`guidelines/` holds the company AI validation guideline catalog (AI-governance,
security, and process rules — the same detection patterns Ignite's onboarding
pipeline enforces) and a pure checks engine, so guidelines can be applied
*during development*, not just at onboarding time.

### MCP server

```bash
npm run guidelines:mcp
```

Runs `mcp-server.js` over stdio. Point any MCP client (Claude Code, Claude
Desktop, etc.) at it. Tools exposed:

- `list_guidelines({ category?, severity? })` — list guidelines, optionally filtered.
- `get_guideline({ id })` — full detail (description, rationale, remediation) for one guideline.
- `check_guidelines({ content, path? })` — check a code snippet/file against the automated guidelines.
- `check_project({ projectPath })` — walk a project directory and check every source file.
- `onboard_project({ projectPath, org, repo, dryRun?, gxp?, gxpLinks?, runLocalCi?, warningDecision?, overrides?, actor? })`
  — runs the **full** onboarding pipeline (phases 1-5, and phase 6 provisioning
  + push if everything passes) against a `POST /api/pipeline/onboard` on a
  running Ignite server. This is a thin proxy: the MCP process itself never
  touches `git`/`gh`, it just calls the HTTP API. Set `dryRun: true` to run
  every check without pushing — the way to "see what would fail" from an
  agent loop before committing to a real push. Requires the Ignite server
  running (`npm start`) and reachable at `IGNITE_BASE_URL` (env, default
  `http://localhost:3000`), with `gh` authenticated on that host.

Example `.mcp.json` entry:

```json
{
  "mcpServers": {
    "ai-validation-guidelines": {
      "command": "node",
      "args": ["/absolute/path/to/ignite/mcp-server.js"]
    }
  }
}
```

### REST API

```bash
npm run guidelines:api   # listens on 127.0.0.1:8090 by default
```

Binds to loopback only by default (`GUIDELINES_API_HOST`/`GUIDELINES_API_PORT`
to override) — `/check-project` reads arbitrary paths on the host filesystem,
so this is a local dev/CI tool, not meant for public exposure.

- `GET /guidelines?category=&severity=` — list guidelines.
- `GET /guidelines/:id` — full detail for one guideline.
- `POST /check` `{ content, path? }` — check a snippet/file; returns `{ violations, hasBlockingViolations }`.
- `POST /check-project` `{ projectPath }` — check a project directory; returns `{ scanned, violations, hasBlockingViolations }`.

Guidelines with `checkId: null` (e.g. `ai-governance-workflow-required`,
`llm-deep-scan-required`) are process rules or covered by the LLM deep-scan in
`server.js`, not mechanically checkable from a snippet alone.

## Overriding flagged guideline checks — audit log & notification

Phase 4 (Security & AI Compliance Scan) collects every flagged issue —
hardcoded secrets, ungoverned AI invocations, and LLM security/quality
findings — into a single addressable list instead of hard-failing
immediately. Any issue (blocking error or advisory warning) can be
overridden, but every override:

1. requires a **justification**,
2. must be **attributed** to a real person (logged-in session, or an
   explicit `{email, name}` actor when auth isn't enforced globally),
3. sends an **email notification** (reusing `notifications.*` config) listing
   exactly what was overridden, by whom, and why,
4. is **persisted to the audit log** (`overrides` table) and shown under
   each project's entry in the Onboarded Projects list (click a project to
   expand — "Audit log — overridden guideline checks" appears if any exist).

Blocking (`severity: "error"`) issues cannot be silently bypassed: the
pipeline stays halted until every blocking issue either has a matching
override+justification, or is fixed in the source.

- **Interactive pipeline** (`POST /api/pipeline`, browser upload): pauses and
  emits a `review_required` event with the full issue list; the UI shows a
  modal to check/justify issues, then posts the decision to
  `POST /api/pipeline/:jobId/review-decision`
  `{ proceed, overrides: [{issueId, justification}], actor? }`.
- **Non-interactive** (`POST /api/pipeline/validate-all`): pass overrides
  up front — `{ ..., overrides: [{issueId, justification}] }` — since there's
  no live client to prompt. `issueId` is the `id` field on each finding
  (`<category>::<file>::<line>`).

## Authentication — standalone accounts or company IdP

`AUTH_MODE` (env) or `auth.mode` (config.json) selects the strategy; both
converge on the same session-cookie + `req.user` shape used for override
attribution.

- **`standalone`** (default): local accounts, `POST /api/auth/register` /
  `login` / `logout`, scrypt-hashed passwords, `auth.allowSelfRegistration`
  gates open registration. Session cookie is a random token in a local
  `sessions` table (12h TTL).
- **`oidc`**: delegates to any standards-compliant company IdP (Okta, Entra
  ID, Auth0, Keycloak, …). Configure `auth.oidc.issuer` / `clientId` /
  `clientSecret` (or `OIDC_CLIENT_SECRET` env) / `redirectUri`. Users sign in
  via `GET /api/auth/oidc/login`, land back on `/api/auth/oidc/callback`,
  and are upserted by IdP `sub`.

Auth isn't required to browse the app or run the pipeline (so the existing
CI/local-validation workflows keep working unauthenticated) — it's only
enforced where attribution matters: submitting an override without a
session must include an explicit `actor {email, name}` in the request body,
or the server responds `401`.

## Testing

```bash
npm test
```

Runs the Node built-in test runner (`node --test`) over `test/*.test.js`.
`test/secrets-scan.test.js` covers the secret-scan pipeline check: the
regex baseline, that gitleaks stays off and unused by default, that
enabling it supplements (never replaces) the regex findings, dedup against
regex hits at the same file/line, and the soft-fail path when gitleaks is
enabled but the binary is missing. A fake `gitleaks` CLI stand-in
(`test/helpers.js`) is used so the suite doesn't require a real gitleaks
install.
