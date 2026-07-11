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
| 3 | Secret leakage | Line matches `/(password\|aws_secret\|api_key\|token\|private_key)\s*[:=]\s*['" \t]*[a-zA-Z0-9_\-.~]{10,}/i` in any text file (binaries, `node_modules`, `.git`, etc. excluded) |
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
