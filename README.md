# Ignite - Onboarding Gatekeeper

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A single-page web app that acts as a compliance gate for onboarding code into a GitHub organization. Users upload a project as a ZIP; the server scans it locally for security and AI-framework violations, and only if **every** check passes does it provision a private GitHub repository and push the code. There's also a [pre-push git hook](#pre-push-hook) (`hooks/pre-push`) for repos that would rather gate on `git push` than a separate upload step.

**Most of the detection below is deterministic static analysis by dedicated tools - Semgrep (SAST), deps.dev/OSV (CVE), Trivy/Checkov/hadolint (IaC), GuardDog (supply-chain), gitleaks (secrets), cosign, Bearer, Spectral - not an LLM guessing.** The local LLM deep-scan is one additional, independently-toggleable layer (`LLM_DEEP_SCAN_ENABLED`) for logic-level review that fixed rule sets can't reach; every static engine below runs identically whether it's on or off. See the [attack & risk coverage table](#attack--risk-coverage--what-each-check-actually-prevents) for the full tool-by-tool mapping.

📖 **[See it in action - screenshots & walkthrough](https://nunomcpereira.github.io/ignite/)** · 📄 **[Executive summary (PDF)](docs/briefings/ignite-executive-briefing.pdf)**

<p align="center">
  <img src="docs/assets/images/02-findings-overview.png" alt="Ignite's final review gate - flagged issues with code expanded" width="720">
</p>

## System Architecture

```
┌───────────────┐  multipart POST (dryRun?)   ┌──────────────────────────────────────────────┐
│    Browser    │ ──────────────────────────▶ │  ignite-server (Rust, axum)                    │
│  (index.html) │                              │                                                │
│  NDJSON       │ ◀────────────────────────── │  1. multipart upload buffered/streamed →       │
│  pipeline UI  │  streamed events (log /      │     $TMPDIR/gatekeeper-uploads/<rand>          │
└───────────────┘  status / review_required /  │  2. safe-extract (zip-slip + zip-bomb guards,  │
                    done)                      │     symlinks skipped) →                        │
┌───────────────┐  POST /validate-all          │     $TMPDIR/gatekeeper-staging/<uuid>/         │
│ pre-push hook │ ──────────────────────────▶ │  3. sequential phase checks, in place:         │
│ / CLI         │  (sync JSON, phases 1-5,     │     Phase 1  Input & metadata                  │
│ (ignite scan) │   never ships)               │     Phase 2  GxP validation docs (off default) │
└───────────────┘                              │     Phase 3  Structure audit · license · unit  │
┌───────────────┐  POST /onboard,               │              tests (Docker, per-language)      │
│ MCP client    │  /pipeline/:id/review-        │     Phase 4  Security & compliance (secrets,   │
│ (Claude Code, │  decision, /projects/:id/     │              AI-governance, LLM deep-scan,      │
│  Desktop, …)  │  effectivate                  │              IaC/SAST/supply-chain/PII/API-     │
└───────┬───────┘ ──────────────────────────▶ │              schema/posture/codebase-intel/     │
        │ stdio or                              │              EU AI Act - 20+ checks, mostly     │
        │ HTTP :51338/mcp                       │              soft-dependency external tools)    │
        ▼                                       │     Phase 5  Org governance CI (act + Docker)  │
┌───────────────┐                               │     Phase 6  (only if all green, not dryRun):  │
│  mcp-server   │  proxies every call over       │              git init/add/commit,               │
│ (Rust binary, │  plain HTTP - never touches    │              gh repo create --private,          │
│  standalone)  │  git/gh itself                 │              git remote add + push              │
└───────────────┘                               │  4. finally: rm -rf staging dir AND uploaded   │
                                                 │     ZIP - success or failure                    │
                                                 └──────────────────────┬──────────────────────────┘
                                                                        │ users, sessions, api_keys,
                                                                        │ projects, overrides,
                                                                        │ file/codeql scan caches,
                                                                        ▼ issue baselines, runtime coverage
                                                                 ┌─────────────┐
                                                                 │  ignite.db  │
                                                                 │  (SQLite)   │
                                                                 └─────────────┘
```

Three request paths, one pipeline: the interactive browser upload (`POST /api/pipeline`, streaming NDJSON), the synchronous headless path used by the pre-push hook/CLI/CI (`POST /api/pipeline/validate-all`, phases 1-5 only, never ships), and the MCP path (`onboard_project`/`resolve_review_decision`/`effectivate_project`), which is a thin proxy from the standalone `mcp-server` binary to the same HTTP API - the MCP process itself never runs `git`/`gh`. All three share the exact same phase-check functions and the same issue/override model, so there's no "lighter" path for one caller versus another.

**File lifecycle:** upload → temp ZIP (multer) → extracted staging directory (per-job UUID, isolated under the OS temp dir) → scanned in place → pushed from staging → **forcefully deleted in a `finally` block**, so no user code lingers on disk regardless of outcome.

**Progress transport:** the interactive pipeline endpoint keeps the POST response open and streams newline-delimited JSON events (`log`, `status`, `review_required`, `done`). The frontend consumes the stream with `fetch` + `ReadableStream` and re-renders the stepper in real time - no WebSocket or polling needed. `validate-all` and the MCP tools instead return a single synchronous JSON response once phases 1-5 finish.

## Pipeline Checks

Six phases, run in order. Phases 1, 3, and 6 always run - everything downstream depends on them. Phases 2, 4, and 5 can be turned on/off in `config.json` (see [Configurable phases](#configurable-phases--gxp) below); a disabled phase is hidden from the UI entirely and never checked, not just skipped.

Phase 4's displayed name drops to **"Security & Compliance Scan"** (from "Security & AI Compliance Scan") whenever the LLM deep-scan endpoint isn't reachable - every other Phase 4 check still runs exactly the same, only the LLM sub-check is skipped, so the name shouldn't claim an AI check ran when it didn't. `GET /api/config` health-probes the endpoint (cached 15s) and swaps the title only if it's still the unmodified default - a title already customized via `config.json`'s `phases` override is left untouched either way.

| Phase | Check | Failure condition | Configurable? |
|---|---|---|---|
| 1 | Input & metadata | Invalid org/repo name, missing GitHub auth | Always on |
| 2 | GxP validation documents | GxP declared but no validation document (upload or link) attached | **Off by default** - see [GxP](#configurable-phases--gxp) |
| 3 | Structure audit | Any file named `.env` or `.env.*` anywhere in the tree | Always on |
| 3 | License compliance | A dependency manifest declares a package with a commercial/proprietary/unrecognized license (red = blocking error, copyleft = warning), or a `LICENSE`/`LICENCE` file anywhere in the tree contains commercial/proprietary terms (e.g. a `Licensee:` grant). Runs first inside Phase 3, before the throwing checks, so findings survive a failed structure audit. See [Dependency & license compliance](#dependency--license-compliance-ort--licensee--depsdev). | Always on |
| 3 | Unit tests | The project's native test suite (Node/Go/Rust/Python/Java, auto-detected) fails in an isolated Docker container | Always on |
| 4 | Secret leakage | Line matches `/(password\|aws_secret\|api_key\|token\|private_key)\s*[:=]\s*['" \t]*[a-zA-Z0-9_\-.~]{10,}/i` in any text file (binaries, `node_modules`, `.git`, etc. excluded). Optionally supplemented by [gitleaks](#gitleaks) - see below. | On/off |
| 4 | AI governance | A `.py`/`.js`/`.ts` file calls `.invoke(` / `.stream(` / `.ainvoke(` / `.astream(` but never mentions `recursion_limit` | On/off |
| 4 | LLM deep-scan | A local LLM reports critical/high vulnerabilities **and** `LLM_SCAN_MODE=block`; otherwise findings are advisory (amber). Skipped softly if the endpoint is down. | On/off |
| 4 | IaC/container misconfiguration | Trivy (primary) flags a Dockerfile/Terraform/Kubernetes/Helm misconfiguration, optionally supplemented by Checkov and hadolint. Falls back to a small built-in Dockerfile heuristic (unpinned base image, missing `USER`) when Trivy isn't installed. See [External tools](#external-tools). | On/off (per sub-tool) |
| 4 | Container image CVEs | Builds every discovered Dockerfile and runs `trivy image` against the result, flagging known CVEs in installed OS/language packages — a gap the misconfiguration check above can't see, since that only lints the Dockerfile source, never what actually ends up inside the image. **Off by default** (needs a real `docker build`, the heaviest Phase 4 check) — `TRIVY_IMAGE_ENABLED=true` to opt in. | On/off |
| 4 | Base-image signature/provenance | Cosign reports a Dockerfile `FROM` base image with no verifiable Sigstore signature. Advisory only - never blocks a run on its own. **On by default** (makes a real network call per image - `COSIGN_ENABLED=false` to opt out). | On/off |
| 4 | Semantic SAST | Semgrep (OSS rulesets) flags a logical flaw or injection-style sink beyond what the LLM deep-scan catches. | On/off |
| 4 | PII/GDPR data-flow | Bearer traces personal data (request params, user objects) reaching a sink (logs, DB writes, 3rd-party calls) - only findings Bearer itself tags as PII/Personal-Data-relevant; its broader generic-security findings (path traversal, weak crypto, ...) are filtered out rather than mislabeled as PII, since Semgrep already covers that ground. **On by default** - needs a git context, which Ignite stages automatically. | On/off |
| 4 | Code duplication | jscpd flags a duplicated code block above its default threshold. Always advisory (warning), never blocking. **Off by default.** | Off by default |
| 4 | File size / encapsulation | Built-in (no external tool) - flags any single source file over `metrics.fileSize.maxLines` (default 1000) as a "low encapsulation" advisory. Always advisory, never blocking. **On by default.** | On/off (`FILE_SIZE_ENABLED`) |
| 4 | API schema lint | Spectral lints every discovered OpenAPI/AsyncAPI file (found by content, not filename) against its bundled ruleset (`spectral:oas` + `spectral:asyncapi` by default). | On/off |
| 4 | Malicious dependency | GuardDog flags a supply-chain-attack pattern (install-script exfiltration, obfuscated payload, silent network call, typosquatting) in an npm/PyPI dependency, independent of whether a CVE has been published. **On by default** (downloads and inspects every dependency's real package contents - slower/heavier than the rest of Phase 4; set `GUARDDOG_ENABLED=false` to opt out). | On/off |
| 4 | Malicious ML model artifact | picklescan flags an unsafe pickle global import (arbitrary code execution on load) in a `.pkl`/`.pickle`/`.pt`/`.pth`/`.ckpt`/`.bin` model file. Deliberately excludes `.safetensors`/`.onnx` (neither is pickle-based). **On by default.** No built-in fallback. | On/off (`PICKLESCAN_ENABLED`) |
| 4 | API breaking-change / shadow-endpoint | oasdiff diffs every discovered OpenAPI/AsyncAPI file against its own previous git revision, flagging a removed endpoint, a field that became required, or a changed response type - only active with real git history to diff against (a fresh upload with nothing to compare simply contributes nothing). **On by default.** No built-in fallback. | On/off (`OASDIFF_ENABLED`) |
| 4 | AI package-hallucination ("slopsquat") | Built-in (no external tool) - checks every manifest dependency name against its ecosystem's real public registry (npm/PyPI/crates.io); a 404 is possibly an AI-invented name vulnerable to squatting. Always advisory - a private/internal package looks identical to a hallucinated one from a public-registry lookup alone. **On by default.** | On/off (`PACKAGE_HALLUCINATION_ENABLED`) |
| 4 | Cross-file static analysis (CodeQL) | CodeQL's `security-extended` query suite flags a vulnerability whose tainted data crosses file/function boundaries - the gap Semgrep OSS's intraprocedural engine structurally can't cover. **On by default.** | On/off (`CODEQL_ENABLED`) |
| 4 | GitHub Actions workflow security | zizmor flags pwn-request patterns (`pull_request_target` checking out and running PR-head code with secrets access), script injection via untrusted `${{ }}` expansions in `run:` steps, excessive `permissions:`, and unpinned actions in every `.github/workflows/*.yml`. Skipped entirely (no invocation) when a repo has no workflow files. **On by default.** No built-in fallback (distinct from the narrower `no-unpinned-gha-action` dev-time guideline). | On/off (`ZIZMOR_ENABLED`) |
| 4 | Dead code / unused exports / unused deps | Built-in module-graph BFS from `package.json` entry points flags an unreached file, a named export never imported anywhere, or a manifest dependency never required/scripted. Always advisory - never blocking. See [Codebase intelligence](#codebase-intelligence---closing-the-fallowtools-gap) below. | On/off (`CONFIG.codeIntelligence.deadCode`) |
| 4 | Complexity / maintainability health | Built-in per-file cyclomatic/cognitive complexity, a calibrated Maintainability Index, and a CRAP score (pulls real coverage when [ingested](#runtime-coverage-ingestion)). Flags `high-complexity`/`low-maintainability` by decision *density*, not raw file length. Always advisory. | On/off (`CONFIG.codeIntelligence.health`) |
| 4 | Architecture / import-boundary enforcement | Built-in zone-based import-graph check (`bulletproof`/`layered`/`hexagonal`/`feature-sliced` presets, or custom `zones`) flags an import that crosses a declared boundary. Always advisory. **Off by default** - a default zone layout on a project that doesn't follow one is pure noise. | On/off (`CONFIG.architecture.boundaries`) |
| 4 | CSS/Tailwind dead-class scan | Built-in scan flags a `.css`/`.scss`/`.less` class selector never referenced in any scanned `class`/`className` attribute. One-directional only (can't flag unused Tailwind utilities). Always advisory. | On/off (`CONFIG.codeIntelligence.cssDeadCode`) |
| 4 | EU AI Act code-detectable signals | `ignite-posture-rules.yaml`'s three `ai-act-*` categories (prohibited-practice, transparency-disclosure, ai-logging) via the Posture Engine. Advisory-only by default; see [EU AI Act coverage](#eu-ai-act-coverage) below. | On/off (rolled into `compliance.posture`); findings mode via `EU_AI_ACT_REPORT_AS_FINDINGS` |
| 4 | EU AI Act document-presence scan | Built-in filename/path scan for risk-management-system, Annex IV technical documentation, FRIA, GPAI training-data summary, and post-market monitoring plan documents. DETECTED/MISSING, never PARTIAL. Advisory-only by default. | On/off (`EU_AI_ACT_DOCS_ENABLED`); findings mode via `EU_AI_ACT_REPORT_AS_FINDINGS` |
| 5 | Org governance CI (act) | Any job of the central `ai-guardrails-orchestrator.yml` fails when executed locally in Docker. Soft-skipped if `act`/Docker are unavailable. | On/off |
| 6 | Shipping | Any `git`/`gh` command exits non-zero | Always on (`dryRun` is the "don't ship" switch, not a phase toggle) |

Four Phase 4 sub-steps are purely descriptive and never produce a flagged issue: Syft generates a CycloneDX SBOM, gocloc computes per-language LOC counts, the **Compliance & Feature Posture Engine** classifies whether the codebase shows SSO/SAML/OIDC, RBAC/ABAC, audit logging, SIEM log forwarding, HTTPS/TLS enforcement, backups/DR, encryption at rest, and rate limiting as `DETECTED` (confirmed usage found), `PARTIAL` (only an import/dependency reference found), or `MISSING`, per category - via a custom Semgrep ruleset (`ignite-posture-rules.yaml`) when Semgrep is connected, or a built-in regex posture scanner (narrower coverage, same weak/strong model) when it isn't; logged as `Engine: Semgrep CLI vX.X (External Posture Scanner)` / `Engine: Ignite Built-In Posture Scanner (Fallback)`, and a **build/commit provenance record** (below) records what was staged and, when available, the source commit it came from. All four are on by default and, when they run, attach their output as a downloadable JSON document on the project (same place GxP validation documents show up), rather than gating anything.

### Build/commit provenance (unsigned)

`generateProvenance` attaches `provenance.json` to every run - an unsigned in-toto `Statement`/SLSA-provenance-v1-shaped predicate recording: a sha256 digest over every staged file's own sha256 (sorted by relative path, so it's deterministic regardless of directory-walk order - `digestProjectTree`), the source commit SHA when the staged tree has git context, `org`/`repo`, and a timestamp. It's attached the same way as the SBOM/LOC-metrics/posture-report artifacts and never gates a run.

**This is explicitly not a signed SLSA attestation** - no keyless/KMS signing, no transparency-log entry, no verified builder identity - and the artifact's own `note` field says so, rather than implying more assurance than it actually provides. What it does give an auditor: a way to confirm the tree that passed the pipeline is the same tree that got pushed, since the staging directory is force-removed after every run and the digest is the only thing that survives to compare against later. Full SLSA L3 needs a real signing/attestation pipeline (e.g. GitHub Actions + `slsa-github-generator`), which is out of scope here. Reachable on demand in Ignite Studio via the 📜 Provenance button (`GET /api/pipeline/:jobId/studio/provenance`), same live-recompute pattern as SBOM/LOC/Posture.

### Configurable phases + GxP

`config.json`'s optional `phases` array overrides any phase's title, description, or `enabled` state by `id` - anything not listed keeps its built-in default:

```jsonc
"phases": [
  { "id": 2, "enabled": true },                                     // turn GxP on
  { "id": 5, "enabled": false, "title": "Org Governance CI (off)" }  // turn a phase off + relabel it
]
```

- **Phase 2 (GxP) defaults to disabled** - most orgs onboarding through Ignite aren't running a GxP-regulated process, so the "Is this a GxP-regulated process?" question and mandatory validation-document upload are hidden from the UI until explicitly enabled. A client that sends `gxp: true` while Phase 2 is disabled is ignored server-side too - disabling it is a real "not checked", not just a UI hide.
- **Phases 1, 3, and 6 can't be disabled** - Phase 3 stages the project every later phase scans/ships, Phase 1 creates the project record, and Phase 6 is the pipeline's actual purpose (`dryRun` is how you skip shipping without disabling a phase). An `enabled: false` override on these ids is silently ignored.
- Title/description overrides apply everywhere the phase is named: the UI timeline, `GET /api/config`, and failure emails.

### Phase 5 - running the org's GitHub Actions locally

Instead of replicating the logic of the centrally defined governance workflows, Phase 5 executes the **real** workflow files with [`act`](https://github.com/nektos/act):

1. The orchestrator (`ai-guardrails-orchestrator.yml`) is fetched fresh from `ai-governance-poc-2026/devops-governance@main` via `gh api` and cached outside the project tree (never committed/pushed).
2. `act pull_request -W <orchestrator>` runs it against the staged project in Docker (`catthehacker/ubuntu:act-latest` runner image). The reusable sub-workflows it `uses:` (node/python/java/rust/go/ai-agent/security pipelines) are resolved from GitHub at run time - exactly as they would be in a real PR, so local results match the remote gate.
3. Any failing job halts the pipeline before anything reaches GitHub.

Requires `brew install act` and a running Docker daemon; if either is missing the phase soft-skips with a warning (the workflows still gate the repo remotely). Configure with `GOVERNANCE_REPO`, `GOVERNANCE_WORKFLOW`, `ACT_EVENT`, `ACT_TIMEOUT_MIN`.

A failed check halts the pipeline, reports offending file paths and line numbers in the phase's terminal widget, marks downstream phases **Skipped**, and cleans up staging.

## External tools

Ignite integrates with seventeen optional external tools (plus an eighteenth compliance-posture check that reuses Semgrep rather than adding its own binary) across dependency/license, secret, IaC/container, supply-chain, SAST, code-metrics, API-schema, ML-artifact, GitHub Actions workflow security, and compliance-posture scanning. **Every one is a soft dependency** - Ignite works without any of them installed, falling back to its own built-in scanner (or simply contributing nothing, for tools with no meaningful heuristic substitute), and never fails a run because one is missing. `GET /api/tools/status` reports live connected/disconnected state for each (also shown as a panel in the top-right corner of the UI, next to the sign-in button); which one actually ran shows up in the relevant view's "Engine:" line and in Phase 3/4's terminal log, e.g. `Engine: Trivy CLI (External)` vs. `Engine: Ignite Built-In Pattern Matcher (Fallback)`.

| Tool | What it does in Ignite | Install |
|---|---|---|
| [ORT](https://oss-review-toolkit.org/ort/) (OSS Review Toolkit) | Resolves real per-dependency licenses straight from each ecosystem's package manager/lockfile (Maven, NPM, Cargo, Go modules, pip) - far more accurate than regex-parsing manifests. Ignite runs `ort analyze` against the staged project and reads back `analyzer-result.json`. | See [Installing ORT](#installing-ort) below - no Homebrew formula; it's a ~250 MB release archive. |
| [licensee](https://github.com/licensee/licensee) | GitHub's own license-detection gem - identifies the *project's own* declared license (root `LICENSE` file) for the "This project's own declared license" row in the Dependencies view. Independent of the per-dependency scan above. | `gem install licensee` (needs Ruby ≥ 3.0 - macOS system Ruby is 2.6, see below). |
| [gitleaks](https://github.com/gitleaks/gitleaks) | Supplemental secret scanner. Ignite's own regex secret scan always runs regardless; gitleaks, if installed **and enabled in config** (`security.gitleaks.enabled`, off by default), runs as an extra pass over the same staged files and its findings are merged in - deduped against anything the regex scan already caught at the same file/line. | `brew install gitleaks` |
| [Trivy](https://github.com/aquasecurity/trivy) | Primary IaC/container misconfiguration scanner - `trivy config` covers Dockerfiles, Terraform, Kubernetes manifests, and Helm charts in one pass. **On by default.** | `brew install trivy` |
| [Checkov](https://www.checkov.io/) | Supplements Trivy with a much larger IaC policy set, merged in and deduped by file/line/rule-id (not line alone - the two tools' rule catalogs routinely flag *different* real issues on the same line). **On by default** (a heavier Python dependency than trivy/hadolint - set `CHECKOV_ENABLED=false` to opt back out). | `brew install checkov` |
| [hadolint](https://github.com/hadolint/hadolint) | Supplements Trivy/Checkov with Dockerfile-only lint rules. **On by default** - small, fast native binary. | `brew install hadolint` |
| [Syft](https://github.com/anchore/syft) | Generates a CycloneDX SBOM for the staged project, attached as a downloadable project document. **On by default.** Falls back to a minimal manifest-derived component list (name/version pairs, no standards-format export) when missing. | `brew install syft` |
| [cosign](https://github.com/sigstore/cosign) | Verifies Sigstore keyless signatures on every base image referenced by a Dockerfile `FROM`. **On by default** - makes a real registry + Rekor network call per unique image; set `COSIGN_ENABLED=false` if that's undesirable in your environment. Unsigned/unverifiable images are flagged as advisory warnings, never blocking. | `brew install cosign` |
| [Semgrep](https://semgrep.dev) (OSS) | Semantic pattern-matching SAST - logical flaws and injection-style sinks beyond the LLM deep-scan. Ruleset defaults to `p/security-audit,p/owasp-top-ten` (comma-separated - each pack is passed as its own `--config`, so packs combine rather than replace each other). **On by default.** No built-in fallback (semantic rule engines can't be meaningfully approximated). **Known limitation:** Semgrep OSS's taint engine is intraprocedural (single-file) - it can't trace a vulnerability whose tainted input crosses multiple files before reaching a sink (e.g. a stored-XSS/IDOR chain spanning a controller, service layer, and template). That gap is covered by CodeQL (below), which Ignite does wire in. | `brew install semgrep` |
| [Bearer](https://github.com/Bearer/bearer) | Sensitive data-flow (PII/GDPR) tracing - traces personal data from source (request params, user objects) to sinks (logs, DB writes, 3rd-party calls). **On by default** - needs a real git context, which `ensureGitContextForBearer` bootstraps automatically for a fresh ZIP/folder upload. | `brew tap bearer/tap && brew install bearer/tap/bearer` |
| [jscpd](https://github.com/kucherenko/jscpd) | Code-duplication scan - flagged clones become advisory (never blocking) quality findings. **Off by default.** No built-in fallback. | `npm install -g jscpd` |
| [gocloc](https://github.com/hhatto/gocloc) | Per-language LOC counts, attached as a downloadable project document. Purely descriptive - never produces issues. **On by default.** | `brew install gocloc` |
| [Spectral](https://github.com/stoplightio/spectral) | Lints every discovered OpenAPI/AsyncAPI file (found by content-sniffing, not filename) against Spectral's ruleset - org REST/AsyncAPI conventions, not just schema validity. **On by default.** Ruleset defaults to the bundled `spectral-default-ruleset.yaml` (`spectral:oas` + `spectral:asyncapi`); point `SPECTRAL_RULESET` at your own for org-specific conventions. | `npm install -g @stoplight/spectral-cli` |
| **Compliance & Feature Posture Engine** - reuses Semgrep | Classifies presence (`DETECTED`/`PARTIAL`/`MISSING`, never a blocking issue) of SSO/SAML/OIDC, RBAC/ABAC, audit logging, SIEM forwarding, HTTPS/TLS, backups/DR, encryption at rest, and rate limiting across TS/JS, Java, Go, Python, C#, and Ruby, via the bundled `ignite-posture-rules.yaml` ruleset. **On by default**, fully conditioned on Semgrep (no separate binary - reuses the same one above). Falls back to a built-in regex posture scanner (same weak/strong model, narrower coverage) when Semgrep is disabled or missing. | Same as Semgrep above |
| [GuardDog](https://github.com/DataDog/guarddog) (Datadog) | Malicious-dependency heuristic scan - downloads and statically inspects every npm (`package.json`)/PyPI (`requirements.txt`) dependency's real package contents against Semgrep-based supply-chain-attack rules (install-script exfiltration, obfuscated/encoded payloads, silent network calls, typosquatting). Catches what a CVE database (deps.dev, above) structurally can't: a malicious package with no advisory yet. **On by default** - slower/heavier than the rest of Phase 4 (a real registry fetch + static inspection per dependency); set `GUARDDOG_ENABLED=false` to opt out in environments with many manifest dependencies. No built-in fallback. | `pip install guarddog` |
| [picklescan](https://github.com/mmaitre314/picklescan) | Malicious ML model artifact scan - Python's pickle format executes arbitrary code on load, and it's the on-disk format underneath `.pkl`/`.pickle` dumps and PyTorch `.pt`/`.pth`/`.bin`/`.ckpt` checkpoints. Flags a dangerous pickle global import (opcode-level parse, not a regex heuristic). Deliberately excludes `.safetensors`/`.onnx` - neither is pickle-based. **On by default.** No built-in fallback. | `pip install picklescan` |
| [oasdiff](https://github.com/oasdiff/oasdiff) | API breaking-change / shadow-endpoint detection - diffs every discovered OpenAPI/AsyncAPI file against its own previous git revision (Spectral, above, only lints a spec in isolation). Catches a removed endpoint, a field that became required, a changed response type. Needs real git history to diff against - a fresh ZIP/folder upload with no prior commit simply contributes nothing. **On by default.** No built-in fallback. | `brew install oasdiff` |
| **AI package-hallucination ("slopsquat") check** - built-in, no external binary | Checks every manifest dependency name (npm/PyPI/crates.io) against its ecosystem's real public registry via a real HTTP existence check - a 404 is possibly an AI-invented package name an attacker could squat on. Upstream of GuardDog: GuardDog inspects a package's contents once it exists, this asks whether it exists at all. Always advisory - a private/internal package looks identical to a hallucinated one from here. **On by default.** | Nothing to install |
| [CodeQL](https://github.com/github/codeql-cli-binaries) | **Cross-file** static analysis (JS/TS, Python, Java, Go by default) - the one check that traces a vulnerability across file/function boundaries, which Semgrep OSS's intraprocedural engine structurally can't do (see the Semgrep row above). Builds a real per-language CodeQL database and runs the `security-extended` query suite, on every run alongside the rest of Phase 4. **On by default** - measured for real against Ignite's own codebase, its database build adds only ~3s to Phase 4's total wall time, since Phase 4 runs every check concurrently and CodeQL's build finishes well inside whichever other tool (typically Bearer) is already the long pole. Results are cached per `(org, repo, language)` keyed by a content hash of that language's file set, so an unchanged codebase skips the rebuild on the next run. No built-in fallback. Set `CODEQL_ENABLED=false` to opt out. | `scripts/install-tools.sh` or see the CLI binaries repo |
| [zizmor](https://docs.zizmor.sh) (Trail of Bits) | GitHub Actions workflow security - pwn-request patterns (`pull_request_target` running PR-head code with secrets/write access), script injection via untrusted `${{ github.event.* }}` expansions spliced into a `run:` shell step, excessive `permissions:`, unpinned actions, and more. Scans every `.github/workflows/*.yml`; skipped entirely (no invocation) on a repo with none. **On by default.** No built-in fallback (needs zizmor's real workflow-expression parser). Distinct from `ignite-guidelines`' narrower `no-unpinned-gha-action` dev-time check, which isn't part of the onboarding gate. | `pip install zizmor` or `cargo install zizmor` |

### Installing all of them at once

`scripts/install-tools.sh` runs every install command in the table above
(plus `act`) in one shot, instead of copy-pasting them one at a time:

```bash
curl -fsSL https://raw.githubusercontent.com/nunomcpereira/ignite/main/scripts/install-tools.sh | bash
```

Idempotent (safe to re-run - only installs what's still missing), macOS
(Homebrew) is the primary target since that's what every command above
uses, and any individual tool can be skipped with `INSTALL_<TOOL>=false`
(e.g. `INSTALL_GUARDDOG=false`). Docker itself isn't installed for you - it
needs its GUI installer - the script just flags it if missing.

### Installing ORT

ORT isn't on Homebrew. Download a release archive and symlink the binary onto `PATH`:

```bash
mkdir -p ~/tools && cd ~/tools
gh release download 91.1.0 -R oss-review-toolkit/ort -p 'ort-91.1.0.tgz'
tar xzf ort-91.1.0.tgz
ln -sf ~/tools/ort-91.1.0/bin/ort /opt/homebrew/bin/ort   # or anywhere else on PATH
ort --version   # sanity check
```

Requires a JDK ≥ 21 on `PATH` (`brew install openjdk`). ORT resolves each ecosystem independently and needs that ecosystem's own tooling/lockfile to do it - e.g. NPM needs a `package-lock.json` (`allowDynamicVersions` isn't set), Cargo needs the `cargo` binary, pip needs `python-inspector`. When ORT can't resolve an ecosystem, Ignite's `scanDependencyLicenses` falls back to its own manifest parser + deps.dev lookup **for that ecosystem only** - the rest of the manifests still use ORT's results (`engine: "ort+fallback"` in the Dependencies view, vs. plain `"ort"` when it resolved everything or `"fallback"` when it isn't installed at all).

ORT also only populates each manifest's real file path (`java/pom.xml`, not a placeholder) when it can detect VCS context - Ignite handles this automatically by `git init`-ing a throwaway commit in the staging directory before invoking `ort analyze` (skipped if the upload already contains a `.git`), so this isn't something you need to set up yourself.

### Installing licensee

macOS ships Ruby 2.6, which licensee's dependencies don't support. Install a newer Ruby via Homebrew first:

```bash
brew install ruby
/opt/homebrew/opt/ruby/bin/gem install licensee
ln -sf /opt/homebrew/lib/ruby/gems/*/bin/licensee /opt/homebrew/bin/licensee
licensee version   # sanity check
```

### gitleaks

The regex secret scan always runs. If gitleaks is installed and enabled in config, it runs as an additional pass over the same staging tree and its findings (tagged `tool: "gitleaks"`) are merged in - deduped against anything the regex already caught at the same file/line. Disabled by default; if it's enabled but the binary isn't found, the scan soft-fails back to regex-only results (a warning is logged, nothing blocks the pipeline).

```jsonc
"security": {
  "gitleaks": {
    "enabled": false,       // env: GITLEAKS_ENABLED=true
    "binary": "gitleaks",   // env: GITLEAKS_BINARY (path or name on $PATH)
    "configPath": ""        // env: GITLEAKS_CONFIG_PATH - optional gitleaks.toml
  }
}
```

### Dependency & license compliance (ORT / licensee / deps.dev)

Every pipeline run (interactive, `validate-all`, and `onboard`) scans dependency manifests and LICENSE files as part of Phase 3, automatically - no separate action needed. Findings show up as regular, file-level, overridable issues (category `license-compliance`) alongside secrets/AI-governance findings, gate the run the same way, and highlight the exact line in Ignite Studio's file viewer.

- **Per-dependency licenses:** ORT if installed (see above), else this app's own manifest parsers (`package.json`, `Cargo.toml`, `requirements.txt`, `go.mod`, `pom.xml`) + a lookup against the public [deps.dev](https://deps.dev) API. Classified into three tiers: green (permissive OSS: MIT, Apache-2.0, BSD, ...), amber/copyleft (GPL, AGPL, LGPL, MPL, ...), red/commercial (SSPL, BUSL, `Commercial`/`Proprietary`, or anything unrecognized - unrecognized is treated as risk until reviewed, not assumed safe).
- **The project's own license:** licensee if installed (project root only), plus a dependency-free scan of every `LICENSE`/`LICENCE` file anywhere in the tree (not just the root - a multi-language monorepo has one per module) for commercial/proprietary language, extracting `Licensee:`/`Licensor:` fields when present.
- On demand, the same scan is also available standalone: `POST /api/dependencies/check` with `{ "projectPath": "..." }` (agent/CI use), or via the "Dependencies" button in Ignite Studio (useful for a byte-for-byte look at every manifest's raw compliance table, independent of the issue list).
- **Range-floor resolution:** the fallback scanner's naive version pick from a manifest range (`^5.6.0` → look up `5.6.0`) 404s on deps.dev whenever that exact patch was never actually published - common, since plenty of packages skip an exact `.0` release or only ever pre-released it (real example: `typescript@^5.6.0` - npm's history goes `5.6.0-beta` → `5.6.0-dev.*` → `5.6.1-rc` → `5.6.2`, no plain `5.6.0`). Rather than reporting that as a blocking "license unknown" finding, it re-resolves against the package's real published version list and retries with the highest version the range actually matches - a package that's really missing from the registry is still correctly flagged.

## Codebase intelligence - closing the fallow.tools gap

Four built-in, zero-external-tool checks (`rust/crates/dead-code`, `rust/crates/complexity-health`, `rust/crates/boundaries`, `rust/crates/css-dead-code`) close a JS/TS codebase-quality gap that Ignite's original secrets/governance/SAST focus didn't cover - the kind of signal tools like [fallow.tools](https://fallow.tools) surface. All four are heuristic (regex/bracket-depth parsing over `rust/crates/module-graph`'s lightweight import graph, not a real type-checker or build system), so every finding is always advisory (`severity: 'warning'`) - a human confirms before deleting/restructuring, never a hard gate.

| Gap (what a tool like fallow.tools flags) | Ignite's check | How it works | Default |
|---|---|---|---|
| Dead files never reached from any entry point | `checkDeadCode` - `unused-file` | BFS over the module graph from `package.json`'s `main`/`module`/`exports`/`bin` plus test/config files as entry points; anything unreached is flagged | On |
| Exported symbols nobody imports | `checkDeadCode` - `unused-export` | Any named export never imported anywhere by name; upgraded to an AST-based check (`ts.createSourceFile`) when the scanned project itself has `typescript` installed, to filter out matches that were really inside a comment/string | On |
| Dependencies declared but never used | `checkDeadCode` - `unused-dependency` | Any `package.json` dependency never `require`/`import`-ed and not mentioned in an npm script | On |
| Cyclomatic/cognitive complexity hotspots | `checkComplexityHealth` - `high-complexity` | Per-file branch-keyword counting (cyclomatic) and nesting-weighted counting (cognitive); flags by decision *density* (per line), not raw file size, to avoid flagging every file over ~65 lines | On |
| Maintainability scoring | `checkComplexityHealth` - `low-maintainability` | A calibrated Maintainability Index (0-100), tuned against Ignite's own codebase rather than the textbook Halstead-based SEI formula (no real parser to compute Halstead Volume from) | On |
| Risk-weighted refactor targets | `checkComplexityHealth` (descriptive only) | CRAP score (`CC² × (1-coverage/100)³ + CC`), pulling real per-file coverage from [ingested runtime data](#runtime-coverage-ingestion) when available, git-churn-weighted hotspots, and a ranked refactor-target list - not issues, same precedent as LOC metrics/posture | On |
| Layered/hexagonal architecture boundary violations | `checkBoundaries` - `boundary-violation` | Opt-in `preset` (`bulletproof` \| `layered` \| `hexagonal` \| `feature-sliced`) and/or custom `zones: [{ name, pattern, allow }]`; first-match-wins zone assignment, with single-`*` glob segments captured so sibling zone instances (e.g. `src/features/auth` vs `src/features/billing`) stay isolated from each other | **Off** - a default zone layout on a project that doesn't follow one is pure noise |
| Dead CSS/Tailwind classes | `checkCssDeadCode` - `unused-css-class` | Flags a `.css`/`.scss`/`.less` class selector never referenced in any scanned `class`/`className` attribute; `is-`/`has-`/`js-`-prefixed classes excluded (commonly toggled via `classList`, never appearing as a literal string) | On |

All four feed the same issue/override model as the external-tool checks (`collect_phase4_issues` in `rust/crates/override-engine`, categories `dead-code`/`complexity-health`/`architecture-boundary`/`css-dead-code`) - findings are addressable and overridable exactly like a secret or SAST finding, just always `severity: 'warning'`.

## EU AI Act coverage

Ignite can only speak to the code-detectable slice of the EU AI Act - most of it (risk-management-system documentation, conformity assessment, FRIA, human-oversight procedure) is an org-process artifact, not something a static scan sees. Two pieces cover what's actually detectable, both **advisory-only by default** (never block a run, never feed `collectPhase4Issues` unless explicitly opted in):

- **Three code-detectable posture categories** (`checkFeaturePosture`/`ignite-posture-rules.yaml`), reusing the same `DETECTED`/`PARTIAL`/`MISSING` weak/strong model as the other eight posture categories:
  - `ai-act-prohibited-practice` (Art. 5) - biometric-categorization/emotion-inference/social-scoring libraries and call sites. Unlike every other posture category, `DETECTED` here flags a **risk to review**, not a safeguard.
  - `ai-act-transparency-disclosure` (Art. 13/50) - user-facing "AI-generated"/"you're talking to an AI" disclosure strings.
  - `ai-act-ai-logging` (Art. 12) - MLflow/W&B/LangSmith-style model input/output/decision logging, distinct from the general-purpose `audit-logging` category.
- **Document-presence scan** (`check_compliance_documents`, `rust/crates/compliance-documents`, `CONFIG.compliance.euAiActDocuments`, `EU_AI_ACT_DOCS_ENABLED`) - a built-in, no-external-tool filename/path scan for the process-obligation documents the posture engine can't detect by code signature: risk-management-system doc (Art. 9), Annex IV technical documentation (Art. 11), an FRIA (Art. 27), a GPAI training-data summary/model card (Art. 53), a post-market monitoring plan (Art. 72). `DETECTED`/`MISSING` per category (no `PARTIAL` tier - there's no weak/strong distinction for "does this file exist"), attached as a downloadable `ai-act-documents-report.json` document. On by default; absence in this one repo's tree is not evidence the document doesn't exist org-wide (a GRC tool, a wiki, a separate compliance repo), so this is context for a human, never a gate.

**Advisory vs. enforced mode** (`CONFIG.compliance.euAiAct.reportAsFindings`, `EU_AI_ACT_REPORT_AS_FINDINGS`, **`false` by default**): controls whether the signals above stay purely descriptive in the two report documents, or actually surface as addressable/overridable issues in `collectPhase4Issues`:

```jsonc
"compliance": {
  "euAiActDocuments": { "enabled": true },   // env: EU_AI_ACT_DOCS_ENABLED
  "euAiAct": { "reportAsFindings": false }   // env: EU_AI_ACT_REPORT_AS_FINDINGS
}
```

- **Advisory (default, `false`)**: the three `ai-act-*` posture categories and the document scan stay in `posture-report.json`/`ai-act-documents-report.json` only - visible in Ignite Studio and the downloadable reports, never blocking, never in the issues list.
- **Enforced (`true`)**: `run_phase4_checks` (`rust/crates/phase4-orchestrator`) calls `derive_eu_ai_act_findings(posture, documents)`, turning the three `ai-act-*` posture matches and any `MISSING` document category into a `euAiAct` findings group fed through the same generic loop `deadCode`/`health`/`cssDeadCode`/`boundaries` use (category `ai-act-prohibited-practice`/`ai-act-transparency-disclosure`/`ai-act-ai-logging`/`ai-act-compliance-documents` in the issues list). Always `severity: 'warning'` regardless of the toggle - these are heuristic regex/filename signals, never promoted to a hard blocker, and still go through the normal justify-and-override flow like any other advisory finding.

## CWE/OWASP tagging - audit-trail identifiers per finding

Every Phase 3/4 issue (built in `rust/crates/override-engine`) carries a `cwe` and `owasp` field alongside its own category label, for SOC2/ISO27001-style compliance reporting that expects a standard identifier rather than an Ignite-specific name. Three-tier precedence:

1. **Explicit per-finding data a tool already reports** - Semgrep's own rule metadata (`p/security-audit`/`p/owasp-top-ten` rules ship a `cwe`/`owasp` field per rule) and Bearer's `cwe_ids` are passed straight through - the most precise source, since it's tied to the exact rule that matched.
2. **Keyword match on the finding's own summary text** - covers the LLM deep-scan's free-text findings, which carry no structured CWE of their own (e.g. an LLM finding whose text mentions "SQL injection" tags as CWE-89/A03:2021).
3. **A fixed category-level fallback** - coarser (one CWE for a whole check, e.g. every IaC misconfiguration reads as CWE-16/A05:2021) but still gives every finding in a mapped category *some* identifier. Categories with no meaningful security mapping (code duplication, license compliance, API schema lint, process/governance checks, ...) are left `null`/`null` rather than forced onto a CWE that doesn't fit.

Surfaced in the downloaded Markdown issues report (a `Ref: CWE-XX — AXX:2021 - ...` line per finding) and as a small badge on each issue card in the review dialog.

## Attack & risk coverage - what each check actually prevents

Every check above exists to stop a specific class of real-world incident, not
just to produce a finding for its own sake. This table maps each threat to
the tool/check combination that catches it, and the phase it runs in -
useful both for security review of Ignite itself and for explaining to a
team *why* a given gate is blocking their push.

| Threat / attack class | How Ignite catches it | Tool(s) / check | Phase | If the tool isn't available |
|---|---|---|---|---|
| Committed raw `.env`/`.env.*` files leaking live credentials into repo history | Denies any `.env`/`.env.*` file anywhere in the tree (unless already `.gitignore`d) before anything else runs | Built-in structure audit | 3 | N/A - built-in, no external tool involved |
| Hardcoded secrets in source (API keys, passwords, tokens, private keys) | Regex scan over every text file; gitleaks runs as a supplemental pass over the same tree when enabled, merged and deduped against the regex hits | Built-in regex scan + [gitleaks](#gitleaks) (optional) | 4 | The built-in regex scan always runs regardless; only gitleaks's supplemental pass is skipped |
| Runaway/uncontrolled AI agent loops - unbounded LangChain/LangGraph `.invoke()`/`.stream()` calls (cost blowup, infinite loops, larger prompt-injection blast radius) | Flags any `.invoke(`/`.stream(`/`.ainvoke(`/`.astream(` call missing `recursion_limit` | Built-in AI-governance regex check | 4 | N/A - built-in, no external tool involved |
| **SQL injection** - unparameterized/string-concatenated queries, tainted input reaching a raw query or ORM `.raw()`/`.exec()` call | Two independent passes, not one: (1) Semgrep's `p/security-audit` ruleset ships dedicated SQL-injection rules per language/framework (Node `pg`/`mysql`/Sequelize, Python `psycopg2`/Django ORM `.raw()`, Java JDBC/JPA, PHP PDO, Ruby ActiveRecord, ...) that flag a query built by concatenating/interpolating unsanitized input instead of using bound parameters; (2) the local LLM deep-scan is explicitly prompted to read the actual data flow and flag SQL injection it finds, including patterns a fixed rule set doesn't have a rule for yet | Semgrep + LLM deep-scan (security pass) | 4 | Semgrep: skipped entirely if missing - no built-in fallback for a rule engine, but the LLM pass still covers this ground independently. LLM: skipped with a warning if the endpoint is unreachable - Semgrep's rules still catch it on their own |
| Command injection, template injection, path traversal, SSRF, insecure deserialization, XSS, broken auth/authz, weak crypto, unsafe `eval`/`exec`, prototype pollution, insecure temp files, missing input validation | Same two independent passes as SQL injection above, same reasoning - Local LLM deep-scan reviews real source for these patterns; Semgrep's `p/security-audit` ruleset catches the same classes via static pattern matching, independently | LLM deep-scan (security pass) + [Semgrep](https://semgrep.dev) | 4 | LLM pass: skipped with a warning if the endpoint is unreachable. Semgrep: skipped entirely if missing - no built-in fallback for a rule engine, but the LLM pass still covers this ground independently |
| Dependency with a **known**, already-disclosed CVE/GHSA advisory | Resolves each manifest dependency's real version and cross-references deps.dev's aggregated OSV/GHSA data | Built-in scanner + [deps.dev](https://deps.dev) API | 3 | Not tied to a locally-installed tool - that specific lookup just fails soft (marked unresolved, not blocking) if deps.dev is unreachable |
| Dependency that is **malicious but has no advisory yet** - install-script exfiltration, obfuscated/encoded payloads, silent network calls, typosquatting (the gap a CVE database can't cover, since a freshly-published malicious package has nothing to look up) | Downloads and statically inspects each npm/PyPI dependency's actual package contents against Semgrep-based supply-chain-attack heuristics | [GuardDog](https://github.com/DataDog/guarddog) (on by default - heavier, per-package registry fetch) | 4 | Check skipped entirely - no fallback (this heuristic can't be meaningfully approximated) |
| A poisoned ML model weight file (`.pkl`/`.pt`/`.pth`/`.ckpt`) executing arbitrary code on load via an unsafe pickle global import - AI agents routinely download/commit these without inspecting their contents | Opcode-level parse of every discovered model artifact for a dangerous pickle global import | [picklescan](https://github.com/mmaitre314/picklescan) (on by default) | 4 | Check skipped entirely - no fallback (needs picklescan's real pickle parser) |
| An AI coding agent silently removing/breaking an existing API endpoint - a shadow change that ships without review | Diffs every discovered OpenAPI/AsyncAPI file against its own previous git revision, flagging breaking changes (removed endpoint, newly-required field, changed response type) | [oasdiff](https://github.com/oasdiff/oasdiff) (on by default) | 4 | Check skipped entirely - no fallback; also contributes nothing on a fresh upload with no prior git history to diff against |
| AI package hallucination ("slopsquatting") - an LLM invents a plausible but non-existent package name, which an attacker registers and ships malware through to the next dev/agent who installs it | Checks every manifest dependency name against its ecosystem's real public registry (npm/PyPI/crates.io); a 404 is flagged (advisory) | Built-in package-hallucination check (on by default) | 4 | N/A - built-in, no external tool involved (always advisory: a private/internal package looks identical to a hallucinated one from a public-registry lookup alone) |
| Commercial/proprietary/unrecognized dependency licenses creating unreviewed IP/legal exposure; the project's own license terms | Resolves real per-dependency licenses (ORT, or the built-in manifest parser + deps.dev fallback) and classifies green/amber/red; scans every `LICENSE`/`LICENCE` file for commercial/proprietary language | [ORT](https://oss-review-toolkit.org/ort/) / [licensee](https://github.com/licensee/licensee) / deps.dev | 3 | Falls back to the built-in manifest parser + deps.dev lookup if ORT is missing; the project's-own-license row is simply omitted if licensee is missing |
| IaC/container misconfiguration - privileged containers, missing resource limits, insecure Terraform/Kubernetes/Helm settings, unpinned base images, missing `USER` | Trivy's config scanner is primary, supplemented by Checkov's larger policy set and hadolint's Dockerfile-only rules, deduped by file/line/rule-id; falls back to a built-in unpinned-tag/missing-`USER` heuristic when none are installed | [Trivy](https://github.com/aquasecurity/trivy) + [Checkov](https://www.checkov.io/) + [hadolint](https://github.com/hadolint/hadolint) | 4 | Falls back to a built-in Dockerfile heuristic if Trivy is missing; Checkov/hadolint just stop supplementing (fewer findings, same baseline coverage) if they're missing |
| **Known-vulnerable OS/language packages baked into a built container image** (the misconfiguration check above only lints Dockerfile *source*, never image *contents*) | Builds every discovered Dockerfile with `docker build`, then runs `trivy image` against the result | [Trivy](https://github.com/aquasecurity/trivy) (`image` mode) | 4 | Check skipped entirely - off by default (`TRIVY_IMAGE_ENABLED=true` to opt in), and soft-skips if Docker/trivy aren't available |
| Supply-chain base-image tampering - a Dockerfile `FROM` image with no verifiable provenance | Verifies Sigstore/cosign keyless signatures on every unique base image referenced; unsigned images are flagged (advisory) | [cosign](https://github.com/sigstore/cosign) | 4 | Check skipped entirely - no fallback (signatures can't be verified without the tool) |
| No record of what code actually passed the pipeline vs. what got pushed, once the (force-removed) staging directory is gone | Attaches an unsigned in-toto/SLSA-provenance-v1-shaped `provenance.json` - a content-addressed digest over every staged file plus the source commit SHA when available | Built-in (`generateProvenance`/`digestProjectTree`) | 4 | N/A - built-in, no external tool involved. Not a signed SLSA attestation - see [Build/commit provenance](#buildcommit-provenance-unsigned) |
| Logical/semantic vulnerabilities beyond single-line pattern matching | Semgrep's registry rulesets (`p/security-audit` by default) | [Semgrep](https://semgrep.dev) | 4 | Check skipped entirely - no fallback |
| PII/GDPR data-flow exposure - personal data (request params, user objects) reaching logs, DB writes, or third-party calls without controls | Traces data flow from source to sink, filtered to Bearer's own PII/Personal-Data-tagged findings only | [Bearer](https://github.com/Bearer/bearer) | 4 | Check skipped entirely - no fallback |
| Copy-pasted vulnerable/stale logic drifting out of sync across a codebase | Flags duplicated code blocks above a configurable threshold (advisory - a maintainability/drift risk, not a direct exploit) | [jscpd](https://github.com/kucherenko/jscpd) (off by default) | 4 | Check skipped entirely - no fallback (off by default regardless) |
| Insecure API design/contract violations in OpenAPI/AsyncAPI schemas | Lints every discovered schema file (found by content, not filename) against org REST/AsyncAPI conventions | [Spectral](https://github.com/stoplightio/spectral) | 4 | Check skipped entirely - no fallback |
| Missing security/compliance controls that widen the attack surface even with no single vulnerable line - no SSO/MFA, no RBAC, no audit logging, no rate limiting, secrets read from plain env vars instead of a vault, etc. | Classifies *presence* (not vulnerabilities) of eight security/compliance categories as DETECTED/PARTIAL/MISSING via a dedicated Semgrep ruleset; built-in regex fallback when Semgrep is unavailable | Compliance & Feature Posture Engine (reuses Semgrep) | 4 | Falls back to a built-in regex posture scanner (same weak/strong model, narrower coverage) if Semgrep is missing |
| Org-mandated security/compliance CI gates silently not enforced locally, only caught after a real PR | Runs the actual central `ai-guardrails-orchestrator.yml` (and every workflow it `uses:`) locally via `act`, so local pass/fail matches the real remote gate | [act](https://github.com/nektos/act) + Docker | 5 | Soft-skipped with a warning if `act`/Docker are missing - the workflows still gate remotely on GitHub, just not caught locally before pushing |
| Unauthorized/unvetted code reaching the org's GitHub regardless of findings above | Provisioning + push only happens after every enabled phase passes (or every blocking issue is overridden with a justified, attributed, emailed audit record) | The pipeline gate itself (`collectPhase4Issues` / override engine) | 6 | N/A - enforced by the pipeline's own logic, not an external tool |
| Zip-slip - a malicious archive entry resolving outside the staging directory | Every archive entry's resolved path is verified to stay inside the staging root before extraction; symlink entries are skipped entirely | Built-in extraction guard | pre-1 | N/A - built-in, no external tool involved |
| Zip-bomb / disk-exhaustion DoS via a malicious or oversized upload | Extracted size capped at 4 GB, upload capped at 1 GB | Built-in size guards | pre-1 | N/A - built-in, no external tool involved |
| Command injection via org/repo names or shelled-out tool arguments | Every `git`/`gh`/tool invocation uses `execFile` with argument arrays (no shell); org/repo names validated against GitHub's naming rules; commands restricted to a fixed allowlist (`ALLOWED_COMMANDS`) | Built-in sanitizers (`sanitizeCommand`/`sanitizeCliArgs`/`sanitizeCwd`) | all | N/A - built-in, no external tool involved |
| The project's own automated test suite silently regressing | Auto-detects Node/Go/Rust/Python/Java and runs that ecosystem's native test runner (`npm test`, `go test`, `cargo test`, `pytest`, `mvn test`) inside an isolated Docker container | Built-in detection + Docker | 3 | Skipped if no recognized test setup is found, or if Docker isn't available - logged, never silently assumed to pass |
| A repo drifting out of compliance *after* onboarding - a new vulnerable/malicious dependency merged later, with no one notified | Effectivated repos can opt into a scheduled (daily/weekly/monthly) re-check of the default branch (phases 1/3/4/5, no push); on failure, emails the repo's CODEOWNERS contact or files a GitHub issue if none can be resolved | Scheduled re-check + CODEOWNERS check | 3 (ongoing) | N/A for the schedule/notify logic itself - the re-check still depends on whichever Phase 4 tools are installed on the server at the time it runs |
| A `CODEOWNERS`-less repo silently having no one accountable for findings | Advisory check for a `CODEOWNERS` file (root/`.github`/`docs`) and any email-address owner listed in it, surfaced in the pipeline log and used to route scheduled-check failures | Built-in CODEOWNERS check | 3 | N/A - built-in, no external tool involved |
| A vulnerability whose tainted data crosses file/function boundaries (a stored-XSS/IDOR chain spanning a controller, service layer, and template) - beyond what an intraprocedural SAST engine can trace | Builds a real per-language CodeQL database and runs the `security-extended` query suite; `crossFile: true` only when the finding's SARIF `codeFlows` actually span more than one file | [CodeQL](https://github.com/github/codeql-cli-binaries) | 4 | Check skipped entirely - no fallback (a cross-file taint engine can't be meaningfully approximated) |
| A malicious/vulnerable GitHub Actions workflow shipped alongside the code it's meant to gate - pwn requests (`pull_request_target` running PR-head code with secrets/write access), script injection via untrusted `${{ }}` expansions spliced into a shell `run:` step, over-broad `permissions:`, unpinned third-party actions | Parses every `.github/workflows/*.yml` with zizmor's real workflow-expression engine, not a regex approximation | [zizmor](https://docs.zizmor.sh) (Trail of Bits, on by default) | 4 | Check skipped entirely (and never invoked at all if the repo has no workflow files) - no fallback |
| Dead files, unused exports, and unused dependencies accumulating unnoticed - larger attack surface and audit burden with no functional purpose | Module-graph BFS from real entry points flags unreached files, name-level unused exports, and manifest dependencies never required/scripted | Built-in (`checkDeadCode`) - see [Codebase intelligence](#codebase-intelligence---closing-the-fallowtools-gap) | 4 | N/A - built-in, no external tool involved |
| Unmaintainable, high-risk hotspots accumulating silently - complex, poorly-covered code that's expensive and dangerous to change | Per-file cyclomatic/cognitive complexity, a calibrated Maintainability Index, and a CRAP score weighted by real ingested coverage when available | Built-in (`checkComplexityHealth`) | 4 | N/A - built-in, no external tool involved |
| Architecture/layering erosion - a lower layer reaching into a higher one, or sibling feature modules importing each other directly, defeating an intended isolation boundary | Zone-based import-graph check against a preset or custom `zones` config; first-match-wins, single-`*` glob captures for sibling isolation | Built-in (`checkBoundaries`) - **off by default** | 4 | N/A - built-in, no external tool involved |
| Dead CSS/Tailwind classes bloating the shipped stylesheet with rules nobody's markup ever selects | Flags a class selector never referenced in any scanned `class`/`className` attribute; `is-`/`has-`/`js-`-prefixed classes excluded (toggled via `classList`) | Built-in (`checkCssDeadCode`) | 4 | N/A - built-in, no external tool involved |
| EU AI Act Art. 5/12/13 code-detectable risk (prohibited biometric/emotion/social-scoring practices, missing AI-interaction disclosure, missing model-decision logging) going unreviewed | Three dedicated posture categories (`ai-act-prohibited-practice`/`ai-act-transparency-disclosure`/`ai-act-ai-logging`) via the same Semgrep-backed weak/strong posture model | Compliance & Feature Posture Engine (reuses Semgrep) - see [EU AI Act coverage](#eu-ai-act-coverage) | 4 | Falls back to the built-in regex posture scanner if Semgrep is missing; advisory-only by default either way (`EU_AI_ACT_REPORT_AS_FINDINGS=true` to enforce) |
| EU AI Act process-obligation documentation (risk-management system, Annex IV technical docs, FRIA, GPAI training-data summary, post-market monitoring plan) missing with no one flagged to produce it | Filename/path scan across the repo tree per document category | Built-in (`checkComplianceDocuments`) | 4 | N/A - built-in, no external tool involved. Absence in one repo isn't proof the document doesn't exist org-wide - see [EU AI Act coverage](#eu-ai-act-coverage) |

## Checks report - every check that ran, split by area

Alongside "View flagged issues" (the problems only, downloadable as Markdown), a **📋 Checks report** button appears next to it - at the top of the page for the run that's live/just finished, and per-project in the Onboarded Projects history list for any past run. It lists every check Ignite performs, grouped by area (Security / Quality / Dependencies / API & Schema), each with a ✓ CLEAN / N WARNING(S) / N BLOCKING result - so a clean run reads as "12 checks ran, all clean" instead of an empty issues list that could just as easily mean "nothing was checked." It's also downloadable as Markdown.

It's rebuilt on demand from the project's already-persisted issues (`GET /api/pipeline/:jobId/issues` or `GET /api/projects/:id/issues`) - nothing new is stored server-side, so it's available for any run in history exactly the same way the issues list already is. The checks that run unconditionally every time by default (IaC/Checkov/hadolint, Cosign, Semgrep, Spectral, plus secrets/AI-governance/license-compliance) always appear, even with zero findings; jscpd (off by default), the LLM-driven checks (deep-scan security/quality/dependency/encapsulation), and the phase-level checks (structure audit, GxP, governance CI) only appear when they actually produced a finding, since those can be disabled or conditionally skipped (LLM endpoint down, GxP disabled, Docker/`act` missing, ...).

## Generate fix PR - AI-suggested fixes for every open issue, bundled into one PR

A **✨ Generate fix PR** button next to "View flagged issues" runs the same AI suggest-fix pass Ignite Studio's per-issue "Suggest AI fix" button uses (below), but over every open issue that has a stored code snippet, then lets you review and drop individual candidates before opening one PR with the ones you keep - no more clicking "Suggest AI fix" issue-by-issue. Two steps, no server-side session state kept between them:

1. **`POST /api/pipeline/:jobId/fix-pr/preview`** - a pure LLM pass, no git involved. Reuses each issue's snippet exactly as captured at scan time, so a bulk run proposes the same fix a human clicking the per-issue button would have gotten. An issue with no stored snippet, or where the model can't safely propose a fix, is silently dropped rather than failing the batch - the response's `consideredCount` vs. returned-candidate count shows how many were skipped and why (in the job log). Shown in a modal as a red/green diff per candidate, each with a checkbox to exclude it.
2. **`POST /api/pipeline/:jobId/fix-pr/apply`** - takes back exactly the (possibly trimmed) candidate list from step 1, clones the repo's default branch fresh, applies every accepted edit (bottom-to-top per file, so one edit's line-count change never shifts another still-pending edit in the same file), commits, pushes to a deterministic per-job branch (`ignite/fix-issues/<jobId>`), and opens one PR bundling all of them. Idempotent - calling it again while that branch is still open on GitHub reports `alreadyOpen` instead of a duplicate PR.

Only available for a job whose project has already shipped to GitHub (there has to be a repo to open a PR against) - returns a clear error otherwise. Available from both a live run's results page and the Onboarded Projects history list, since - unlike Ignite Studio's Dependencies/SBOM/LOC/Posture views - it never touches the staging directory (long gone for a historical run): candidate generation reads from the persisted `issues` table, and applying fixes clones a fresh copy straight from GitHub.

## Scheduled re-scans & automatic fix PRs - Dependabot-equivalent continuous coverage

Every check above only runs when a scan is *triggered* - a push, a CLI run, an upload. Nothing re-checks an already-shipped repo's unchanged code against a CVE disclosed *after* it was onboarded, the way Dependabot does on a schedule. Two standalone binaries close that gap together:

- **`scheduled-rescan`** (`rust/crates/scheduled-rescan`) - has no scheduler of its own; it's a one-shot binary that iterates every onboarded `(org, repo)` pair Ignite already knows about, shallow-clones each one's current GitHub default branch, runs a real `validate-all`, and - only if that turns up something - posts the result back as a commit status/PR comment. *You* put it on a timer (cron/systemd, or a GitHub Actions `schedule:` trigger) - see `docs-site/docs/ci-integration.md` for both.
- **`auto-fix-pr`** (`rust/crates/auto-fix-pr`) - the piece Dependabot has and a bare rescan doesn't: proposing the fix, not just detecting the problem. For each repo, resolves every dependency-vulnerability finding's minimum fixed version via OSV.dev and opens one PR per safe (single, non-major-version) bump. Runnable standalone against any repo (`./target/release/auto-fix-pr <org/repo> [--apply]`, dry-run unless `--apply`), **or chained automatically off `scheduled-rescan`** via `IGNITE_SCHEDULED_RESCAN_AUTO_FIX=dry-run|apply` - so a newly-disclosed CVE found on a repo that already shipped can get a reviewable fix PR opened with no human in the loop, not just a notification. Off by default; opt in per the env var above.

This is a different mechanism from the interactive **✨ Generate fix PR** above: that one is triggered by a person, covers any open finding (not just dependency CVEs), and uses an LLM to draft the diff. `auto-fix-pr` is unattended, scoped to dependency-vulnerability findings only, and resolves the fix deterministically from the advisory data - no LLM involved.

## Onboarded Repos - every repo at a glance

A second lateral-nav screen (next to Dashboard, `GET /api/onboarded-repos`) lists every distinct `(org, repo)` Ignite has ever onboarded, one row each, sorted by most recent activity:

| Column | Source |
| --- | --- |
| Org / Repo | the `projects` table, deduplicated to one row per `(org, repo)` - repo name links to GitHub when `repoUrl` is known |
| License problems | open `license-compliance` issues from that repo's **latest** run only (a fresh snapshot, not a running total) |
| Findings | every open issue from that repo's **latest** run only |
| Acknowledgments | every override ever recorded for that repo, across **all** runs - a stable audit fact doesn't stop counting just because a later run didn't repeat it. Shown as a count that downloads the full history (issue id, justification, actor, timestamp) as one markdown file |
| Recent PRs | every PR Ignite has opened for that repo, across all runs: the onboarding PR (🚀, recorded automatically when a run ships) and any interactive fix-PRs (✨, recorded when `/fix-pr/apply` succeeds) - each a direct link to the PR on GitHub |
| Last scan | the latest run's `finished_at` (or `created_at` if still running) |

Backed by `DbStore::list_onboarded_repo_summaries` (`rust/crates/db-store`) and a new `pull_requests` table that unifies both PR sources - the onboarding PR (`projects.pr_url`) and interactive fix-PRs are recorded into it the moment they're opened, with a one-time startup backfill for any `pr_url` set before this table existed. Note this list is **every repo Ignite has ever run a check against that created a project row** (including headless `validate-all` calls from the CLI/pre-push hook against an already-existing repo), not only ones freshly provisioned through the onboarding flow - a repo can appear here with zero PRs if it's only ever been gate-checked, never (re-)onboarded through Ignite itself.

## Ignite Studio - one place for every connected tool's findings

Studio's top bar (reachable from the review gate, or the "Studio" button on a finished run) has one button per non-issue artifact, each replacing the code pane with a live, on-demand report - the same "recompute against the still-staged project" pattern the existing 📦 Dependencies button uses, backed by `GET /api/pipeline/:jobId/studio/{sbom,loc-metrics,posture}`:

- **📄 SBOM** - the CycloneDX component table (Syft, or the built-in fallback list).
- **📊 LOC Metrics** - per-language line/file counts (gocloc).
- **🛡️ Posture** - the Compliance & Feature Posture Engine's 8-category DETECTED/PARTIAL/MISSING grid; clicking a match jumps straight to that file/line.

Findings from the other seven tools (IaC/Checkov/hadolint, cosign, Semgrep, Bearer, jscpd, Spectral) already flow into the same flagged-issues list secrets/AI-governance findings use - the project-wide summary bar just below the header breaks that list down by category (`iac-security`, `image-provenance`, `semantic-sast`, `pii-dataflow`, `code-duplication`, `api-schema-lint`, plus the pre-existing `secret`/`ai-governance`/`license-compliance`/etc.). Each category label is a button: clicking one narrows the file tree to only files with a finding in that category - a quick way to see everything one specific tool flagged without hunting file-by-file - and clicking it again (or the "✕ clear filter" button that appears) restores the full tree. Five of those six (all but jscpd, which is off by default) always show a chip even at zero findings; jscpd's `code-duplication` chip only appears once it's enabled and finds something.

The right-hand "External tools" panel lists live connected/disconnected state for all eighteen tools (seventeen binaries + the posture engine, which shares Semgrep's) - same data as the top-right pill panel outside Studio, via `GET /api/tools/status`. (The built-in AI package-hallucination check has no binary to probe, so it isn't part of this panel.)

### Historical Studio - browsing a past project

A 🧪 **Studio** button appears next to any project in Recent Checks history that has flagged issues, opening a read-only Studio reconstructed entirely from what's persisted in the `issues` table (category/severity/summary/file/line and a small snippet per finding) - the staging directory for that run is long gone by then (staging dirs are force-removed in a `finally` block after every run, pass or fail). An amber banner makes the limitation explicit, and Dependencies/SBOM/LOC/Posture/Rescan are hidden since they'd need to recompute against a real staged project.

Per file, the persisted snippets are stitched together in line order; wherever there's a gap between one finding's captured lines and the next, a `⋯ N lines not shown ⋯` divider marks the code that was never retained - so it's always clear how much of the file you're *not* looking at, not just what you are. Explain-this-issue/Suggest-AI-fix still work exactly as before, since both already only ever operated on the snippet, never the full file.

## White-label branding & multi-language UI

The web UI (`public/index.html`) never hardcodes brand values or English literals for its own copy - both are runtime configuration, not code, so a customer deployment never has to fork the app to look and speak like its own product.

- **Branding** (`public/branding.config.js`): product name, page title, header logo, support link, and the full `brand` accent color scale (buttons, links, active states) are read from `window.IGNITE_BRAND`, merged over Ignite's own defaults. Ships checked in with an empty override object - the app renders unchanged until a customer sets one or more keys (see the file's own header comment for the full list and an example). Because `index.html` only ever *reads* this object and a customer's overrides live entirely in this one file, upstream feature commits and a customer's branding edits never touch the same lines - `git pull`/merge never conflicts on this.
- **Internationalization** (`public/i18n.js`): the static UI chrome - buttons, labels, headers, modals, tooltips, placeholders - ships fully localized in **English, French, Portuguese, and German**, switchable from a picker in the header (persisted per-browser via `localStorage`). Scope is deliberately limited to copy the app itself authors; server-generated text (phase titles/logs, finding summaries, CWE/OWASP ids, tool output, raw API error messages) is never translated and always renders exactly as the backend sends it. A missing translation key falls back to English, then to the raw key itself, so an incomplete locale degrades gracefully instead of breaking.

Neither system needs a rebuild or a redeploy to take effect - both files are served as-is by the same static-file service that serves `index.html`.

## Hardening notes

- **Zip-slip:** every archive entry's resolved path must stay inside the staging root, or extraction aborts.
- **Zip bombs:** total extracted size is capped at 4 GB; uploads capped at 1 GB.
- **Symlinks:** symlink archive entries are skipped; the directory walker never follows symlinks.
- **Command injection:** all `git`/`gh` invocations use `execFile` with argument arrays (no shell), and org/repo names are validated against GitHub's naming rules before use.

## Configuration - `config.json`

All settings live in `config.json` at the repo root, read by `ignite-server` via `IGNITE_CONFIG_DIR` (environment variables override it):

```jsonc
{
  "port": 51337,
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
      "pass": ""                 // Gmail app password - see below
    }
  },
  "security": {
    "gitleaks": {                // optional supplemental secret scan
      "enabled": false,
      "binary": "gitleaks",
      "configPath": ""
    },
    "trivy": { "enabled": true, "binary": "trivy" },
    "trivyImage": { "enabled": false, "severityThreshold": "HIGH,CRITICAL" },
    "checkov": { "enabled": false, "binary": "checkov" },
    "hadolint": { "enabled": true, "binary": "hadolint" },
    "cosign": { "enabled": false, "binary": "cosign", "identityRegexp": ".*", "issuerRegexp": ".*" },
    "semgrep": { "enabled": true, "binary": "semgrep", "config": "p/security-audit" },
    "bearer": { "enabled": false, "binary": "bearer" }
  },
  "sbom": {
    "syft": { "enabled": true, "binary": "syft" }
  },
  "metrics": {
    "jscpd": { "enabled": false, "binary": "jscpd" },
    "gocloc": { "enabled": true, "binary": "gocloc" }
  },
  "api": {
    "spectral": { "enabled": true, "binary": "spectral", "ruleset": "" }  // "" = bundled spectral-default-ruleset.yaml
  },
  // Optional per-phase title/description/enabled overrides - see
  // "Configurable phases + GxP" above. Omit entirely to keep every
  // built-in default (Phase 2/GxP disabled, everything else enabled).
  "phases": [
    { "id": 2, "enabled": true }
  ],
  "mcp": {                        // see "MCP server" below
    "autoStart": true,
    "httpPort": 51338
  }
}
```

### Failure emails

When any phase fails, Ignite emails a detailed report to `notifications.to`: target repo, failed phase, a status table of all six phases, and the full terminal logs of every failed phase.

- **With SMTP credentials** (`smtp.host`+`user`+`pass` set): sends through that server. For Gmail, create an [app password](https://myaccount.google.com/apppasswords) and paste it into `pass` - your normal account password will not work.
- **Without credentials**: falls back to the local `sendmail` binary. The message is handed to the OS mail system, but delivery to external addresses (Gmail) is unreliable without a configured relay - set the app password for dependable delivery.

## Prerequisites

1. **Rust** (stable toolchain — `rustup` is the easy path)
2. **git** available on `PATH`
3. **A way to authenticate to GitHub** - either works:
   - **GitHub CLI (`gh`)**, installed and authenticated:
     ```bash
     gh auth login
     gh auth status   # verify - must show a logged-in account with repo scope
     ```
   - **No `gh` at all** - see [Running without the gh CLI](#running-without-the-gh-cli) below.

   Whichever you use, the account needs permission to create repositories in the target organization. Per-onboarding-request auth (the "Connect GitHub" button / OAuth) is separate from either of these and always required for the interactive/API onboarding flows regardless - see [Authentication](#authentication--standalone-accounts-or-company-idp).

### Pushing via SSH instead of gh's credential helper

By default, Phase 6 pushes over `https://github.com/...`, authenticated through `gh auth git-credential` using the connected account's token. Set `GITHUB_REMOTE_PROTOCOL=ssh` (or `"github": { "remoteProtocol": "ssh" }` in `config.json`) to push over `git@github.com:...` instead, authenticated by whatever SSH key/agent is already configured for `github.com` on this machine - no git credential helper involved for the push itself.

This only replaces the **git push transport** - repo creation, enabling auto-merge, and creating the `main` ref still go through the GitHub REST API in both modes, since SSH keys authenticate git operations, not GitHub API calls. See the next section for running those API calls without `gh` installed at all.

### Running without the gh CLI

`gh` is a soft dependency for every plain GitHub API call (repo creation, PR open/auto-merge/checks, issue filing, cloning) - the same soft-dependency pattern as the external scanning tools. If it isn't installed, Ignite transparently falls back to calling the GitHub REST/GraphQL API directly over HTTPS with a token, no functionality lost:

- **Per-onboarding-request calls** (repo creation, PR, auto-merge, checks) already use the connected account's own token (`GET /api/auth/github/connect` / the "Connect GitHub" button) - nothing extra to configure, this fallback just kicks in automatically once `gh` isn't found.
- **Server-level calls with no per-request user** (fetching the org's governance workflow for Phase 5, cloning + filing issues for a [scheduled re-check](#pre-push-hook)) have no connected-user token to fall back on - set `GH_TOKEN` or `GITHUB_TOKEN` (the same env vars `gh`/GitHub Actions itself recognizes) to a personal access token with `repo` scope for those to keep working.

Combine with `GITHUB_REMOTE_PROTOCOL=ssh` for a host with no `gh` binary at all: git push goes over SSH, and every remaining GitHub interaction goes over plain HTTPS with a token.

## Local LLM deep-scan (on by default)

On top of the deterministic checks, the pipeline submits source files to a **local** LLM served by llama.cpp (OpenAI-compatible `/v1/chat/completions` endpoint) that hunts for real vulnerabilities - injection, path traversal, SSRF, unsafe eval, weak crypto, etc. Code never leaves the machine. If the endpoint is unreachable, the scan is skipped with a warning rather than failing the run.

Configure via environment variables (all optional):

| Variable | Default | Meaning |
|---|---|---|
| `LLM_SCAN_URL` | `http://localhost:8050` | llama.cpp / OpenAI-compatible base URL |
| `LLM_SCAN_MODEL` | `default` | Model name (llama.cpp serves its loaded model regardless) |
| `LLM_SCAN_MODE` | `warn` | `warn` = findings are advisory; `block` = critical/high findings halt the pipeline |
| `LLM_DEEP_SCAN_ENABLED` | `true` | Gates only Phase 4's automated deep-scan (Check 3). The on-demand **Explain this issue** / **Suggest AI fix** buttons in Ignite Studio call the same LLM connection independently of this flag, so turning deep-scan off (e.g. for a faster/deterministic-only run) doesn't disable per-issue AI analysis. |
| `LLM_MAX_FILES` | `40` | Cap on source files sent to the model |

Files are batched into ~24 KB chunks with numbered lines, and the model must answer in strict JSON (`{"findings":[{file,line,severity,issue}]}`); malformed responses skip that chunk only.

## Setup & Run

```bash
cd rust && cargo build --release -p ignite-server
IGNITE_CONFIG_DIR=.. ./target/release/ignite-server
# → http://localhost:51337
```

Then in the browser:

1. Drag a `.zip` **or a whole project folder** onto the drop zone (or use the Choose ZIP / Choose Folder buttons). Folder uploads skip `node_modules`, `.git`, and build output automatically - no repacking needed between iterations.
2. Enter the GitHub organization name; the repository name is auto-proposed from the ZIP/folder name (editable).
3. Click **Initiate Onboarding Pipeline** and watch the four phases stream their logs. Click any phase card to expand/collapse its terminal output.
4. On success, the final banner shows the live repository URL as a clickable link.

> **Security note:** this server executes `git`/`gh` with the host machine's credentials. Run it locally or behind authentication - never expose it unauthenticated to a network.

## Simulation mode (`dryRun`) - check without pushing

`POST /api/pipeline` (the same multipart endpoint the browser UI uses) accepts
an optional `dryRun` form field (`"true"`/`"false"`, default `"false"`). When
set, phases 1-5 run exactly as normal (structure audit, secret scan, AI
governance, LLM deep-scan, local CI via `act`) but phase 6 - repo
provisioning and `git push` - is skipped; the job is recorded as a success
with no `repoUrl`/`prUrl`. This is the mode to reach for when driving the
pipeline from an agent/MCP client that just wants to surface errors without
committing to a real onboarding: run the checks, inspect the streamed NDJSON
events, and only re-run with `dryRun` unset (or omitted) once everything is
green.

`POST /api/pipeline/validate-all` (below) is already dry-run-only - it never
ships - but it takes a `projectPath` on the local filesystem rather than an
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
curl -sS -X POST http://localhost:51337/api/pipeline/validate-all \
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

**`changedFiles` (agent fix-verify loops):** pass an optional `changedFiles:
["src/app.js", "src/util.py"]` (project-relative paths) to narrow the
returned `issues` array to just those files, plus `totalIssueCount` and
`filteredByChangedFiles: true` for context. This is a *view* only - every
blocking issue in the whole project still has to be resolved or overridden
for `ok: true`; `changedFiles` just saves an agent from re-reading the full
issue list on every "edit a couple files, re-scan" iteration.

## SARIF export

`GET /api/pipeline/:jobId/sarif` returns the same flagged-issue list `GET
/api/pipeline/:jobId/issues` does (secrets, AI-governance, LLM deep-scan,
license/vulnerability, every Phase 4 external-tool check, and CodeQL),
reshaped into [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) - so
GitHub code scanning, most SAST dashboards, or any agent that already
speaks SARIF can ingest a run's output with no Ignite-specific parsing.
Works for both a still-running job and a completed one (job id from either
`validate-all`/`onboard_project`'s response, or the browser UI's URL).
`error`-severity issues map to SARIF `level: "error"`, `warning` maps to
`warning`; an issue a human already overrode downgrades to `note` rather
than disappearing. Excludes non-issue artifacts (SBOM, LOC metrics, posture
report) - those stay on their own Studio document endpoints.

```bash
curl -sS http://localhost:51337/api/pipeline/<jobId>/sarif | jq
```

## CLI (`ignite scan`)

```bash
ignite scan [path] [--changed-files a.js,b.py] [--json] [--base-url URL]
```

A thin wrapper around `validate-all` (the `ignite-cli` crate, `rust/crates/cli`, binary name `ignite`) for agents/CI that
want a plain command + exit code instead of the raw HTTP API. Always
dry-run - `validate-all` never ships, so this needs no auth for its own
sake. Exit codes: `0` passed, `1` blocking issues/validation failure, `2`
couldn't reach the server or bad usage. `--json` prints the raw
`validate-all` response; without it, prints a human-readable pass/fail
summary with each issue's location. Requires a running Ignite server
reachable at `IGNITE_BASE_URL` (default `http://localhost:51337`) - same
requirement as the pre-push hook and VS Code extension below.

## Pre-push hook

`hooks/pre-push` wraps `validate-all` in a git hook, for repos that would
rather gate on `git push` than a separate ZIP-upload step. It posts the
repo's own absolute path (`git rev-parse --show-toplevel`), fails closed
with a clear message if the Ignite server isn't reachable, and prints the
failing phase's logs so you don't have to open the UI to see what broke.

**Blocking findings can be acknowledged from the terminal.** On a blocking
finding, the hook writes `.ignite/acknowledgments.md` at the repo root - one
entry per finding, each with a blank `Acknowledge:` line, same shape as the id
(`<category>::<file>::<line>`) `validate-all`'s response now carries for
exactly this purpose (`issues` on a failed response). Fill in a
justification, `git push` again: the hook resubmits every filled-in line as
a real override (`{issueId, justification}`), attributed via `git config
user.name`/`user.email`, and rewrites the file from scratch to match the
current scan: a justified entry survives as long as its finding is still
reported - including across a pure line-number shift, carried forward
automatically to the new id - but once the underlying issue is actually
fixed, its entry is dropped rather than kept forever. Each surviving entry
is also numbered (`# Issue #1`, `#2`, ...) as a running count, recomputed
every push.

Every run (pass or fail) also drops a point-in-time snapshot of every
reported finding at `.ignite/scans/<timestamp>/findings.md` - a per-scan
history folder, unlike the refreshed-every-run acknowledgments file.

```bash
# Install into one repo:
cp hooks/pre-push /path/to/other-repo/.git/hooks/pre-push
chmod +x /path/to/other-repo/.git/hooks/pre-push

# Or every repo on this machine, via a shared hooks dir (.git/hooks/ isn't
# itself tracked by git, so this is the way to cover every repo at once):
mkdir -p ~/.git-hooks && cp hooks/pre-push ~/.git-hooks/
git config --global core.hooksPath ~/.git-hooks
```

Requires a running Ignite server reachable at `IGNITE_BASE_URL` (default
`http://localhost:51337`) and `jq` on `PATH`. Off by default: `runLocalCi`
(Phase 5's `act`/Docker governance CI - slow, belongs in real CI) and
blocking on warnings (only `error`-severity findings gate the push). Both
configurable via env vars documented at the top of the script
(`IGNITE_RUN_LOCAL_CI`, `IGNITE_WARNING_MODE`), plus a logged
`IGNITE_PREPUSH_SKIP=true` escape hatch for one push, preferable to a silent
`git push --no-verify`. Full walkthrough with sample output: [the docs
site](https://nunomcpereira.github.io/ignite/pre-push-hook).

## VS Code extension

`vscode-extension/` is a thin client that runs the same `validate-all` pipeline against the currently open workspace folder, natively in the editor - no separate web UI, no upload/picker flow. Works with VS Code, Cursor, or VS Code Insiders.

```bash
cd vscode-extension
./install.sh   # builds + installs the .vsix, reload window after
```

Requires a running Ignite server (`./target/release/ignite-server` from `rust/`, default `http://localhost:51337`).

Commands (Command Palette):

- **Ignite: Scan Workspace** - runs phases 1-5 (phase 5 only if `ignite.runLocalCi` is on) against the open folder; findings land in the Problems panel, a Findings tree, and an Output channel. Guarded against double-firing while a scan is already running, and the reachability probe now logs a per-attempt reason (timeout, `ECONNREFUSED`, 5xx body, ...) to the Output channel instead of a flat "isn't reachable".
- **Ignite: Toggle Findings Grouping (Finding / Phase)** - switches the Findings tree between the original per-phase layout and a per-finding layout that groups every occurrence of the same (category + summary) finding under one collapsible row, unresolved findings sorted first. A toolbar icon in the Findings view title bar toggles it without opening the Command Palette.
- **Ignite: Acknowledge Selected** - available on a finding group or a multi-selection in the Findings tree (`Cmd`/`Ctrl`-click to select several); prompts once for a justification and writes an `Acknowledge:`-filled stanza for every unresolved occurrence in the selection to `.ignite/acknowledgments.md` in one shot, instead of acknowledging one occurrence at a time.
- **Ignite: Install Pre-Push Hook** - installs `hooks/pre-push` (above) into this repo's git hooks.
- **Ignite: Open Review File** - opens `.ignite/acknowledgments.md` for filling in `Acknowledge:` justifications on blocking findings, same file/flow the pre-push hook uses.
- **Ignite: Refresh Tools Status** - re-probes the optional external tools in a Tools Status tree.
- **Ignite: Show License Compliance** / **Show SBOM** / **Show LOC Metrics** / **Show Compliance & Feature Posture** - on-demand report panels for the four non-issue Phase 4 artifacts, opened beside the editor. Backed by the same `projectPath` convention as `validate-all`: license compliance calls the existing `POST /api/dependencies/check`; SBOM/LOC/posture call the new standalone `POST /api/reports/{sbom,loc-metrics,posture}` endpoints (`rust/crates/server/src/routes/reports.rs`) added specifically for the extension, since it only ever calls `validate-all` and has no `jobId`/review-gate state to hang a Studio request off of. Each renders as pretty-printed JSON in a reused webview panel (one per report kind) - the same data the web UI's Studio buttons show in full table form.

Settings: `ignite.baseUrl` (default `http://localhost:51337`), `ignite.runLocalCi` (default `false`), `ignite.showOverriddenIssues` (default `false`). Full detail, dev/debug instructions, and building the `.vsix` for someone else without installing it: [`vscode-extension/README.md`](vscode-extension/README.md).

Screenshots (Findings/Tools Status trees, inline Problems-panel diagnostics): see the [docs site's VS Code section](https://nunomcpereira.github.io/ignite/how-it-works#5-or-scan-straight-from-vs-code--no-upload-no-browser).

## AI validation guidelines - MCP server & API

`guidelines/` holds the company AI validation guideline catalog (AI-governance,
security, and process rules - the same detection patterns Ignite's onboarding
pipeline enforces) and a pure checks engine, so guidelines can be applied
*during development*, not just at onboarding time.

### MCP server

Two ways to run it:

1. **Stdio** (one instance per client, no shared state — the default transport):
   ```bash
   ./target/release/mcp-server
   ```
   Point any MCP client (Claude Code, Claude Desktop, etc.) at it directly - example `.mcp.json` entry:
   ```json
   {
     "mcpServers": {
       "ai-validation-guidelines": {
         "command": "/absolute/path/to/ignite/rust/target/release/mcp-server"
       }
     }
   }
   ```
2. **Streamable HTTP** - run the same binary with `MCP_TRANSPORT=http`, listening on `http://localhost:51338/mcp` by default:
   ```bash
   MCP_TRANSPORT=http ./target/release/mcp-server
   ```
   Its own logs are prefixed `[mcp]`. Port via `MCP_HTTP_PORT`.

Tools exposed:

- `list_guidelines({ category?, severity? })` - list guidelines, optionally filtered.
- `get_guideline({ id })` - full detail (description, rationale, remediation) for one guideline.
- `check_guidelines({ content, path? })` - check a code snippet/file against the automated guidelines.
- `check_project({ projectPath })` - walk a project directory and check every source file.
- `check_dependency_licenses({ projectPath })` - the same [dependency + LICENSE-file license compliance scan](#dependency--license-compliance-ort--licensee--depsdev) Phase 3 runs automatically, standalone. Thin proxy to `POST /api/dependencies/check` on a running Ignite server.
- `check_dependency_vulnerabilities({ projectPath })` - scans resolved dependency versions for known CVE/GHSA advisories via deps.dev's aggregated OSV data (CVSS ≥ 7 is blocking, lower is advisory). Thin proxy to `POST /api/dependencies/vulnerabilities`.
- `onboard_project({ projectPath, org, repo, dryRun?, gxp?, gxpLinks?, runLocalCi?, warningDecision?, overrides?, actor? })`
  - runs the **full** onboarding pipeline (all enabled phases, and phase 6 provisioning
  + push if everything passes) against a `POST /api/pipeline/onboard` on a
  running Ignite server. This is a thin proxy: the MCP process itself never
  touches `git`/`gh`, it just calls the HTTP API. Set `dryRun: true` to run
  every check without pushing - the way to "see what would fail" from an
  agent loop before committing to a real push. Requires the Ignite server
  running (`ignite-server`) and reachable at `IGNITE_BASE_URL` (env, default
  `http://localhost:51337`), with `gh` authenticated on that host.

**Acknowledging findings via MCP:** a failed `onboard_project` call's
response carries the exact unresolved `issues` (id, category, severity,
summary, file, line) needed to build overrides - same shape the [pre-push
hook's CLI acknowledgment](#pre-push-hook) works from. Call it, read back
which findings are still blocking, call it again with `overrides:
[{issueId, justification}]` and an `actor` for whichever ones get justified
- only what's genuinely unresolved keeps blocking. No browser involved at
any point in the loop.

Two more tools cover flows that one-shot `onboard_project` call doesn't:

- `resolve_review_decision({ jobId, proceed, overrides?, actor? })` - resume
  a run paused mid-flight on the *interactive* `POST /api/pipeline` endpoint
  (e.g. one a human started in the browser and handed off to an agent, or
  the reverse). Thin proxy to `POST /api/pipeline/:jobId/review-decision`.
- `effectivate_project({ projectId, overrides?, actor? })` - the "check
  first, ship later" loop: call `onboard_project` with `dryRun: true`,
  inspect the returned issues over one or more turns, then call this once
  satisfied - it provisions + pushes the exact already-validated snapshot
  without re-running phases 1-5. Thin proxy to
  `POST /api/projects/:projectId/effectivate`. Needs the caller's GitHub
  account connected same as a real (non-dryRun) `onboard_project` call.

### REST API

```bash
./target/release/guidelines-api   # listens on 127.0.0.1:8090 by default
```

Binds to loopback only by default (`GUIDELINES_API_HOST`/`GUIDELINES_API_PORT`
to override) - `/check-project` reads arbitrary paths on the host filesystem,
so this is a local dev/CI tool, not meant for public exposure.

- `GET /guidelines?category=&severity=` - list guidelines.
- `GET /guidelines/:id` - full detail for one guideline.
- `POST /check` `{ content, path? }` - check a snippet/file; returns `{ violations, hasBlockingViolations }`.
- `POST /check-project` `{ projectPath }` - check a project directory; returns `{ scanned, violations, hasBlockingViolations }`.

Guidelines with `checkId: null` (e.g. `ai-governance-workflow-required`,
`llm-deep-scan-required`) are process rules or covered by the LLM deep-scan in
`rust/crates/llm-deep-scan`, not mechanically checkable from a snippet alone.

## Overriding flagged guideline checks - audit log & notification

Phase 4 (Security & AI Compliance Scan) collects every flagged issue -
hardcoded secrets, ungoverned AI invocations, LLM security/quality
findings, IaC/container misconfigurations, unsigned base images, semantic
SAST findings, PII/GDPR data-flow findings, code duplication, and API
schema lint findings - into a single addressable list instead of
hard-failing immediately. Any issue (blocking error or advisory warning)
can be overridden, but every override:

1. requires a **justification**,
2. must be **attributed** to a real person (logged-in session, or an
   explicit `{email, name}` actor when auth isn't enforced globally),
3. sends an **email notification** (reusing `notifications.*` config) listing
   exactly what was overridden, by whom, and why,
4. is **persisted to the audit log** (`overrides` table) and shown under
   each project's entry in the Onboarded Projects list (click a project to
   expand - "Audit log - overridden guideline checks" appears if any exist).

Blocking (`severity: "error"`) issues cannot be silently bypassed: the
pipeline stays halted until every blocking issue either has a matching
override+justification, or is fixed in the source.

- **Interactive pipeline** (`POST /api/pipeline`, browser upload): pauses and
  emits a `review_required` event with the full issue list; the UI shows a
  modal to check/justify issues, then posts the decision to
  `POST /api/pipeline/:jobId/review-decision`
  `{ proceed, overrides: [{issueId, justification}], actor? }`.
- **Non-interactive** (`POST /api/pipeline/validate-all`): pass overrides
  up front - `{ ..., overrides: [{issueId, justification}] }` - since there's
  no live client to prompt. `issueId` is the `id` field on each finding
  (`<category>::<file>::<line>`).

### Bulk-acknowledging via the downloaded report

The review dialog's **Download ⤓** button (the same one that generates the
Markdown "flagged issues" report) now writes an `ID:` line and a blank
`Acknowledge:` line under every overridable issue. Fill in a one-line
justification after `Acknowledge:` for whichever issues you want to
override, save the file, and use **Import acknowledgments ⤒** in the same
dialog to check the box and fill the justification for every matching issue
in one shot - instead of doing it one row at a time in the browser. This is
a client-side convenience only (it fills the same checkbox/textarea fields
a human would, submitted through the normal `review-decision`/override flow
above) - no new API surface, and every attribution/audit-log rule above
still applies. An id that doesn't match any issue in the current review
(e.g. the file was edited between download and import) is reported, not
silently dropped.

## Authentication - standalone accounts or company IdP

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
CI/local-validation workflows keep working unauthenticated) - it's only
enforced where attribution matters: submitting an override without a
session must include an explicit `actor {email, name}` in the request body,
or the server responds `401`.

### API keys (headless/agent auth)

Every mode above requires a browser to complete a login/OAuth redirect -
something no unattended agent or CI job can do. A real (non-`dryRun`) push
also hard-requires a connected GitHub account tied to a logged-in user, so
without a session an agent can run dry-run checks but can never actually
ship. API keys close that gap:

1. Sign up / log in once via the web UI (whichever `AUTH_MODE` is
   configured) and connect GitHub if you'll need real pushes.
2. Mint a key for that account:
   ```bash
   ./target/release/create-api-key you@example.com "ci-agent"
   ```
   Prints the raw key exactly once (`ignite_<64 hex chars>`) - only its
   SHA-256 hash is stored, so save it now; it can't be recovered later.
3. Send it as `Authorization: Bearer ignite_<key>` on any request. It
   resolves to the same `req.user` a session cookie would, so it works
   everywhere attribution or `resolve_effective_github_token` is needed -
   `onboard_project` with `dryRun: false`, `effectivate_project`, submitting
   overrides without an explicit `actor`, etc. A session cookie takes
   priority if both are present.

The `mcp-server` binary (all its tools) and the `ignite` CLI (`ignite scan`)
both pick this up automatically from an `IGNITE_API_KEY` env var:

```bash
export IGNITE_API_KEY="<the key create-api-key printed>"
```

There's no revoke endpoint yet - `store.revoke_api_key(id)` in
`rust/crates/db-store` works from a one-off script against `ignite.db` in
the meantime.

## Testing

```bash
cd rust && cargo test
```

Every crate has its own `#[cfg(test)] mod tests` alongside its source
(`rust/crates/<name>/src/lib.rs`), following the same coverage pattern the
Node test suite established: config/env wiring, fake-CLI parsing/dedup/
soft-fail behavior for every soft-dependency external tool, and a real-binary
end-to-end case that self-skips when the tool isn't installed on this
machine rather than failing the suite (checked against the actual installed
binaries, not just the fallback paths, per `rust/MIGRATION_STATUS.md`).
Run a single crate's tests with `cargo test -p <crate-name>`.

### End-to-end (Playwright)

```bash
cd rust && cargo build --release -p ignite-server && cd ..
npm install   # once, for @playwright/test
npm run test:e2e
```

Spawns the compiled `ignite-server` binary on a throwaway port (built above
— the e2e suite itself stays on Node/Playwright, same as `docs-site/` and
`vscode-extension/`, but the thing it's testing is the Rust server), uploads
the `aigovernancedevops/vulnerable-app-multilang` fixture through the actual
browser UI, and drives it through Ignite Studio:

- `e2e/studio-license-issues.spec.js` - proves license-compliance findings
  appear automatically in the review gate and in Studio's file tree/issue
  panel/line highlights, with no manual "Dependencies" click needed.
- `e2e/ort-licensee-engines.spec.js` - spawns the server with fake ORT/
  licensee CLIs on PATH and asserts the Dependencies view reports
  `Engine: ORT (OSS Review Toolkit)` and the licensee-detected project
  license, proving the real tool-invocation path (not just the fallback).

## License

[MIT](LICENSE)
