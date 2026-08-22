---
title: What gets checked
sidebar_position: 3
---

# What gets checked

Six phases and fifteen+ optional external-tool integrations (all soft
dependencies — Ignite works without any of them installed, falling back to
a built-in check where one exists). Most of this list is **static analysis
by a dedicated tool, no LLM involved**:

- Hardcoded secrets & credential leakage — regex scan + gitleaks (static)
- Known-CVE dependencies — deps.dev/OSV lookups against resolved versions (static, deterministic — not a guess)
- Newly-published, not-yet-disclosed malicious dependencies — GuardDog's supply-chain heuristics (static)
- Dependency license risk (commercial/copyleft) — ORT/licensee + deps.dev (static)
- Semantic vulnerabilities — Semgrep's `p/security-audit` SAST ruleset (static, real SAST — not the LLM)
- **Cross-file** vulnerabilities — a stored-XSS/IDOR chain spanning a controller, service layer, and template — CodeQL's `security-extended` query suite, closing a gap Semgrep's single-file engine structurally can't reach (static)
- IaC/container misconfiguration & supply-chain image provenance — Trivy, Checkov, hadolint, cosign (static)
- Known-vulnerable OS/language packages baked into a built container image — `trivy image` against a real `docker build` (static, off by default)
- PII/GDPR data-flow exposure — Bearer's source-to-sink tracing (static)
- Missing security/compliance posture (SSO, RBAC, audit logging, rate limiting, ...) — Semgrep-backed pattern matching (static)
- Low encapsulation — any single source file over a configurable line-count threshold — built-in, always advisory (static)
- Your org's own governance CI, run locally via `act` before it ever reaches a real PR (static, runs your actual workflows)
- Ungoverned AI/LangChain invocations — regex/AST check (static)

The **one** LLM-driven check is the local deep-scan pass: injection, path
traversal, SSRF, insecure deserialization, XSS, weak crypto, and similar
logic-level flaws that a fixed rule set can miss. It's independently
toggleable (`LLM_DEEP_SCAN_ENABLED`) — everything above it in this list
keeps running exactly the same with it off.

Every check exists to stop a specific class of real-world incident, not just
to produce a finding for its own sake. The table below maps each threat to
the tool/check combination that catches it — and, since every external tool
is a soft dependency, exactly which tool actually intervenes *if it's
installed* (Ignite still runs, and falls back where it can, if it isn't).

| Threat / attack class | How Ignite catches it | Tool(s) / check | If the tool isn't available |
|---|---|---|---|
| Committed raw `.env`/`.env.*` files leaking live credentials into repo history | Denies any `.env`/`.env.*` file anywhere in the tree (unless already `.gitignore`d) before anything else runs | Built-in structure audit | N/A — built-in, no external tool involved |
| Hardcoded secrets in source (API keys, passwords, tokens, private keys) | Regex scan over every text file; gitleaks runs as a supplemental pass over the same tree when enabled, merged and deduped against the regex hits | Built-in regex scan + gitleaks (optional) | The built-in regex scan always runs regardless; only gitleaks's supplemental pass is skipped |
| Runaway/uncontrolled AI agent loops — unbounded LangChain/LangGraph `.invoke()`/`.stream()` calls (cost blowup, infinite loops, larger prompt-injection blast radius) | Flags any `.invoke(`/`.stream(`/`.ainvoke(`/`.astream(` call missing `recursion_limit` | Built-in AI-governance regex check | N/A — built-in, no external tool involved |
| **SQL injection** — unparameterized/string-concatenated queries, tainted input reaching a raw query or ORM `.raw()`/`.exec()` call | Two independent passes: (1) Semgrep's `p/security-audit` ruleset ships dedicated SQL-injection rules per language/framework (Node `pg`/`mysql`/Sequelize, Python `psycopg2`/Django ORM `.raw()`, Java JDBC/JPA, PHP PDO, Ruby ActiveRecord, ...) flagging a query built by concatenating/interpolating unsanitized input instead of bound parameters; (2) the local LLM deep-scan is explicitly prompted to read the data flow and flag SQL injection it finds, including patterns with no rule yet | Semgrep + LLM deep-scan (security pass) | Semgrep: skipped entirely if missing — no built-in fallback, but the LLM pass still covers this independently. LLM: skipped with a warning if the endpoint is unreachable — Semgrep's rules still catch it on their own |
| Command injection, template injection, path traversal, SSRF, insecure deserialization, XSS, broken auth/authz, weak crypto, unsafe `eval`/`exec`, prototype pollution, insecure temp files, missing input validation | Same two independent passes as SQL injection above, same reasoning | LLM deep-scan (security pass) + Semgrep | LLM pass: skipped with a warning if the endpoint is unreachable. Semgrep: skipped entirely if missing — no built-in fallback for a rule engine, but the LLM pass still covers this ground independently |
| Dependency with a **known**, already-disclosed CVE/GHSA advisory | Resolves each manifest dependency's real version and cross-references deps.dev's aggregated OSV/GHSA data | Built-in scanner + deps.dev API | Not tied to a locally-installed tool — that specific lookup just fails soft (marked unresolved, not blocking) if deps.dev is unreachable |
| Dependency that is **malicious but has no advisory yet** — install-script exfiltration, obfuscated/encoded payloads, silent network calls, typosquatting | Downloads and statically inspects each npm/PyPI dependency's actual package contents against Semgrep-based supply-chain-attack heuristics | GuardDog (on by default if installed) | Check skipped entirely — no fallback (this heuristic can't be meaningfully approximated) |
| Commercial/proprietary/unrecognized dependency licenses creating unreviewed IP/legal exposure; the project's own license terms | Resolves real per-dependency licenses (ORT, or the built-in manifest parser + deps.dev fallback) and classifies green/amber/red; scans every `LICENSE`/`LICENCE` file for commercial/proprietary language | ORT / licensee / deps.dev | Falls back to the built-in manifest parser + deps.dev lookup if ORT is missing; the project's-own-license row is simply omitted if licensee is missing |
| IaC/container misconfiguration — privileged containers, missing resource limits, insecure Terraform/Kubernetes/Helm settings, unpinned base images, missing `USER` | Trivy's config scanner is primary, supplemented by Checkov's larger policy set and hadolint's Dockerfile-only rules, deduped by file/line/rule-id; falls back to a built-in unpinned-tag/missing-`USER` heuristic when none are installed | Trivy + Checkov + hadolint | Falls back to a built-in Dockerfile heuristic if Trivy is missing; Checkov/hadolint just stop supplementing (fewer findings, same baseline coverage) if they're missing |
| Supply-chain base-image tampering — a Dockerfile `FROM` image with no verifiable provenance | Verifies Sigstore/cosign keyless signatures on every unique base image referenced; unsigned images are flagged (advisory) | cosign | Check skipped entirely — no fallback (signatures can't be verified without the tool) |
| **Known-vulnerable OS/language packages baked into a built container image** — the misconfiguration check above only lints Dockerfile *source*, never image *contents* | Builds every discovered Dockerfile with `docker build`, then runs `trivy image` against the result | Trivy (`image` mode) | Check skipped entirely — off by default, and soft-skips if Docker/trivy aren't available |
| Logical/semantic vulnerabilities beyond single-line pattern matching | Semgrep's registry rulesets (`p/security-audit` by default) | Semgrep | Check skipped entirely — no fallback |
| **Cross-file** vulnerabilities — tainted data crossing file/function boundaries before reaching a sink, which Semgrep's single-file engine can't trace | Builds a real per-language CodeQL database and runs the `security-extended` query suite | CodeQL | Check skipped entirely — no fallback |
| PII/GDPR data-flow exposure — personal data (request params, user objects) reaching logs, DB writes, or third-party calls without controls | Traces data flow from source to sink, filtered to Bearer's own PII/Personal-Data-tagged findings only | Bearer | Check skipped entirely — no fallback |
| Copy-pasted vulnerable/stale logic drifting out of sync across a codebase | Flags duplicated code blocks above a configurable threshold (advisory) | jscpd (off by default) | Check skipped entirely — no fallback (off by default regardless) |
| Insecure API design/contract violations in OpenAPI/AsyncAPI schemas | Lints every discovered schema file (found by content, not filename) against org REST/AsyncAPI conventions | Spectral | Check skipped entirely — no fallback |
| Missing security/compliance controls that widen the attack surface even with no single vulnerable line — no SSO/MFA, no RBAC, no audit logging, no rate limiting, secrets read from plain env vars instead of a vault, etc. | Classifies *presence* (not vulnerabilities) of eight security/compliance categories as DETECTED/PARTIAL/MISSING via a dedicated Semgrep ruleset; built-in regex fallback when Semgrep is unavailable | Compliance & Feature Posture Engine (reuses Semgrep) | Falls back to a built-in regex posture scanner (same weak/strong model, narrower coverage) if Semgrep is missing |
| Org-mandated security/compliance CI gates silently not enforced locally, only caught after a real PR | Runs the actual central `ai-guardrails-orchestrator.yml` (and every workflow it `uses:`) locally via `act`, so local pass/fail matches the real remote gate | act + Docker | Soft-skipped with a warning if `act`/Docker are missing — the workflows still gate remotely on GitHub, just not caught locally before pushing |
| Unauthorized/unvetted code reaching the org's GitHub regardless of findings above | Provisioning + push only happens after every enabled phase passes (or every blocking issue is overridden with a justified, attributed, emailed audit record) | The pipeline gate itself | N/A — enforced by the pipeline's own logic, not an external tool |
| Zip-slip — a malicious archive entry resolving outside the staging directory | Every archive entry's resolved path is verified to stay inside the staging root before extraction; symlink entries are skipped entirely | Built-in extraction guard | N/A — built-in, no external tool involved |
| Zip-bomb / disk-exhaustion DoS via a malicious or oversized upload | Extracted size capped at 1 GB, upload capped at 250 MB | Built-in size guards | N/A — built-in, no external tool involved |
| Command injection via org/repo names or shelled-out tool arguments | Every `git`/`gh`/tool invocation uses `execFile` with argument arrays (no shell); org/repo names validated against GitHub's naming rules; commands restricted to a fixed allowlist | Built-in sanitizers | N/A — built-in, no external tool involved |
| The project's own automated test suite silently regressing | Auto-detects Node/Go/Rust/Python/Java and runs that ecosystem's native test runner (`npm test`, `go test`, `cargo test`, `pytest`, `mvn test`) inside an isolated Docker container | Built-in detection + Docker | Skipped if no recognized test setup is found, or if Docker isn't available — logged, never silently assumed to pass |
| A repo drifting out of compliance *after* onboarding — a new vulnerable/malicious dependency merged later, with no one notified | Effectivated repos can opt into a scheduled (daily/weekly/monthly) re-check of the default branch; on failure, emails the repo's CODEOWNERS contact or files a GitHub issue if none can be resolved | Scheduled re-check + CODEOWNERS check | N/A for the schedule/notify logic itself — the re-check still depends on whichever Phase 4 tools are installed on the server at the time it runs |
| A `CODEOWNERS`-less repo silently having no one accountable for findings | Advisory check for a `CODEOWNERS` file and any email-address owner listed in it | Built-in CODEOWNERS check | N/A — built-in, no external tool involved |

Full details, install instructions, and the on/off default for every tool: see the [README's tool table](https://github.com/nunomcpereira/ignite#external-tools).
