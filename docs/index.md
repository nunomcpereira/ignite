---
layout: default
title: Ignite — Onboarding Gatekeeper
---

# Ignite

**A compliance gate for onboarding code into a GitHub org.** Upload a project — a
ZIP or a whole folder — and Ignite runs it through secret scanning, license
compliance, AI-governance checks, a local LLM security deep-scan, IaC/
supply-chain/SAST scanning, and your org's own governance CI, entirely on
your machine. Only if every check passes (or every blocking issue is
justified and overridden) does it provision a private repo and push.

[View the full technical README on GitHub »](https://github.com/nunomcpereira/ignite#readme)

## How it works

### 1. Upload a project — checks run locally, streamed live

Drop a ZIP or a folder onto the app, name the target org/repo, and hit
**Initiate Onboarding Pipeline**. Every phase — structure audit, secret
scan, license compliance, AI-governance, IaC/supply-chain/SAST scanning,
your org's governance CI — streams its log output live as it runs. Nothing
leaves the machine until the run passes.

![Analysis running — phases streaming live](assets/images/01-analysis-running.png)

### 2. Nothing ships until every finding is reviewed

Before anything is provisioned or pushed, Ignite pauses at a final review
gate listing every flagged issue — blocking and advisory — with the exact
code snippet behind each one. A blocking issue needs a justified override
(logged to an audit trail and emailed) or a source fix before the run can
continue.

![Final review — flagged issues with code expanded](assets/images/02-findings-overview.png)

### 3. Ignite Studio — AI-assisted triage, in place

Every finding is addressable in **Ignite Studio**: browse the staged file
tree, jump straight to the flagged line, and ask the AI to explain the issue
in plain language or suggest a concrete fix for that exact snippet —
independent of whether the automated LLM deep-scan itself is enabled for
that run.

![Ignite Studio — Explain this issue and Suggest AI fix](assets/images/03-studio-ai-explain-fix.png)

## What gets checked

Six phases, twelve+ optional external-tool integrations (all soft
dependencies — Ignite works without any of them installed), and a local LLM
deep-scan, covering:

- Hardcoded secrets & credential leakage
- Ungoverned AI/LangChain invocations
- Injection, path traversal, SSRF, insecure deserialization, XSS, weak crypto
- Known-CVE **and** newly-published, not-yet-disclosed malicious dependencies
- Dependency license risk (commercial/copyleft)
- IaC/container misconfiguration & supply-chain image provenance
- PII/GDPR data-flow exposure
- Missing security/compliance posture (SSO, RBAC, audit logging, rate limiting, ...)
- Your org's own governance CI, run locally via `act` before it ever reaches a real PR

See the [attack & risk coverage table](https://github.com/nunomcpereira/ignite#attack--risk-coverage--what-each-check-actually-prevents)
in the README for the full mapping of threat class → tool/check → phase.

## Get started

```bash
git clone https://github.com/nunomcpereira/ignite.git
cd ignite
npm install
npm start
# → http://localhost:3000
```

Full setup, configuration, and API docs: [github.com/nunomcpereira/ignite](https://github.com/nunomcpereira/ignite).
