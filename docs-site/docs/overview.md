---
title: Overview
sidebar_position: 1
slug: /
---

# Ignite

<figure className="heroShot">

<svg viewBox="0 0 1080 400" role="img" aria-label="Four entry points, web upload, git push, VS Code, and MCP agent calls, converge into one local staging directory, run through six deterministic phases plus an optional local LLM deep-scan, then a pass/fail gate. A pass, or a justified attributed override, is the only way to reach GitHub; a fail without either loops back to fix the source. Each phase links to its own detailed diagram on the What gets checked page.">
  <defs>
    <marker id="arrowGray" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="var(--ifm-color-emphasis-500)"/>
    </marker>
    <marker id="arrowAccent" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="var(--ifm-color-primary)"/>
    </marker>
  </defs>

  <text x="540" y="16" text-anchor="middle" font-family="system-ui, sans-serif" font-size="13" fill="var(--ifm-color-emphasis-600)">Runs entirely on your machine — nothing crosses to GitHub until the gate passes</text>

  <g font-family="system-ui, sans-serif">
    <rect x="30" y="36" width="190" height="55" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
    <text x="125" y="59" text-anchor="middle" font-size="14" font-weight="600" fill="var(--ifm-color-emphasis-900)">Web UI</text>
    <text x="125" y="76" text-anchor="middle" font-size="11" fill="var(--ifm-color-emphasis-600)">ZIP / folder upload</text>

    <rect x="30" y="116" width="190" height="55" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
    <text x="125" y="139" text-anchor="middle" font-size="14" font-weight="600" fill="var(--ifm-color-emphasis-900)">git push</text>
    <text x="125" y="156" text-anchor="middle" font-size="11" fill="var(--ifm-color-emphasis-600)">pre-push hook</text>

    <rect x="30" y="196" width="190" height="55" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
    <text x="125" y="219" text-anchor="middle" font-size="14" font-weight="600" fill="var(--ifm-color-emphasis-900)">VS Code</text>
    <text x="125" y="236" text-anchor="middle" font-size="11" fill="var(--ifm-color-emphasis-600)">Ignite: Scan Workspace</text>

    <rect x="30" y="276" width="190" height="55" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
    <text x="125" y="299" text-anchor="middle" font-size="14" font-weight="600" fill="var(--ifm-color-emphasis-900)">MCP agent</text>
    <text x="125" y="316" text-anchor="middle" font-size="11" fill="var(--ifm-color-emphasis-600)">onboard_project call</text>
  </g>

  <g fill="none" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray)">
    <polyline points="220,63 260,63 260,141 296,141"/>
    <polyline points="220,143 260,143 260,166 296,166"/>
    <polyline points="220,223 260,223 260,208 296,208"/>
    <polyline points="220,303 260,303 260,234 296,234"/>
  </g>

  <rect x="300" y="126" width="150" height="120" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="375" y="179" text-anchor="middle" font-family="system-ui, sans-serif" font-size="14" font-weight="600" fill="var(--ifm-color-emphasis-900)">Staging</text>
  <text x="375" y="196" text-anchor="middle" font-family="system-ui, sans-serif" font-size="11" fill="var(--ifm-color-emphasis-600)">per-job temp dir</text>

  <line x1="450" y1="186" x2="486" y2="186" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray)"/>

  <rect x="490" y="46" width="250" height="280" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="615" y="70" text-anchor="middle" font-family="system-ui, sans-serif" font-size="11" letter-spacing="1" fill="var(--ifm-color-emphasis-600)">PIPELINE — ALL LOCAL</text>
  <line x1="505" y1="80" x2="725" y2="80" stroke="var(--ifm-color-emphasis-300)"/>
  <g font-family="system-ui, sans-serif" font-size="12.5" fill="var(--ifm-color-emphasis-900)">
    <a class="phase-link" href="what-gets-checked#phase-1-input-and-metadata">
      <rect x="498" y="92" width="234" height="20" rx="4"/>
      <text x="505" y="106"><tspan fill="var(--ifm-color-primary)" font-weight="600">1</tspan>  Input &amp; metadata  <tspan font-size="11">🔍</tspan></text>
    </a>
    <a class="phase-link" href="what-gets-checked#phase-2-gxp-docs-optional">
      <rect x="498" y="126" width="234" height="20" rx="4"/>
      <text x="505" y="140"><tspan fill="var(--ifm-color-primary)" font-weight="600">2</tspan>  GxP docs (optional)  <tspan font-size="11">🔍</tspan></text>
    </a>
    <a class="phase-link" href="what-gets-checked#phase-3-structure-license-and-tests">
      <rect x="498" y="160" width="234" height="20" rx="4"/>
      <text x="505" y="174"><tspan fill="var(--ifm-color-primary)" font-weight="600">3</tspan>  Structure, license &amp; tests  <tspan font-size="11">🔍</tspan></text>
    </a>
    <a class="phase-link" href="what-gets-checked#phase-4-security-and-compliance-scan">
      <rect x="498" y="194" width="234" height="20" rx="4"/>
      <text x="505" y="208"><tspan fill="var(--ifm-color-primary)" font-weight="600">4</tspan>  Security &amp; compliance scan  <tspan font-size="11">🔍</tspan></text>
    </a>
    <a class="phase-link" href="what-gets-checked#phase-5-org-governance-ci">
      <rect x="498" y="228" width="234" height="20" rx="4"/>
      <text x="505" y="242"><tspan fill="var(--ifm-color-primary)" font-weight="600">5</tspan>  Org governance CI  <tspan font-size="11">🔍</tspan></text>
    </a>
    <a class="phase-link" href="what-gets-checked#phase-6-provisioning-and-shipping">
      <rect x="498" y="262" width="234" height="20" rx="4"/>
      <text x="505" y="276"><tspan fill="var(--ifm-color-primary)" font-weight="600">6</tspan>  Provisioning &amp; shipping  <tspan font-size="11">🔍</tspan></text>
    </a>
  </g>

  <line x1="740" y1="186" x2="766" y2="186" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray)"/>

  <polygon points="840,126 910,186 840,246 770,186" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-primary)" stroke-width="2"/>
  <text x="840" y="182" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">All</text>
  <text x="840" y="198" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">pass?</text>

  <line x1="955" y1="26" x2="955" y2="386" stroke="var(--ifm-color-emphasis-300)" stroke-width="1.5" stroke-dasharray="6 6"/>

  <line x1="910" y1="182" x2="976" y2="174" stroke="var(--ifm-color-primary)" stroke-width="2" marker-end="url(#arrowAccent)"/>
  <text x="945" y="164" text-anchor="middle" font-family="system-ui, sans-serif" font-size="11" font-weight="600" fill="var(--ifm-color-primary)">pass</text>

  <rect x="980" y="146" width="80" height="80" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-primary)" stroke-width="2"/>
  <text x="1020" y="181" text-anchor="middle" font-family="system-ui, sans-serif" font-size="13.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">GitHub</text>
  <text x="1020" y="198" text-anchor="middle" font-family="system-ui, sans-serif" font-size="11" fill="var(--ifm-color-emphasis-600)">org repo</text>

  <line x1="840" y1="246" x2="840" y2="316" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray)"/>
  <text x="850" y="285" font-family="system-ui, sans-serif" font-size="11" fill="var(--ifm-color-emphasis-600)">blocking issue</text>

  <rect x="770" y="320" width="140" height="50" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="840" y="350" text-anchor="middle" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">Blocked</text>

  <polyline points="770,345 720,345 720,330" fill="none" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" stroke-dasharray="5 5" marker-end="url(#arrowGray)"/>
  <text x="748" y="337" text-anchor="end" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">fix source</text>

  <line x1="580" y1="326" x2="580" y2="342" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" stroke-dasharray="4 4" marker-end="url(#arrowGray)"/>
  <rect x="490" y="346" width="180" height="45" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" stroke-dasharray="4 4"/>
  <text x="580" y="366" text-anchor="middle" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">Local LLM</text>
  <text x="580" y="381" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">deep-scan — optional</text>

  <polyline points="910,345 1020,345 1020,230" fill="none" stroke="var(--ifm-color-primary)" stroke-width="2" stroke-dasharray="5 5" marker-end="url(#arrowAccent)"/>
  <text x="965" y="338" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-primary)">justified, attributed override</text>
</svg>

<figcaption>Every path in (upload, <code>git push</code>, VS Code, or an MCP agent call) funnels through the same six local phases, plus an optional local LLM deep-scan, and the same gate. Nothing reaches GitHub without a pass or a justified, attributed override. Click any phase in the diagram to jump to its own detailed diagram on the <a href="what-gets-checked">What gets checked</a> page.</figcaption>

</figure>

## What

Ignite is a self-hosted compliance gate for code entering a GitHub org.
Point it at a project — a ZIP, a folder, a `git push`, or a call from an
MCP-connected coding agent — and it runs that project through a battery of
deterministic, purpose-built static analysis tools: a real SAST engine
(Semgrep) plus a **cross-file** SAST engine (CodeQL) for vulnerabilities
that span multiple files, CVE/GHSA lookups (deps.dev), IaC/container
scanners (Trivy, Checkov, hadolint) and known-CVE container-image scanning
(`trivy image`), a supply-chain malicious-dependency scanner (GuardDog),
malicious ML model artifact scanning (picklescan), API breaking-change
detection (oasdiff), a GitHub Actions workflow-security scanner (zizmor),
an AI package-hallucination ("slopsquat") check, secret scanning (regex +
gitleaks), image signature verification (cosign), PII data-flow tracing
(Bearer), API schema linting (Spectral), a compliance-posture engine, and
your org's own governance CI (`act`) —
entirely on your machine. A local LLM adds one *additional*, optional layer
for logic-level review; it is not what does the SAST or CVE detection
above. Every finding is exportable as
[SARIF](https://github.com/nunomcpereira/ignite#sarif-export) for GitHub
code scanning or any SARIF-speaking dashboard.

**Nothing gets provisioned or pushed to GitHub until every check passes —
or every blocking issue is explicitly justified and overridden**, with that
justification attributed, emailed, and logged to an audit trail. That's the
whole mechanism: one gate, the same standard, regardless of whether a human
clicked upload or an agent called an API.

:::tip[Not "just an LLM wrapper"]
Most of the checks above are static analysis by dedicated tools with no
model in the loop at all — the same category of tool a dedicated SAST/SCA
platform runs, wired into one pipeline with a single review gate. The LLM
deep-scan (off-able independently via `LLM_DEEP_SCAN_ENABLED`) is a
supplementary pass for the kind of logic-level reasoning pattern-matching
can't do, not a replacement for the static engines.
:::

## Why

AI just gave everyone — and everything — the ability to ship an app. It
didn't give everyone the ability to secure one.

Product managers, analysts, and non-engineers across your org can now build
real, working applications with an AI assistant — no CS background, no
security training, no idea what a hardcoded secret or an unbounded LLM call
costs downstream. Coding agents can go further: given a task and a `git
push`, they'll happily commit whatever gets the task done, with no concept
of "should this actually ship" unless something external stops them. Either
way, that code is already reaching your GitHub org.

The volume is the actual problem, on both fronts. Your AppSec team can
review a handful of PRs a week with real scrutiny. It cannot review the
avalanche of AI-generated projects that non-engineers can now produce on
their own, and it cannot sit in the loop for every commit an autonomous
agent makes either — the review bottleneck didn't scale when the
code-generation bottleneck disappeared, for people or for agents.

Ignite is the review layer for that gap: a gate that runs the scrutiny your
team can't scale to — automatically, on every project, before anything
reaches your org's GitHub — whether or not whoever (or whatever) wrote the
code knew to ask for it.

[View the full technical README on GitHub »](https://github.com/nunomcpereira/ignite#readme)

## White-label branding & multi-language UI

The web UI deploys as your own product, not a bolted-on vendor tool:

- **Branding** - product name, logo, support link, and accent color are a single config file (`public/branding.config.js`), never a hardcoded literal in the app itself, so a customer's brand and Ignite's own upstream updates never touch the same lines and never conflict.
- **Languages** - the console's UI chrome ships fully localized in **English, French, Portuguese, and German**, switchable from a picker in the header. (Server-generated content - findings, logs, phase titles - always stays in the language the backend sends it in.)

See the [README](https://github.com/nunomcpereira/ignite#white-label-branding--multi-language-ui) for the full configuration reference.

## Executive summary

For a board- or leadership-level view — why this gate exists, how it fits
next to GitHub Advanced Security, and what it costs to run — see the
one-page executive briefing:

📄 **[Executive summary (PDF)](/files/ignite-executive-briefing.pdf)**
