---
title: What gets checked
sidebar_position: 3
---

# What gets checked

Six phases, always run in the same order, always locally. Phases 1, 3, and
6 can't be turned off. Everything downstream depends on them. Phase 2 is
off by default (most projects aren't GxP-regulated). Fifteen+ optional
external-tool integrations live inside Phase 4 and Phase 5, all soft
dependencies, so Ignite runs (and falls back to a built-in check where one
exists) even with none of them installed.

## Phase 1: Input and metadata

<div className="phaseDiagram">

<svg viewBox="0 0 1000 112" role="img">
  <defs>
    <marker id="arrowGray2" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="var(--ifm-color-emphasis-500)"/>
    </marker>
  </defs>
  <rect x="20.0" y="20" width="213.0" height="68" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="126.5" y="49.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">ZIP / folder / git push</text>
  <text x="126.5" y="65.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">received</text>
  <rect x="269.0" y="20" width="213.0" height="68" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="375.5" y="43.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">Zip-slip guard</text>
  <text x="375.5" y="59.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">every archive entry must stay</text>
  <text x="375.5" y="73.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">inside the staging root</text>
  <line x1="233.0" y1="54.0" x2="265.0" y2="54.0" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray2)"/>
  <rect x="518.0" y="20" width="213.0" height="68" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="624.5" y="50.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">Zip-bomb guard</text>
  <text x="624.5" y="66.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">≤4GB extracted, ≤1GB upload</text>
  <line x1="482.0" y1="54.0" x2="514.0" y2="54.0" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray2)"/>
  <rect x="767.0" y="20" width="213.0" height="68" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="873.5" y="50.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">org/repo name validated</text>
  <text x="873.5" y="66.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">against GitHub naming rules</text>
  <line x1="731.0" y1="54.0" x2="763.0" y2="54.0" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray2)"/>
</svg>

</div>

Ignite extracts whatever comes in (a ZIP, a folder, a `git push`, a VS Code
scan, or an MCP `onboard_project` call) into a per-job staging directory,
under a zip-slip guard (every archive entry's resolved path must stay
inside the staging root; symlink entries are skipped, never followed) and a
zip-bomb guard (4GB extracted, 1GB upload caps). It validates the target
org/repo name against GitHub's own naming rules before using it in any
command.

## Phase 2: GxP docs (optional)

<div className="phaseDiagram">

<svg viewBox="0 0 1000 100" role="img">
  <defs>
    <marker id="arrowGray2" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="var(--ifm-color-emphasis-500)"/>
    </marker>
  </defs>
  <rect x="20.0" y="20" width="296.0" height="56" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="168.0" y="51.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">Staged project</text>
  <rect x="352.0" y="20" width="296.0" height="56" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="500.0" y="44.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">GxP Validation Documents</text>
  <text x="500.0" y="60.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">off by default — opt in per project</text>
  <line x1="316.0" y1="48.0" x2="348.0" y2="48.0" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray2)"/>
  <rect x="684.0" y="20" width="296.0" height="56" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="832.0" y="44.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">Mandatory docs archived to DB</text>
  <text x="832.0" y="60.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">for GxP-regulated processes</text>
  <line x1="648.0" y1="48.0" x2="680.0" y2="48.0" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray2)"/>
</svg>

</div>

Off by default, declared and checked only for projects that opt in. When
enabled, mandatory GxP validation documents are required and archived to
the database alongside the run.

## Phase 3: Structure, license and tests

<div className="phaseDiagram">

<svg viewBox="0 0 1000 100" role="img">
  <defs>
    <marker id="arrowGray2" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="var(--ifm-color-emphasis-500)"/>
    </marker>
  </defs>
  <rect x="20.0" y="20" width="296.0" height="56" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="168.0" y="44.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">Structure audit</text>
  <text x="168.0" y="60.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">deny raw .env* files anywhere in the tree</text>
  <rect x="352.0" y="20" width="296.0" height="56" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="500.0" y="44.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">License scan</text>
  <text x="500.0" y="60.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">ORT / licensee + deps.dev, green/amber/red</text>
  <line x1="316.0" y1="48.0" x2="348.0" y2="48.0" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray2)"/>
  <rect x="684.0" y="20" width="296.0" height="56" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="832.0" y="44.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">Native test suite</text>
  <text x="832.0" y="60.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">npm/go/cargo/pytest/mvn, in Docker</text>
  <line x1="648.0" y1="48.0" x2="680.0" y2="48.0" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray2)"/>
</svg>

</div>

Three checks run against the staged project: a structure audit that denies
any raw `.env`/`.env.*` file anywhere in the tree (unless already
`.gitignore`d); a license scan (ORT, or the built-in manifest parser +
deps.dev fallback) classifying every dependency green/amber/red and
scanning `LICENSE`/`LICENCE` files for commercial/proprietary language; and
the project's own test suite, auto-detected by ecosystem (Node/Go/Rust
/Python/Java) and run inside an isolated Docker container.

## Phase 4: Security and compliance scan

<div className="phaseDiagram">

<svg viewBox="0 0 1000 526" role="img">
  <text x="500.0" y="16" text-anchor="middle" font-family="system-ui, sans-serif" font-size="11" letter-spacing="1" fill="var(--ifm-color-emphasis-600)">STAGED PROJECT — ONE EXTERNAL TOOL PER AREA, RUN CONCURRENTLY</text>
  <line x1="15" y1="26" x2="985" y2="26" stroke="var(--ifm-color-emphasis-300)"/>
  <rect x="15.0" y="46.0" width="232.0" height="87" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="27.0" y="64.0" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">Secrets</text>
  <text x="27.0" y="83.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">Finds passwords, API keys, and</text>
  <text x="27.0" y="96.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">tokens left in code</text>
  <text x="27.0" y="113.0" font-family="system-ui, sans-serif" font-size="10" fill="var(--ifm-color-emphasis-500)">gitleaks</text>
  <rect x="261.0" y="46.0" width="232.0" height="87" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="273.0" y="64.0" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">Code bugs (SAST)</text>
  <text x="273.0" y="83.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">Scans code for common security</text>
  <text x="273.0" y="96.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">mistakes</text>
  <text x="273.0" y="113.0" font-family="system-ui, sans-serif" font-size="10" fill="var(--ifm-color-emphasis-500)">Semgrep</text>
  <rect x="507.0" y="46.0" width="232.0" height="87" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="519.0" y="64.0" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">Cross-file attacks</text>
  <text x="519.0" y="83.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">Traces attacks that span multiple</text>
  <text x="519.0" y="96.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">files</text>
  <text x="519.0" y="113.0" font-family="system-ui, sans-serif" font-size="10" fill="var(--ifm-color-emphasis-500)">CodeQL</text>
  <rect x="753.0" y="46.0" width="232.0" height="87" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="765.0" y="64.0" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">Component inventory</text>
  <text x="765.0" y="83.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">Lists every open-source package the</text>
  <text x="765.0" y="96.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">project uses</text>
  <text x="765.0" y="113.0" font-family="system-ui, sans-serif" font-size="10" fill="var(--ifm-color-emphasis-500)">Syft</text>
  <rect x="15.0" y="147.0" width="232.0" height="87" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="27.0" y="165.0" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">Cloud/container config</text>
  <text x="27.0" y="184.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">Flags insecure cloud and container</text>
  <text x="27.0" y="197.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">settings</text>
  <text x="27.0" y="214.0" font-family="system-ui, sans-serif" font-size="10" fill="var(--ifm-color-emphasis-500)">Trivy, Checkov, hadolint</text>
  <rect x="261.0" y="147.0" width="232.0" height="87" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="273.0" y="165.0" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">Container vulnerabilities</text>
  <text x="273.0" y="184.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">Scans the built container image for</text>
  <text x="273.0" y="197.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">known flaws</text>
  <text x="273.0" y="214.0" font-family="system-ui, sans-serif" font-size="10" fill="var(--ifm-color-emphasis-500)">trivy image</text>
  <rect x="507.0" y="147.0" width="232.0" height="87" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="519.0" y="165.0" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">Image tampering</text>
  <text x="519.0" y="184.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">Verifies a container image has not</text>
  <text x="519.0" y="197.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">been altered</text>
  <text x="519.0" y="214.0" font-family="system-ui, sans-serif" font-size="10" fill="var(--ifm-color-emphasis-500)">cosign</text>
  <rect x="753.0" y="147.0" width="232.0" height="87" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="765.0" y="165.0" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">Personal data handling</text>
  <text x="765.0" y="184.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">Flags personal data used without</text>
  <text x="765.0" y="197.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">proper controls</text>
  <text x="765.0" y="214.0" font-family="system-ui, sans-serif" font-size="10" fill="var(--ifm-color-emphasis-500)">Bearer</text>
  <rect x="15.0" y="248.0" width="232.0" height="87" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="27.0" y="266.0" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">API design</text>
  <text x="27.0" y="285.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">Checks API definitions follow house</text>
  <text x="27.0" y="298.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">conventions</text>
  <text x="27.0" y="315.0" font-family="system-ui, sans-serif" font-size="10" fill="var(--ifm-color-emphasis-500)">Spectral</text>
  <rect x="261.0" y="248.0" width="232.0" height="87" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="273.0" y="266.0" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">Malicious packages</text>
  <text x="273.0" y="285.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">Flags newly published malicious</text>
  <text x="273.0" y="298.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">dependencies</text>
  <text x="273.0" y="315.0" font-family="system-ui, sans-serif" font-size="10" fill="var(--ifm-color-emphasis-500)">GuardDog</text>
  <rect x="507.0" y="248.0" width="232.0" height="87" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="519.0" y="266.0" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">Missing safeguards</text>
  <text x="519.0" y="285.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">Flags missing security features like</text>
  <text x="519.0" y="298.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">SSO or audit logs</text>
  <text x="519.0" y="315.0" font-family="system-ui, sans-serif" font-size="10" fill="var(--ifm-color-emphasis-500)">Semgrep</text>
  <rect x="753.0" y="248.0" width="232.0" height="87" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="765.0" y="266.0" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">Risky dependencies</text>
  <text x="765.0" y="285.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">Flags risky licenses and known</text>
  <text x="765.0" y="298.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">vulnerable versions</text>
  <text x="765.0" y="315.0" font-family="system-ui, sans-serif" font-size="10" fill="var(--ifm-color-emphasis-500)">deps.dev</text>
  <line x1="15" y1="352" x2="985" y2="352" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="500" y="368" text-anchor="middle" font-family="system-ui, sans-serif" font-size="11" fill="var(--ifm-color-emphasis-600)">Findings merge into one issue list. A blocking one needs a source fix or a justified, attributed override.</text>
  <g transform="translate(0,376)">
  <rect x="15.0" y="15.0" width="478.0" height="74" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="27.0" y="33.0" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">Codebase-intelligence</text>
  <text x="27.0" y="52.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">Dead code, complexity, boundaries, unused CSS. Built in, no external tool</text>
  <rect x="507.0" y="15.0" width="478.0" height="74" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="519.0" y="33.0" font-family="system-ui, sans-serif" font-size="13" font-weight="600" fill="var(--ifm-color-emphasis-900)">Local LLM deep-scan</text>
  <text x="519.0" y="52.0" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-700)">Optional logic-level review, independent of the tools above</text>
  </g>
  <text x="985" y="504" text-anchor="end" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">Every tool above is a soft dependency. A missing one soft-skips or falls back; it never crashes the run.</text>
</svg>

</div>

The bulk of Ignite's static analysis lives here. Twelve tools, each
covering one area, run concurrently against the staged project (see [the
full tool table below](#threat-coverage) for exactly what each one catches
and what happens if it isn't installed). Two more checks run alongside them
with zero external tools: the four built-in [codebase-intelligence
checks](#codebase-intelligence-checks), and a local LLM deep-scan pass,
independently toggleable via `LLM_DEEP_SCAN_ENABLED`, for the logic-level
flaws a fixed rule set can miss (injection, path traversal, SSRF, insecure
deserialization, XSS, weak crypto). Every finding from every tool in this
phase merges into one issue list; a blocking one needs a source fix or a
justified, attributed override before the run can pass.

## Phase 5: Org governance CI

<div className="phaseDiagram">

<svg viewBox="0 0 1000 110" role="img">
  <defs>
    <marker id="arrowGray3" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="var(--ifm-color-emphasis-500)"/>
    </marker>
  </defs>

  <rect x="15" y="30" width="170" height="44" rx="6" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="100" y="48" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12" font-weight="600" fill="var(--ifm-color-emphasis-900)">GitHub</text>
  <text x="100" y="63" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">org's governance repo</text>

  <line x1="185" y1="52" x2="219" y2="52" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray3)"/>
  <text x="202" y="26" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10" fill="var(--ifm-color-emphasis-600)">gh api</text>

  <rect x="223" y="30" width="320" height="44" rx="6" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="383" y="56" text-anchor="middle" font-family="ui-monospace, monospace" font-size="11.5" fill="var(--ifm-color-emphasis-900)">ai-guardrails-orchestrator.yml</text>

  <line x1="543" y1="52" x2="577" y2="52" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray3)"/>
  <text x="560" y="26" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10" fill="var(--ifm-color-emphasis-600)">run via</text>

  <rect x="581" y="30" width="200" height="44" rx="6" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="681" y="48" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12" font-weight="600" fill="var(--ifm-color-emphasis-900)">act + Docker</text>
  <text x="681" y="63" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">runs locally, against the staged project</text>

  <line x1="781" y1="52" x2="815" y2="52" stroke="var(--ifm-color-primary)" stroke-width="1.5" marker-end="url(#arrowGray3)"/>

  <rect x="819" y="30" width="166" height="44" rx="6" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-primary)" stroke-width="1.5"/>
  <text x="902" y="48" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12" font-weight="600" fill="var(--ifm-color-emphasis-900)">Pass / fail</text>
  <text x="902" y="63" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">feeds the same gate</text>

  <text x="500" y="98" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">Same workflow, same pass/fail a real pull request would get — soft-skips with a warning if act/Docker aren't installed</text>
</svg>

</div>

Rather than reimplementing the central org's workflow logic, Ignite fetches
the real `ai-guardrails-orchestrator.yml` from the governance repo via
`gh api` and runs it locally with `act` against the staged project in
Docker, so local pass/fail matches exactly what a real pull request would
get. It soft-skips with a warning if `act`/Docker aren't available; the
workflows still gate remotely on GitHub either way.

## Phase 6: Provisioning and shipping

<div className="phaseDiagram">

<svg viewBox="0 0 1000 112" role="img">
  <defs>
    <marker id="arrowGray2" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="var(--ifm-color-emphasis-500)"/>
    </marker>
  </defs>
  <rect x="20.0" y="20" width="213.0" height="68" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="126.5" y="43.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">All phases passed</text>
  <text x="126.5" y="59.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">or every blocking issue justified</text>
  <text x="126.5" y="73.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10.5" fill="var(--ifm-color-emphasis-600)">&amp; overridden</text>
  <rect x="269.0" y="20" width="213.0" height="68" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="375.5" y="57.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">git init + commit</text>
  <line x1="233.0" y1="54.0" x2="265.0" y2="54.0" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray2)"/>
  <rect x="518.0" y="20" width="213.0" height="68" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="624.5" y="57.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">gh repo create --private</text>
  <line x1="482.0" y1="54.0" x2="514.0" y2="54.0" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray2)"/>
  <rect x="767.0" y="20" width="213.0" height="68" rx="8" fill="var(--ifm-color-emphasis-100)" stroke="var(--ifm-color-emphasis-300)"/>
  <text x="873.5" y="57.0" text-anchor="middle" font-family="system-ui, sans-serif" font-size="12.5" font-weight="600" fill="var(--ifm-color-emphasis-900)">push to main</text>
  <line x1="731.0" y1="54.0" x2="763.0" y2="54.0" stroke="var(--ifm-color-emphasis-500)" stroke-width="1.5" marker-end="url(#arrowGray2)"/>
</svg>

</div>

This phase only runs once every enabled phase above has passed, or every
blocking issue has been overridden with a justified, attributed, emailed
audit record. `git init` + commit, `gh repo create --private`, then push,
all using `execFile` with argument arrays (no shell), with org/repo names
already validated in Phase 1.

## Threat coverage

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
| Zip-bomb / disk-exhaustion DoS via a malicious or oversized upload | Extracted size capped at 4 GB, upload capped at 1 GB | Built-in size guards | N/A — built-in, no external tool involved |
| Command injection via org/repo names or shelled-out tool arguments | Every `git`/`gh`/tool invocation uses `execFile` with argument arrays (no shell); org/repo names validated against GitHub's naming rules; commands restricted to a fixed allowlist | Built-in sanitizers | N/A — built-in, no external tool involved |
| The project's own automated test suite silently regressing | Auto-detects Node/Go/Rust/Python/Java and runs that ecosystem's native test runner (`npm test`, `go test`, `cargo test`, `pytest`, `mvn test`) inside an isolated Docker container | Built-in detection + Docker | Skipped if no recognized test setup is found, or if Docker isn't available — logged, never silently assumed to pass |
| A repo drifting out of compliance *after* onboarding — a new vulnerable/malicious dependency merged later, with no one notified | Effectivated repos can opt into a scheduled (daily/weekly/monthly) re-check of the default branch; on failure, emails the repo's CODEOWNERS contact or files a GitHub issue if none can be resolved | Scheduled re-check + CODEOWNERS check | N/A for the schedule/notify logic itself — the re-check still depends on whichever Phase 4 tools are installed on the server at the time it runs |
| A `CODEOWNERS`-less repo silently having no one accountable for findings | Advisory check for a `CODEOWNERS` file and any email-address owner listed in it | Built-in CODEOWNERS check | N/A — built-in, no external tool involved |

Full details, install instructions, and the on/off default for every tool: see the [README's tool table](https://github.com/nunomcpereira/ignite#external-tools).

## Codebase-intelligence checks

Four more checks run inside Phase 4, alongside the external tools above,
but these are **zero-external-tool**, built entirely into Ignite. All four
are heuristic (regex/bracket-depth parsing over a lightweight import graph,
not a real type-checker or build system), so every finding is always
advisory (`severity: warning`). A human confirms before deleting or
restructuring; it's never a hard gate.

| Check | What it flags | Config / env |
|---|---|---|
| **Dead code / unused exports / unused deps** | Builds a module graph from `package.json`'s entry points, then flags any file never transitively imported (`unused-file`), any named export never imported anywhere by name (`unused-export`), and any dependency never required/imported and not mentioned in an npm script (`unused-dependency`) | On by default — `DEAD_CODE_ENABLED=false` to opt out |
| **Complexity / maintainability health** | Per-file cyclomatic and cognitive complexity, a calibrated Maintainability Index, and a CRAP score (pulls real test coverage from a project's own CI-submitted runtime coverage report when available, otherwise assumes 0%); also computes git-churn-weighted refactor hotspots (descriptive, not a finding) | On by default — `HEALTH_ENABLED=false` to opt out |
| **Architecture / import-boundary enforcement** | Flags an import that crosses a zone boundary you've defined (e.g. `features/billing` reaching into `features/auth`) | **Off by default** — a default zone layout on a project with no defined layout would be pure noise. Opt in with `ARCHITECTURE_BOUNDARIES_ENABLED=true` and a `preset` (`bulletproof` \| `layered` \| `hexagonal` \| `feature-sliced`) via `ARCHITECTURE_BOUNDARIES_PRESET`, or custom zones in `config.json` |
| **CSS/Tailwind dead-class scan** | Flags a `.css`/`.scss`/`.less` class selector never referenced in any scanned `class`/`className` attribute. One-directional only — can't flag unused Tailwind utilities, since those only exist if referenced in the first place | On by default — `CSS_DEAD_CODE_ENABLED=false` to opt out |

Dead-code findings (`unused-file`, `unused-dependency`, a subset of
`unused-export`) can be turned into a fix plan — and, optionally, applied —
via the auto-fix endpoint. `unused-export` findings that can't be safely
narrowed to an `export {}` list fall back to a `manual` action rather than
regex-deleting a function body with no real parser backing the edit.

## EU AI Act coverage

Three of the posture categories above (`ai-act-prohibited-practice`,
`ai-act-transparency-disclosure`, `ai-act-ai-logging`) plus a dedicated
process-document scan (risk-management docs, Annex IV technical docs, FRIA,
GPAI training-data summary, post-market monitoring plan) cover the
code-detectable slice of the EU AI Act — see
[EU AI Act coverage](/eu-ai-act) for the full breakdown.
