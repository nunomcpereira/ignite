---
theme: default
title: Ignite — Executive Security Briefing
info: |
  ## The compliance gate for code entering our GitHub organization.
  Executive security briefing regenerated from the board-briefing PDF.
transition: fade
mdc: true
css: unocss
colorSchema: light
canvasWidth: 1180
---

<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600;700&display=swap');

:root{
  --bg:#f8fafc; --surface:#ffffff; --border:#e2e8f0;
  --text:#0f172a; --muted:#475569; --faint:#94a3b8;
  --teal:#1d4ed8; --blue:#3b82f6; --indigo:#6366f1; --purple:#7c3aed; --amber:#b45309;
}
.slidev-layout{
  background:
    radial-gradient(ellipse 900px 500px at 12% -10%, color-mix(in srgb, var(--teal) 12%, transparent), transparent),
    radial-gradient(ellipse 700px 500px at 100% 0%, color-mix(in srgb, var(--indigo) 12%, transparent), transparent),
    var(--bg) !important;
  color: var(--text) !important;
  font-family:'Inter',ui-sans-serif,system-ui,sans-serif !important;
  padding: 56px 64px 46px !important;
  position: relative;
}
.mono{font-family:'JetBrains Mono',ui-monospace,monospace;}
.eyebrow{ font-size:11px; letter-spacing:.18em; color:var(--teal); margin-bottom:10px; text-transform:uppercase; }
.slidev-layout h1{ font-size:30px; line-height:1.18; margin:0 0 10px; font-weight:800; letter-spacing:-0.01em; color:var(--text); }
.slidev-layout h1 .accent{ color:var(--indigo); }
.lede{ font-size:14px; line-height:1.55; color:var(--muted); max-width:760px; margin:0 0 20px; }
.card{
  background: var(--surface);
  border:1px solid var(--border); border-radius:12px; padding:16px;
}
.badge{ font-size:10.5px; font-weight:500; color:var(--faint); }
.icon{
  width:34px; height:34px; border-radius:9px; display:flex; align-items:center; justify-content:center;
  font-size:16px; margin-bottom:10px; flex:none;
}
.footer{
  position:absolute; left:0; right:0; bottom:0;
  display:flex; justify-content:space-between; align-items:center;
  padding:11px 40px; font-size:9.5px; letter-spacing:.16em; color:var(--faint);
  border-top:1px solid var(--border); text-transform:uppercase;
}
.brandmark{ position:absolute; top:30px; left:36px; display:flex; align-items:center; gap:9px; }
.brandmark .glyph{
  width:32px; height:32px; border-radius:9px; display:flex; align-items:center; justify-content:center;
  background:linear-gradient(135deg,var(--teal),var(--blue)); color:#04140f; font-size:15px;
}
.brandmark span{ font-weight:700; letter-spacing:.14em; font-size:12px; }
.confpill{
  position:absolute; top:32px; right:36px; font-size:9.5px; letter-spacing:.14em;
  border:1px solid var(--border); border-radius:999px; padding:6px 13px; color:var(--muted);
}
.tag{ font-size:11px; font-weight:400; color:var(--faint); }
ul.plain{ margin:0; padding-left:16px; }
ul.plain li{ margin-bottom:7px; font-size:12.5px; color:var(--muted); line-height:1.45; }
</style>

<div class="brandmark"><div class="glyph">🛡</div><span>IGNITE</span></div>
<div class="confpill mono">🔒 CONFIDENTIAL — BOARD BRIEFING</div>
<div style="padding-top:78px;max-width:640px;">
  <div class="eyebrow mono">— Executive Security Briefing</div>
  <h1 style="font-size:34px;">The Compliance Gate for Code Entering<br><span class="accent">Our GitHub Organization</span></h1>
  <p class="lede" style="max-width:520px;">A unified, automated control point that stands between every uploaded project and production — enforcing secrets hygiene, secure-coding standards, supply-chain integrity, and AI-era risk controls before a single line ships.</p>
  <div style="display:flex;gap:40px;margin-top:22px;flex-wrap:wrap;">
    <div><div style="font-size:26px;font-weight:800;color:var(--teal);">20+</div><div class="mono" style="font-size:10px;letter-spacing:.14em;color:var(--faint);margin-top:3px;">INTEGRATED ENGINES</div></div>
    <div><div style="font-size:26px;font-weight:800;color:var(--teal);">6</div><div class="mono" style="font-size:10px;letter-spacing:.14em;color:var(--faint);margin-top:3px;">GATE PHASES</div></div>
    <div><div style="font-size:26px;font-weight:800;color:var(--teal);">0</div><div class="mono" style="font-size:10px;letter-spacing:.14em;color:var(--faint);margin-top:3px;">SILENT BYPASSES</div></div>
    <div style="display:flex;align-items:center;font-size:11.5px;color:var(--faint);">Prepared for Executive &amp; Board Review · FY26</div>
  </div>
</div>

---
layout: default
---

<div class="eyebrow mono">— 01 · Executive Summary</div>
<h1>Every new codebase is a new blast radius — until it passes the gate</h1>
<p class="lede">Code brought into our organization — by engineers, contractors, or increasingly by AI coding assistants — is the single largest source of unmanaged risk in the software supply chain. Ignite closes that gap with one automated, non-negotiable checkpoint applied to <b style="color:var(--text);">100% of onboarded projects</b>.</p>
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:6px;">
  <div class="card"><div class="icon" style="background:color-mix(in srgb, var(--teal) 20%, transparent);color:var(--teal);">🛡</div><div style="font-weight:700;font-size:13.5px;margin-bottom:5px;">Breach exposure, cut at the source</div><div style="font-size:12px;color:var(--muted);line-height:1.5;">Leaked credentials, vulnerable dependencies, and insecure patterns are caught before code ever reaches a repository a threat actor can reach.</div></div>
  <div class="card"><div class="icon" style="background:color-mix(in srgb, var(--indigo) 20%, transparent);color:var(--indigo);">📋</div><div style="font-weight:700;font-size:13.5px;margin-bottom:5px;">Audit-ready by default</div><div style="font-size:12px;color:var(--muted);line-height:1.5;">Every decision — pass, block, or human-justified override — is attributed, timestamped, and logged. Evidence for SOC 2, ISO 27001, and EU AI Act reviews is a byproduct, not a project.</div></div>
  <div class="card"><div class="icon" style="background:color-mix(in srgb, var(--amber) 20%, transparent);color:var(--amber);">⚡</div><div style="font-weight:700;font-size:13.5px;margin-bottom:5px;">Security that doesn't slow delivery</div><div style="font-size:12px;color:var(--muted);line-height:1.5;">Fully automated and parallelized — engineering teams get a pass/fail verdict in minutes, with a self-service fix loop instead of a ticket queue.</div></div>
</div>

<div class="footer"><span>IGNITE / EXECUTIVE BRIEFING</span><span class="mono">02 · CONFIDENTIAL</span></div>

---
layout: default
---

<div class="eyebrow mono">— 02 · How the Gate Works</div>
<h1>One pipeline, six gates, zero silent exceptions</h1>
<p class="lede">Every upload flows left to right through independent checkpoints. A single failed gate halts the run — nothing reaches GitHub without every phase clearing, or a justified, attributed override.</p>

<div style="position:relative;flex:1;margin-top:6px;height:380px;">
  <svg viewBox="0 0 1000 100" preserveAspectRatio="none" style="position:absolute;inset:0;width:100%;height:100%;">
    <defs>
      <linearGradient id="pipeGrad" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="var(--faint)"/>
        <stop offset="15%" stop-color="var(--teal)"/>
        <stop offset="35%" stop-color="var(--blue)"/>
        <stop offset="50%" stop-color="var(--indigo)"/>
        <stop offset="65%" stop-color="var(--purple)"/>
        <stop offset="80%" stop-color="var(--teal)"/>
        <stop offset="92%" stop-color="var(--blue)"/>
        <stop offset="100%" stop-color="var(--blue)"/>
      </linearGradient>
    </defs>
    <path d="M 40 66 C 135 66, 135 16, 190 16 C 245 16, 245 80, 340 80 C 395 80, 395 16, 490 16 C 555 16, 555 60, 640 60 C 705 60, 705 16, 800 16 C 850 16, 850 80, 910 80 C 935 80, 935 16, 970 16" fill="none" stroke="url(#pipeGrad)" stroke-width="0.6" opacity="0.55" vector-effect="non-scaling-stroke"/>
  </svg>

  <div style="position:absolute;left:4%;top:66%;transform:translate(-50%,-50%);text-align:center;width:126px;">
    <div style="width:50px;height:50px;margin:0 auto;border-radius:50%;border:2px solid var(--faint);background:var(--surface);display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 0 0 5px color-mix(in srgb, var(--faint) 10%, transparent);">📥</div>
    <div style="font-size:11.5px;font-weight:600;margin-top:7px;line-height:1.2;">Ingest</div>
    <div style="font-size:9.5px;color:var(--faint);margin-top:1px;">ZIP / folder</div>
  </div>

  <div style="position:absolute;left:19%;top:16%;transform:translate(-50%,-50%);text-align:center;width:126px;">
    <div class="mono" style="font-size:8.5px;font-weight:700;color:var(--teal);letter-spacing:.1em;margin-bottom:5px;">PHASE 1</div>
    <div style="width:50px;height:50px;margin:0 auto;border-radius:50%;border:2px solid var(--teal);background:var(--surface);display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 0 0 5px color-mix(in srgb, var(--teal) 10%, transparent);">📋</div>
    <div style="font-size:11.5px;font-weight:600;margin-top:7px;line-height:1.2;">Structure Audit</div>
  </div>

  <div style="position:absolute;left:34%;top:80%;transform:translate(-50%,-50%);text-align:center;width:126px;">
    <div class="mono" style="font-size:8.5px;font-weight:700;color:var(--blue);letter-spacing:.1em;margin-bottom:5px;">PHASE 2</div>
    <div style="width:50px;height:50px;margin:0 auto;border-radius:50%;border:2px solid var(--blue);background:var(--surface);display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 0 0 5px color-mix(in srgb, var(--blue) 10%, transparent);">🔑</div>
    <div style="font-size:11.5px;font-weight:600;margin-top:7px;line-height:1.2;">Secret Scan</div>
  </div>

  <div style="position:absolute;left:49%;top:16%;transform:translate(-50%,-50%);text-align:center;width:126px;">
    <div class="mono" style="font-size:8.5px;font-weight:700;color:var(--indigo);letter-spacing:.1em;margin-bottom:5px;">PHASE 3</div>
    <div style="width:50px;height:50px;margin:0 auto;border-radius:50%;border:2px solid var(--indigo);background:var(--surface);display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 0 0 5px color-mix(in srgb, var(--indigo) 10%, transparent);">🤖</div>
    <div style="font-size:11.5px;font-weight:600;margin-top:7px;line-height:1.2;">AI-Governance Audit</div>
  </div>

  <div style="position:absolute;left:64%;top:60%;transform:translate(-50%,-50%);width:210px;text-align:center;padding:12px 16px;border:1.5px dashed color-mix(in srgb, var(--purple) 55%, var(--border));background:color-mix(in srgb, var(--purple) 10%, var(--surface));border-radius:12px;">
    <div class="mono" style="font-size:10px;font-weight:700;color:var(--purple);">PHASE 4</div>
    <div style="font-size:13px;font-weight:700;margin-top:2px;">Deep-Scan Engine</div>
    <div style="font-size:9.5px;color:var(--faint);margin-top:2px;">20+ integrated tools, run concurrently</div>
  </div>

  <div style="position:absolute;left:80%;top:16%;transform:translate(-50%,-50%);text-align:center;width:126px;">
    <div class="mono" style="font-size:8.5px;font-weight:700;color:var(--teal);letter-spacing:.1em;margin-bottom:5px;">PHASE 5</div>
    <div style="width:50px;height:50px;margin:0 auto;border-radius:50%;border:2px solid var(--teal);background:var(--surface);display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 0 0 5px color-mix(in srgb, var(--teal) 10%, transparent);">🗂️</div>
    <div style="font-size:11.5px;font-weight:600;margin-top:7px;line-height:1.2;">Org Governance CI</div>
  </div>

  <div style="position:absolute;left:91%;top:80%;transform:translate(-50%,-50%);text-align:center;width:126px;">
    <div class="mono" style="font-size:8.5px;font-weight:700;color:var(--blue);letter-spacing:.1em;margin-bottom:5px;">PHASE 6</div>
    <div style="width:50px;height:50px;margin:0 auto;border-radius:50%;border:2px solid var(--blue);background:var(--surface);display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 0 0 5px color-mix(in srgb, var(--blue) 10%, transparent);">🧪</div>
    <div style="font-size:11.5px;font-weight:600;margin-top:7px;line-height:1.2;">Unit Tests</div>
  </div>

  <div style="position:absolute;left:97%;top:16%;transform:translate(-50%,-50%);text-align:center;width:126px;">
    <div style="width:50px;height:50px;margin:0 auto;border-radius:50%;border:2px solid var(--blue);background:var(--surface);display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 0 0 5px color-mix(in srgb, var(--blue) 10%, transparent);">🐙</div>
    <div style="font-size:11.5px;font-weight:600;margin-top:7px;line-height:1.2;">Provision &amp; Push</div>
    <div style="font-size:9.5px;color:var(--faint);margin-top:1px;">Private repo</div>
  </div>
</div>

<div class="footer"><span>IGNITE / EXECUTIVE BRIEFING</span><span class="mono">03 · CONFIDENTIAL</span></div>

---
layout: default
---

<div class="eyebrow mono">— 03 · Engine Detail</div>
<h1>Static analysis &amp; secret detection</h1>
<p class="lede">The first line of code-level defense — every one of these engines is a category leader, not an in-house heuristic.</p>
<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px;">
  <div class="card"><div style="font-weight:700;font-size:13px;">🔍 Semgrep <span class="tag mono">SEMGREP, INC.</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">OWASP-aligned static-analysis engine covering 30+ languages; the default SAST layer for security-mature engineering orgs and CI/CD pipelines industry-wide.</div></div>
  <div class="card"><div style="font-weight:700;font-size:13px;">🕸 CodeQL <span class="tag mono">GITHUB / MICROSOFT</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">Cross-file, cross-function taint-tracking engine powering GitHub Advanced Security — catches injection and IDOR chains single-file scanners miss entirely.</div></div>
  <div class="card"><div style="font-weight:700;font-size:13px;">👁 Bearer <span class="tag mono">BEARER.COM</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">Purpose-built PII / GDPR data-flow analysis — traces sensitive data from source to sink for privacy-risk and regulatory-exposure reporting.</div></div>
  <div class="card"><div style="font-weight:700;font-size:13px;">🔑 Gitleaks <span class="tag mono">OPEN-SOURCE STANDARD</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">The most widely deployed open-source secret scanner — entropy + regex detection before a commit ever leaves staging.</div></div>
</div>
<div class="card" style="margin-top:12px;border-color:color-mix(in srgb, var(--amber) 40%, var(--border));"><div style="font-weight:700;font-size:13px;">📄 Picklescan <span class="tag mono">AI-ERA ADDITION</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">Opcode-level scan of ML model artifacts (.pkl/.pt/.bin/.ckpt) for malicious deserialization payloads — a risk vector standard SAST tools were never built to see.</div></div>

<div class="footer"><span>IGNITE / EXECUTIVE BRIEFING</span><span class="mono">04 · CONFIDENTIAL</span></div>

---
layout: default
---

<div class="eyebrow mono">— 03 · Engine Detail</div>
<h1>Supply chain, container &amp; infrastructure security</h1>
<p class="lede">The tooling that closed the SolarWinds- and Log4j-class gap: what's inside the artifact, and can its origin be trusted.</p>
<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px;">
  <div class="card"><div style="font-weight:700;font-size:13px;">📦 Trivy <span class="tag mono">AQUA SECURITY / CNCF</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">The de-facto standard for container image, IaC misconfiguration, and dependency vulnerability scanning.</div></div>
  <div class="card"><div style="font-weight:700;font-size:13px;">🛡 Checkov <span class="tag mono">PALO ALTO NETWORKS</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">Policy-as-code IaC compliance across Terraform, CloudFormation, and Kubernetes manifests.</div></div>
  <div class="card"><div style="font-weight:700;font-size:13px;">🔏 Syft &amp; Cosign <span class="tag mono">SIGSTORE / LINUX FOUNDATION</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">CycloneDX SBOM generation plus Sigstore-backed signature verification for supply-chain integrity.</div></div>
  <div class="card"><div style="font-weight:700;font-size:13px;">🐶 GuardDog <span class="tag mono">DATADOG SECURITY RESEARCH</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">Heuristic inspection of npm/PyPI packages for malicious behavior before they're trusted.</div></div>
</div>
<div class="card" style="margin-top:12px;"><div style="font-weight:700;font-size:13px;">🐳 hadolint <span class="tag mono">OPEN-SOURCE STANDARD</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">Dockerfile best-practice linting — unpinned base images, missing non-root USER, caught pre-build.</div></div>

<div class="footer"><span>IGNITE / EXECUTIVE BRIEFING</span><span class="mono">05 · CONFIDENTIAL</span></div>

---
layout: default
---

<div class="eyebrow mono">— 03 · Engine Detail</div>
<h1>AI-era risk &amp; compliance governance</h1>
<p class="lede">Risk vectors that didn't exist five years ago — purpose-built for a world where a meaningful share of committed code is AI-generated or AI-assisted.</p>
<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px;">
  <div class="card"><div style="font-weight:700;font-size:13px;">🔀 Package-Hallucination Guard <span class="tag mono">IGNITE, BUILT-IN</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">Live registry checks against npm / PyPI / crates.io catch "slopsquatting" — an LLM-invented package name an attacker already registered.</div></div>
  <div class="card"><div style="font-weight:700;font-size:13px;">🔀 oasdiff <span class="tag mono">OPEN-SOURCE STANDARD</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">Diffs every API spec against its prior committed revision to catch breaking changes and shadow endpoints.</div></div>
  <div class="card"><div style="font-weight:700;font-size:13px;">📄 Spectral <span class="tag mono">STOPLIGHT</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">OpenAPI / AsyncAPI governance linting against organizational schema standards.</div></div>
  <div class="card"><div style="font-weight:700;font-size:13px;">⚖ Compliance &amp; Posture Engine <span class="tag mono">IGNITE, ON SEMGREP</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">Classifies SSO / RBAC / audit-logging / encryption posture, plus EU AI Act Art. 5, 12, 13 &amp; 50 signals.</div></div>
</div>
<div class="card" style="margin-top:12px;"><div style="font-weight:700;font-size:13px;">🕸 CodeQL Cross-File Analysis <span class="tag mono">GITHUB / MICROSOFT</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">The <code style="font-family:'JetBrains Mono',monospace;font-size:11px;">security-extended</code> query suite, applied whole-project — closing the gap when a tainted-data chain spans a controller, a service layer, and a template.</div></div>
<div class="card" style="margin-top:12px;"><div style="font-weight:700;font-size:13px;">⚙ zizmor <span class="tag mono">TRAIL OF BITS</span></div><div style="font-size:12px;color:var(--muted);margin-top:5px;line-height:1.5;">Audits every committed GitHub Actions workflow for pwn requests, script injection via untrusted <code style="font-family:'JetBrains Mono',monospace;font-size:11px;">${{ }}</code> expansions, and over-broad permissions — the CI-pipeline supply-chain risk a source-code scanner never sees.</div></div>

<div class="footer"><span>IGNITE / EXECUTIVE BRIEFING</span><span class="mono">06 · CONFIDENTIAL</span></div>

---
layout: default
---

<div class="eyebrow mono">— 04 · Why Not Just GitHub Advanced Security</div>
<h1>GHAS is one engine in the gate, not the gate itself</h1>
<p class="lede">GHAS is genuinely best-in-class for what it does — Ignite runs its CodeQL engine directly. The difference is scope and timing: GHAS secures a repo that already exists; Ignite decides whether the repo gets created at all.</p>

<div style="display:grid;grid-template-columns:1.35fr 1fr 1fr;border:1px solid var(--border);border-radius:10px;overflow:hidden;background:var(--surface);">
  <div style="display:contents;">
    <div class="mono" style="padding:8px 10px;font-size:9.5px;letter-spacing:.1em;color:var(--faint);background:color-mix(in srgb, var(--teal) 5%, var(--surface));">CHECK</div>
    <div class="mono" style="padding:8px 10px;font-size:9.5px;letter-spacing:.1em;color:var(--faint);background:color-mix(in srgb, var(--teal) 5%, var(--surface));">🐙 GHAS</div>
    <div class="mono" style="padding:8px 10px;font-size:9.5px;letter-spacing:.1em;color:var(--teal);background:color-mix(in srgb, var(--teal) 5%, var(--surface));">🛡 IGNITE</div>
  </div>
  <div style="display:contents;">
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:12px;font-weight:600;">Secret scanning</div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--teal);font-weight:700;">✓</span><span>Push protection + scanning</span></div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--teal);font-weight:700;">✓</span><span>Gitleaks + custom regex</span></div>
  </div>
  <div style="display:contents;">
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:12px;font-weight:600;">Static analysis (SAST)</div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--teal);font-weight:700;">✓</span><span>CodeQL only</span></div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--teal);font-weight:700;">✓</span><span>CodeQL + Semgrep + Bearer</span></div>
  </div>
  <div style="display:contents;">
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:12px;font-weight:600;">Dependency vulnerabilities</div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--teal);font-weight:700;">✓</span><span>Dependabot</span></div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--teal);font-weight:700;">✓</span><span>Trivy + SBOM diffing</span></div>
  </div>
  <div style="display:contents;">
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:12px;font-weight:600;">IaC &amp; container misconfig.</div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--faint);font-weight:700;">–</span><span>Not covered</span></div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--teal);font-weight:700;">✓</span><span>Trivy, Checkov, hadolint</span></div>
  </div>
  <div style="display:contents;">
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:12px;font-weight:600;">SBOM &amp; signature verification</div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--amber);font-weight:700;">◐</span><span>Dependency graph only</span></div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--teal);font-weight:700;">✓</span><span>Syft SBOM + Cosign signing</span></div>
  </div>
  <div style="display:contents;">
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:12px;font-weight:600;">PII / GDPR data-flow analysis</div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--faint);font-weight:700;">–</span><span>Not covered</span></div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--teal);font-weight:700;">✓</span><span>Bearer</span></div>
  </div>
  <div style="display:contents;">
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:12px;font-weight:600;">AI package-hallucination check</div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--faint);font-weight:700;">–</span><span>Not covered</span></div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--teal);font-weight:700;">✓</span><span>Package-Hallucination Guard</span></div>
  </div>
  <div style="display:contents;">
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:12px;font-weight:600;">Pre-push blocking gate</div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--faint);font-weight:700;">–</span><span>PR annotation only</span></div>
    <div style="padding:7px 10px;border-top:1px solid var(--border);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:7px;"><span style="color:var(--teal);font-weight:700;">✓</span><span>Blocks provisioning until fixed/overridden</span></div>
  </div>
</div>
<p style="font-size:10.5px;color:var(--faint);text-align:center;margin-top:8px;">Not a replacement for GHAS where it's already licensed — Ignite folds it in as one of twenty-plus engines behind a single go/no-go gate.</p>

<div class="footer"><span>IGNITE / EXECUTIVE BRIEFING</span><span class="mono">07 · CONFIDENTIAL</span></div>

---
layout: default
---

<div class="eyebrow mono">— 05 · Summary &amp; Recommendation</div>
<h1>Best-in-class tooling, applied consistently, with a paper trail</h1>
<p class="lede">No engine in this stack is an unproven internal script — each is either the recognized leader in its category, or a purpose-built Ignite control for a risk class those vendors don't yet cover. The value isn't any single scanner; it's that all of them run <b style="color:var(--text);">every time, on every project, with no exceptions that aren't logged.</b></p>
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:14px;">
  <div class="card"><div style="font-size:17px;margin-bottom:6px;">📈</div><div style="font-weight:700;font-size:13px;margin-bottom:4px;">Consistent enforcement</div><div style="font-size:12px;color:var(--muted);line-height:1.5;">One gate, zero exceptions for who's uploading — engineer, contractor, or agent.</div></div>
  <div class="card"><div style="font-size:17px;margin-bottom:6px;">📋</div><div style="font-weight:700;font-size:13px;margin-bottom:4px;">Regulator-ready evidence</div><div style="font-size:12px;color:var(--muted);line-height:1.5;">Attributed overrides and full scan history, on demand — no scramble before an audit.</div></div>
  <div class="card"><div style="font-size:17px;margin-bottom:6px;">🧑</div><div style="font-weight:700;font-size:13px;margin-bottom:4px;">Board-level assurance</div><div style="font-size:12px;color:var(--muted);line-height:1.5;">A single control the executive team can point to, backed by industry-standard tooling.</div></div>
</div>
<div class="card" style="margin-top:14px;border-color:color-mix(in srgb, var(--teal) 40%, var(--border));display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;">
  <div style="display:flex;align-items:center;gap:10px;"><span style="font-size:18px;">🛡</span><span style="font-size:12.5px;color:var(--muted);">Recommendation: keep Ignite as the single mandatory onboarding gate; expand override-review cadence to quarterly board visibility.</span></div>
  <div class="mono" style="font-size:9.5px;letter-spacing:.14em;color:var(--faint);white-space:nowrap;">END OF BRIEFING</div>
</div>

<div class="footer"><span>IGNITE / EXECUTIVE BRIEFING</span><span class="mono">08 · CONFIDENTIAL</span></div>
