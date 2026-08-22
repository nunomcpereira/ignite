'use strict';

/**
 * Ignite configuration — config.json < environment variables.
 *
 * Extracted from server.js (Phase A of the module split — see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md): a pure function, no
 * shared mutable state, so it's safe to require() directly. server.js still
 * owns calling loadConfig() and holding the resulting CONFIG singleton at
 * its own top level (re-computed fresh on every re-require, which is what
 * test/helpers.js's withServerEnv relies on for per-test env isolation).
 */

const fs = require('fs');
const path = require('path');

function loadConfig() {
  const defaults = {
    port: 51337,
    // deepScanEnabled gates only Phase 4's automated LLM deep-scan (Check
    // 3, checkLlmDeepScan) — the on-demand "Explain issue"/"Suggest AI fix"
    // calls in Ignite Studio (explainIssueForHuman/suggestFixForIssue) share
    // the same LLM connection but aren't gated by this flag, so they keep
    // working even with automated deep-scanning turned off.
    llm: { url: 'http://localhost:8050', model: 'default', mode: 'warn', maxFiles: 40, chunkChars: 10_000, deepScanEnabled: true },
    github: {
      orgs: '',
      bootstrapBranch: 'ignite',
      // 'https' (default) pushes over an https://github.com/... remote,
      // authenticated via `gh auth git-credential` using the connected
      // user's GH_TOKEN. 'ssh' pushes over git@github.com:... instead,
      // authenticated by whatever SSH key/agent is already configured for
      // github.com on this machine — no git credential helper involved.
      // Either way, repo creation/auto-merge/ref-creation still go through
      // the GitHub REST API (`gh api`) with GH_TOKEN — SSH keys authenticate
      // git's transport, not the GitHub API, so a connected account is
      // still required in both modes.
      remoteProtocol: 'https', // 'https' | 'ssh' — env: GITHUB_REMOTE_PROTOCOL
      oauth: { clientId: '', clientSecret: '', redirectUri: '', scope: 'repo' },
    },
    governance: {
      repo: 'ai-governance-poc-2026/devops-governance',
      workflow: 'ai-guardrails-orchestrator.yml',
      event: 'pull_request',
      timeoutMinutes: 30,
    },
    notifications: {
      enabled: false,
      to: '',
      from: 'Ignite Gatekeeper <ignite@localhost>',
      smtp: { host: '', port: 587, secure: false, user: '' },
    },
    auth: {
      mode: 'standalone', // 'standalone' | 'oidc' | 'github'
      allowSelfRegistration: true,
      oidc: { issuer: '', clientId: '', clientSecret: '', redirectUri: '', scope: 'openid email profile' },
    },
    security: {
      // Optional: augments the built-in regex secret scan with gitleaks
      // (https://github.com/gitleaks/gitleaks) when installed. Soft-fails
      // (falls back to regex-only results) if disabled or the binary is
      // missing, so this is safe to leave off in environments without it.
      gitleaks: { enabled: false, binary: 'gitleaks', configPath: '' },
      // Opt-in, project-declared regex patterns for secret VALUES that are
      // public by design (e.g. a Firebase Web apiKey — access is controlled
      // by Firebase Security Rules/App Check, not by hiding the key; same
      // pattern for Algolia search-only keys, Sentry DSNs, etc.). Deliberately
      // NOT a blanket allowlist by finding *kind* (a "gcp-api-key" match can
      // just as easily be a real server-side key that must stay secret) —
      // matched against the exact flagged value, and only after the project
      // opts in, so this can't silently start hiding real leaks. Empty by
      // default.
      secrets: { knownPublicKeyPatterns: [] },
      // Opt-in, project-declared paths (gitignore-style glob patterns) to
      // exclude wholesale from iac-security/container-image-cve findings —
      // e.g. a retired .devcontainer/ that nothing actually deploys from.
      // Scoped to just those two categories (not every Phase 4 check):
      // they're the ones that flag a whole scaffold/image rather than a
      // specific line, so a "not a runtime, don't chase these" project
      // decision is a path-level call, not a per-finding one. Empty by
      // default.
      excludePaths: [],
      // Optional: IaC/container misconfiguration scan (Dockerfiles,
      // Terraform, Kubernetes manifests, Helm charts) via Trivy's config
      // scanner (https://github.com/aquasecurity/trivy). Unlike gitleaks,
      // this is on by default — there's no equivalent built-in check to
      // "supplement", so Trivy is the primary source of IaC findings when
      // present. Soft-fails to a small built-in Dockerfile heuristic scan
      // (unpinned base image tag, missing USER) when disabled or missing.
      trivy: { enabled: true, binary: 'trivy' },
      // Optional: supplements trivy's IaC misconfig scan with Checkov's
      // (https://www.checkov.io/) much larger policy set — same relationship
      // gitleaks has to the regex secret scan, merged in and deduped by
      // file/line rather than replacing trivy's findings. On by default —
      // a heavier (Python) dependency than trivy/hadolint, but still a
      // soft-skip (no findings, not a failure) if it isn't installed.
      checkov: { enabled: true, binary: 'checkov' },
      // Optional: supplements trivy/checkov with hadolint's Dockerfile-only
      // rule set (https://github.com/hadolint/hadolint) — a small, fast
      // native binary, so on by default like trivy.
      hadolint: { enabled: true, binary: 'hadolint' },
      // Optional: verifies Sigstore/cosign keyless signatures on every
      // external base image referenced by a Dockerfile FROM (supply-chain
      // provenance), via `cosign verify` (https://github.com/sigstore/cosign).
      // On by default. Note this makes a real network call (registry +
      // Rekor transparency log) per unique image, adding latency and an
      // external-service dependency to every run that references one — set
      // COSIGN_ENABLED=false to opt back out if that's undesirable in your
      // environment. An unsigned/unverifiable image is reported as a
      // warning, never a blocking error — plenty of legitimate base images
      // (e.g. plain `ubuntu`) aren't cosign-signed.
      // cacheTtlSeconds: unlike GuardDog's manifest cache (permanent — an
      // npm/PyPI package version's published content never changes), a
      // Docker image *tag* is a mutable reference that can be re-pushed to
      // point at different content at any time, so a cosign verdict is
      // only safe to reuse for a bounded window, not forever. Default 1h —
      // long enough to make repeated runs in one working session (CI
      // re-triggers, iterative local pushes) fast, short enough to bound
      // how stale a signature verdict can get. 0 disables caching entirely.
      cosign: {
        enabled: true, binary: 'cosign', identityRegexp: '.*', issuerRegexp: '.*', cacheTtlSeconds: 3600,
      },
      // Optional: semantic pattern-matching SAST via Semgrep OSS
      // (https://semgrep.dev) — logical flaws and injection-style sinks
      // beyond what the LLM deep-scan (Phase 4's other security check)
      // covers on its own. `config` is a comma-separated list of semgrep
      // --config values (registry packs like "p/security-audit"/
      // "p/owasp-top-ten", "auto", or a local rule file/dir path) — each
      // gets passed as its own --config flag, so combining packs widens
      // rule coverage rather than replacing one pack with another.
      // p/owasp-top-ten is included alongside p/security-audit by default
      // for explicit OWASP Top 10 category coverage on top of
      // security-audit's broader (and overlapping) rule set.
      // IMPORTANT LIMITATION: Semgrep OSS's pattern/taint engine is
      // intraprocedural (single-file) — it cannot trace taint across
      // function/file boundaries the way Semgrep Pro or CodeQL can. A
      // vulnerability where untrusted input crosses multiple files before
      // reaching a sink (e.g. a stored-XSS or IDOR chain spanning a
      // controller, a service layer, and a template) will not reliably be
      // caught by this check — that gap is covered only by the LLM
      // deep-scan's best-effort read of the actual data flow, which is
      // probabilistic and capped at `llm.maxFiles` files per run, not a
      // deterministic guarantee. Real cross-file taint analysis needs a
      // paid Semgrep Pro subscription or a CodeQL setup — see
      // security.codeql below, which is exactly that gap-filler.
      semgrep: { enabled: true, binary: 'semgrep', config: 'p/security-audit,p/owasp-top-ten' },
      // Optional: sensitive data-flow (PII/GDPR) tracking via Bearer CLI
      // (https://github.com/Bearer/bearer) — traces personal data from
      // source (request params, user objects) to sinks (logs, DB writes,
      // 3rd-party calls) rather than pattern-matching single lines like
      // semgrep. On by default. Needs real git context (it shells out to
      // git for its own bookkeeping) — server.js's ensureGitContextForBearer
      // bootstraps a throwaway one for a fresh ZIP/folder upload
      // automatically, so this isn't something you need to set up.
      bearer: { enabled: true, binary: 'bearer' },
      // Optional: malicious-dependency heuristic scan via Datadog's GuardDog
      // (https://github.com/DataDog/guarddog) — Semgrep-based rules that
      // catch supply-chain-attack patterns (install-script exfiltration,
      // obfuscated payloads, silent network calls) in npm/PyPI dependencies,
      // independent of whether a CVE/GHSA advisory has been published yet
      // (scanDependencyVulnerabilities above only catches already-known
      // vulnerabilities). On by default — unlike the mostly-static tools
      // above, GuardDog downloads and inspects every manifest dependency's
      // actual package contents from the registry, which is slower and
      // heavier than the rest of Phase 4; set GUARDDOG_ENABLED=false to opt
      // out in environments with many manifest dependencies. No built-in
      // fallback: this heuristic can't be meaningfully approximated without
      // the real tool.
      guarddog: { enabled: true, binary: 'guarddog' },
      // Optional: cross-file static analysis via the CodeQL CLI
      // (https://github.com/github/codeql-cli-binaries) — the gap
      // security.semgrep's comment above documents: Semgrep OSS's engine is
      // intraprocedural, so a vulnerability whose tainted data crosses
      // file/function boundaries before reaching a sink isn't reliably
      // caught by anything else in Phase 4. A CodeQL database build is
      // whole-project and can take minutes per language in isolation, but
      // measured for real against Ignite's own codebase it added only
      // ~3 seconds to Phase 4's total wall time — Phase 4 runs every check
      // concurrently, and CodeQL's build finishes well inside whichever
      // other tool is already the long pole (typically Bearer). On by
      // default as of that measurement, same as the always-on tools above
      // — runs on every push, not a separate opt-in "deep scan" path (one
      // existed, routes/pipeline-deep-scan.js, removed once the numbers
      // showed the split wasn't earning its complexity). Set
      // CODEQL_ENABLED=false to opt back out — e.g. if Bearer/Semgrep/
      // GuardDog are disabled or fast enough on your codebase that
      // CodeQL's own cost would actually become visible. `languages`
      // limits which of CodeQL's query suites actually run (JS/TS, Python,
      // Java, Go ship by default here); `querySuites` maps each language
      // to a CodeQL query pack (security-extended by default — broad
      // taint-tracking + security-and-quality coverage); `threads`/`ramMB`
      // are passed straight to `codeql database create`/`analyze` (0 = let
      // CodeQL pick its own default). No built-in fallback: cross-file
      // taint analysis has no meaningful heuristic substitute.
      codeql: {
        enabled: true,
        binary: 'codeql',
        languages: ['javascript', 'python', 'java', 'go'],
        querySuites: {
          javascript: 'codeql/javascript-queries:codeql-suites/javascript-security-extended.qls',
          python: 'codeql/python-queries:codeql-suites/python-security-extended.qls',
          java: 'codeql/java-queries:codeql-suites/java-security-extended.qls',
          go: 'codeql/go-queries:codeql-suites/go-security-extended.qls',
        },
        threads: 0,
        ramMB: 0,
        timeoutMs: 20 * 60_000,
      },
      // Optional: OWASP A05/A06 gap — `trivy config` (above) only lints the
      // *Dockerfile source* for misconfiguration; it never looks at what's
      // actually inside the image a Dockerfile builds, so a base image with
      // known-vulnerable OS packages baked in (e.g. an unpatched apt/apk
      // package with a real CVE) sails through untouched. This builds every
      // discovered Dockerfile with `docker build` and runs `trivy image`
      // against the result to catch that gap. Off by default — unlike the
      // rest of Phase 4, this needs a real image build (network pulls,
      // build time), the heaviest single check in the pipeline — enable
      // with TRIVY_IMAGE_ENABLED=true once you've accepted that cost. No
      // built-in fallback: image-content vulnerability scanning needs the
      // real tool. Reuses security.trivy's binary (same trivy CLI, `image`
      // subcommand instead of `config`) — no separate binary setting.
      // severityThreshold filters trivy's own CVE severities.
      trivyImage: { enabled: false, severityThreshold: 'HIGH,CRITICAL', buildTimeoutMs: 8 * 60_000 },
    },
    compliance: {
      // Optional: Compliance & Feature Posture Engine — scans for the
      // *presence* of security/compliance features (SSO, RBAC, audit
      // logging, TLS, backups, encryption at rest, rate limiting), not
      // vulnerabilities. Fully conditioned on Semgrep's presence (shares
      // security.semgrep's binary/tooling probe — same CLI, a separate
      // ruleset and enable flag): runs `semgrep --config=<ruleset>`
      // against ignite-posture-rules.yaml when connected, and soft-falls
      // back to a built-in regex pattern matcher (same category/tier
      // model, narrower coverage) when Semgrep is disabled or missing —
      // this scan never fails a run or blocks the pipeline either way.
      posture: { enabled: true, ruleset: path.join(__dirname, 'ignite-posture-rules.yaml') },
      // Optional: EU AI Act document-presence scan (see
      // checks/compliance-documents.js) — flags whether a risk-management
      // system doc, Annex IV technical documentation, an FRIA, a GPAI
      // training-data summary, or a post-market monitoring plan exists
      // anywhere in the repo by filename/path pattern.
      euAiActDocuments: { enabled: true },
      // Whether the EU AI Act signals above — the three ai-act-* posture
      // categories (ignite-posture-rules.yaml) plus checkComplianceDocuments'
      // MISSING document categories — surface as addressable, overridable
      // issues (collectPhase4Issues) or stay purely advisory context in
      // posture-report.json/ai-act-documents-report.json. false by default:
      // these are heuristic (regex/filename matching, no legal judgment),
      // so promoting them to findings is an explicit opt-in. Always
      // severity: 'warning' when on — heuristic AI Act signals never block
      // a run outright, only a human-reviewable override.
      euAiAct: { reportAsFindings: false },
    },
    sbom: {
      // Optional: generates a CycloneDX SBOM for the staged project via
      // Syft (https://github.com/anchore/syft), attached as a downloadable
      // project document. On by default — Syft is a fast, self-contained
      // native binary. Soft-fails to a minimal manifest-derived component
      // list (name/version pairs from package.json/requirements.txt/etc,
      // no dependency graph or standards-format export) when missing, so a
      // run is never blocked on it.
      syft: { enabled: true, binary: 'syft' },
    },
    metrics: {
      // Optional: code-duplication detection via jscpd
      // (https://github.com/kucherenko/jscpd) — flagged clones become
      // 'code-duplication' issues (quality-level, always a warning, never
      // blocking). Off by default. No built-in fallback: duplicate-block
      // detection needs the real tool, so this simply contributes nothing
      // when disabled/missing.
      // minLines/minTokens (jscpd's own defaults) are now passed to the
      // CLI explicitly rather than left implicit, and checkCodeDuplication
      // additionally drops any reported clone shorter than minLines or
      // whose duplicated span is pure punctuation (stray closing
      // brackets/braces) — jscpd's per-clone `lines` count can otherwise
      // undercount a dense, bracket-heavy line that clears minTokens while
      // spanning ~1 real line, surfacing single-line/bracket-only
      // "duplicates" that aren't a meaningful block.
      // ignorePatterns (jscpd's own --ignore glob syntax) excludes three
      // categories that duplication-scan real runs consistently surface as
      // noise, not maintenance risk: (1) generated/design-export content —
      // e.g. Stitch/Figma-to-code static mockups under docs/** — which are
      // independently exported snapshots never meant to share a component
      // tree, so "dedupe this" has no actionable target; (2) test files,
      // where fixture/setup duplication across suites is standard practice
      // (keeps suites independent) rather than logic that could drift;
      // (3) package-manager lockfiles, which are machine-written and never
      // hand-edited — their "duplication" is just the same resolved
      // dependency/platform-binary metadata mirrored across entries, an
      // artifact of how lockfiles work, not a code smell with an
      // actionable fix. Override per-project via JSCPD_IGNORE
      // (comma-separated globs) if a repo's docs/tests genuinely do
      // contain shippable, dedupe-worthy code.
      jscpd: {
        enabled: false, binary: 'jscpd', minLines: 5, minTokens: 50,
        ignorePatterns: [
          'docs/**', '**/*.test.*', '**/*.spec.*', '**/__tests__/**',
          '**/package-lock.json', '**/yarn.lock', '**/pnpm-lock.yaml',
          '**/Gemfile.lock', '**/poetry.lock', '**/Cargo.lock', '**/go.sum',
          '**/composer.lock',
        ],
      },
      // Optional: precise per-language LOC counts via gocloc
      // (https://github.com/hhatto/gocloc) — purely descriptive, attached
      // as a downloadable project document (same as the SBOM), never
      // produces issues. On by default.
      gocloc: { enabled: true, binary: 'gocloc' },
      // Built-in (no external tool, always available): flags a single
      // source file exceeding maxLines as a "low encapsulation" advisory
      // finding — one file doing too much is a maintainability smell
      // (harder to review, harder to test in isolation) independent of
      // any one language's own conventions, and — concretely, discovered
      // while investigating Ignite's own pipeline performance — a real
      // cost multiplier for per-file-cached SAST tools (Bearer): a
      // monolithic file invalidates its own cache entry on nearly every
      // commit, dragging down what would otherwise be an incremental
      // scan. On by default — cheap (a line count per file), no process
      // spawned. Always advisory (warning), never blocks a run: file size
      // alone is a smell to flag and track, not a hard gate a team should
      // be forced through mid-pipeline.
      fileSize: { enabled: true, maxLines: 1000 },
    },
    api: {
      // Optional: lints OpenAPI/AsyncAPI schema files against Spectral's
      // built-in rulesets (https://github.com/stoplightio/spectral) — org
      // REST/AsyncAPI conventions, not just schema validity. `ruleset` is
      // any spectral --ruleset path/URL; defaults to a small bundled file
      // (spectral-default-ruleset.yaml) extending spectral:oas +
      // spectral:asyncapi. On by default. No built-in fallback: schema
      // linting needs the real rule engine, so this simply contributes
      // nothing when disabled/missing, or when no matching files exist.
      spectral: { enabled: true, binary: 'spectral', ruleset: path.join(__dirname, 'spectral-default-ruleset.yaml') },
    },
    // Built-in JS/TS codebase-intelligence checks (dead code, complexity/
    // health, architecture boundaries, CSS dead-class scan) — closes the
    // gap set against fallow.tools (see project memory). No external
    // tool/install for any of these; each soft-skips to nothing when its
    // own `enabled` is false. Findings feed the same issue/override model
    // as every other Phase 4 check (see server.js's runPhase4Checks and
    // override-engine.js's collectPhase4Issues) and are always advisory
    // (`severity: 'warning'`) — heuristic, regex/AST-lite analysis without
    // a full type-checker or build graph can produce false positives (see
    // each check module's own doc comment for specifics), so a human
    // confirms before deleting, never a hard gate.
    codeIntelligence: {
      // Dead-code / unused-export / unused-dependency scan
      // (checks/dead-code.js). Upgrades to AST-based export confirmation
      // automatically when the *scanned project* has `typescript` in its
      // own node_modules — no Ignite-side dependency needed either way.
      deadCode: { enabled: true },
      // Complexity/maintainability health scan (checks/complexity-
      // health.js): cyclomatic/cognitive complexity, Maintainability
      // Index, CRAP score, git-churn-weighted hotspots.
      health: {
        enabled: true,
        cyclomaticWarnThreshold: 20, // the classic "hard to test exhaustively" line
        complexityDensityWarnThreshold: 0.3, // decision points per line of code; normalizes the (whole-file, not per-function) complexity total for file size
        maintainabilityWarnThreshold: 40,
        topHotspots: 10,
      },
      // CSS/Tailwind dead-class scan (checks/css-dead-code.js): declared-
      // but-never-referenced CSS classes across the project's markup.
      cssDeadCode: { enabled: true },
    },
    // Architecture/import-boundary enforcement (checks/boundaries.js) —
    // off by default (unlike codeIntelligence above): a wrong/default zone
    // layout on a project that doesn't follow one of the four presets
    // (bulletproof/layered/hexagonal/feature-sliced — same as
    // fallow.tools ships) would be pure noise, so this only activates on
    // explicit project opt-in via `preset` and/or custom `zones`.
    architecture: {
      boundaries: { enabled: false, preset: '', zones: [] },
    },
    // Optional per-phase title/description/enabled overrides, e.g.:
    //   "phases": [{ "id": 4, "enabled": false }]
    // Matched by id; any phase not listed (or the whole key omitted) keeps
    // its built-in title/description/enabled state exactly as shipped.
    // Phases 1 (input validation), 3 (extraction/structure audit) and 6
    // (provisioning/shipping) can't be disabled — everything downstream
    // depends on them — so an `enabled: false` override on those ids is
    // ignored. Phase 2 (GxP) defaults to disabled: most orgs onboarding
    // through Ignite aren't running a GxP-regulated process, so the
    // declaration + mandatory validation-document UI stays hidden, and the
    // phase itself is never checked, until explicitly turned on.
    phases: [],
    mcp: {
      // Auto-starts mcp-server.js (Streamable HTTP transport) as a child
      // process alongside this one, so MCP clients that want HTTP (rather
      // than spawning their own stdio instance per the editor's own
      // .mcp.json) have somewhere to connect without a separate manual
      // step. Purely additive — stdio-mode MCP (the editor spawning
      // mcp-server.js itself) works exactly as before regardless of this.
      autoStart: true,
      httpPort: 51338,
    },
  };
  // Same override convention as IGNITE_DB_PATH — lets the test suite (see
  // test/helpers.js's withServerEnv) point at an empty fixture file instead
  // of this developer's real, locally-customized config.json, so tests
  // asserting on *default* values stay hermetic regardless of what's
  // actually configured on this machine.
  const configPath = process.env.IGNITE_CONFIG_PATH || path.join(__dirname, 'config.json');
  let fileConfig = {};
  try {
    fileConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } catch (err) {
    if (err.code !== 'ENOENT') {
      console.error(`${configPath} is invalid (${err.message}) — using defaults.`);
    }
  }
  const merge = (base, over) =>
    Object.fromEntries(
      Object.keys(base).map((k) => [
        k,
        over?.[k] !== undefined && typeof base[k] === 'object' && base[k] !== null
          ? merge(base[k], over[k])
          : over?.[k] !== undefined ? over[k] : base[k],
      ])
    );
  const merged = merge(defaults, fileConfig);
  // `merge` deep-merges plain objects keyed by the *default's* own keys —
  // useless for an empty-by-default array like `phases`, since there are no
  // default keys to walk. Arrays are a replace, not a merge.
  merged.phases = Array.isArray(fileConfig.phases) ? fileConfig.phases : [];
  // Same array-vs-plain-object merge gap as `phases` above — the default
  // `[]` recurses through `merge` as an empty object instead of being
  // replaced, so this needs the same explicit override.
  merged.security.secrets.knownPublicKeyPatterns =
    Array.isArray(fileConfig?.security?.secrets?.knownPublicKeyPatterns)
      ? fileConfig.security.secrets.knownPublicKeyPatterns
      : [];
  merged.security.excludePaths =
    Array.isArray(fileConfig?.security?.excludePaths) ? fileConfig.security.excludePaths : [];
  const smtpPass =
    process.env.NOTIFICATIONS_SMTP_PASS ||
    process.env.SMTP_PASS ||
    process.env.SMTP_PASSWORD ||
    '';
  if (smtpPass) {
    merged.notifications.smtp.pass = smtpPass;
  }
  if (process.env.AUTH_MODE) merged.auth.mode = process.env.AUTH_MODE;
  if (process.env.OIDC_CLIENT_SECRET) merged.auth.oidc.clientSecret = process.env.OIDC_CLIENT_SECRET;
  if (process.env.GITLEAKS_ENABLED !== undefined) {
    merged.security.gitleaks.enabled = String(process.env.GITLEAKS_ENABLED) === 'true';
  }
  if (process.env.GITLEAKS_BINARY) merged.security.gitleaks.binary = process.env.GITLEAKS_BINARY;
  if (process.env.GITLEAKS_CONFIG_PATH) merged.security.gitleaks.configPath = process.env.GITLEAKS_CONFIG_PATH;
  // Comma-separated list of regex patterns (JS regex syntax, no delimiters)
  // matched against a flagged secret's exact VALUE — see config.json's
  // security.secrets.knownPublicKeyPatterns comment for why this stays
  // value-matched, not kind-matched.
  if (process.env.SECRETS_KNOWN_PUBLIC_KEY_PATTERNS !== undefined) {
    merged.security.secrets.knownPublicKeyPatterns = process.env.SECRETS_KNOWN_PUBLIC_KEY_PATTERNS
      .split(',').map((s) => s.trim()).filter(Boolean);
  }
  if (process.env.SECURITY_EXCLUDE_PATHS !== undefined) {
    merged.security.excludePaths = process.env.SECURITY_EXCLUDE_PATHS
      .split(',').map((s) => s.trim()).filter(Boolean);
  }
  if (process.env.TRIVY_ENABLED !== undefined) {
    merged.security.trivy.enabled = String(process.env.TRIVY_ENABLED) === 'true';
  }
  if (process.env.TRIVY_BINARY) merged.security.trivy.binary = process.env.TRIVY_BINARY;
  if (process.env.CHECKOV_ENABLED !== undefined) {
    merged.security.checkov.enabled = String(process.env.CHECKOV_ENABLED) === 'true';
  }
  if (process.env.CHECKOV_BINARY) merged.security.checkov.binary = process.env.CHECKOV_BINARY;
  if (process.env.HADOLINT_ENABLED !== undefined) {
    merged.security.hadolint.enabled = String(process.env.HADOLINT_ENABLED) === 'true';
  }
  if (process.env.HADOLINT_BINARY) merged.security.hadolint.binary = process.env.HADOLINT_BINARY;
  if (process.env.COSIGN_ENABLED !== undefined) {
    merged.security.cosign.enabled = String(process.env.COSIGN_ENABLED) === 'true';
  }
  if (process.env.COSIGN_BINARY) merged.security.cosign.binary = process.env.COSIGN_BINARY;
  if (process.env.COSIGN_IDENTITY_REGEXP) merged.security.cosign.identityRegexp = process.env.COSIGN_IDENTITY_REGEXP;
  if (process.env.COSIGN_ISSUER_REGEXP) merged.security.cosign.issuerRegexp = process.env.COSIGN_ISSUER_REGEXP;
  if (process.env.COSIGN_CACHE_TTL_SECONDS !== undefined) merged.security.cosign.cacheTtlSeconds = Number(process.env.COSIGN_CACHE_TTL_SECONDS);
  if (process.env.SEMGREP_ENABLED !== undefined) {
    merged.security.semgrep.enabled = String(process.env.SEMGREP_ENABLED) === 'true';
  }
  if (process.env.SEMGREP_BINARY) merged.security.semgrep.binary = process.env.SEMGREP_BINARY;
  if (process.env.SEMGREP_CONFIG) merged.security.semgrep.config = process.env.SEMGREP_CONFIG;
  if (process.env.BEARER_ENABLED !== undefined) {
    merged.security.bearer.enabled = String(process.env.BEARER_ENABLED) === 'true';
  }
  if (process.env.BEARER_BINARY) merged.security.bearer.binary = process.env.BEARER_BINARY;
  if (process.env.GUARDDOG_ENABLED !== undefined) {
    merged.security.guarddog.enabled = String(process.env.GUARDDOG_ENABLED) === 'true';
  }
  if (process.env.GUARDDOG_BINARY) merged.security.guarddog.binary = process.env.GUARDDOG_BINARY;
  if (process.env.CODEQL_ENABLED !== undefined) {
    merged.security.codeql.enabled = String(process.env.CODEQL_ENABLED) === 'true';
  }
  if (process.env.CODEQL_BINARY) merged.security.codeql.binary = process.env.CODEQL_BINARY;
  if (process.env.CODEQL_LANGUAGES) {
    merged.security.codeql.languages = process.env.CODEQL_LANGUAGES.split(',').map((s) => s.trim()).filter(Boolean);
  }
  if (process.env.CODEQL_QUERY_SUITES) {
    try {
      merged.security.codeql.querySuites = { ...merged.security.codeql.querySuites, ...JSON.parse(process.env.CODEQL_QUERY_SUITES) };
    } catch { /* malformed JSON — keep the default/config.json suites rather than crash boot */ }
  }
  if (process.env.CODEQL_THREADS !== undefined) merged.security.codeql.threads = Number(process.env.CODEQL_THREADS) || 0;
  if (process.env.CODEQL_RAM_MB !== undefined) merged.security.codeql.ramMB = Number(process.env.CODEQL_RAM_MB) || 0;
  if (process.env.CODEQL_TIMEOUT_MS !== undefined) merged.security.codeql.timeoutMs = Number(process.env.CODEQL_TIMEOUT_MS) || (20 * 60_000);
  if (process.env.DEAD_CODE_ENABLED !== undefined) merged.codeIntelligence.deadCode.enabled = String(process.env.DEAD_CODE_ENABLED) === 'true';
  if (process.env.HEALTH_ENABLED !== undefined) merged.codeIntelligence.health.enabled = String(process.env.HEALTH_ENABLED) === 'true';
  if (process.env.CSS_DEAD_CODE_ENABLED !== undefined) merged.codeIntelligence.cssDeadCode.enabled = String(process.env.CSS_DEAD_CODE_ENABLED) === 'true';
  if (process.env.ARCHITECTURE_BOUNDARIES_ENABLED !== undefined) merged.architecture.boundaries.enabled = String(process.env.ARCHITECTURE_BOUNDARIES_ENABLED) === 'true';
  if (process.env.ARCHITECTURE_BOUNDARIES_PRESET) merged.architecture.boundaries.preset = process.env.ARCHITECTURE_BOUNDARIES_PRESET;
  if (process.env.TRIVY_IMAGE_ENABLED !== undefined) {
    merged.security.trivyImage.enabled = String(process.env.TRIVY_IMAGE_ENABLED) === 'true';
  }
  if (process.env.TRIVY_IMAGE_SEVERITY) merged.security.trivyImage.severityThreshold = process.env.TRIVY_IMAGE_SEVERITY;
  if (process.env.POSTURE_ENABLED !== undefined) {
    merged.compliance.posture.enabled = String(process.env.POSTURE_ENABLED) === 'true';
  }
  if (process.env.POSTURE_RULESET) merged.compliance.posture.ruleset = process.env.POSTURE_RULESET;
  if (process.env.EU_AI_ACT_DOCS_ENABLED !== undefined) {
    merged.compliance.euAiActDocuments.enabled = String(process.env.EU_AI_ACT_DOCS_ENABLED) === 'true';
  }
  if (process.env.EU_AI_ACT_REPORT_AS_FINDINGS !== undefined) {
    merged.compliance.euAiAct.reportAsFindings = String(process.env.EU_AI_ACT_REPORT_AS_FINDINGS) === 'true';
  }
  if (process.env.JSCPD_ENABLED !== undefined) {
    merged.metrics.jscpd.enabled = String(process.env.JSCPD_ENABLED) === 'true';
  }
  if (process.env.JSCPD_BINARY) merged.metrics.jscpd.binary = process.env.JSCPD_BINARY;
  if (process.env.JSCPD_MIN_LINES) merged.metrics.jscpd.minLines = Number(process.env.JSCPD_MIN_LINES);
  if (process.env.JSCPD_MIN_TOKENS) merged.metrics.jscpd.minTokens = Number(process.env.JSCPD_MIN_TOKENS);
  if (process.env.JSCPD_IGNORE !== undefined) {
    merged.metrics.jscpd.ignorePatterns = process.env.JSCPD_IGNORE.split(',').map((p) => p.trim()).filter(Boolean);
  }
  if (process.env.GOCLOC_ENABLED !== undefined) {
    merged.metrics.gocloc.enabled = String(process.env.GOCLOC_ENABLED) === 'true';
  }
  if (process.env.GOCLOC_BINARY) merged.metrics.gocloc.binary = process.env.GOCLOC_BINARY;
  if (process.env.FILE_SIZE_ENABLED !== undefined) {
    merged.metrics.fileSize.enabled = String(process.env.FILE_SIZE_ENABLED) === 'true';
  }
  if (process.env.FILE_SIZE_MAX_LINES) merged.metrics.fileSize.maxLines = Number(process.env.FILE_SIZE_MAX_LINES);
  if (process.env.SPECTRAL_ENABLED !== undefined) {
    merged.api.spectral.enabled = String(process.env.SPECTRAL_ENABLED) === 'true';
  }
  if (process.env.SPECTRAL_BINARY) merged.api.spectral.binary = process.env.SPECTRAL_BINARY;
  if (process.env.SPECTRAL_RULESET) merged.api.spectral.ruleset = process.env.SPECTRAL_RULESET;
  if (process.env.SYFT_ENABLED !== undefined) {
    merged.sbom.syft.enabled = String(process.env.SYFT_ENABLED) === 'true';
  }
  if (process.env.SYFT_BINARY) merged.sbom.syft.binary = process.env.SYFT_BINARY;
  if (process.env.MCP_AUTOSTART !== undefined) merged.mcp.autoStart = String(process.env.MCP_AUTOSTART) === 'true';
  if (process.env.MCP_HTTP_PORT) merged.mcp.httpPort = Number(process.env.MCP_HTTP_PORT);
  return merged;
}

module.exports = { loadConfig };
