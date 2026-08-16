'use strict';

/**
 * Company AI validation guideline catalog.
 * Each guideline is a static rule a developer/agent can be checked against
 * during development, independent of the full Ignite onboarding pipeline.
 *
 * severity: 'error' (blocking) | 'warning' (advisory)
 * automated: true if `checkId` maps to a function in checks.js that can
 *   evaluate this guideline mechanically; false if it's judgment-only
 *   (e.g. covered by the LLM deep-scan in server.js, or a process rule).
 */
const GUIDELINES = Object.freeze([
  {
    id: 'ai-recursion-limit',
    category: 'ai-governance',
    severity: 'error',
    title: 'Bound AI agent recursion/iteration',
    description:
      'Any call to an LLM/agent invocation method (.invoke, .stream, .ainvoke, .astream) must be governed by an explicit recursion or iteration limit so a runaway agent loop cannot consume unbounded cost or compute.',
    rationale:
      'Ungoverned agent loops have caused runaway token spend and hangs in production. A recursion_limit (or equivalent) makes the ceiling explicit and reviewable.',
    remediation:
      'Pass a recursion_limit (LangGraph/LangChain) or equivalent max-iteration bound wherever an agent/chain is invoked.',
    checkId: 'aiRecursionLimit',
    appliesTo: ['.py', '.js', '.ts'],
  },
  {
    id: 'no-hardcoded-secrets',
    category: 'security',
    severity: 'error',
    title: 'No hardcoded secrets or credentials',
    description:
      'Passwords, API keys, tokens, and private keys must not be hardcoded as string literals in source or config files.',
    rationale:
      'Hardcoded secrets leak through git history, forks, and logs, and are the most common cause of credential-exposure incidents.',
    remediation:
      'Load secrets from environment variables or a secrets manager; never commit literal credential values.',
    checkId: 'noHardcodedSecrets',
    appliesTo: ['*'],
  },
  {
    id: 'no-committed-env-files',
    category: 'security',
    severity: 'error',
    title: 'No raw .env files in the repository',
    description:
      '.env / .env.* files must not be committed. Use .env.example with placeholder values instead.',
    rationale:
      '.env files typically hold live credentials; committing them ships secrets to every clone/fork.',
    remediation:
      'Add .env* to .gitignore and commit a .env.example with placeholder keys only.',
    checkId: 'noCommittedEnvFiles',
    appliesTo: ['*'],
  },
  {
    id: 'no-injection-sinks',
    category: 'security',
    severity: 'error',
    title: 'No unguarded injection sinks',
    description:
      'Do not build SQL, shell commands, or templates by concatenating untrusted input. Do not use eval/exec on dynamic strings.',
    rationale:
      'Unguarded sinks are the root cause of SQL/command injection and unsafe eval vulnerabilities — OWASP Top 10 A03 (Injection).',
    remediation:
      'Use parameterized queries, allowlisted command args (execFile with an argv array, never a shell string), and avoid eval/new Function on dynamic input.',
    checkId: 'noInjectionSinks',
    appliesTo: ['.py', '.js', '.ts'],
  },
  {
    id: 'no-insecure-deserialization',
    category: 'security',
    severity: 'error',
    title: 'No insecure deserialization',
    description:
      'Do not deserialize untrusted data with unsafe primitives (Python pickle.loads, yaml.load without SafeLoader, Node vm.runInNewContext on untrusted input).',
    rationale:
      'Insecure deserialization allows arbitrary code execution from attacker-controlled payloads.',
    remediation:
      'Use safe loaders (yaml.safe_load, json), or a schema-validated serialization format; never unpickle untrusted input.',
    checkId: 'noInsecureDeserialization',
    appliesTo: ['.py', '.js', '.ts'],
  },
  {
    id: 'no-plaintext-http-egress',
    category: 'security',
    severity: 'warning',
    title: 'Outbound calls to non-loopback hosts must use HTTPS',
    description:
      'HTTP (not HTTPS) requests to non-loopback hosts should be flagged; only localhost/127.0.0.1 traffic may use plain HTTP.',
    rationale:
      'Plaintext HTTP to remote hosts exposes request/response data (often including credentials) to network-level interception.',
    remediation:
      'Use https:// for any non-loopback endpoint; restrict http:// to local development origins.',
    checkId: 'noPlaintextHttpEgress',
    appliesTo: ['.py', '.js', '.ts'],
  },
  {
    id: 'no-sql-injection',
    category: 'security',
    severity: 'error',
    title: 'No string-built SQL queries',
    description:
      'Do not build a SQL query by interpolating or concatenating untrusted input directly into the query string.',
    rationale:
      'String-built queries are the classic shape of SQL injection — OWASP Top 10 A03 (Injection) — and remain one of the most common causes of full data-breach incidents.',
    remediation:
      'Use parameterized queries/prepared statements (?, %s, $1, or your ORM\'s bound-parameter API) instead of interpolating values into the query string.',
    checkId: 'noSqlInjection',
    appliesTo: ['.py', '.js', '.ts'],
  },
  {
    id: 'no-xss-sinks',
    category: 'security',
    severity: 'error',
    title: 'No unguarded XSS sinks',
    description:
      'Do not render untrusted input as raw HTML (innerHTML, dangerouslySetInnerHTML, document.write, Jinja2 |safe/Markup) without sanitizing it first.',
    rationale:
      'Rendering untrusted input as HTML without sanitization is the root cause of stored/reflected XSS — OWASP Top 10 A03 (Injection).',
    remediation:
      'Let the framework escape by default (textContent, JSX text children, Jinja2 autoescaping); if raw HTML is genuinely required, sanitize with a library like DOMPurify/bleach first.',
    checkId: 'noXssSinks',
    appliesTo: ['.py', '.js', '.ts'],
  },
  {
    id: 'no-weak-crypto',
    category: 'security',
    severity: 'error',
    title: 'No broken/deprecated cryptographic primitives',
    description:
      'Do not use MD5 or SHA-1 for hashing, or DES/ECB-mode for encryption — all have known, practical breaks.',
    rationale:
      'MD5 and SHA-1 are collision-broken and DES/ECB are trivially attackable; using any of them signals either passwords hashed unsafely or data encrypted with a cipher that offers no real confidentiality — OWASP Top 10 A02 (Cryptographic Failures).',
    remediation:
      'Hash passwords with bcrypt/scrypt/argon2 (never a bare fast hash); use SHA-256+ for non-password hashing; encrypt with AES-GCM (or another authenticated mode) instead of DES/ECB.',
    checkId: 'noWeakCrypto',
    appliesTo: ['.py', '.js', '.ts'],
  },
  {
    id: 'no-ssrf-sinks',
    category: 'security',
    severity: 'error',
    title: 'No unvalidated request-derived URLs in outbound calls',
    description:
      'Do not pass a request-derived value (req.*/request.*) directly as the URL/host of an outbound HTTP call.',
    rationale:
      'Letting untrusted input control the destination of a server-side request is server-side request forgery (SSRF) — it can be used to reach internal services, cloud metadata endpoints, or otherwise-firewalled hosts. #1 on OWASP Top 10:2025.',
    remediation:
      'Validate the target against an allowlist of expected hosts/schemes before making the call, or route through a proxy that enforces one — never pass the raw request value straight into the HTTP client.',
    checkId: 'noSsrfSinks',
    appliesTo: ['.py', '.js', '.ts'],
  },
  {
    id: 'no-csrf-disabled',
    category: 'security',
    severity: 'error',
    title: 'CSRF protection must not be explicitly disabled',
    description:
      'Do not turn off a framework\'s built-in CSRF protection (Django\'s @csrf_exempt, Rails\' skip_before_action :verify_authenticity_token, or an explicit csrf: false).',
    rationale:
      'CSRF lets an attacker-controlled page trigger state-changing requests using a logged-in victim\'s own session — #4 on the 2024 CWE Top 25 (CWE-352). Frameworks default this protection on; explicitly turning it off removes it for that endpoint.',
    remediation:
      'Remove the exemption; if a specific endpoint genuinely can\'t use token-based CSRF protection (e.g. a webhook), protect it a different way (signature verification) instead of blanket-disabling the framework default.',
    checkId: 'noCsrfDisabled',
    appliesTo: ['.py', '.js', '.ts', '.rb'],
  },
  {
    id: 'no-unpinned-gha-action',
    category: 'security',
    severity: 'warning',
    title: 'GitHub Actions steps should pin to a commit SHA, not a branch/tag',
    description:
      'A workflow `uses:` a third-party action pinned to a mutable ref (@main, @master, @latest, or a bare major-version tag like @v4) rather than a commit SHA.',
    rationale:
      'A mutable ref can be repointed by the action\'s maintainer (or an attacker who compromises their repo) to different code without your workflow file changing — a supply-chain integrity gap (OWASP Top 10:2025 A08, Software/Data Integrity Failures). Directly relevant here: Ignite\'s own Phase 5 fetches and runs the org\'s governance workflow.',
    remediation:
      'Pin third-party actions to a full commit SHA (`uses: owner/action@<40-char-sha>`), with a trailing comment noting the version, e.g. `# v4.1.0`.',
    checkId: 'noUnpinnedGhaAction',
    appliesTo: ['.yml', '.yaml'],
  },
  {
    id: 'ai-governance-workflow-required',
    category: 'process',
    severity: 'error',
    title: 'AI/security governance CI workflow must run before merge',
    description:
      "Projects onboarded through Ignite must keep the org's required governance GitHub Actions workflow enabled on the default branch.",
    rationale:
      'Local checks (this MCP server, pre-commit hooks) are advisory; the org-required workflow is the enforcement point once code reaches GitHub.',
    remediation:
      'Do not remove or disable the required workflow file; if it fails, fix the underlying issue rather than bypassing the check.',
    checkId: null,
    appliesTo: ['*'],
  },
  {
    id: 'llm-deep-scan-required',
    category: 'process',
    severity: 'warning',
    title: 'Run the LLM security/quality deep-scan before shipping',
    description:
      'Source changes should pass the local LLM deep-scan (security/dependency + quality/encapsulation passes) that Ignite runs during onboarding.',
    rationale:
      'Pattern-based checks catch known-shape issues; the LLM pass catches contextual issues (business-logic auth bypass, subtle injection, leaky abstractions) regex cannot.',
    remediation:
      'Run the Ignite pipeline (or `check_project` in this MCP server for the mechanical subset) before opening a PR.',
    checkId: null,
    appliesTo: ['*'],
  },
]);

function listGuidelines({ category, severity } = {}) {
  return GUIDELINES.filter(
    (g) => (!category || g.category === category) && (!severity || g.severity === severity)
  );
}

function getGuideline(id) {
  return GUIDELINES.find((g) => g.id === id) || null;
}

function listCategories() {
  return Array.from(new Set(GUIDELINES.map((g) => g.category)));
}

module.exports = { GUIDELINES, listGuidelines, getGuideline, listCategories };
