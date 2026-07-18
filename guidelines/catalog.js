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
