'use strict';

/**
 * Compliance & Feature Posture Engine — detects the PRESENCE of security/
 * compliance features (SSO, RBAC, audit logging, TLS, backups, encryption
 * at rest, rate limiting), not vulnerabilities. Phase C of the server.js
 * module split (see /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {Function} deps.semgrepTooling - the *already-created* semgrepTooling
 *   from checks/semantic-sast.js's factory — shared, not re-probed, since
 *   this engine is "fully conditioned on Semgrep" (same binary, same probe).
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles, looksBinary, buildSnippet, relativeToRoot, BINARY_EXTENSIONS)
 * @param {object} deps.config - { enabled, ruleset, maxScanFileBytes }
 */
function createFeaturePostureCheck({ runTool, semgrepTooling, fsUtils, config }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const { walkFiles, looksBinary, buildSnippet, relativeToRoot, BINARY_EXTENSIONS } = fsUtils;

  const POSTURE_ENABLED = Boolean(config.enabled);
  const POSTURE_RULESET = String(config.ruleset || '');
  const MAX_SCAN_FILE_BYTES = Number(config.maxScanFileBytes) || 5 * 1024 * 1024;

  const POSTURE_CATEGORIES = [
    'sso-saml-oidc', 'rbac-abac', 'audit-logging', 'siem-log-forwarding',
    'https-tls', 'backups-dr', 'encryption-at-rest', 'rate-limiting',
    'mfa-2fa', 'secrets-management',
  ];

  // Mirrors ignite-posture-rules.yaml's pattern-regex bodies, narrower in
  // coverage (single JS regex per tier vs. Semgrep's proper multi-file
  // engine) — used only when Semgrep is disabled or not installed. Keeping
  // these in sync with the YAML file is a manual step; a mismatch just means
  // the fallback and Semgrep paths disagree on posture for the affected
  // category, never a crash either way.
  const POSTURE_FALLBACK_PATTERNS = {
    'sso-saml-oidc': {
      weak: /passport-saml|passport-openidconnect|passport-oauth2|org\.springframework\.security\.oauth2|org\.keycloak|keycloak-connect|auth0(-java|-spa-js)?|okta-sdk|okta-auth-js|com\.okta|cognito|microsoft-identity-web|omniauth-saml|omniauth-oauth2|ruby-saml|python3-saml|django-allauth/,
      strong: /new\s+SamlStrategy\(|new\s+OIDCStrategy\(|new\s+Auth0Client\(|new\s+CognitoUserPool\(|OktaAuth\(|@EnableOAuth2Sso|KeycloakInstance\(|Keycloak\(\{|SAML2AuthenticationProvider\(|OidcClient\(/,
    },
    'rbac-abac': {
      weak: /casbin|open-policy-agent|org\.opa|opa-wasm|django-guardian|pundit|cancancan|micronaut-security-annotations/,
      strong: /@PreAuthorize\(|@PostAuthorize\(|@RolesAllowed\(|@Secured\(|@RequireRole|casbin\.NewEnforcer\(|enforcer\.Enforce\(|opa\.Eval\(|requireRole\(|requirePermission\(|checkPermission\(|authorize!\(|can\?\(/,
    },
    'audit-logging': {
      weak: /AuditLogger|AuditEvent|audit_log|AuditingEntityListener|@Audited|django-auditlog|paper_trail|audited\s/,
      strong: /auditLogger\.(log|record|emit)\(|AuditLog\.create\(|logger\.audit\(|audit_log\.(info|record|create)\(|PaperTrail\.request|@Audited\b/,
    },
    'siem-log-forwarding': {
      weak: /winston-syslog|fluent-logger|logstash|@opentelemetry|go\.opentelemetry\.io|SyslogAppender|serilog-sinks-syslog|nlog\.targets\.syslog/,
      strong: /new\s+FluentLogger\(|winston\.transports\.Syslog\(|new\s+LogstashTransport\(|zap\.NewSyslogWriter\(|SyslogAppender\(|OpenTelemetry\.trace\.getTracer\(/,
    },
    'https-tls': {
      weak: /\bhelmet\b|force-ssl|django\.middleware\.security|Rack::SSL|Microsoft\.AspNetCore\.HttpsPolicy/,
      strong: /helmet\.hsts\(|Strict-Transport-Security|forceSSL|SECURE_SSL_REDIRECT\s*=\s*True|app\.UseHsts\(|https\.createServer\(|config\.force_ssl\s*=\s*true/,
    },
    'backups-dr': {
      weak: /pg_dump|pg_basebackup|mongodump|mysqldump|velero|restic\s|borgbackup/,
      strong: /backup_retention_period|BackupRetentionPeriod|RetentionPolicy|CreateDBSnapshot|CreateSnapshot\(/,
    },
    'encryption-at-rest': {
      weak: /aws-sdk.*kms|@aws-sdk\/client-kms|com\.amazonaws\.services\.kms|hashicorp\/vault|com\.google\.cloud\.kms|azure-keyvault/,
      strong: /kms\.encrypt\(|kmsClient\.Encrypt\(|vault\.write\(|createCipheriv\(|Aes\.Encrypt\(|EncryptField\(|Cipher\.getInstance\("AES/,
    },
    'rate-limiting': {
      weak: /express-rate-limit|bucket4j|django-ratelimit|rack-attack|flask-limiter|aspnetcoreratelimit/,
      strong: /rateLimit\(\{|new\s+RateLimiterRedis\(|Bucket4j\.builder\(|RateLimiter\.create\(|@ratelimit\(|Rack::Attack\.throttle\(/,
    },
    'mfa-2fa': {
      weak: /speakeasy|otplib|pyotp|django-otp|devise-two-factor|rotp|com\.warrenstrange\.googleauth|authy/,
      strong: /speakeasy\.totp\.verify\(|totp\.verify\(|pyotp\.TOTP\(|authenticator\.verify\(|GoogleAuthenticator\(\)\.authorize\(|TwoFactorAuthenticationProvider|verifyMfaChallenge\(/,
    },
    'secrets-management': {
      weak: /hashicorp\/vault|node-vault|@aws-sdk\/client-secrets-manager|azure-keyvault-secrets|com\.google\.cloud\.secretmanager|com\.bettercloud\.vault|doppler|python-dotenv-vault/,
      strong: /vault\.read\(|vaultClient\.read\(|secretsManagerClient\.getSecretValue\(|new\s+SecretClient\(|secretmanager\.accessSecretVersion\(|SecretsManagerClient\(\)\.getSecretValue\(/,
    },
  };

  function emptyPostureReport() {
    const posture = {};
    for (const cat of POSTURE_CATEGORIES) posture[cat] = { status: 'MISSING', matches: [] };
    return posture;
  }

  // >=1 "strong" (confirmed usage) match => DETECTED. Only "weak" (import/
  // dependency-only) matches => PARTIAL. Neither => MISSING.
  function classifyPostureMatches(matches) {
    if (matches.some((m) => m.tier === 'strong')) return 'DETECTED';
    if (matches.length > 0) return 'PARTIAL';
    return 'MISSING';
  }

  // Engine: Ignite Built-In Posture Scanner (Fallback) — used only when
  // Semgrep is unavailable. Same weak/strong two-tier model as the Semgrep
  // ruleset, just a line-by-line JS regex sweep instead of Semgrep's engine.
  async function checkFeaturePostureFallback(root) {
    const posture = emptyPostureReport();
    for await (const file of walkFiles(root)) {
      const ext = path.extname(file).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) continue;
      const stat = await fsp.stat(file).catch(() => null);
      if (!stat || stat.size > MAX_SCAN_FILE_BYTES) continue;
      const buffer = await fsp.readFile(file);
      if (looksBinary(buffer)) continue;
      const content = buffer.toString('utf8');
      const rel = path.relative(root, file);
      const lines = content.split(/\r?\n/);
      for (const category of POSTURE_CATEGORIES) {
        const { weak, strong } = POSTURE_FALLBACK_PATTERNS[category];
        lines.forEach((line, i) => {
          const tier = strong.test(line) ? 'strong' : (weak.test(line) ? 'weak' : null);
          if (!tier) return;
          posture[category].matches.push({
            file: rel, line: i + 1, tier, tool: 'ignite-fallback',
            message: `${category} (${tier} signal, built-in fallback — Semgrep not installed)`,
            code: buildSnippet(content, i + 1),
          });
        });
      }
    }
    for (const category of POSTURE_CATEGORIES) {
      posture[category].status = classifyPostureMatches(posture[category].matches);
    }
    return posture;
  }

  // Fully conditioned on Semgrep: runs the custom ignite-posture-rules.yaml
  // ruleset when connected, engine-attributed as "Semgrep CLI vX.X (External
  // Posture Scanner)"; soft-falls back to checkFeaturePostureFallback,
  // attributed as "Ignite Built-In Posture Scanner (Fallback)", when
  // disabled or not installed. Semgrep and the fallback never both run for
  // the same category in this design (one soft-conditions the other, not a
  // supplement like checkov/trivy) — the per-(category,file,line,tier) `seen`
  // dedup below still guards against Semgrep itself reporting the same
  // match twice (observed in practice: overlapping regex spans on one line).
  async function checkFeaturePosture(root, log) {
    const tooling = POSTURE_ENABLED ? await semgrepTooling() : { ok: false, reason: 'posture scan is disabled (compliance.posture.enabled=false).' };
    if (!tooling.ok) {
      log?.(`⚠ Semgrep unavailable for posture scan: ${tooling.reason}`);
      log?.('Engine: Ignite Built-In Posture Scanner (Fallback)');
      const posture = await checkFeaturePostureFallback(root);
      return { engine: 'fallback', posture };
    }

    log?.(`Engine: Semgrep CLI v${tooling.version} (External Posture Scanner)`);
    const posture = emptyPostureReport();
    try {
      const { stdout } = await runTool('semgrep', [
        'scan', '--config', POSTURE_RULESET, '--json', '--quiet', '--metrics', 'off', root,
      ], root, { allowedExitCodes: [0, 1] });
      const data = stdout.trim() ? JSON.parse(stdout) : { results: [] };
      const results = Array.isArray(data.results) ? data.results : [];
      const seen = new Set();
      for (const r of results) {
        const category = r.extra?.metadata?.category;
        const tier = r.extra?.metadata?.tier;
        if (!category || !posture[category]) continue;
        const relFile = await relativeToRoot(root, r.path);
        const line = Number(r.start?.line) || 1;
        const key = `${category}:${relFile}:${line}:${tier}`;
        if (seen.has(key)) continue;
        seen.add(key);
        let content = null;
        try { content = await fsp.readFile(path.join(root, relFile), 'utf8'); } catch { /* best-effort */ }
        posture[category].matches.push({
          file: relFile,
          line,
          tier,
          tool: 'semgrep',
          message: r.extra?.message || category,
          code: content ? buildSnippet(content, line) : null,
        });
      }
    } catch (e) {
      log?.(`⚠ Posture scan failed: ${e.message}`);
    }
    for (const category of POSTURE_CATEGORIES) {
      posture[category].status = classifyPostureMatches(posture[category].matches);
    }
    return { engine: 'semgrep', posture };
  }

  return { checkFeaturePosture, checkFeaturePostureFallback, POSTURE_CATEGORIES };
}

module.exports = { createFeaturePostureCheck };
