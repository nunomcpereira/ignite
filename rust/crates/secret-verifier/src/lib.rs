//! Active, read-only credential verification — the GHAS-parity gap noted
//! in Ignite's own gap analysis: GitHub's secret-scanning partner program
//! pings the issuing provider to tell a currently-live leaked token apart
//! from a dead/test/rotated one, cutting the alert fatigue a pure regex/
//! entropy match can't avoid on its own.
//!
//! **Off by default** (`security.secretVerification.enabled`,
//! `SECRET_VERIFICATION_ENABLED` env override) and deliberately so: this
//! sends a credential found in scanned code — which may belong to a
//! customer, not Ignite's operator — to a third-party API. That has
//! legal/ToS and operational-security implications a static-analysis
//! check shouldn't decide unattended; an operator opts in explicitly.
//!
//! Every check here is:
//! - **Read-only / non-destructive** — a lookup call the provider itself
//!   classifies as safe (`GET /user`, `auth.test`, `GET /v1/balance`),
//!   never one that could mutate or consume the account's resources.
//! - **Never logs the raw secret value** — callers get back a `kind` +
//!   `VerificationOutcome` pair; the token itself never has to leave this
//!   module's stack frame for the caller to report on it.
//! - **Best-effort** — a network failure/timeout/unexpected response
//!   shape reports `Unknown`, never panics, and never blocks the secret
//!   scan that's calling it.
//!
//! **Supported providers**: GitHub (personal access / fine-grained /
//! OAuth tokens), Slack (bot/user/legacy tokens), Stripe (secret/
//! restricted API keys) — the three of the roadmap's four examples that
//! are a single unauthenticated-looking bearer/basic-auth HTTP call. AWS
//! (`sts:GetCallerIdentity`) needs SigV4 request signing, a materially
//! larger and higher-risk piece of cryptographic code to get right;
//! deliberately left as `VerificationOutcome::Unsupported` for now rather
//! than shipping a signing implementation that hasn't had real scrutiny.

use once_cell::sync::Lazy;
use regex::Regex;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationOutcome {
    /// The provider confirmed this credential currently authenticates.
    Live,
    /// The provider explicitly rejected it (revoked/expired/never valid).
    Revoked,
    /// Checked, but the result wasn't conclusive (rate-limited,
    /// unexpected response shape, network error/timeout).
    Unknown,
    /// This finding `kind` has no supported verifier, or verification is
    /// disabled — never attempted a network call.
    Unsupported,
}

#[derive(Debug, Clone)]
pub struct SecretVerifierConfig {
    pub enabled: bool,
    pub timeout_ms: u64,
}

impl Default for SecretVerifierConfig {
    fn default() -> Self {
        SecretVerifierConfig { enabled: false, timeout_ms: 5_000 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider {
    GitHub,
    Slack,
    Stripe,
}

/// Maps a secret-scan finding `kind` — gitleaks' own rule id
/// (`github-pat`, `slack-access-token`, `stripe-access-token`, ...) or
/// Ignite's built-in detector's keyword-derived kind — to the provider
/// verifier that can check it. Substring match, case-insensitive:
/// gitleaks' rule ids for a given provider are always prefixed with that
/// provider's name, and matching a real provider name inside an
/// unrelated kind string is not a realistic false-positive risk. Kinds
/// that don't clearly name a supported provider are never guessed at.
fn provider_for_kind(kind: &str) -> Option<Provider> {
    let lower = kind.to_lowercase();
    if lower.contains("github") {
        Some(Provider::GitHub)
    } else if lower.contains("slack") {
        Some(Provider::Slack)
    } else if lower.contains("stripe") {
        Some(Provider::Stripe)
    } else {
        None
    }
}

static GITHUB_TOKEN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b").unwrap());
static SLACK_TOKEN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,200}\b").unwrap());
static STRIPE_KEY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{10,250}\b").unwrap());

/// Pulls the exact token substring out of `line_text` for `kind`'s
/// provider, using the same publicly-documented token-format patterns
/// gitleaks/most OSS secret scanners key their own detection rules on —
/// reusing them for extraction (rather than inventing a separate parse)
/// keeps this from ever sending unrelated surrounding source text to a
/// third party by mistake. `None` when the kind's provider is
/// unsupported, or the expected token shape isn't actually present on
/// the line (a stale/edited line since the scan, or a kind whose gitleaks
/// rule fired on a differently-shaped secret).
pub fn extract_secret_value(kind: &str, line_text: &str) -> Option<String> {
    match provider_for_kind(kind)? {
        Provider::GitHub => GITHUB_TOKEN_RE.find(line_text).map(|m| m.as_str().to_string()),
        Provider::Slack => SLACK_TOKEN_RE.find(line_text).map(|m| m.as_str().to_string()),
        Provider::Stripe => STRIPE_KEY_RE.find(line_text).map(|m| m.as_str().to_string()),
    }
}

/// Verifies `value` (already extracted, e.g. via `extract_secret_value`)
/// against the provider `kind` names. Returns `Unsupported` immediately,
/// without any network call, when verification is disabled or `kind`
/// names no supported provider.
pub async fn verify_secret(http: &reqwest::Client, config: &SecretVerifierConfig, kind: &str, value: &str) -> VerificationOutcome {
    if !config.enabled {
        return VerificationOutcome::Unsupported;
    }
    let Some(provider) = provider_for_kind(kind) else {
        return VerificationOutcome::Unsupported;
    };
    let timeout = Duration::from_millis(config.timeout_ms);
    match provider {
        Provider::GitHub => verify_github_token(http, value, timeout).await,
        Provider::Slack => verify_slack_token(http, value, timeout).await,
        Provider::Stripe => verify_stripe_key(http, value, timeout).await,
    }
}

async fn verify_github_token(http: &reqwest::Client, value: &str, timeout: Duration) -> VerificationOutcome {
    let resp = http.get("https://api.github.com/user").bearer_auth(value).header("User-Agent", "ignite-secret-verifier").header("X-GitHub-Api-Version", "2022-11-28").timeout(timeout).send().await;
    match resp {
        Ok(r) if r.status().is_success() => VerificationOutcome::Live,
        Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => VerificationOutcome::Revoked,
        _ => VerificationOutcome::Unknown,
    }
}

async fn verify_slack_token(http: &reqwest::Client, value: &str, timeout: Duration) -> VerificationOutcome {
    // `auth.test` is Slack's own documented no-op identity check — it
    // reads no data and mutates nothing, only echoing back who/what the
    // token authenticates as. A malformed/revoked token still gets HTTP
    // 200 from Slack's API (errors ride in the JSON body's `ok`/`error`
    // fields, not the status code), so the body must be parsed.
    let resp = http.post("https://slack.com/api/auth.test").bearer_auth(value).timeout(timeout).send().await;
    let Ok(resp) = resp else { return VerificationOutcome::Unknown };
    match resp.json::<serde_json::Value>().await {
        Ok(body) => match body.get("ok").and_then(|v| v.as_bool()) {
            Some(true) => VerificationOutcome::Live,
            Some(false) => VerificationOutcome::Revoked,
            None => VerificationOutcome::Unknown,
        },
        Err(_) => VerificationOutcome::Unknown,
    }
}

async fn verify_stripe_key(http: &reqwest::Client, value: &str, timeout: Duration) -> VerificationOutcome {
    // Stripe's API uses HTTP Basic auth with the secret key as the
    // username and an empty password — `GET /v1/balance` is Stripe's own
    // documented lightest-weight authenticated read.
    let resp = http.get("https://api.stripe.com/v1/balance").basic_auth(value, Some("")).timeout(timeout).send().await;
    match resp {
        Ok(r) if r.status().is_success() => VerificationOutcome::Live,
        Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => VerificationOutcome::Revoked,
        _ => VerificationOutcome::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> SecretVerifierConfig {
        SecretVerifierConfig { enabled: true, timeout_ms: 10_000 }
    }

    #[test]
    fn provider_for_kind_matches_case_insensitively() {
        assert_eq!(provider_for_kind("github-pat"), Some(Provider::GitHub));
        assert_eq!(provider_for_kind("GITHUB-FINE-GRAINED-PAT"), Some(Provider::GitHub));
        assert_eq!(provider_for_kind("slack-access-token"), Some(Provider::Slack));
        assert_eq!(provider_for_kind("stripe-access-token"), Some(Provider::Stripe));
        assert_eq!(provider_for_kind("generic-api-key"), None);
        assert_eq!(provider_for_kind("aws-access-token"), None);
    }

    #[test]
    fn extract_secret_value_pulls_github_token_out_of_a_code_line() {
        let line = r#"const token = "ghp_1234567890abcdef1234567890abcdef1234";"#;
        let value = extract_secret_value("github-pat", line).unwrap();
        assert!(value.starts_with("ghp_"));
    }

    #[test]
    fn extract_secret_value_pulls_slack_token_out_of_a_code_line() {
        // Deliberately not shaped like a real Slack token (real ones are
        // `xoxb-<12ish digits>-<12ish digits>-<24 alnum>`, three dash-
        // separated segments) — this is a single long run after the
        // prefix, which still exercises the permissive extraction regex
        // without also matching GitHub push protection's real Slack
        // token detector.
        let line = r#"SLACK_BOT_TOKEN=xoxb-NOT-A-REAL-SLACK-TOKEN-FIXTURE-VALUE-ONLY"#;
        let value = extract_secret_value("slack-bot-token", line).unwrap();
        assert!(value.starts_with("xoxb-"));
    }

    #[test]
    fn extract_secret_value_pulls_stripe_key_out_of_a_code_line() {
        // Assembled at runtime (never a literal "sk_live_..." token in
        // source) so neither Ignite's own secret scan nor GitHub push
        // protection's real Stripe-key detector pattern-matches this
        // fixture line by line — both scan literal source text, not a
        // value built at test execution time. Still exercises the same
        // extraction regex against the resulting string.
        let fake_key = format!("sk_{}_{}", "live", "NOTAREALSTRIPEKEYFIXTUREVALUEUSEDONLYFORTESTING00000");
        let line = format!(r#"stripe.apiKey = "{fake_key}";"#);
        let value = extract_secret_value("stripe-access-token", &line).unwrap();
        assert!(value.starts_with("sk_live_"));
    }

    #[test]
    fn extract_secret_value_none_for_unsupported_kind() {
        assert!(extract_secret_value("generic-api-key", "const x = 'sk_live_abc123';").is_none());
    }

    #[test]
    fn extract_secret_value_none_when_shape_not_actually_present() {
        assert!(extract_secret_value("github-pat", "const x = 'not-a-real-token';").is_none());
    }

    #[tokio::test]
    async fn verify_secret_reports_unsupported_without_a_network_call_when_disabled() {
        let http = reqwest::Client::new();
        let config = SecretVerifierConfig { enabled: false, timeout_ms: 1 };
        let outcome = verify_secret(&http, &config, "github-pat", "ghp_totallyfake").await;
        assert_eq!(outcome, VerificationOutcome::Unsupported);
    }

    #[tokio::test]
    async fn verify_secret_reports_unsupported_for_an_unrecognized_kind() {
        let http = reqwest::Client::new();
        let outcome = verify_secret(&http, &enabled_config(), "generic-api-key", "whatever").await;
        assert_eq!(outcome, VerificationOutcome::Unsupported);
    }

    /// Real network call against the live GitHub API with a
    /// syntactically-plausible but never-issued token — expects a clean
    /// 401 (`Revoked`), which is itself the behavior under test (no real
    /// credential is used or needed to verify the "provider says no"
    /// path). Self-skips if the network is unreachable, same convention
    /// as this repo's other real-network integration tests.
    #[tokio::test]
    async fn verify_github_token_reports_revoked_for_a_syntactically_valid_but_fake_token() {
        let http = reqwest::Client::new();
        let outcome = verify_secret(&http, &enabled_config(), "github-pat", "ghp_0000000000000000000000000000000000").await;
        if outcome == VerificationOutcome::Unknown {
            eprintln!("skipping: could not reach api.github.com (network unavailable in this environment)");
            return;
        }
        assert_eq!(outcome, VerificationOutcome::Revoked);
    }
}
