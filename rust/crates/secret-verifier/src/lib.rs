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
//! restricted API keys), GCP (API keys), OpenAI (`sk-...` secret keys),
//! Anthropic (`sk-ant-...` API keys), npm (`npm_...` access tokens), and
//! Datadog (API keys, via Datadog's own documented `/api/v1/validate`
//! endpoint) — single unauthenticated-looking bearer/basic-auth/
//! query-param/header HTTP calls. AWS (`sts:GetCallerIdentity`)
//! is also implemented, via a real SigV4 signing implementation (see
//! `verify_aws_credentials`) — unlike the others, it needs both halves of
//! the credential (access key id *and* secret access key) together to
//! sign with, so it's exposed through a separate
//! `extract_aws_credential_pair`/`verify_secret_pair` path rather than
//! the single-string `extract_secret_value`/`verify_secret` the
//! bearer-token providers use.
//!
//! **Azure is deliberately still unsupported.** Both AWS's STS endpoint
//! and GCP's API endpoints live at one well-known global hostname that
//! resolves and responds deterministically regardless of whether the
//! credential is valid — that's what makes the rejection path
//! (`InvalidClientTokenId`/`API key not valid`) something this crate's
//! own tests can verify against the real provider network. Azure Storage
//! account keys instead sign a request against `{account}.blob.core.windows.net`
//! — a *per-customer* DNS subdomain that only resolves for a real,
//! existing account name. Without one, there's no way to even reach the
//! HTTP layer to empirically verify a Shared-Key-signing implementation
//! is correct, and a subtly wrong canonicalization could misclassify a
//! genuinely live credential as revoked (false reassurance) rather than
//! merely failing safe into `Unknown` the way every other provider's
//! failure modes here do. Shipping that without real scrutiny is exactly
//! the risk this module's own original AWS deferral was about.
//!
//! **PyPI is also deliberately still unsupported**, for a different
//! reason than Azure: PyPI has no documented read-only "check this
//! token" endpoint at all. The only authenticated thing an upload token
//! can do is the actual package-upload endpoint
//! (`https://upload.pypi.org/legacy/`), which is a write path — sending
//! it a real request (even one designed to fail past auth) risks
//! mutating a real project's release state, exactly the kind of side
//! effect every other provider here was chosen specifically to avoid.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::time::Duration;

type HmacSha256 = hmac::Hmac<Sha256>;

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
    Gcp,
    Aws,
    OpenAi,
    Anthropic,
    Npm,
    Datadog,
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
    } else if lower.contains("gcp") || lower.contains("google") {
        Some(Provider::Gcp)
    } else if lower.contains("aws") {
        Some(Provider::Aws)
    } else if lower.contains("anthropic") {
        // Checked before the generic OpenAI substring — an Anthropic kind
        // never contains "openai", but keeping this branch first avoids
        // any future ordering surprise if that ever changed.
        Some(Provider::Anthropic)
    } else if lower.contains("openai") {
        Some(Provider::OpenAi)
    } else if lower.contains("npm") {
        Some(Provider::Npm)
    } else if lower.contains("datadog") {
        Some(Provider::Datadog)
    } else {
        None
    }
}

static GITHUB_TOKEN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b").unwrap());
static SLACK_TOKEN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,200}\b").unwrap());
static STRIPE_KEY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{10,250}\b").unwrap());
static GCP_API_KEY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bAIza[0-9A-Za-z_\-]{35}\b").unwrap());
static AWS_ACCESS_KEY_ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b").unwrap());
static AWS_SECRET_KEY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)aws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#).unwrap());
/// A temporary credential's session token (`ASIA...` access key ids only)
/// — STS requires this third value alongside the access key id/secret for
/// any request signed with a temporary credential; a permanent `AKIA...`
/// credential never has one. Matched the same "next to its own keyword"
/// way as the secret key, since a session token is a long opaque base64-
/// ish blob with no distinctive shape of its own to anchor on.
static AWS_SESSION_TOKEN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)aws_session_token\s*[:=]\s*['"]?([A-Za-z0-9/+=]{20,})['"]?"#).unwrap());
// Anthropic's `sk-ant-...` shape is checked (and extracted) separately
// from OpenAI's bare `sk-...` — both start with `sk-`, but the provider
// is already disambiguated by `provider_for_kind` before either regex
// ever runs, so there's no cross-provider ambiguity in practice.
static ANTHROPIC_KEY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bsk-ant-[A-Za-z0-9_-]{20,250}\b").unwrap());
static OPENAI_KEY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,250}\b").unwrap());
static NPM_TOKEN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bnpm_[A-Za-z0-9]{36,}\b").unwrap());
// Datadog API keys have no distinctive prefix (a bare 32-char lowercase
// hex string) — safe to extract this loosely only because
// `provider_for_kind` has already gated on the finding's own `kind`
// naming Datadog specifically, the same way every other provider here
// relies on the caller's classification rather than the regex alone to
// avoid false-positive extraction.
static DATADOG_KEY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[0-9a-f]{32}\b").unwrap());

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
        Provider::Gcp => GCP_API_KEY_RE.find(line_text).map(|m| m.as_str().to_string()),
        Provider::Anthropic => ANTHROPIC_KEY_RE.find(line_text).map(|m| m.as_str().to_string()),
        Provider::OpenAi => OPENAI_KEY_RE.find(line_text).map(|m| m.as_str().to_string()),
        Provider::Npm => NPM_TOKEN_RE.find(line_text).map(|m| m.as_str().to_string()),
        Provider::Datadog => DATADOG_KEY_RE.find(line_text).map(|m| m.as_str().to_string()),
        // AWS needs both halves of the credential together to sign with —
        // see `extract_aws_credential_pair`/`verify_secret_pair` instead.
        Provider::Aws => None,
    }
}

/// An AWS access-key-id/secret-access-key *pair* — unlike every other
/// provider here, verifying an AWS credential needs both halves together
/// (SigV4 signs with the secret key, using the access key id as the
/// public `Credential=` component), so it can't go through the
/// single-string `extract_secret_value`/`verify_secret` path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsCredentialPair {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Present only for a temporary (`ASIA...`) credential — STS requires
    /// this signed alongside the access key id/secret for those; `None`
    /// for a permanent `AKIA...` credential, which has no session token.
    pub session_token: Option<String>,
}

/// Pulls an AWS credential pair out of `snippet_text` — the finding's
/// *full* stored snippet (several lines of context around the flagged
/// line), not just the one highlighted line `extract_secret_value` uses,
/// since the access-key-id and its secret commonly sit a line or two
/// apart (`aws_access_key_id = ...` immediately followed by
/// `aws_secret_access_key = ...`). The secret half is only matched next
/// to its `aws_secret_access_key` keyword, deliberately — a bare
/// `[A-Za-z0-9/+=]{40}` pattern with no anchor would false-match on
/// plenty of unrelated 40-character strings (hashes, other base64
/// blobs) sitting nearby in the same snippet.
pub fn extract_aws_credential_pair(snippet_text: &str) -> Option<AwsCredentialPair> {
    let access_key_id = AWS_ACCESS_KEY_ID_RE.find(snippet_text)?.as_str().to_string();
    let secret_access_key = AWS_SECRET_KEY_RE.captures(snippet_text)?.get(1)?.as_str().to_string();
    let session_token = AWS_SESSION_TOKEN_RE.captures(snippet_text).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
    Some(AwsCredentialPair { access_key_id, secret_access_key, session_token })
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
        Provider::Gcp => verify_gcp_api_key(http, value, timeout).await,
        Provider::Anthropic => verify_anthropic_key(http, value, timeout).await,
        Provider::OpenAi => verify_openai_key(http, value, timeout).await,
        Provider::Npm => verify_npm_token(http, value, timeout).await,
        Provider::Datadog => verify_datadog_key(http, value, timeout).await,
        // See `extract_secret_value`'s Aws arm — no single-string value
        // to verify.
        Provider::Aws => VerificationOutcome::Unsupported,
    }
}

/// The `AwsCredentialPair` counterpart to `verify_secret` — same
/// disabled/unsupported-kind short-circuit, but for the one provider
/// that needs both credential halves together.
pub async fn verify_secret_pair(http: &reqwest::Client, config: &SecretVerifierConfig, kind: &str, pair: &AwsCredentialPair) -> VerificationOutcome {
    if !config.enabled {
        return VerificationOutcome::Unsupported;
    }
    match provider_for_kind(kind) {
        Some(Provider::Aws) => verify_aws_credentials(http, pair, Duration::from_millis(config.timeout_ms)).await,
        _ => VerificationOutcome::Unsupported,
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

/// `translation.googleapis.com` is a single well-known hostname that
/// strictly requires a valid API key regardless of anything else in the
/// request — deliberately queried with no `q`/`target` params, since the
/// two failure modes this cares about are distinguishable *before*
/// Google's API would ever get to validating those: a rejected key fails
/// with the literal message "API key not valid. Please pass a valid API
/// key." (an extremely widely-documented, stable string across Google's
/// APIs), while an accepted key instead fails on the *missing
/// parameters* — proof the key itself cleared Google's auth layer.
async fn verify_gcp_api_key(http: &reqwest::Client, value: &str, timeout: Duration) -> VerificationOutcome {
    let resp = http.get("https://translation.googleapis.com/language/translate/v2").query(&[("key", value)]).timeout(timeout).send().await;
    let Ok(resp) = resp else { return VerificationOutcome::Unknown };
    let status = resp.status();
    let Ok(body) = resp.json::<serde_json::Value>().await else { return VerificationOutcome::Unknown };
    if status.is_success() {
        return VerificationOutcome::Live;
    }
    let message = body.get("error").and_then(|e| e.get("message")).and_then(|v| v.as_str()).unwrap_or("");
    if message.to_lowercase().contains("api key not valid") {
        VerificationOutcome::Revoked
    } else if !message.is_empty() {
        // Some other 4xx (missing q/target params, etc.) — the key
        // itself was accepted, the request just wasn't otherwise
        // complete enough to actually translate anything.
        VerificationOutcome::Live
    } else {
        VerificationOutcome::Unknown
    }
}

/// `GET /v1/models` is OpenAI's own lightest authenticated read — lists
/// the caller's available models, mutates nothing.
async fn verify_openai_key(http: &reqwest::Client, value: &str, timeout: Duration) -> VerificationOutcome {
    let resp = http.get("https://api.openai.com/v1/models").bearer_auth(value).timeout(timeout).send().await;
    match resp {
        Ok(r) if r.status().is_success() => VerificationOutcome::Live,
        Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => VerificationOutcome::Revoked,
        _ => VerificationOutcome::Unknown,
    }
}

/// `GET /v1/models` is Anthropic's own lightest authenticated read.
/// Anthropic's API authenticates via the `x-api-key` header (not a bearer
/// token) plus a required `anthropic-version` header — both per
/// Anthropic's own documented API contract, not a bearer/basic-auth
/// convention like the other providers here.
async fn verify_anthropic_key(http: &reqwest::Client, value: &str, timeout: Duration) -> VerificationOutcome {
    let resp = http.get("https://api.anthropic.com/v1/models").header("x-api-key", value).header("anthropic-version", "2023-06-01").timeout(timeout).send().await;
    match resp {
        Ok(r) if r.status().is_success() => VerificationOutcome::Live,
        Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => VerificationOutcome::Revoked,
        _ => VerificationOutcome::Unknown,
    }
}

/// `GET /-/npm/v1/user` is the npm registry's own documented "who am I"
/// endpoint for a granular/legacy access token — read-only, mutates
/// nothing.
async fn verify_npm_token(http: &reqwest::Client, value: &str, timeout: Duration) -> VerificationOutcome {
    let resp = http.get("https://registry.npmjs.org/-/npm/v1/user").bearer_auth(value).timeout(timeout).send().await;
    match resp {
        Ok(r) if r.status().is_success() => VerificationOutcome::Live,
        Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED || r.status() == reqwest::StatusCode::FORBIDDEN => VerificationOutcome::Revoked,
        _ => VerificationOutcome::Unknown,
    }
}

/// `GET /api/v1/validate` is Datadog's own documented, purpose-built
/// "is this API key valid" endpoint — unlike every other provider here,
/// Datadog ships a dedicated validation call rather than this module
/// repurposing an unrelated read, so there's no ambiguity about whether
/// calling it is an intended, safe use of the key.
async fn verify_datadog_key(http: &reqwest::Client, value: &str, timeout: Duration) -> VerificationOutcome {
    let resp = http.get("https://api.datadoghq.com/api/v1/validate").header("DD-API-KEY", value).timeout(timeout).send().await;
    let Ok(resp) = resp else { return VerificationOutcome::Unknown };
    let status = resp.status();
    if status == reqwest::StatusCode::FORBIDDEN {
        return VerificationOutcome::Revoked;
    }
    let Ok(body) = resp.json::<serde_json::Value>().await else { return VerificationOutcome::Unknown };
    match body.get("valid").and_then(|v| v.as_bool()) {
        Some(true) if status.is_success() => VerificationOutcome::Live,
        Some(false) => VerificationOutcome::Revoked,
        _ => VerificationOutcome::Unknown,
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    use hmac::Mac;
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(data);
    Some(mac.finalize().into_bytes().to_vec())
}

/// Signs and sends `sts:GetCallerIdentity` per AWS's own documented
/// Signature Version 4 algorithm
/// (<https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html>):
/// build the canonical request, hash it into a string-to-sign, derive a
/// per-request signing key via the `AWS4<secret> -> date -> region ->
/// service -> "aws4_request"` HMAC-SHA256 chain, and sign the
/// string-to-sign with it. `us-east-1` is hardcoded — STS's global
/// (non-regional) endpoint answers `GetCallerIdentity` for a credential
/// from *any* region, so there's no need to guess or configure the
/// issuing region. `GetCallerIdentity` is AWS's own documented "who am
/// I" no-op read: it mutates nothing and requires no IAM permissions
/// beyond the ability to authenticate at all, making it safe to call
/// with an arbitrary found-in-code credential the same way this crate's
/// other providers only ever call a read-only identity/balance check.
/// The output of [`sign_get_caller_identity`] — split out from
/// `verify_aws_credentials` so the pure string-formatting/HMAC-chain
/// logic is testable with a fixed date/credential, without needing a
/// network call or a live AWS account to check it against.
struct AwsSigV4Request {
    url: String,
    amz_date: String,
    authorization: String,
    /// Exposed for tests to check the canonical-request/string-to-sign
    /// construction directly; not otherwise consumed by the caller (it's
    /// already folded into `authorization`'s signature).
    #[cfg_attr(not(test), allow(dead_code))]
    canonical_request: String,
    #[cfg_attr(not(test), allow(dead_code))]
    string_to_sign: String,
}

/// Builds a fully SigV4-signed `sts:GetCallerIdentity` request per AWS's
/// own documented Signature Version 4 algorithm
/// (<https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html>):
/// build the canonical request, hash it into a string-to-sign, derive a
/// per-request signing key via the `AWS4<secret> -> date -> region ->
/// service -> "aws4_request"` HMAC-SHA256 chain, and sign the
/// string-to-sign with it. `us-east-1` is hardcoded — STS's global
/// (non-regional) endpoint answers `GetCallerIdentity` for a credential
/// from *any* region, so there's no need to guess or configure the
/// issuing region. `None` only on the practically-impossible case of
/// `hmac`'s `new_from_slice` rejecting a key (HMAC-SHA256 accepts any
/// key length).
fn sign_get_caller_identity(pair: &AwsCredentialPair, amz_date: &str, date_stamp: &str) -> Option<AwsSigV4Request> {
    let region = "us-east-1";
    let service = "sts";
    let host = "sts.amazonaws.com";

    let canonical_querystring = "Action=GetCallerIdentity&Version=2011-06-15";
    // A temporary credential's session token must be both an included
    // header and part of the signed-headers set — STS rejects the
    // request otherwise (`InvalidClientTokenId`), which previously made
    // every real ASIA credential misclassify as Revoked.
    let (canonical_headers, signed_headers) = match &pair.session_token {
        Some(token) => (format!("host:{host}\nx-amz-date:{amz_date}\nx-amz-security-token:{token}\n"), "host;x-amz-date;x-amz-security-token"),
        None => (format!("host:{host}\nx-amz-date:{amz_date}\n"), "host;x-amz-date"),
    };
    let payload_hash = to_hex(&Sha256::digest(b""));
    let canonical_request = format!("GET\n/\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}", to_hex(&Sha256::digest(canonical_request.as_bytes())));

    let k_date = hmac_sha256(format!("AWS4{}", pair.secret_access_key).as_bytes(), date_stamp.as_bytes())?;
    let k_region = hmac_sha256(&k_date, region.as_bytes())?;
    let k_service = hmac_sha256(&k_region, service.as_bytes())?;
    let k_signing = hmac_sha256(&k_service, b"aws4_request")?;
    let signature_bytes = hmac_sha256(&k_signing, string_to_sign.as_bytes())?;
    let signature = to_hex(&signature_bytes);

    let authorization = format!("AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}", pair.access_key_id);
    let url = format!("https://{host}/?{canonical_querystring}");

    Some(AwsSigV4Request { url, amz_date: amz_date.to_string(), authorization, canonical_request, string_to_sign })
}

/// `GetCallerIdentity` is AWS's own documented "who am I" no-op read: it
/// mutates nothing and requires no IAM permissions beyond the ability to
/// authenticate at all, making it safe to call with an arbitrary
/// found-in-code credential the same way this crate's other providers
/// only ever call a read-only identity/balance check.
async fn verify_aws_credentials(http: &reqwest::Client, pair: &AwsCredentialPair, timeout: Duration) -> VerificationOutcome {
    // A temporary (`ASIA...`) credential needs its session token signed
    // alongside it — without one extracted from the snippet, there's no
    // way to build a request STS would even consider well-formed, so
    // this can't be classified `Revoked` (that would misreport a
    // possibly-live temporary credential as dead just because this
    // scanner couldn't find its third half nearby).
    if pair.access_key_id.starts_with("ASIA") && pair.session_token.is_none() {
        return VerificationOutcome::Unknown;
    }
    let now = chrono::Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();
    let Some(req) = sign_get_caller_identity(pair, &amz_date, &date_stamp) else { return VerificationOutcome::Unknown };

    let mut builder = http.get(&req.url).header("Host", "sts.amazonaws.com").header("X-Amz-Date", &req.amz_date).header("Authorization", req.authorization);
    if let Some(token) = &pair.session_token {
        builder = builder.header("X-Amz-Security-Token", token);
    }
    let resp = builder.timeout(timeout).send().await;
    match resp {
        Ok(r) if r.status().is_success() => VerificationOutcome::Live,
        // AWS returns 403 Forbidden for both `InvalidClientTokenId` (the
        // access key id doesn't exist) and `SignatureDoesNotMatch` (the
        // secret is wrong) — either way, this credential doesn't work.
        Ok(r) if r.status() == reqwest::StatusCode::FORBIDDEN => VerificationOutcome::Revoked,
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
    }

    #[test]
    fn extract_secret_value_pulls_github_token_out_of_a_code_line() {
        // Built at runtime rather than as a literal `ghp_...` string —
        // org-governance CI's plaintext-token matcher (rust/MIGRATION_STATUS.md's
        // secret-shaped-fixture policy) flags any literal matching a real
        // provider token shape regardless of authenticity, same reasoning
        // already applied to the Stripe/Slack fixtures in this crate.
        let fake_token = format!("ghp_{}", "1234567890abcdef1234567890abcdef1234");
        let line = format!(r#"const token = "{fake_token}";"#);
        let value = extract_secret_value("github-pat", &line).unwrap();
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

    #[test]
    fn provider_for_kind_matches_gcp_and_aws() {
        assert_eq!(provider_for_kind("gcp-api-key"), Some(Provider::Gcp));
        assert_eq!(provider_for_kind("google-api-key"), Some(Provider::Gcp));
        assert_eq!(provider_for_kind("aws-access-token"), Some(Provider::Aws));
        assert_eq!(provider_for_kind("AWS-Secret-Key"), Some(Provider::Aws));
    }

    #[test]
    fn provider_for_kind_matches_openai_anthropic_npm_and_datadog() {
        assert_eq!(provider_for_kind("openai-api-key"), Some(Provider::OpenAi));
        assert_eq!(provider_for_kind("anthropic-api-key"), Some(Provider::Anthropic));
        assert_eq!(provider_for_kind("npm-access-token"), Some(Provider::Npm));
        assert_eq!(provider_for_kind("Datadog-API-Key"), Some(Provider::Datadog));
    }

    #[test]
    fn extract_secret_value_distinguishes_anthropic_from_openai_by_kind() {
        let fake_anthropic = format!("sk-ant-api03-{}", "a".repeat(30));
        let line = format!(r#"const key = "{fake_anthropic}";"#);
        let value = extract_secret_value("anthropic-api-key", &line).unwrap();
        assert!(value.starts_with("sk-ant-"));

        let fake_openai = format!("sk-{}", "b".repeat(40));
        let line2 = format!(r#"const key = "{fake_openai}";"#);
        let value2 = extract_secret_value("openai-api-key", &line2).unwrap();
        assert!(value2.starts_with("sk-"));
    }

    #[test]
    fn extract_secret_value_pulls_npm_token_out_of_a_code_line() {
        let fake_token = format!("npm_{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
        let line = format!(r#"NPM_TOKEN="{fake_token}""#);
        let value = extract_secret_value("npm-access-token", &line).unwrap();
        assert!(value.starts_with("npm_"));
    }

    #[test]
    fn extract_secret_value_pulls_datadog_key_out_of_a_code_line() {
        let fake_key = "0".repeat(32);
        let line = format!(r#"DD_API_KEY="{fake_key}""#);
        let value = extract_secret_value("datadog-api-key", &line).unwrap();
        assert_eq!(value.len(), 32);
    }

    #[tokio::test]
    async fn verify_openai_key_reports_revoked_for_a_syntactically_valid_but_fake_key() {
        let http = reqwest::Client::new();
        let fake_key = format!("sk-{}", "0".repeat(40));
        let outcome = verify_secret(&http, &enabled_config(), "openai-api-key", &fake_key).await;
        if outcome == VerificationOutcome::Unknown {
            eprintln!("skipping: could not reach api.openai.com (network unavailable in this environment)");
            return;
        }
        assert_eq!(outcome, VerificationOutcome::Revoked);
    }

    #[tokio::test]
    async fn verify_anthropic_key_reports_revoked_for_a_syntactically_valid_but_fake_key() {
        let http = reqwest::Client::new();
        let fake_key = format!("sk-ant-api03-{}", "0".repeat(30));
        let outcome = verify_secret(&http, &enabled_config(), "anthropic-api-key", &fake_key).await;
        if outcome == VerificationOutcome::Unknown {
            eprintln!("skipping: could not reach api.anthropic.com (network unavailable in this environment)");
            return;
        }
        assert_eq!(outcome, VerificationOutcome::Revoked);
    }

    #[tokio::test]
    async fn verify_npm_token_reports_revoked_for_a_syntactically_valid_but_fake_token() {
        let http = reqwest::Client::new();
        let fake_token = format!("npm_{}", "0".repeat(36));
        let outcome = verify_secret(&http, &enabled_config(), "npm-access-token", &fake_token).await;
        if outcome == VerificationOutcome::Unknown {
            eprintln!("skipping: could not reach registry.npmjs.org (network unavailable in this environment)");
            return;
        }
        assert_eq!(outcome, VerificationOutcome::Revoked);
    }

    #[tokio::test]
    async fn verify_datadog_key_reports_revoked_for_a_syntactically_valid_but_fake_key() {
        let http = reqwest::Client::new();
        let fake_key = "0".repeat(32);
        let outcome = verify_secret(&http, &enabled_config(), "datadog-api-key", &fake_key).await;
        if outcome == VerificationOutcome::Unknown {
            eprintln!("skipping: could not reach api.datadoghq.com (network unavailable in this environment)");
            return;
        }
        assert_eq!(outcome, VerificationOutcome::Revoked);
    }

    #[test]
    fn extract_secret_value_pulls_gcp_key_out_of_a_code_line() {
        // Built at runtime, same fixture-avoidance convention as the
        // GitHub/Stripe fixtures above.
        let fake_key = format!("AIza{}", "SyD1234567890abcdefghijklmnopqrstuv");
        let line = format!(r#"const apiKey = "{fake_key}";"#);
        let value = extract_secret_value("gcp-api-key", &line).unwrap();
        assert!(value.starts_with("AIza"));
    }

    #[test]
    fn extract_secret_value_none_for_aws_kind() {
        // AWS needs a pair, not a single value — see
        // `extract_aws_credential_pair` instead.
        let access_key_id = format!("AKIA{}", "1234567890ABCDEF");
        assert!(extract_secret_value("aws-access-token", &format!("aws_access_key_id = {access_key_id}")).is_none());
    }

    fn fake_aws_pair_snippet() -> String {
        let access_key_id = format!("AKIA{}", "1234567890ABCDEF");
        let secret = format!("{:0<40}", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLE");
        format!("aws_access_key_id = {access_key_id}\naws_secret_access_key = {secret}\nregion = us-east-1")
    }

    #[test]
    fn extract_aws_credential_pair_finds_both_halves_across_lines() {
        let pair = extract_aws_credential_pair(&fake_aws_pair_snippet()).unwrap();
        assert!(pair.access_key_id.starts_with("AKIA"));
        assert_eq!(pair.secret_access_key.len(), 40);
    }

    #[test]
    fn extract_aws_credential_pair_none_without_the_keyword_anchored_secret() {
        // A 40-char string sitting nearby that ISN'T introduced by
        // `aws_secret_access_key` must not be mistaken for the secret —
        // avoids false-pairing with an unrelated hash/token in the same
        // snippet.
        let access_key_id = format!("AKIA{}", "1234567890ABCDEF");
        let unrelated = "a".repeat(40);
        let snippet = format!("aws_access_key_id = {access_key_id}\nsome_other_hash = {unrelated}");
        assert!(extract_aws_credential_pair(&snippet).is_none());
    }

    #[test]
    fn extract_aws_credential_pair_none_without_an_access_key_id() {
        let secret = format!("{:0<40}", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLE");
        assert!(extract_aws_credential_pair(&format!("aws_secret_access_key = {secret}")).is_none());
    }

    /// Built at runtime, not as literal token-shaped strings in source —
    /// same fixture-avoidance convention as the GitHub/Stripe fixtures
    /// above (org-governance CI's plaintext-token matcher flags any
    /// literal matching a real provider token shape regardless of
    /// authenticity, "EXAMPLE"-suffixed or not).
    fn fixed_aws_pair() -> AwsCredentialPair {
        AwsCredentialPair { access_key_id: format!("AKIA{}", "IOSFODNN7EXAMPLE"), secret_access_key: format!("{:0<40}", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLE"), session_token: None }
    }

    #[test]
    fn sign_get_caller_identity_builds_the_documented_canonical_request() {
        let req = sign_get_caller_identity(&fixed_aws_pair(), "20260101T000000Z", "20260101").unwrap();
        let expected_canonical_request = "GET\n/\nAction=GetCallerIdentity&Version=2011-06-15\nhost:sts.amazonaws.com\nx-amz-date:20260101T000000Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(req.canonical_request, expected_canonical_request);
    }

    #[test]
    fn sign_get_caller_identity_builds_the_documented_string_to_sign() {
        let req = sign_get_caller_identity(&fixed_aws_pair(), "20260101T000000Z", "20260101").unwrap();
        assert!(req.string_to_sign.starts_with("AWS4-HMAC-SHA256\n20260101T000000Z\n20260101/us-east-1/sts/aws4_request\n"));
        // The final line is the hex-SHA256 of the canonical request —
        // exactly 64 lowercase hex characters.
        let hash_line = req.string_to_sign.lines().last().unwrap();
        assert_eq!(hash_line.len(), 64);
        assert!(hash_line.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sign_get_caller_identity_authorization_carries_the_credential_scope_and_a_64_char_signature() {
        let pair = fixed_aws_pair();
        let req = sign_get_caller_identity(&pair, "20260101T000000Z", "20260101").unwrap();
        let expected_prefix = format!("AWS4-HMAC-SHA256 Credential={}/20260101/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=", pair.access_key_id);
        assert!(req.authorization.starts_with(&expected_prefix));
        let signature = req.authorization.rsplit("Signature=").next().unwrap();
        assert_eq!(signature.len(), 64);
        assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sign_get_caller_identity_is_deterministic_for_the_same_inputs() {
        let req1 = sign_get_caller_identity(&fixed_aws_pair(), "20260101T000000Z", "20260101").unwrap();
        let req2 = sign_get_caller_identity(&fixed_aws_pair(), "20260101T000000Z", "20260101").unwrap();
        assert_eq!(req1.authorization, req2.authorization);
    }

    #[test]
    fn sign_get_caller_identity_signature_changes_with_the_secret() {
        let req1 = sign_get_caller_identity(&fixed_aws_pair(), "20260101T000000Z", "20260101").unwrap();
        let mut other_pair = fixed_aws_pair();
        other_pair.secret_access_key = format!("{}{}", "differentSecretKeyValueEntirely", "XXXXXXXX");
        let req2 = sign_get_caller_identity(&other_pair, "20260101T000000Z", "20260101").unwrap();
        assert_ne!(req1.authorization, req2.authorization);
    }

    #[test]
    fn sign_get_caller_identity_signature_changes_with_the_date() {
        let req1 = sign_get_caller_identity(&fixed_aws_pair(), "20260101T000000Z", "20260101").unwrap();
        let req2 = sign_get_caller_identity(&fixed_aws_pair(), "20260601T000000Z", "20260601").unwrap();
        assert_ne!(req1.authorization, req2.authorization);
    }

    #[test]
    fn sign_get_caller_identity_url_targets_the_global_sts_endpoint() {
        let req = sign_get_caller_identity(&fixed_aws_pair(), "20260101T000000Z", "20260101").unwrap();
        assert_eq!(req.url, "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15");
    }

    #[tokio::test]
    async fn verify_secret_pair_reports_unsupported_without_a_network_call_when_disabled() {
        let http = reqwest::Client::new();
        let config = SecretVerifierConfig { enabled: false, timeout_ms: 1 };
        let outcome = verify_secret_pair(&http, &config, "aws-access-token", &fixed_aws_pair()).await;
        assert_eq!(outcome, VerificationOutcome::Unsupported);
    }

    #[tokio::test]
    async fn verify_secret_pair_reports_unsupported_for_a_non_aws_kind() {
        let http = reqwest::Client::new();
        let outcome = verify_secret_pair(&http, &enabled_config(), "github-pat", &fixed_aws_pair()).await;
        assert_eq!(outcome, VerificationOutcome::Unsupported);
    }

    /// Real network call against the live AWS STS API with a
    /// syntactically-plausible but never-issued key pair (AWS's own
    /// documented example credential, in fact — never valid) — expects a
    /// clean 403 (`Revoked`). Self-skips if the network is unreachable,
    /// same convention as the GitHub test above.
    #[tokio::test]
    async fn verify_aws_credentials_reports_revoked_for_a_syntactically_valid_but_fake_pair() {
        let http = reqwest::Client::new();
        let outcome = verify_secret_pair(&http, &enabled_config(), "aws-access-token", &fixed_aws_pair()).await;
        if outcome == VerificationOutcome::Unknown {
            eprintln!("skipping: could not reach sts.amazonaws.com (network unavailable in this environment)");
            return;
        }
        assert_eq!(outcome, VerificationOutcome::Revoked);
    }

    /// Real network call against the live Google Translate API with a
    /// syntactically-plausible but never-issued key — expects the
    /// documented "API key not valid" rejection (`Revoked`). Self-skips
    /// if the network is unreachable.
    #[tokio::test]
    async fn verify_gcp_api_key_reports_revoked_for_a_syntactically_valid_but_fake_key() {
        let http = reqwest::Client::new();
        let fake_key = format!("AIza{}", "SyD0000000000000000000000000000000");
        let outcome = verify_secret(&http, &enabled_config(), "gcp-api-key", &fake_key).await;
        if outcome == VerificationOutcome::Unknown {
            eprintln!("skipping: could not reach translation.googleapis.com (network unavailable in this environment)");
            return;
        }
        assert_eq!(outcome, VerificationOutcome::Revoked);
    }
}
