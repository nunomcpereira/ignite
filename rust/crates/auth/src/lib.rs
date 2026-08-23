//! Pluggable authentication core logic. Faithful port of the
//! non-route-wiring pieces of `auth.js` — password hashing (scrypt,
//! matching Node's crypto.scrypt default cost parameters N=16384/r=8/p=1),
//! API key generation/hashing, cookie parsing, email validation, and a
//! fixed-window rate limiter. The Express `Router` (`createAuth`'s route
//! handlers, OIDC/GitHub OAuth flows) is deliberately not ported here —
//! that wiring depends on the HTTP framework chosen for the eventual axum
//! server crate and belongs there, not in this framework-agnostic crate.

use once_cell::sync::Lazy;
use rand_core::{OsRng, RngCore};
use regex::Regex;
use scrypt::Params;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const SESSION_COOKIE: &str = "ignite_sid";
pub const SESSION_TTL_MS: u64 = 12 * 60 * 60 * 1000;
pub const API_KEY_PREFIX: &str = "ignite_";

const SCRYPT_LOG_N: u8 = 14; // N = 16384, Node's crypto.scrypt default cost
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const SCRYPT_KEYLEN: usize = 64;

fn scrypt_params() -> Params {
    Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, SCRYPT_KEYLEN).expect("valid scrypt params")
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// API keys are high-entropy random secrets (not user-chosen passwords), so
/// there's no offline-guessing risk to slow down with scrypt — a plain
/// SHA-256 lookup hash is standard practice for this class of token.
pub fn hash_api_key(raw_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    hex_encode(&hasher.finalize())
}

pub fn generate_api_key() -> String {
    format!("{}{}", API_KEY_PREFIX, hex_encode(&random_bytes(32)))
}

/// `__proto__`/`constructor`/`prototype` guard from the JS original is a
/// prototype-pollution concern specific to JS plain objects — a Rust
/// `HashMap` has no such hazard — but the same key set is still rejected
/// here to keep parsed-cookie behavior identical across both ports.
fn is_unsafe_cookie_key(key: &str) -> bool {
    matches!(key, "__proto__" | "constructor" | "prototype")
}

pub fn parse_cookies(header: Option<&str>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(header) = header else { return out };
    for pair in header.split(';') {
        let Some(idx) = pair.find('=') else { continue };
        let key = pair[..idx].trim();
        let val = pair[idx + 1..].trim();
        if !key.is_empty() && !is_unsafe_cookie_key(key) {
            out.insert(key.to_string(), urlencoding::decode(val).map(|c| c.into_owned()).unwrap_or_else(|_| val.to_string()));
        }
    }
    out
}

pub fn hash_password(password: &str) -> String {
    let salt = hex_encode(&random_bytes(16));
    let mut derived = vec![0u8; SCRYPT_KEYLEN];
    scrypt::scrypt(password.as_bytes(), salt.as_bytes(), &scrypt_params(), &mut derived).expect("scrypt derivation");
    format!("{}:{}", salt, hex_encode(&derived))
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    let mut parts = stored.splitn(2, ':');
    let (Some(salt), Some(hash_hex)) = (parts.next(), parts.next()) else { return false };
    if salt.is_empty() || hash_hex.is_empty() {
        return false;
    }
    let Some(expected) = hex_decode(hash_hex) else { return false };
    let mut derived = vec![0u8; SCRYPT_KEYLEN];
    if scrypt::scrypt(password.as_bytes(), salt.as_bytes(), &scrypt_params(), &mut derived).is_err() {
        return false;
    }
    constant_time_eq(&derived, &expected)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

static EMAIL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap());

pub fn is_valid_email(email: &str) -> bool {
    // RFC 5321's own length cap — also bounds the regex's worst-case
    // backtracking cost to trivial input sizes regardless of crafted input.
    if email.is_empty() || email.len() > 254 {
        return false;
    }
    EMAIL_RE.is_match(email)
}

/// A fixed, valid-shaped hash to verify against when the account doesn't
/// exist (or isn't a local-password account), computed once lazily.
/// Verifying against it costs the same one scrypt derivation a real
/// wrong-password attempt does, so a login response's timing doesn't
/// distinguish "no such account" from "wrong password" (CWE-208/CWE-203).
static DUMMY_HASH: Lazy<String> = Lazy::new(|| hash_password(&hex_encode(&random_bytes(24))));

pub fn dummy_hash() -> &'static str {
    &DUMMY_HASH
}

pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

struct RateLimitEntry {
    count: u32,
    reset_at: Instant,
}

/// Minimal fixed-window limiter, in-memory (single-process). Stale entries
/// are pruned lazily on `check()` rather than a background timer — the
/// JS original's `setInterval` sweep is server-process infrastructure that
/// belongs in the eventual axum server crate, not this logic crate; the
/// lazy sweep here bounds the same unbounded-growth failure mode (a flood
/// against an endpoint that never succeeds) without needing one.
pub struct RateLimiter {
    hits: Mutex<HashMap<String, RateLimitEntry>>,
    window: Duration,
    max: u32,
}

impl RateLimiter {
    pub fn new(window: Duration, max: u32) -> Self {
        RateLimiter { hits: Mutex::new(HashMap::new()), window, max }
    }

    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock().unwrap();
        hits.retain(|_, v| v.reset_at > now);
        let entry = hits.entry(key.to_string()).or_insert_with(|| RateLimitEntry { count: 0, reset_at: now + self.window });
        if entry.reset_at <= now {
            entry.count = 0;
            entry.reset_at = now + self.window;
        }
        entry.count += 1;
        entry.count <= self.max
    }

    pub fn reset(&self, key: &str) {
        self.hits.lock().unwrap().remove(key);
    }
}

pub fn login_limiter() -> &'static RateLimiter {
    static LIMITER: Lazy<RateLimiter> = Lazy::new(|| RateLimiter::new(Duration::from_secs(15 * 60), 8));
    &LIMITER
}

pub fn register_limiter() -> &'static RateLimiter {
    static LIMITER: Lazy<RateLimiter> = Lazy::new(|| RateLimiter::new(Duration::from_secs(60 * 60), 8));
    &LIMITER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_api_key_is_deterministic_sha256() {
        let h1 = hash_api_key("ignite_abc123");
        let h2 = hash_api_key("ignite_abc123");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn generate_api_key_has_expected_prefix_and_length() {
        let key = generate_api_key();
        assert!(key.starts_with(API_KEY_PREFIX));
        assert_eq!(key.len(), API_KEY_PREFIX.len() + 64);
    }

    #[test]
    fn parse_cookies_rejects_unsafe_keys_and_decodes_values() {
        let cookies = parse_cookies(Some("ignite_sid=abc%20def; __proto__=evil; foo=bar"));
        assert_eq!(cookies.get("ignite_sid").unwrap(), "abc def");
        assert!(!cookies.contains_key("__proto__"));
        assert_eq!(cookies.get("foo").unwrap(), "bar");
    }

    #[test]
    fn parse_cookies_handles_none_header() {
        let cookies = parse_cookies(None);
        assert!(cookies.is_empty());
    }

    #[test]
    fn hash_and_verify_password_roundtrip() {
        let hash = hash_password("correct horse battery staple");
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn verify_password_rejects_malformed_stored_value() {
        assert!(!verify_password("x", ""));
        assert!(!verify_password("x", "no-colon-here"));
        assert!(!verify_password("x", ":"));
    }

    #[test]
    fn is_valid_email_accepts_and_rejects() {
        assert!(is_valid_email("user@example.com"));
        assert!(!is_valid_email("not-an-email"));
        assert!(!is_valid_email(""));
        assert!(!is_valid_email(&format!("{}@example.com", "a".repeat(300))));
    }

    #[test]
    fn dummy_hash_is_stable_and_verifiable_shape() {
        let h1 = dummy_hash();
        let h2 = dummy_hash();
        assert_eq!(h1, h2); // lazily computed once
        assert!(!verify_password("anything", h1)); // never matches a real password
    }

    #[test]
    fn escape_html_escapes_all_five_entities() {
        assert_eq!(escape_html(r#"<a href="x">it's & "safe"</a>"#), "&lt;a href=&quot;x&quot;&gt;it&#39;s &amp; &quot;safe&quot;&lt;/a&gt;");
    }

    #[test]
    fn rate_limiter_blocks_after_max_and_resets() {
        let limiter = RateLimiter::new(Duration::from_secs(60), 3);
        assert!(limiter.check("k"));
        assert!(limiter.check("k"));
        assert!(limiter.check("k"));
        assert!(!limiter.check("k")); // 4th hit exceeds max=3
        limiter.reset("k");
        assert!(limiter.check("k"));
    }

    #[test]
    fn rate_limiter_keys_are_independent() {
        let limiter = RateLimiter::new(Duration::from_secs(60), 1);
        assert!(limiter.check("a"));
        assert!(limiter.check("b"));
        assert!(!limiter.check("a"));
    }
}
