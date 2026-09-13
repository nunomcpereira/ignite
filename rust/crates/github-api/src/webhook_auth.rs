//! Shared `X-Hub-Signature-256` verification for GitHub's inbound webhooks.
//!
//! Previously reimplemented byte-for-byte in each of the server's four
//! webhook route handlers (`code_scanning_webhook.rs`,
//! `push_protection_webhook.rs`, `repository_events_webhook.rs`,
//! `secret_scanning_webhook.rs`) — pulled out here once a 5th webhook made
//! the duplication worth resolving.

use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

/// GitHub's webhook HMAC scheme has no timestamp or nonce baked into the
/// signature itself (unlike, e.g., Stripe's) — there's nothing to check a
/// "signing window" against. What GitHub *does* provide is
/// `X-GitHub-Delivery`, a UUID unique per delivery attempt (including
/// GitHub's own automatic retries, which intentionally reuse the same id)
/// — tracking seen ids here is what actually closes the real replay gap:
/// an attacker capturing and re-POSTing a validly-signed payload shortly
/// after the real event.
static SEEN_DELIVERIES: Lazy<Mutex<HashMap<String, Instant>>> = Lazy::new(|| Mutex::new(HashMap::new()));
const DELIVERY_DEDUP_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_TRACKED_DELIVERIES: usize = 10_000;

/// `true` the first time `delivery_id` is seen (caller should process the
/// webhook); `false` on every subsequent call with the same id within
/// [`DELIVERY_DEDUP_WINDOW`] (caller should acknowledge and no-op, same as
/// GitHub's own retry semantics already expect from a receiver).
pub fn record_delivery_once(delivery_id: &str) -> bool {
    if delivery_id.is_empty() {
        // No `X-GitHub-Delivery` header at all (a hand-crafted request, or
        // a test) — nothing to dedup against, so let it through; the HMAC
        // check is still the real authentication boundary.
        return true;
    }
    let mut seen = SEEN_DELIVERIES.lock();
    seen.retain(|_, at| at.elapsed() < DELIVERY_DEDUP_WINDOW);
    if seen.contains_key(delivery_id) {
        return false;
    }
    if seen.len() >= MAX_TRACKED_DELIVERIES {
        // Defensive cap so a flood of distinct delivery ids can't grow
        // this map unboundedly — drop the oldest entries rather than the
        // new one, since the new id is the one about to be inserted.
        if let Some(oldest) = seen.iter().min_by_key(|(_, at)| **at).map(|(k, _)| k.clone()) {
            seen.remove(&oldest);
        }
    }
    seen.insert(delivery_id.to_string(), Instant::now());
    true
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.is_ascii() || !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    (0..bytes.len()).step_by(2).map(|i| u8::from_str_radix(std::str::from_utf8(&bytes[i..i + 2]).ok()?, 16).ok()).collect()
}

/// Constant-time-verifies `X-Hub-Signature-256: sha256=<hex hmac>` against
/// `body` using `secret`. `Mac::verify_slice` does the constant-time
/// comparison internally — this function never short-circuits on the
/// digest bytes themselves, only on cheap, secret-independent shape
/// checks (header prefix, hex validity, HMAC key length).
pub fn verify_webhook_signature(secret: &str, body: &[u8], header_value: &str) -> bool {
    let Some(hex_sig) = header_value.strip_prefix("sha256=") else { return false };
    let Some(sig_bytes) = decode_hex(hex_sig) else { return false };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else { return false };
    mac.update(body);
    mac.verify_slice(&sig_bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(secret: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        format!("sha256={}", hex_encode(&mac.finalize().into_bytes()))
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn accepts_a_correctly_signed_body() {
        let sig = sign("topsecret", b"hello world");
        assert!(verify_webhook_signature("topsecret", b"hello world", &sig));
    }

    #[test]
    fn rejects_wrong_secret() {
        let sig = sign("topsecret", b"hello world");
        assert!(!verify_webhook_signature("wrongsecret", b"hello world", &sig));
    }

    #[test]
    fn rejects_missing_prefix() {
        assert!(!verify_webhook_signature("topsecret", b"hello world", "deadbeef"));
    }

    #[test]
    fn rejects_malformed_hex() {
        assert!(!verify_webhook_signature("topsecret", b"hello world", "sha256=zzzz"));
    }
}
