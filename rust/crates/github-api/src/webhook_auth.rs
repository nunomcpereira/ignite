//! Shared `X-Hub-Signature-256` verification for GitHub's inbound webhooks.
//!
//! Previously reimplemented byte-for-byte in each of the server's four
//! webhook route handlers (`code_scanning_webhook.rs`,
//! `push_protection_webhook.rs`, `repository_events_webhook.rs`,
//! `secret_scanning_webhook.rs`) — pulled out here once a 5th webhook made
//! the duplication worth resolving.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
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
