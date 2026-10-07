//! GitHub App authentication: the server-to-server alternative to a person's
//! OAuth token or PAT. Ignite signs a short-lived JWT with the App's private
//! key, looks up the App's installation on the target org (or user account),
//! and exchanges it for an installation token (`ghs_…`, valid ~1 hour).
//!
//! Why this exists: in an org enforcing SAML SSO, a user's OAuth token is
//! only honoured while that user has an active SSO session, so unattended
//! scans started failing whenever the session lapsed. Installation tokens
//! aren't tied to any person or SSO session, and are scoped to exactly the
//! repositories the org granted the App.
//!
//! Tokens are cached per owner and re-minted 5 minutes before they expire;
//! installation ids are cached too. Nothing here logs a token or the key.
use crate::GithubApiError;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_API_BASE: &str = "https://api.github.com";
/// Re-mint a cached installation token this long before GitHub expires it,
/// so a caller never gets one that dies mid-request.
const REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);
/// How long "the App isn't installed on this owner" is remembered. Without
/// a limit, installing the App on an org later went unnoticed until a restart.
const NOT_INSTALLED_TTL: Duration = Duration::from_secs(5 * 60);

pub struct GithubAppAuth {
    app_id: String,
    key: jsonwebtoken::EncodingKey,
    api_base: String,
    http: reqwest::Client,
    /// owner (lowercased) -> (installation id, or `None` when the App isn't
    /// installed there, cached at unix seconds). A `None` expires after
    /// `NOT_INSTALLED_TTL`; a found id is kept until a mint 404s.
    installations: Mutex<HashMap<String, (Option<u64>, u64)>>,
    /// owner (lowercased) -> (token, unix expiry seconds).
    tokens: Mutex<HashMap<String, (String, u64)>>,
    /// Serializes minting so concurrent callers for one owner share a token.
    mint_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for GithubAppAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubAppAuth").field("app_id", &self.app_id).field("api_base", &self.api_base).finish_non_exhaustive()
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Parses GitHub's RFC 3339 `expires_at` (`2026-09-29T12:34:56Z`) into unix
/// seconds without pulling in a date crate; `None` on anything unexpected.
fn parse_expires_at(s: &str) -> Option<u64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-').map(|p| p.parse::<i64>());
    let (y, m, day) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let mut t = time.split(':').map(|p| p.split('.').next().unwrap_or("").parse::<i64>());
    let (hh, mm, ss) = (t.next()?.ok()?, t.next()?.ok()?, t.next()?.ok()?);
    // Days from civil (Howard Hinnant's algorithm).
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hh * 3600 + mm * 60 + ss).ok()
}

impl GithubAppAuth {
    /// `private_key_pem` is the `.pem` GitHub generates for the App (PKCS#1
    /// or PKCS#8).
    pub fn new(app_id: &str, private_key_pem: &[u8]) -> Result<Self, String> {
        let app_id = app_id.trim();
        if app_id.is_empty() || !app_id.chars().all(|c| c.is_ascii_digit()) {
            return Err("GitHub App id must be the numeric App ID from the App's settings page.".to_string());
        }
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem).map_err(|e| format!("GitHub App private key is not a valid RSA PEM: {e}"))?;
        Ok(GithubAppAuth {
            app_id: app_id.to_string(),
            key,
            api_base: DEFAULT_API_BASE.to_string(),
            http: reqwest::Client::builder().timeout(Duration::from_secs(15)).build().unwrap_or_default(),
            installations: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
            mint_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Builds from `GITHUB_APP_ID` plus `GITHUB_APP_PRIVATE_KEY` (the PEM
    /// itself) or `GITHUB_APP_PRIVATE_KEY_PATH`. `None` when no App is
    /// configured; `Some(Err)` when it's configured but unusable.
    pub fn from_env() -> Option<Result<Self, String>> {
        let app_id = std::env::var("GITHUB_APP_ID").ok().filter(|v| !v.trim().is_empty())?;
        let pem = match std::env::var("GITHUB_APP_PRIVATE_KEY").ok().filter(|v| !v.trim().is_empty()) {
            Some(inline) => inline.replace("\\n", "\n").into_bytes(),
            None => match std::env::var("GITHUB_APP_PRIVATE_KEY_PATH").ok().filter(|v| !v.trim().is_empty()) {
                Some(path) => match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(e) => return Some(Err(format!("cannot read GITHUB_APP_PRIVATE_KEY_PATH {path}: {e}"))),
                },
                None => return Some(Err("GITHUB_APP_ID is set but neither GITHUB_APP_PRIVATE_KEY nor GITHUB_APP_PRIVATE_KEY_PATH is.".to_string())),
            },
        };
        Some(Self::new(&app_id, &pem))
    }

    /// Points API calls somewhere else (GitHub Enterprise Server, or a test server).
    pub fn with_api_base(mut self, base: &str) -> Self {
        self.api_base = base.trim_end_matches('/').to_string();
        self
    }

    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    /// The App JWT: issued a minute in the past (clock skew), valid 9 minutes
    /// (GitHub's cap is 10).
    fn jwt(&self) -> Result<String, GithubApiError> {
        let now = now_secs();
        let claims = json!({ "iat": now.saturating_sub(60), "exp": now + 9 * 60, "iss": self.app_id });
        jsonwebtoken::encode(&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256), &claims, &self.key).map_err(|e| GithubApiError::GraphQl(format!("could not sign GitHub App JWT: {e}")))
    }

    async fn app_request(&self, method: reqwest::Method, path: &str) -> Result<(u16, Value), GithubApiError> {
        let res = self
            .http
            .request(method, format!("{}/{}", self.api_base, path.trim_start_matches('/')))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "ignite")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("Authorization", format!("Bearer {}", self.jwt()?))
            .send()
            .await?;
        let status = res.status().as_u16();
        let text = res.text().await?;
        let body = if text.is_empty() { Value::Null } else { serde_json::from_str(&text).unwrap_or(Value::String(text)) };
        Ok((status, body))
    }

    /// The App's installation id on `owner` (an org, falling back to a user
    /// account), or `None` when it isn't installed there.
    async fn installation_id(&self, owner: &str) -> Result<Option<u64>, GithubApiError> {
        let key = owner.to_ascii_lowercase();
        if let Some((cached, at)) = self.installations.lock().get(&key) {
            if cached.is_some() || now_secs() < at + NOT_INSTALLED_TTL.as_secs() {
                return Ok(*cached);
            }
        }
        let mut found = None;
        for path in [format!("orgs/{owner}/installation"), format!("users/{owner}/installation")] {
            let (status, body) = self.app_request(reqwest::Method::GET, &path).await?;
            match status {
                200 => {
                    found = body.get("id").and_then(|v| v.as_u64());
                    break;
                }
                404 => continue,
                _ => return Err(GithubApiError::ApiFailed { method: "GET".into(), path, status, detail: body.to_string().chars().take(300).collect() }),
            }
        }
        self.installations.lock().insert(key, (found, now_secs()));
        Ok(found)
    }

    fn cached_token(&self, key: &str) -> Option<String> {
        let tokens = self.tokens.lock();
        tokens.get(key).filter(|(_, exp)| *exp > now_secs() + REFRESH_MARGIN.as_secs()).map(|(t, _)| t.clone())
    }

    /// An installation token for `owner`, or `Ok(None)` when the App isn't
    /// installed on that org/user (callers then fall back to other tokens).
    pub async fn installation_token(&self, owner: &str) -> Result<Option<String>, GithubApiError> {
        let key = owner.to_ascii_lowercase();
        if let Some(t) = self.cached_token(&key) {
            return Ok(Some(t));
        }
        let _guard = self.mint_lock.lock().await;
        if let Some(t) = self.cached_token(&key) {
            return Ok(Some(t));
        }
        let Some(id) = self.installation_id(owner).await? else { return Ok(None) };
        let path = format!("app/installations/{id}/access_tokens");
        let (status, body) = self.app_request(reqwest::Method::POST, &path).await?;
        if status == 404 {
            // Uninstalled since we cached the id: forget it and report "not installed".
            self.installations.lock().remove(&key);
            return Ok(None);
        }
        if status != 201 {
            return Err(GithubApiError::ApiFailed { method: "POST".into(), path, status, detail: body.to_string().chars().take(300).collect() });
        }
        let token = body.get("token").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        if token.is_empty() {
            return Err(GithubApiError::ApiFailed { method: "POST".into(), path, status, detail: "response carried no token".into() });
        }
        let expires = body.get("expires_at").and_then(|v| v.as_str()).and_then(parse_expires_at).unwrap_or_else(|| now_secs() + 3600);
        self.tokens.lock().insert(key, (token.clone(), expires));
        Ok(Some(token))
    }

    /// `GET /app` signed with the App JWT: proves the private key belongs to
    /// this App ID (GitHub answers 401 otherwise) and returns the App's
    /// public metadata (`slug`, `name`, `html_url`, ...).
    pub async fn app_info(&self) -> Result<Value, GithubApiError> {
        let (status, body) = self.app_request(reqwest::Method::GET, "app").await?;
        if status != 200 {
            return Err(GithubApiError::ApiFailed { method: "GET".into(), path: "app".into(), status, detail: body.to_string().chars().take(300).collect() });
        }
        Ok(body)
    }

    /// Forgets cached tokens and installation ids (e.g. after the App was
    /// installed on a new org).
    pub fn clear_cache(&self) {
        self.installations.lock().clear();
        self.tokens.lock().clear();
    }
}

/// For standalone CLIs (`scheduled-rescan`, `org-onboard`): an installation
/// token for `owner` when a GitHub App is configured via env and installed
/// there, otherwise the plain `GH_TOKEN`/`GITHUB_TOKEN`.
pub async fn resolve_token_for_owner_from_env(owner: &str) -> String {
    static APP: once_cell::sync::OnceCell<Option<GithubAppAuth>> = once_cell::sync::OnceCell::new();
    let app = APP.get_or_init(|| match GithubAppAuth::from_env() {
        Some(Ok(app)) => Some(app),
        Some(Err(e)) => {
            eprintln!("GitHub App disabled: {e}");
            None
        }
        None => None,
    });
    if let Some(app) = app {
        match app.installation_token(owner).await {
            Ok(Some(t)) => return t,
            Ok(None) => {}
            Err(e) => eprintln!("GitHub App token for {owner} unavailable, falling back to GH_TOKEN: {e}"),
        }
    }
    crate::resolve_server_github_token()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_github_expiry_timestamps() {
        assert_eq!(parse_expires_at("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_expires_at("2026-09-29T12:00:00Z"), Some(1_790_683_200));
        assert_eq!(parse_expires_at("2024-02-29T23:59:59Z"), Some(1_709_251_199));
        assert_eq!(parse_expires_at("not a date"), None);
    }

    #[test]
    fn rejects_a_non_numeric_app_id_and_a_bad_key() {
        assert!(GithubAppAuth::new("my-app", b"x").is_err());
        assert!(GithubAppAuth::new("12345", b"-----BEGIN RSA PRIVATE KEY-----\nnope\n-----END RSA PRIVATE KEY-----\n").is_err());
    }
}
