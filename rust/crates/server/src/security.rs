//! Port of `server.js`'s two app-level security middlewares (server.js:77-104):
//! `helmet(...)`'s security-header set (customized CSP,
//! `crossOriginEmbedderPolicy: false`), and a coarse `express-rate-limit`
//! backstop on the `/api` prefix. Both are process-wide `axum::middleware`
//! layers, not per-route state, matching how Express mounts them before any
//! route handler.

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `helmet`'s default header set plus the CSP directives/`crossOriginEmbedderPolicy: false`
/// override server.js passes explicitly. See server.js:70-92 for the
/// rationale on `'unsafe-inline'`/the CDN allowance and the disabled COEP.
pub async fn security_headers_middleware(req: Request<Body>, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'self';script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com;style-src 'self' 'unsafe-inline';img-src 'self' data:;connect-src 'self';object-src 'none';frame-ancestors 'none';base-uri 'self';form-action 'self'",
        ),
    );
    headers.insert("Cross-Origin-Opener-Policy", HeaderValue::from_static("same-origin"));
    headers.insert("Cross-Origin-Resource-Policy", HeaderValue::from_static("same-origin"));
    headers.insert("Origin-Agent-Cluster", HeaderValue::from_static("?1"));
    headers.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    headers.insert("Strict-Transport-Security", HeaderValue::from_static("max-age=15552000; includeSubDomains"));
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-DNS-Prefetch-Control", HeaderValue::from_static("off"));
    headers.insert("X-Download-Options", HeaderValue::from_static("noopen"));
    headers.insert("X-Frame-Options", HeaderValue::from_static("SAMEORIGIN"));
    headers.insert("X-Permitted-Cross-Domain-Policies", HeaderValue::from_static("none"));
    headers.insert("X-XSS-Protection", HeaderValue::from_static("0"));
    // crossOriginEmbedderPolicy: false in the Node config — deliberately no
    // Cross-Origin-Embedder-Policy header (would block the non-CORS
    // <script src="https://cdn.tailwindcss.com"> tag public/index.html uses).
    res
}

const WINDOW: Duration = Duration::from_secs(60);
const MAX_REQUESTS: u32 = 300;

/// Fixed-window per-IP counter mirroring `express-rate-limit`'s
/// `{ windowMs: 60_000, max: 300, standardHeaders: true, legacyHeaders: false }`
/// (server.js:99-104) closely enough for its stated purpose — a loose
/// backstop against one client hammering `/api`, not a precise sliding-window
/// implementation.
#[derive(Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

struct Decision {
    allowed: bool,
    remaining: u32,
    reset_secs: u64,
}

impl RateLimiter {
    fn check(&self, ip: IpAddr) -> Decision {
        let mut windows = self.windows.lock().unwrap();
        let now = Instant::now();
        let entry = windows.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= WINDOW {
            *entry = (now, 0);
        }
        entry.1 += 1;
        let reset_secs = WINDOW.saturating_sub(now.duration_since(entry.0)).as_secs();
        if entry.1 > MAX_REQUESTS {
            Decision { allowed: false, remaining: 0, reset_secs }
        } else {
            Decision { allowed: true, remaining: MAX_REQUESTS - entry.1, reset_secs }
        }
    }
}

/// Only `/api`-prefixed paths are limited, matching `app.use('/api',
/// rateLimit(...))` — everything else (static assets, non-API routes) is
/// unaffected.
pub async fn rate_limit_middleware(
    State(limiter): State<std::sync::Arc<RateLimiter>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if !req.uri().path().starts_with("/api") {
        return next.run(req).await;
    }
    let decision = limiter.check(addr.ip());
    if !decision.allowed {
        let mut res = (StatusCode::TOO_MANY_REQUESTS, "Too many requests, please try again later.").into_response();
        res.headers_mut().insert("RateLimit-Limit", HeaderValue::from(MAX_REQUESTS));
        res.headers_mut().insert("RateLimit-Remaining", HeaderValue::from(0));
        res.headers_mut().insert("RateLimit-Reset", HeaderValue::from(decision.reset_secs));
        return res;
    }
    let mut res = next.run(req).await;
    res.headers_mut().insert("RateLimit-Limit", HeaderValue::from(MAX_REQUESTS));
    res.headers_mut().insert("RateLimit-Remaining", HeaderValue::from(decision.remaining));
    res.headers_mut().insert("RateLimit-Reset", HeaderValue::from(decision.reset_secs));
    res
}
