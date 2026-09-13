//! GHAS-parity audit/SIEM log streaming (Milestone 3.3): GHAS's audit log
//! API lets a security team stream every governance-relevant event
//! (secret-scanning alert dismissed, branch protection changed, ...) into
//! their own SIEM. Ignite's audit trail (overrides, gate results, API key
//! creation) previously lived only in `ignite.db`, readable only through
//! Ignite's own UI/API — this crate formats those events and delivers them
//! asynchronously to configured HTTPS endpoints (Splunk HTTP Event
//! Collector, Datadog Logs intake, or a generic HTTPS JSON webhook).
//!
//! Deliberately best-effort/fire-and-forget, same posture as every other
//! "push to an external system" integration in this codebase (SARIF
//! upload, dependency-graph snapshot, PR sticky comments): a SIEM endpoint
//! being unreachable must never fail — or even slow down — the actual
//! gate/override/API-key operation that triggered the event. Callers
//! should `tokio::spawn` [`dispatch`] rather than `.await` it inline.
//!
//! An S3-destination sink (mentioned alongside Splunk/Datadog in the
//! original gap analysis) is deliberately not implemented here — it needs
//! SigV4 request signing (the same reason `secret-verifier` left AWS
//! token verification unimplemented), a materially different integration
//! than "POST JSON to an HTTPS URL". A generic HTTPS webhook already
//! covers any collector that fronts S3 with its own ingest endpoint.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// One governance-relevant fact worth streaming to a SIEM. Kept flat and
/// generic (not per-event-type structs) since every sink below just wants
/// "what happened, to what, by whom, how bad" — richer detail goes in
/// `metadata`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    /// Stable machine-readable kind, e.g. "override.approved",
    /// "gate.passed_with_overrides", "gate.push_rejected",
    /// "api_key.created".
    pub event_type: String,
    pub summary: String,
    /// "info" | "warning" | "critical" — drives CEF's numeric severity
    /// and a SIEM's own alert routing.
    pub severity: String,
    pub actor: Option<String>,
    pub org: Option<String>,
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
    /// RFC 3339 UTC, set by `AuditEvent::new` — never caller-supplied, so
    /// every event is timestamped at the moment it actually happened.
    pub timestamp: String,
}

impl AuditEvent {
    pub fn new(event_type: impl Into<String>, severity: impl Into<String>, summary: impl Into<String>) -> Self {
        AuditEvent {
            event_type: event_type.into(),
            summary: summary.into(),
            severity: severity.into(),
            actor: None,
            org: None,
            repo: None,
            metadata: Value::Null,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    pub fn repo(mut self, org: impl Into<String>, repo: impl Into<String>) -> Self {
        self.org = Some(org.into());
        self.repo = Some(repo.into());
        self
    }

    pub fn metadata(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self
    }

    /// CEF (Common Event Format) — the format most on-prem SIEMs (ArcSight
    /// and others) that accept CEF-over-HTTP collectors expect.
    /// `deviceEventClassId` is `event_type`; every other field rides in
    /// the extension as `key=value` pairs, matching CEF's own convention.
    fn to_cef(&self) -> String {
        let severity_num = match self.severity.as_str() {
            "critical" => 9,
            "warning" => 5,
            _ => 2,
        };
        // CEF is a single-line syslog record — an unescaped `\r`/`\n` in a
        // field (an event summary, an actor email, ...) splits the record
        // across multiple lines, corrupting the framing every downstream
        // syslog/CEF parser relies on. Escaped the same way CEF's own
        // spec-mandated `\`/`=`/`|` are, per convention (there's no
        // standard CEF escape for raw newlines otherwise).
        let escape = |s: &str| s.replace('\\', "\\\\").replace('=', "\\=").replace('|', "\\|").replace('\r', "\\r").replace('\n', "\\n");
        let mut ext = format!("msg={} rt={}", escape(&self.summary), escape(&self.timestamp));
        if let Some(actor) = &self.actor {
            ext.push_str(&format!(" suser={}", escape(actor)));
        }
        if let (Some(org), Some(repo)) = (&self.org, &self.repo) {
            ext.push_str(&format!(" cs1Label=repo cs1={}", escape(&format!("{org}/{repo}"))));
        }
        format!("CEF:0|Ignite|Ignite|1.0|{}|{}|{}|{}", escape(&self.event_type), escape(&self.summary), severity_num, ext)
    }
}

/// One configured delivery target. `kind` picks the request shape a real
/// collector expects — everything else about `dispatch` (retries: none,
/// timeout, error handling) stays uniform across kinds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditSink {
    pub url: String,
    #[serde(default)]
    pub kind: AuditSinkKind,
    /// Splunk HEC token (sent as `Authorization: Splunk <token>`) or
    /// Datadog API key (sent as `DD-API-KEY`) — meaningless for `Generic`.
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuditSinkKind {
    #[default]
    Generic,
    SplunkHec,
    Datadog,
    /// Body becomes a raw CEF string (`text/plain`) instead of JSON, for
    /// a collector fronting a CEF-over-HTTP or CEF-over-syslog bridge.
    Cef,
}

/// Builds the (headers, body) a real request to this sink needs, kept as
/// a pure function so the request-shaping logic is unit-testable without
/// a live HTTP server.
fn build_request(sink: &AuditSink, event: &AuditEvent) -> (Vec<(&'static str, String)>, String, &'static str) {
    match sink.kind {
        AuditSinkKind::Generic => (vec![], serde_json::to_string(event).unwrap_or_default(), "application/json"),
        AuditSinkKind::SplunkHec => {
            let mut headers = vec![];
            if let Some(token) = &sink.token {
                headers.push(("Authorization", format!("Splunk {token}")));
            }
            (headers, json!({ "event": event }).to_string(), "application/json")
        }
        AuditSinkKind::Datadog => {
            let mut headers = vec![];
            if let Some(token) = &sink.token {
                headers.push(("DD-API-KEY", token.clone()));
            }
            (headers, serde_json::to_string(event).unwrap_or_default(), "application/json")
        }
        AuditSinkKind::Cef => (vec![], event.to_cef(), "text/plain"),
    }
}

/// Delivers one event to every configured sink concurrently. Every
/// failure (network error, non-2xx) is logged via `tracing::warn!` and
/// otherwise swallowed — never propagated, per this crate's own
/// fire-and-forget contract.
/// A sink that hangs (never dropping the connection, never sending a
/// response) or is simply unreachable behind a firewall previously left
/// `req.send()` waiting forever — for the server's own fire-and-forget
/// `tokio::spawn` caller that's merely wasted background work, but
/// `create-api-key`'s blocking equivalent awaits this same dispatch
/// inline, so an operator's one-shot CLI command would simply never
/// return.
const SINK_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// A transient failure (429 rate limit, 5xx, or a network-level send
/// error) gets a couple of short-backoff retries before being logged and
/// dropped — a real SIEM outage lasting longer than that still loses the
/// event (this crate has no durable queue/storage to persist it for a
/// later flush, which would need its own DB-backed retry worker), but a
/// blip no longer drops an event it didn't have to.
const SINK_MAX_ATTEMPTS: u32 = 3;

fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

pub async fn dispatch(http: &reqwest::Client, sinks: &[AuditSink], event: &AuditEvent) {
    let sends = sinks.iter().map(|sink| async move {
        let (headers, body, content_type) = build_request(sink, event);
        for attempt in 1..=SINK_MAX_ATTEMPTS {
            let mut req = http.post(&sink.url).header("Content-Type", content_type).body(body.clone()).timeout(SINK_REQUEST_TIMEOUT);
            for (name, value) in &headers {
                req = req.header(*name, value);
            }
            match req.send().await {
                Ok(res) if res.status().is_success() => return,
                Ok(res) if is_retryable_status(res.status()) && attempt < SINK_MAX_ATTEMPTS => {
                    tracing::warn!(url = %sink.url, status = %res.status(), attempt, event_type = %event.event_type, "audit-log sink returned a retryable status, retrying");
                }
                Ok(res) => {
                    tracing::warn!(url = %sink.url, status = %res.status(), attempt, event_type = %event.event_type, "audit-log sink returned non-2xx, giving up");
                    return;
                }
                Err(e) if attempt < SINK_MAX_ATTEMPTS => {
                    tracing::warn!(url = %sink.url, error = %e, attempt, event_type = %event.event_type, "audit-log sink request failed, retrying");
                }
                Err(e) => {
                    tracing::warn!(url = %sink.url, error = %e, attempt, event_type = %event.event_type, "audit-log sink request failed, giving up");
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(200 * 2u64.pow(attempt - 1))).await;
        }
    });
    futures::future::join_all(sends).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_sink_sends_the_event_as_json_with_no_auth_headers() {
        let sink = AuditSink { url: "https://example.com/hook".into(), kind: AuditSinkKind::Generic, token: None };
        let event = AuditEvent::new("override.approved", "info", "license override approved").actor("dev@acme.example").repo("acme", "widgets");
        let (headers, body, content_type) = build_request(&sink, &event);
        assert!(headers.is_empty());
        assert_eq!(content_type, "application/json");
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["eventType"], "override.approved");
        assert_eq!(parsed["actor"], "dev@acme.example");
        assert_eq!(parsed["org"], "acme");
    }

    #[test]
    fn splunk_hec_sink_wraps_the_event_and_sets_auth_header() {
        let sink = AuditSink { url: "https://splunk.example.com/hec".into(), kind: AuditSinkKind::SplunkHec, token: Some("tok123".into()) };
        let event = AuditEvent::new("api_key.created", "warning", "headless API key minted");
        let (headers, body, _) = build_request(&sink, &event);
        assert_eq!(headers, vec![("Authorization", "Splunk tok123".to_string())]);
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["event"]["eventType"], "api_key.created");
    }

    #[test]
    fn datadog_sink_sets_dd_api_key_header() {
        let sink = AuditSink { url: "https://http-intake.logs.datadoghq.com/v1/input".into(), kind: AuditSinkKind::Datadog, token: Some("ddkey".into()) };
        let event = AuditEvent::new("gate.push_rejected", "critical", "blocking findings unresolved");
        let (headers, _, _) = build_request(&sink, &event);
        assert_eq!(headers, vec![("DD-API-KEY", "ddkey".to_string())]);
    }

    #[test]
    fn cef_sink_produces_a_well_formed_cef_line() {
        let sink = AuditSink { url: "https://example.com/cef".into(), kind: AuditSinkKind::Cef, token: None };
        let event = AuditEvent::new("gate.passed_with_overrides", "warning", "gate passed with 2 override(s)").actor("dev@acme.example").repo("acme", "widgets");
        let (_, body, content_type) = build_request(&sink, &event);
        assert_eq!(content_type, "text/plain");
        assert!(body.starts_with("CEF:0|Ignite|Ignite|1.0|gate.passed_with_overrides|gate passed with 2 override(s)|5|"));
        assert!(body.contains("suser=dev@acme.example"));
        assert!(body.contains("cs1=acme/widgets"));
    }

    #[test]
    fn cef_escapes_pipe_and_equals_in_free_text_fields() {
        let event = AuditEvent::new("test", "info", "a|weird=summary");
        let cef = event.to_cef();
        assert!(cef.contains("a\\|weird\\=summary"));
    }
}
