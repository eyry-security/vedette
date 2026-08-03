//! Output schema for a single probe result.
//!
//! This is the shared host/service record the rest of the Eyry suite speaks
//! (Purser queue payloads, Aplomado scanner input). Keep it stable and additive.

use serde::Serialize;

/// The result of probing one input host.
///
/// Serialized as a single line of JSON (JSONL) so results stream and pipe cleanly.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    /// The raw input line we were given (e.g. `admin.example.com`).
    pub input: String,

    /// Whether we got any HTTP response at all.
    pub ok: bool,

    /// Final URL after following redirects (the one that produced the response).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,

    pub host: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,

    /// Number of redirects followed to reach `url`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirects: Option<usize>,

    /// Resolved IP addresses for the host.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<String>,

    /// Best-effort technology guesses (from headers + body markers).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tech: Vec<String>,

    /// SHA-256 of the response body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_sha256: Option<String>,

    /// Round-trip time for the successful request, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time_ms: Option<u128>,

    /// Populated when `ok` is false: the last error encountered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// RFC 3339 timestamp of when the probe completed.
    pub timestamp: String,
}

impl ProbeResult {
    /// Build a failed result for `input`/`host` with an error message.
    pub fn failed(input: &str, host: &str, error: impl Into<String>) -> Self {
        ProbeResult {
            input: input.to_string(),
            ok: false,
            url: None,
            scheme: None,
            host: host.to_string(),
            port: None,
            status: None,
            title: None,
            server: None,
            content_type: None,
            content_length: None,
            redirects: None,
            ips: Vec::new(),
            tech: Vec::new(),
            body_sha256: None,
            response_time_ms: None,
            error: Some(error.into()),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}
