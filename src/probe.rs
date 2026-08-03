//! Probing logic: turn an input host into a [`ProbeResult`].

use crate::model::ProbeResult;
use regex::Regex;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Options that shape how each host is probed.
#[derive(Clone)]
pub struct ProbeOptions {
    /// Schemes to try, in order, for a bare host (e.g. `["https", "http"]`).
    pub schemes: Vec<String>,
    /// Retries per scheme after the first attempt.
    pub retries: u32,
    /// Cap the response body we read, in bytes (title + hash). 0 = no cap.
    pub max_body: usize,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        ProbeOptions {
            schemes: vec!["https".into(), "http".into()],
            retries: 1,
            max_body: 2 * 1024 * 1024,
        }
    }
}

/// A normalized probe target derived from one input line.
struct Target {
    host: String,
    /// Ordered (scheme, port) candidates to attempt.
    candidates: Vec<(String, u16)>,
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "http" {
        80
    } else {
        443
    }
}

/// Parse an input line into a target. Accepts `host`, `host:port`, or a full URL.
fn parse_input(input: &str, schemes: &[String]) -> Target {
    let trimmed = input.trim();

    // Full URL form: use it verbatim as the single candidate.
    if let Some(idx) = trimmed.find("://") {
        let scheme = trimmed[..idx].to_lowercase();
        let rest = &trimmed[idx + 3..];
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        let (host, port) = split_host_port(authority, &scheme);
        return Target {
            host: host.clone(),
            candidates: vec![(scheme, port)],
        };
    }

    // Bare `host` or `host:port`.
    let (host, explicit_port) = split_host_port_opt(trimmed);
    let candidates = match explicit_port {
        Some(port) => schemes.iter().map(|s| (s.clone(), port)).collect(),
        None => schemes
            .iter()
            .map(|s| (s.clone(), default_port(s)))
            .collect(),
    };
    Target { host, candidates }
}

fn split_host_port(authority: &str, scheme: &str) -> (String, u16) {
    let (h, p) = split_host_port_opt(authority);
    (h, p.unwrap_or_else(|| default_port(scheme)))
}

fn split_host_port_opt(authority: &str) -> (String, Option<u16>) {
    // Strip any leading userinfo (user:pass@host) just in case.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some((h, p)) = authority.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), Some(port));
        }
    }
    (authority.to_string(), None)
}

fn title_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap())
}

fn extract_title(body: &str) -> Option<String> {
    let caps = title_regex().captures(body)?;
    let raw = caps.get(1)?.as_str();
    let title = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if title.is_empty() {
        None
    } else {
        Some(title.chars().take(300).collect())
    }
}

/// Best-effort tech fingerprint from headers and a body snippet.
fn detect_tech(server: Option<&str>, powered_by: Option<&str>, body: &str) -> Vec<String> {
    let mut tech = Vec::new();
    if let Some(s) = server {
        if !s.is_empty() {
            tech.push(s.to_string());
        }
    }
    if let Some(p) = powered_by {
        if !p.is_empty() {
            tech.push(p.to_string());
        }
    }
    let lower = body.to_lowercase();
    let markers = [
        ("wp-content", "WordPress"),
        ("/_next/", "Next.js"),
        ("__nuxt", "Nuxt.js"),
        ("ng-version", "Angular"),
        ("react", "React"),
        ("drupal-settings-json", "Drupal"),
        ("joomla", "Joomla"),
        ("csrf-param", "Rails"),
        ("x-shopify", "Shopify"),
        ("grafana", "Grafana"),
        ("kibana", "Kibana"),
        ("phpmyadmin", "phpMyAdmin"),
        ("jenkins", "Jenkins"),
        ("swagger-ui", "Swagger"),
    ];
    for (needle, name) in markers {
        if lower.contains(needle) && !tech.iter().any(|t| t == name) {
            tech.push(name.to_string());
        }
    }
    tech
}

/// Resolve a host:port to a list of IP strings (deduped, best effort).
async fn resolve_ips(host: &str, port: u16) -> Vec<String> {
    match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => {
            let mut ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            ips.sort();
            ips.dedup();
            ips
        }
        Err(_) => Vec::new(),
    }
}

/// Probe a single input host, trying each scheme/port candidate until one responds.
pub async fn probe(client: &Client, input: &str, opts: &ProbeOptions) -> ProbeResult {
    let target = parse_input(input, &opts.schemes);
    let mut last_err = String::from("no candidates");

    for (scheme, port) in &target.candidates {
        let url = build_url(scheme, &target.host, *port);

        let mut attempt = 0;
        loop {
            let started = Instant::now();
            match client.get(&url).send().await {
                Ok(resp) => {
                    let elapsed = started.elapsed().as_millis();
                    return build_result(input, &target.host, scheme, *port, resp, elapsed, opts)
                        .await;
                }
                Err(e) => {
                    last_err = e.to_string();
                    if attempt >= opts.retries {
                        break;
                    }
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            }
        }
    }

    let mut result = ProbeResult::failed(input, &target.host, last_err);
    if let Some((_, port)) = target.candidates.first() {
        result.ips = resolve_ips(&target.host, *port).await;
    }
    result
}

fn build_url(scheme: &str, host: &str, port: u16) -> String {
    if port == default_port(scheme) {
        format!("{scheme}://{host}/")
    } else {
        format!("{scheme}://{host}:{port}/")
    }
}

async fn build_result(
    input: &str,
    host: &str,
    scheme: &str,
    port: u16,
    resp: reqwest::Response,
    elapsed_ms: u128,
    opts: &ProbeOptions,
) -> ProbeResult {
    let status = resp.status().as_u16();
    let final_url = resp.url().clone();

    let header = |name: &str| -> Option<String> {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };
    let server = header("server");
    let powered_by = header("x-powered-by");
    let content_type = header("content-type");
    let content_length = header("content-length").and_then(|v| v.parse::<u64>().ok());

    let ips = resolve_ips(host, port).await;

    // Read the body (capped) for title, tech, and hash.
    let full = resp.bytes().await.unwrap_or_default();
    let body_len = full.len();
    let body_bytes: &[u8] = if opts.max_body > 0 && full.len() > opts.max_body {
        &full[..opts.max_body]
    } else {
        &full[..]
    };
    let mut hasher = Sha256::new();
    hasher.update(body_bytes);
    let body_sha256 = hex::encode(hasher.finalize());

    let body_str = String::from_utf8_lossy(body_bytes);
    let title = extract_title(&body_str);
    let tech = detect_tech(server.as_deref(), powered_by.as_deref(), &body_str);

    let redirects = if final_url.host_str() != Some(host)
        || final_url.scheme() != scheme
        || final_url.path() != "/"
    {
        Some(1)
    } else {
        Some(0)
    };

    ProbeResult {
        input: input.to_string(),
        ok: true,
        url: Some(final_url.to_string()),
        scheme: Some(scheme.to_string()),
        host: host.to_string(),
        port: Some(port),
        status: Some(status),
        title,
        server,
        content_type,
        content_length: content_length.or(Some(body_len as u64)),
        redirects,
        ips,
        tech,
        body_sha256: Some(body_sha256),
        response_time_ms: Some(elapsed_ms),
        error: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

