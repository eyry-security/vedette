//! Probing logic: turn an input host into a [`ProbeResult`].

use crate::model::ProbeResult;
use aho_corasick::AhoCorasick;
use futures::StreamExt;
use regex::Regex;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Options that shape how each host is probed.
#[derive(Clone)]
pub struct ProbeOptions {
    /// Schemes to try for a bare host (e.g. `["https", "http"]`). One entry means
    /// no racing; two means https and http are probed concurrently (https wins).
    pub schemes: Vec<String>,
    /// Retries per attempt after the first send fails at the connection level.
    pub retries: u32,
    /// Stop reading the body after this many bytes (0 = unlimited). Bounds transfer,
    /// hashing, and parsing cost. Enough for `<title>` and tech markers.
    pub max_body: usize,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        ProbeOptions {
            schemes: vec!["https".into(), "http".into()],
            retries: 1,
            max_body: 512 * 1024,
        }
    }
}

struct Target {
    host: String,
    /// Ordered (scheme, port) candidates.
    candidates: Vec<(String, u16)>,
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "http" {
        80
    } else {
        443
    }
}

fn parse_input(input: &str, schemes: &[String]) -> Target {
    let trimmed = input.trim();

    if let Some(idx) = trimmed.find("://") {
        let scheme = trimmed[..idx].to_lowercase();
        let rest = &trimmed[idx + 3..];
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        let (host, port) = split_host_port(authority, &scheme);
        return Target {
            host,
            candidates: vec![(scheme, port)],
        };
    }

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

/// Normalize a header value into something worth storing: trim, strip a single
/// layer of surrounding quotes, and reject values with no useful content
/// (empty, quote-only, or punctuation-only like `''`).
fn clean_header(value: &str) -> Option<String> {
    let mut v = value.trim();
    if (v.starts_with('"') && v.ends_with('"') && v.len() >= 2)
        || (v.starts_with('\'') && v.ends_with('\'') && v.len() >= 2)
    {
        v = &v[1..v.len() - 1];
        v = v.trim();
    }
    if v.is_empty() || !v.chars().any(|c| c.is_alphanumeric()) {
        return None;
    }
    Some(v.chars().take(120).collect())
}

/// Body markers → tech name, compiled once into a case-insensitive automaton.
const MARKERS: &[(&str, &str)] = &[
    ("wp-content", "WordPress"),
    ("/_next/", "Next.js"),
    ("__nuxt", "Nuxt.js"),
    ("ng-version", "Angular"),
    ("drupal-settings-json", "Drupal"),
    ("joomla", "Joomla"),
    ("x-shopify", "Shopify"),
    ("grafana", "Grafana"),
    ("kibana", "Kibana"),
    ("phpmyadmin", "phpMyAdmin"),
    ("jenkins", "Jenkins"),
    ("swagger-ui", "Swagger"),
];

fn tech_matcher() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(MARKERS.iter().map(|(needle, _)| *needle))
            .expect("valid patterns")
    })
}

/// Best-effort tech fingerprint from headers and the (raw) body bytes.
/// Single case-insensitive pass over the body, no lowercase allocation.
fn detect_tech(server: Option<&str>, powered_by: Option<&str>, body: &[u8]) -> Vec<String> {
    let mut tech = Vec::new();
    if let Some(s) = server {
        tech.push(s.to_string());
    }
    if let Some(p) = powered_by {
        if !tech.iter().any(|t| t == p) {
            tech.push(p.to_string());
        }
    }
    let matched: HashSet<usize> = tech_matcher()
        .find_iter(body)
        .map(|m| m.pattern().as_usize())
        .collect();
    for (idx, (_, name)) in MARKERS.iter().enumerate() {
        if matched.contains(&idx) && !tech.iter().any(|t| t == name) {
            tech.push((*name).to_string());
        }
    }
    tech
}

fn build_url(scheme: &str, host: &str, port: u16) -> String {
    if port == default_port(scheme) {
        format!("{scheme}://{host}/")
    } else {
        format!("{scheme}://{host}:{port}/")
    }
}

/// Attempt one scheme/port. Returns a full [`ProbeResult`] (minus `ips`, filled
/// by the caller) on any HTTP response, or an error string if it never responded.
async fn attempt_one(
    client: &Client,
    input: &str,
    host: &str,
    scheme: &str,
    port: u16,
    retries: u32,
    max_body: usize,
) -> Result<ProbeResult, String> {
    let url = build_url(scheme, host, port);
    let mut attempt = 0;
    let started = Instant::now();

    let resp = loop {
        match client.get(&url).send().await {
            Ok(resp) => break resp,
            Err(e) => {
                if attempt >= retries {
                    return Err(e.to_string());
                }
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(120)).await;
            }
        }
    };

    let status = resp.status().as_u16();
    let final_url = resp.url().clone();

    let header = |name: &str| -> Option<String> {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };
    let server = header("server").and_then(|s| clean_header(&s));
    let powered_by = header("x-powered-by").and_then(|s| clean_header(&s));
    let content_type = header("content-type");
    let header_len = header("content-length").and_then(|v| v.parse::<u64>().ok());

    // Stream the body only up to max_body, then stop (drops the connection).
    let mut body: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                if max_body > 0 {
                    let remaining = max_body.saturating_sub(body.len());
                    if remaining == 0 {
                        break;
                    }
                    let take = remaining.min(bytes.len());
                    body.extend_from_slice(&bytes[..take]);
                    if body.len() >= max_body {
                        break;
                    }
                } else {
                    body.extend_from_slice(&bytes);
                }
            }
            Err(_) => break,
        }
    }
    let elapsed = started.elapsed().as_millis();

    let mut hasher = Sha256::new();
    hasher.update(&body);
    let body_sha256 = hex::encode(hasher.finalize());

    // Title lives in <head>; scan a generous prefix (covers heavy heads like
    // GitHub) without decoding the whole capped body to UTF-8.
    let head = &body[..body.len().min(128 * 1024)];
    let title = extract_title(&String::from_utf8_lossy(head));
    let tech = detect_tech(server.as_deref(), powered_by.as_deref(), &body);

    let redirected =
        final_url.host_str() != Some(host) || final_url.scheme() != scheme || final_url.path() != "/";

    Ok(ProbeResult {
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
        content_length: header_len.or(Some(body.len() as u64)),
        redirects: Some(if redirected { 1 } else { 0 }),
        ips: Vec::new(),
        tech,
        body_sha256: Some(body_sha256),
        response_time_ms: Some(elapsed),
        error: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Probe a single input host. For a bare host with two schemes, https and http
/// are raced concurrently: https is preferred, http runs in parallel so http-only
/// and dead hosts don't pay a second serial timeout.
pub async fn probe(
    client: Arc<Client>,
    dns: &crate::resolver::Dns,
    input: &str,
    opts: &ProbeOptions,
) -> ProbeResult {
    let target = parse_input(input, &opts.schemes);

    // Resolve first. No records → no point attempting HTTP (saves connect timeouts
    // on stale/dead hosts). reqwest reuses this resolver's cache when connecting.
    let ips = dns.lookup(&target.host).await;
    if ips.is_empty() {
        return ProbeResult::failed(input, &target.host, "dns: no records");
    }

    let retries = opts.retries;
    let max_body = opts.max_body;

    let mut result = if target.candidates.len() == 1 {
        let (scheme, port) = &target.candidates[0];
        match attempt_one(&client, input, &target.host, scheme, *port, retries, max_body).await {
            Ok(r) => r,
            Err(e) => ProbeResult::failed(input, &target.host, e),
        }
    } else {
        // Two candidates: race https (preferred) against http.
        let (s0, p0) = target.candidates[0].clone();
        let (s1, p1) = target.candidates[1].clone();

        let primary = attempt_one(&client, input, &target.host, &s0, p0, retries, max_body);
        let secondary = attempt_one(&client, input, &target.host, &s1, p1, retries, max_body);
        tokio::pin!(primary, secondary);

        let mut secondary_result: Option<Result<ProbeResult, String>> = None;
        loop {
            tokio::select! {
                biased;
                r = &mut primary => {
                    match r {
                        Ok(res) => break res,               // https won; secondary is dropped/cancelled
                        Err(e0) => {
                            // https failed; use whatever http gives us.
                            let r1 = match secondary_result.take() {
                                Some(v) => v,
                                None => (&mut secondary).await,
                            };
                            break match r1 {
                                Ok(res) => res,
                                Err(e1) => ProbeResult::failed(input, &target.host, format!("{e0}; {e1}")),
                            };
                        }
                    }
                }
                r = &mut secondary, if secondary_result.is_none() => {
                    // http finished first, but we prefer https: stash and keep waiting.
                    secondary_result = Some(r);
                }
            }
        }
    };

    result.ips = ips;
    result
}
