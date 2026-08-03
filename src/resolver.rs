//! Async DNS. A single shared hickory resolver is used both for the `ips` field
//! and (via reqwest's `Resolve` trait) for connecting, so each host resolves
//! through one async, cached path instead of the blocking `getaddrinfo` pool.

use std::net::SocketAddr;
use std::sync::Arc;

use hickory_resolver::config::{LookupIpStrategy, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Shared async resolver. Cheap to clone (an `Arc` inside).
#[derive(Clone)]
pub struct Dns {
    resolver: Arc<TokioAsyncResolver>,
}

impl Dns {
    pub fn new() -> Self {
        let mut opts = ResolverOpts::default();
        // Hold in-flight hosts so the https+http race and the connect share one query.
        opts.cache_size = 4096;
        // Return both families, matching getaddrinfo behavior.
        opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);
        Dns {
            resolver: Arc::new(resolver),
        }
    }

    /// Resolve a host to a sorted, deduped list of IP strings (empty on failure).
    pub async fn lookup(&self, host: &str) -> Vec<String> {
        match self.resolver.lookup_ip(host).await {
            Ok(l) => {
                let mut v: Vec<String> = l.iter().map(|ip| ip.to_string()).collect();
                v.sort();
                v.dedup();
                v
            }
            Err(_) => Vec::new(),
        }
    }
}

impl Default for Dns {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolve for Dns {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let lookup = resolver.lookup_ip(name.as_str()).await?;
            let addrs: Addrs = Box::new(lookup.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}
