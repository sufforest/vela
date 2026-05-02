//! Matrix server name resolution per `server-server-api.md:94-215`.
//!
//! Six-step algorithm:
//! 1. **IP literal** (optionally with port) — connect directly.
//! 2. **Hostname with explicit port** — A/AAAA on the hostname; use given port.
//! 3. **`.well-known/matrix/server` delegation** — fetch and recurse on the
//!    delegated target.
//! 4. **SRV `_matrix-fed._tcp.{hostname}`** (v1.8+).
//! 5. **SRV `_matrix._tcp.{hostname}`** (deprecated, only if step 4 fails).
//! 6. **Fallback**: A/AAAA on hostname, port 8448.
//!
//! Important spec constraints:
//! - The X-Matrix `origin` field is always the *original* server_name before
//!   any delegation — handled by callers, not this resolver.
//! - Delegation via `.well-known` does NOT affect the `origin`/`destination`
//!   fields used in signed requests.
//!
//! This module covers resolution only. Connection setup (how reqwest should
//! use a `ResolvedServer`) is left to the caller.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, warn};

use crate::federation_client::now_ms;

/// A resolved federation target.
///
/// Fields follow spec conventions (§3.1–3.6):
/// - `target_host` + `target_port`: where to open the TCP connection.
/// - `tls_server_name`: SNI + cert validation hostname. Equals `target_host`
///   for direct connections but differs for SRV / `.well-known` delegation,
///   where SNI must be the ORIGINAL server_name per spec.
/// - `host_header`: value of the HTTP `Host` header per spec.
/// - `resolved_ips`: pre-resolved A/AAAA addresses for `target_host`. Used to
///   override reqwest's DNS: the URL carries `tls_server_name` (so SNI is
///   correct), and the reqwest client maps that hostname to these IPs (so we
///   connect to the right place). Empty for IP-literal targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedServer {
    pub target_host: String,
    pub target_port: u16,
    pub tls_server_name: String,
    pub host_header: String,
    pub resolved_ips: Vec<std::net::IpAddr>,
}

impl ResolvedServer {
    /// URL prefix for federation requests to this server. Uses `tls_server_name`
    /// as the host so reqwest derives SNI correctly; callers arrange for the
    /// DNS mapping via `ClientBuilder::resolve(tls_server_name, ip:port)`.
    pub fn base_url(&self) -> String {
        format!("https://{}:{}", self.tls_server_name, self.target_port)
    }

    /// SocketAddr pairs suitable for `reqwest::ClientBuilder::resolve`.
    pub fn socket_addrs(&self) -> Vec<std::net::SocketAddr> {
        self.resolved_ips
            .iter()
            .map(|ip| std::net::SocketAddr::new(*ip, self.target_port))
            .collect()
    }
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("invalid server_name: {0}")]
    InvalidServerName(String),
    #[error("dns lookup failed: {0}")]
    DnsFailure(String),
    #[error("well-known fetch failed: {0}")]
    WellKnownFailure(String),
    #[error("well-known response malformed")]
    WellKnownMalformed,
    #[error("well-known redirect chain too deep")]
    WellKnownTooDeep,
}

/// Default `.well-known` cache lifetime (24h per spec recommendation).
const WELL_KNOWN_DEFAULT_TTL_MS: u64 = 24 * 60 * 60 * 1000;
/// Maximum `.well-known` cache lifetime (48h per spec recommendation).
const WELL_KNOWN_MAX_TTL_MS: u64 = 48 * 60 * 60 * 1000;
/// Negative cache lifetime on `.well-known` failure (1h per spec recommendation).
const WELL_KNOWN_NEG_TTL_MS: u64 = 60 * 60 * 1000;
/// Limit well-known recursion depth (a server delegating to itself would loop).
const WELL_KNOWN_MAX_DEPTH: u8 = 2;

#[derive(Debug, Clone)]
struct CachedWellKnown {
    /// `m.server` value from the response, or `None` if lookup failed (negative cache).
    delegated: Option<String>,
    expires_at_ms: u64,
}

/// Federation server name resolver.
pub struct FederationResolver {
    dns: Arc<TokioResolver>,
    well_known: DashMap<String, CachedWellKnown>,
    http: Client,
}

impl FederationResolver {
    pub fn new() -> Result<Self, ResolveError> {
        let mut builder = TokioResolver::builder_with_config(
            ResolverConfig::default(),
            TokioRuntimeProvider::default(),
        );
        *builder.options_mut() = ResolverOpts::default();
        let dns = builder
            .build()
            .map_err(|e| ResolveError::WellKnownFailure(format!("dns resolver build: {e}")))?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("vela/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ResolveError::WellKnownFailure(e.to_string()))?;
        Ok(Self {
            dns: Arc::new(dns),
            well_known: DashMap::new(),
            http,
        })
    }

    /// Resolve a server name to a target. Implements the 6-step spec algorithm.
    pub async fn resolve(&self, server_name: &str) -> Result<ResolvedServer, ResolveError> {
        self.resolve_inner(server_name, 0).await
    }

    async fn resolve_inner(
        &self,
        server_name: &str,
        depth: u8,
    ) -> Result<ResolvedServer, ResolveError> {
        if depth > WELL_KNOWN_MAX_DEPTH {
            return Err(ResolveError::WellKnownTooDeep);
        }

        let parsed = parse_server_name(server_name)?;

        // Step 1: IP literal
        if let Some(ip) = parsed.ip {
            let port = parsed.port.unwrap_or(8448);
            let target_host = format_ip_for_url(ip);
            return Ok(ResolvedServer {
                target_host: target_host.clone(),
                target_port: port,
                tls_server_name: target_host,
                host_header: server_name.to_string(),
                // IP-literal case: no resolve override needed; reqwest connects
                // directly to the IP URL. Empty Vec signals "use URL as-is."
                resolved_ips: vec![ip],
            });
        }

        let hostname = parsed.hostname.as_deref().expect("non-IP implies hostname");

        // Step 2: hostname with explicit port
        if let Some(port) = parsed.port {
            let ips = self.lookup_host_ips(hostname).await;
            return Ok(ResolvedServer {
                target_host: hostname.to_string(),
                target_port: port,
                tls_server_name: hostname.to_string(),
                host_header: server_name.to_string(),
                resolved_ips: ips,
            });
        }

        // Step 3: .well-known delegation (bare hostname, no port)
        if depth == 0 {
            // Only check well-known for the ORIGINAL server_name, not recursed targets.
            if let Some(delegated) = self.lookup_well_known(hostname).await {
                debug!(%hostname, %delegated, "following .well-known delegation");
                // Recurse on the delegated target (may itself be IP:port / host:port / bare).
                // Per spec, the delegated target's host_header should be the DELEGATED server name
                // (with port if applicable), NOT the original.
                return Box::pin(self.resolve_inner(&delegated, depth + 1)).await;
            }
        }

        // Step 4: SRV _matrix-fed._tcp
        let srv_name = format!("_matrix-fed._tcp.{}", hostname);
        if let Some((srv_target, srv_port)) = self.lookup_srv(&srv_name).await {
            let ips = self.lookup_host_ips(&srv_target).await;
            return Ok(ResolvedServer {
                target_host: srv_target,
                target_port: srv_port,
                // Per spec: SNI + Host header use the original hostname, NOT the SRV target.
                tls_server_name: hostname.to_string(),
                host_header: hostname.to_string(),
                resolved_ips: ips,
            });
        }

        // Step 5: deprecated SRV _matrix._tcp
        let srv_name_legacy = format!("_matrix._tcp.{}", hostname);
        if let Some((srv_target, srv_port)) = self.lookup_srv(&srv_name_legacy).await {
            warn!(%hostname, "using deprecated _matrix._tcp SRV record");
            let ips = self.lookup_host_ips(&srv_target).await;
            return Ok(ResolvedServer {
                target_host: srv_target,
                target_port: srv_port,
                tls_server_name: hostname.to_string(),
                host_header: hostname.to_string(),
                resolved_ips: ips,
            });
        }

        // Step 6: fallback — A/AAAA at port 8448
        let ips = self.lookup_host_ips(hostname).await;
        Ok(ResolvedServer {
            target_host: hostname.to_string(),
            target_port: 8448,
            tls_server_name: hostname.to_string(),
            host_header: hostname.to_string(),
            resolved_ips: ips,
        })
    }

    /// A/AAAA lookup for a hostname. Returns empty Vec on failure — callers
    /// fall back to reqwest's own DNS, which is fine when `tls_server_name`
    /// equals `target_host` (the hostname resolves directly).
    async fn lookup_host_ips(&self, hostname: &str) -> Vec<std::net::IpAddr> {
        match self.dns.lookup_ip(hostname).await {
            Ok(resp) => resp.iter().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Fetch and cache `.well-known/matrix/server`. Returns the delegated target
    /// (a server_name, possibly with port) or `None` if the lookup failed or
    /// the server has no well-known (both are cached negatively for 1h).
    async fn lookup_well_known(&self, hostname: &str) -> Option<String> {
        let now = now_ms();

        // Check cache
        if let Some(entry) = self.well_known.get(hostname) {
            if entry.expires_at_ms > now {
                return entry.delegated.clone();
            }
            drop(entry);
            self.well_known.remove(hostname);
        }

        // Fetch
        let url = format!("https://{hostname}/.well-known/matrix/server");
        let result = self.http.get(&url).send().await;
        let (delegated, ttl_ms) = match result {
            Ok(resp) if resp.status().is_success() => {
                // Compute cache TTL from Cache-Control: max-age, clamped to 48h.
                let ttl = resp
                    .headers()
                    .get("cache-control")
                    .and_then(|v| v.to_str().ok())
                    .and_then(parse_max_age_seconds)
                    .map(|secs| (secs * 1000).min(WELL_KNOWN_MAX_TTL_MS))
                    .unwrap_or(WELL_KNOWN_DEFAULT_TTL_MS);

                match resp.json::<WellKnownBody>().await {
                    Ok(body) => {
                        if body.m_server.is_empty() {
                            (None, WELL_KNOWN_NEG_TTL_MS)
                        } else {
                            (Some(body.m_server), ttl)
                        }
                    }
                    Err(e) => {
                        warn!(%hostname, error = %e, "well-known body malformed");
                        (None, WELL_KNOWN_NEG_TTL_MS)
                    }
                }
            }
            _ => (None, WELL_KNOWN_NEG_TTL_MS),
        };

        self.well_known.insert(
            hostname.to_string(),
            CachedWellKnown {
                delegated: delegated.clone(),
                expires_at_ms: now + ttl_ms,
            },
        );

        delegated
    }

    async fn lookup_srv(&self, name: &str) -> Option<(String, u16)> {
        match self.dns.srv_lookup(name).await {
            Ok(lookup) => {
                use hickory_resolver::proto::rr::RData;
                // hickory v0.26 returns generic Records via `Lookup::answers()`;
                // pull out the SRV-typed records ourselves. Sort by priority
                // ascending then weight descending (RFC 2782 — weighted
                // random selection within a priority is overkill for a
                // single-pick resolver, take top-priority).
                let mut recs: Vec<_> = lookup
                    .answers()
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::SRV(srv) => Some(srv.clone()),
                        _ => None,
                    })
                    .collect();
                recs.sort_by(|a, b| a.priority.cmp(&b.priority).then(b.weight.cmp(&a.weight)));
                recs.first().map(|r| {
                    let target = r.target.to_utf8();
                    // hickory appends a trailing "." to FQDNs; strip it.
                    let target = target.trim_end_matches('.').to_string();
                    (target, r.port)
                })
            }
            Err(_) => None,
        }
    }

    /// Test-only: pre-seed the well-known cache.
    #[cfg(test)]
    pub fn seed_well_known(&self, hostname: &str, delegated: Option<String>, ttl_ms: u64) {
        self.well_known.insert(
            hostname.to_string(),
            CachedWellKnown {
                delegated,
                expires_at_ms: now_ms() + ttl_ms,
            },
        );
    }
}

/// Parsed server_name components.
struct ParsedServerName {
    ip: Option<IpAddr>,
    hostname: Option<String>,
    port: Option<u16>,
}

/// Parse a Matrix server_name. Grammar per `appendices.md:444-507`.
fn parse_server_name(server_name: &str) -> Result<ParsedServerName, ResolveError> {
    if server_name.is_empty() {
        return Err(ResolveError::InvalidServerName("empty".into()));
    }

    // IPv6 literal: `[addr]` or `[addr]:port`
    if let Some(rest) = server_name.strip_prefix('[') {
        let (addr_str, port_str) = match rest.split_once(']') {
            Some((a, p)) => (a, p),
            None => return Err(ResolveError::InvalidServerName(server_name.into())),
        };
        let ip: IpAddr = addr_str
            .parse()
            .map_err(|_| ResolveError::InvalidServerName(server_name.into()))?;
        let port = if port_str.is_empty() {
            None
        } else if let Some(p) = port_str.strip_prefix(':') {
            Some(
                p.parse()
                    .map_err(|_| ResolveError::InvalidServerName(server_name.into()))?,
            )
        } else {
            return Err(ResolveError::InvalidServerName(server_name.into()));
        };
        return Ok(ParsedServerName {
            ip: Some(ip),
            hostname: None,
            port,
        });
    }

    // IPv4 or hostname; optional :port
    let (host, port) = match server_name.rsplit_once(':') {
        Some((h, p)) => {
            let parsed_port = p
                .parse::<u16>()
                .map_err(|_| ResolveError::InvalidServerName(server_name.into()))?;
            (h, Some(parsed_port))
        }
        None => (server_name, None),
    };

    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ParsedServerName {
            ip: Some(ip),
            hostname: None,
            port,
        });
    }

    if host.is_empty() {
        return Err(ResolveError::InvalidServerName(server_name.into()));
    }

    Ok(ParsedServerName {
        ip: None,
        hostname: Some(host.to_string()),
        port,
    })
}

/// Format an IP for a URL host, wrapping IPv6 in brackets.
fn format_ip_for_url(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{}]", v6),
    }
}

#[derive(Debug, Deserialize)]
struct WellKnownBody {
    #[serde(rename = "m.server")]
    m_server: String,
}

/// Parse `max-age=N` from a Cache-Control header value.
fn parse_max_age_seconds(value: &str) -> Option<u64> {
    for directive in value.split(',') {
        let directive = directive.trim();
        if let Some(n) = directive.strip_prefix("max-age=") {
            return n.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_hostname() {
        let p = parse_server_name("example.com").unwrap();
        assert!(p.ip.is_none());
        assert_eq!(p.hostname.as_deref(), Some("example.com"));
        assert_eq!(p.port, None);
    }

    #[test]
    fn parse_hostname_with_port() {
        let p = parse_server_name("example.com:8090").unwrap();
        assert_eq!(p.hostname.as_deref(), Some("example.com"));
        assert_eq!(p.port, Some(8090));
    }

    #[test]
    fn parse_ipv4_literal() {
        let p = parse_server_name("1.2.3.4").unwrap();
        assert_eq!(p.ip.unwrap().to_string(), "1.2.3.4");
        assert_eq!(p.port, None);
    }

    #[test]
    fn parse_ipv4_with_port() {
        let p = parse_server_name("1.2.3.4:8448").unwrap();
        assert_eq!(p.ip.unwrap().to_string(), "1.2.3.4");
        assert_eq!(p.port, Some(8448));
    }

    #[test]
    fn parse_ipv6_literal() {
        let p = parse_server_name("[::1]").unwrap();
        assert_eq!(p.ip.unwrap().to_string(), "::1");
        assert_eq!(p.port, None);
    }

    #[test]
    fn parse_ipv6_with_port() {
        let p = parse_server_name("[fd00::1]:8448").unwrap();
        assert_eq!(p.ip.unwrap().to_string(), "fd00::1");
        assert_eq!(p.port, Some(8448));
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(parse_server_name("").is_err());
    }

    #[test]
    fn parse_rejects_bad_port() {
        assert!(parse_server_name("example.com:not-a-port").is_err());
    }

    #[tokio::test]
    async fn resolve_ip_literal_uses_default_port() {
        let r = FederationResolver::new().unwrap();
        let resolved = r.resolve("1.2.3.4").await.unwrap();
        assert_eq!(resolved.target_host, "1.2.3.4");
        assert_eq!(resolved.target_port, 8448);
        assert_eq!(resolved.host_header, "1.2.3.4");
    }

    #[tokio::test]
    async fn resolve_ip_literal_preserves_port() {
        let r = FederationResolver::new().unwrap();
        let resolved = r.resolve("1.2.3.4:9000").await.unwrap();
        assert_eq!(resolved.target_host, "1.2.3.4");
        assert_eq!(resolved.target_port, 9000);
    }

    #[tokio::test]
    async fn resolve_ipv6_wraps_target_in_brackets() {
        let r = FederationResolver::new().unwrap();
        let resolved = r.resolve("[::1]:8448").await.unwrap();
        assert_eq!(resolved.target_host, "[::1]");
        assert_eq!(resolved.target_port, 8448);
    }

    #[tokio::test]
    async fn resolve_hostname_with_port_uses_port_directly() {
        // Step 2: explicit port means no .well-known, no SRV.
        let r = FederationResolver::new().unwrap();
        let resolved = r.resolve("nonexistent.example:8090").await.unwrap();
        assert_eq!(resolved.target_host, "nonexistent.example");
        assert_eq!(resolved.target_port, 8090);
        assert_eq!(resolved.host_header, "nonexistent.example:8090");
        assert_eq!(resolved.tls_server_name, "nonexistent.example");
    }

    #[tokio::test]
    async fn resolve_follows_well_known_delegation() {
        // Seed the cache directly to avoid real HTTP. The delegated target
        // has an explicit port, so it goes through step 2 and returns immediately.
        let r = FederationResolver::new().unwrap();
        r.seed_well_known(
            "example.com",
            Some("matrix.example.com:8090".into()),
            60_000,
        );
        let resolved = r.resolve("example.com").await.unwrap();
        assert_eq!(resolved.target_host, "matrix.example.com");
        assert_eq!(resolved.target_port, 8090);
        // After delegation, host_header follows the delegated name, not original.
        assert_eq!(resolved.host_header, "matrix.example.com:8090");
    }

    #[test]
    fn max_age_parser_handles_directives() {
        assert_eq!(parse_max_age_seconds("max-age=3600"), Some(3600));
        assert_eq!(
            parse_max_age_seconds("public, max-age=7200, must-revalidate"),
            Some(7200)
        );
        assert_eq!(parse_max_age_seconds("no-cache"), None);
        assert_eq!(parse_max_age_seconds(""), None);
    }

    #[test]
    fn resolved_server_base_url_uses_tls_server_name() {
        // Even when target_host differs (SRV delegation), base_url() must use
        // tls_server_name so reqwest derives the correct SNI.
        let r = ResolvedServer {
            target_host: "node1.internal".into(),
            target_port: 8443,
            tls_server_name: "example.com".into(),
            host_header: "example.com".into(),
            resolved_ips: vec!["10.0.0.1".parse().unwrap()],
        };
        assert_eq!(r.base_url(), "https://example.com:8443");
    }

    #[test]
    fn resolved_server_socket_addrs_uses_target_port() {
        use std::net::IpAddr;
        let r = ResolvedServer {
            target_host: "node1.internal".into(),
            target_port: 8443,
            tls_server_name: "example.com".into(),
            host_header: "example.com".into(),
            resolved_ips: vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()],
        };
        let addrs = r.socket_addrs();
        assert_eq!(addrs.len(), 2);
        for a in &addrs {
            assert_eq!(a.port(), 8443);
        }
        let ips: Vec<IpAddr> = addrs.iter().map(|a| a.ip()).collect();
        assert!(ips.contains(&"10.0.0.1".parse().unwrap()));
        assert!(ips.contains(&"10.0.0.2".parse().unwrap()));
    }
}
