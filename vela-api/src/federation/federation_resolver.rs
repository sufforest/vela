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
//!
//! ## SSRF hardening
//!
//! A malicious peer can delegate (via `.well-known/matrix/server` or SRV)
//! to a name that resolves into the operator's internal network — e.g.
//! `10.0.0.1`, `127.0.0.1`, or a link-local address. Without mitigation,
//! our outbound federation client would obediently dial that address and
//! fan out into the LAN.
//!
//! [`FederationPolicy`] gates resolution against:
//!   - A private-IP block list (RFC 1918, loopback, link-local, CGNAT,
//!     IPv6 ULA + link-local, unspecified, broadcast, multicast).
//!   - An optional allow-list of acceptable server_names.
//!
//! The block is default-on; the only ergonomic carve-out is a self-loop
//! exception so a server that points its own server_name at `127.0.0.1`
//! (test harnesses, single-host evaluations) keeps working.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

use crate::federation::federation_client::now_ms;

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
    #[error("destination {server_name} resolves to private IP {ip}; blocked by policy")]
    PrivateIpBlocked { server_name: String, ip: IpAddr },
    #[error("destination {0} is not in the federation allow-list")]
    NotAllowed(String),
}

/// Outbound federation safety policy. Defaults to "block private IPs,
/// no allow-list filter" — the safe production posture. Construct via
/// [`FederationPolicy::strict`] for production, [`FederationPolicy::permissive`]
/// for tests that must reach loopback/private addresses without naming the
/// server explicitly.
#[derive(Debug, Clone)]
pub struct FederationPolicy {
    /// When true, any resolution producing an IP in a private/loopback/
    /// link-local/multicast/etc. range is rejected unless covered by the
    /// self-loop exception. Default: true.
    pub private_ip_block: bool,
    /// If non-empty, only destinations whose server_name matches an entry
    /// (exact string match, host-only — the port suffix is stripped before
    /// comparison) may be reached. Empty = allow any (subject to other
    /// rules). Default: empty.
    pub allow_list: Vec<String>,
    /// Our own server_name, used for the self-loop exception. When the
    /// destination's host portion matches this, loopback IPs are allowed
    /// through. Set to empty in tests that don't care.
    pub our_server_name: String,
}

impl FederationPolicy {
    /// Production-safe default: block private IPs, no allow-list filter,
    /// self-loop exception keyed on `our_server_name`.
    pub fn strict(our_server_name: String) -> Self {
        Self {
            private_ip_block: true,
            allow_list: Vec::new(),
            our_server_name,
        }
    }

    /// Test-friendly: no blocks, no allow-list. Use for unit tests that
    /// resolve documentation IPs / loopback without exercising the policy.
    pub fn permissive() -> Self {
        Self {
            private_ip_block: false,
            allow_list: Vec::new(),
            our_server_name: String::new(),
        }
    }
}

impl Default for FederationPolicy {
    fn default() -> Self {
        Self {
            private_ip_block: true,
            allow_list: Vec::new(),
            our_server_name: String::new(),
        }
    }
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
    policy: FederationPolicy,
}

impl FederationResolver {
    /// Permissive constructor. Used by tests and historical call sites.
    /// Production code should call [`FederationResolver::with_policy`] with
    /// a strict policy carrying the operator's `server_name`.
    pub fn new() -> Result<Self, ResolveError> {
        Self::with_policy(FederationPolicy::permissive())
    }

    /// Construct a resolver bound to a specific safety policy.
    pub fn with_policy(policy: FederationPolicy) -> Result<Self, ResolveError> {
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
            policy,
        })
    }

    /// Resolve a server name to a target. Implements the 6-step spec algorithm
    /// and applies the [`FederationPolicy`] SSRF guard on the resolved IPs.
    pub async fn resolve(&self, server_name: &str) -> Result<ResolvedServer, ResolveError> {
        // Allow-list is keyed on the ORIGINAL server_name (what the operator
        // configured), not the delegated target — checked once at entry so
        // .well-known recursion can't smuggle an off-list peer through.
        self.check_allow_list(server_name)?;
        let resolved = self.resolve_inner(server_name, 0).await?;
        self.check_resolved_ips(server_name, &resolved)?;
        Ok(resolved)
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

    fn check_allow_list(&self, server_name: &str) -> Result<(), ResolveError> {
        if self.policy.allow_list.is_empty() {
            return Ok(());
        }
        let host = host_only(server_name);
        if self
            .policy
            .allow_list
            .iter()
            .any(|entry| host_only(entry) == host)
        {
            Ok(())
        } else {
            warn!(%server_name, "federation: destination not in allow-list");
            Err(ResolveError::NotAllowed(server_name.to_string()))
        }
    }

    fn check_resolved_ips(
        &self,
        server_name: &str,
        resolved: &ResolvedServer,
    ) -> Result<(), ResolveError> {
        if !self.policy.private_ip_block {
            return Ok(());
        }
        // Self-loop exception: a server pointing its own server_name at
        // loopback (test harness, single-host eval) needs to talk to itself.
        // Scope it narrowly: only loopback addresses are excused, and only
        // when the destination's host portion exactly matches ours.
        let is_self = !self.policy.our_server_name.is_empty()
            && host_only(server_name) == host_only(&self.policy.our_server_name);
        for ip in &resolved.resolved_ips {
            if is_blocked_ip(*ip) {
                if is_self && ip.is_loopback() {
                    continue;
                }
                warn!(
                    %server_name,
                    %ip,
                    "federation: outbound refused — destination resolves to private/loopback IP"
                );
                return Err(ResolveError::PrivateIpBlocked {
                    server_name: server_name.to_string(),
                    ip: *ip,
                });
            }
        }
        Ok(())
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

    /// Are the resolved IPs of a `.well-known` host acceptable to connect to?
    /// Mirrors `check_resolved_ips`: under `private_ip_block`, reject any
    /// non-public address — with the self-loop loopback exception when the
    /// host is our own server_name. An empty set is rejected (we can't
    /// validate what we couldn't resolve). With the guard off, anything goes.
    fn well_known_ips_permitted(&self, hostname: &str, ips: &[IpAddr]) -> bool {
        if !self.policy.private_ip_block {
            return true;
        }
        if ips.is_empty() {
            return false;
        }
        let is_self = !self.policy.our_server_name.is_empty()
            && host_only(hostname) == host_only(&self.policy.our_server_name);
        !ips.iter()
            .any(|ip| is_blocked_ip(*ip) && !(is_self && ip.is_loopback()))
    }

    /// HTTP client for a `.well-known` fetch. The well-known GET is the first,
    /// attacker-influenced network touch when resolving a destination, so
    /// under `private_ip_block` we resolve the host ourselves, refuse
    /// non-public targets, and PIN the connection to the validated IPs (so a
    /// DNS rebind can't swap in an internal address) with redirects disabled
    /// (so a redirect can't escape the pin to an unvalidated host). Returns
    /// `None` to refuse the fetch. With the guard off, reuses the shared
    /// client unchanged.
    ///
    /// Deliberate spec deviation: the spec SAYS well-known SHOULD follow 30x
    /// redirects (a SHOULD, not a MUST). Under the guard we don't, because a
    /// redirect target wouldn't be covered by the IP pin — following it would
    /// reopen the SSRF hole. A server that serves its well-known via a
    /// redirect loses delegation here; serving it directly (the common case)
    /// is unaffected.
    async fn well_known_client(&self, hostname: &str) -> Option<reqwest::Client> {
        if !self.policy.private_ip_block {
            return Some(self.http.clone());
        }
        let ips = self.lookup_host_ips(hostname).await;
        if !self.well_known_ips_permitted(hostname, &ips) {
            warn!(%hostname, "well-known fetch refused — host unresolvable or resolves to a private/loopback IP");
            return None;
        }
        // Pin to ALL validated IPs at once (`resolve_to_addrs` keeps the set;
        // a per-IP `.resolve` loop would overwrite down to the last one). The
        // connection can only land on an address we already checked.
        let pinned: Vec<std::net::SocketAddr> = ips
            .iter()
            .map(|ip| std::net::SocketAddr::new(*ip, 443))
            .collect();
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("vela/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(hostname, &pinned)
            .build()
            .ok()
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

        // Fetch through the SSRF-guarded client (refuses/pins non-public
        // targets under private_ip_block; a None client means "refused").
        let url = format!("https://{hostname}/.well-known/matrix/server");
        let result = match self.well_known_client(hostname).await {
            Some(client) => client.get(&url).send().await,
            None => {
                // Cache the refusal negatively so we don't re-resolve every call.
                self.well_known.insert(
                    hostname.to_string(),
                    CachedWellKnown {
                        delegated: None,
                        expires_at_ms: now + WELL_KNOWN_NEG_TTL_MS,
                    },
                );
                return None;
            }
        };
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

/// Strip a trailing `:port` from a `server_name`, preserving the bracketed
/// IPv6 literal form. Used for allow-list and self-loop comparison so
/// `"acme.com"` matches `"acme.com:8448"`.
fn host_only(server_name: &str) -> &str {
    if let Some(rest) = server_name.strip_prefix('[')
        && let Some(idx) = rest.find(']')
    {
        // Return through the closing bracket, dropping any `:port` after.
        return &server_name[..idx + 2];
    }
    match server_name.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => h,
        _ => server_name,
    }
}

/// Classify an IP as unsafe for outbound federation. Covers:
/// - IPv4 RFC 1918 (10/8, 172.16/12, 192.168/16), loopback (127/8),
///   link-local (169.254/16), CGNAT (100.64/10), broadcast, multicast,
///   unspecified (0.0.0.0).
/// - IPv6 loopback (::1), link-local (fe80::/10), ULA (fc00::/7),
///   unspecified (::), multicast (ff00::/8), IPv4-mapped/-compatible
///   ranges that wrap any of the above.
pub(crate) fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_v4(mapped);
            }
            // IPv4-compatible addresses (::a.b.c.d, deprecated by RFC 4291
            // but still parseable) — top 96 bits are zero. An attacker
            // could otherwise smuggle 127.0.0.1 as `::7f00:1`.
            let segs = v6.segments();
            if segs[0] == 0
                && segs[1] == 0
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0
                && (segs[6] != 0 || segs[7] > 1)
            {
                let v4 = Ipv4Addr::new(
                    (segs[6] >> 8) as u8,
                    (segs[6] & 0xff) as u8,
                    (segs[7] >> 8) as u8,
                    (segs[7] & 0xff) as u8,
                );
                if is_blocked_v4(v4) {
                    return true;
                }
            }
            is_blocked_v6(v6)
        }
    }
}

fn is_blocked_v4(v4: Ipv4Addr) -> bool {
    if v4.is_unspecified()
        || v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_documentation()
    {
        return true;
    }
    // CGNAT (RFC 6598): 100.64.0.0/10. `Ipv4Addr::is_private` covers
    // RFC 1918 only, so handle this band manually.
    let [a, b, _, _] = v4.octets();
    if a == 100 && (64..=127).contains(&b) {
        return true;
    }
    // Benchmarking range (RFC 2544): 198.18.0.0/15.
    if a == 198 && (b == 18 || b == 19) {
        return true;
    }
    // "This network" reserved 0.0.0.0/8 (other than 0.0.0.0 itself, already
    // covered by is_unspecified) — refuse anything that names itself.
    if a == 0 {
        return true;
    }
    false
}

fn is_blocked_v6(v6: Ipv6Addr) -> bool {
    if v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() {
        return true;
    }
    let segments = v6.segments();
    // Unique Local Addresses (RFC 4193): fc00::/7 — first 7 bits are
    // 1111110, so the top byte is 0xfc or 0xfd.
    let top_byte = (segments[0] >> 8) as u8;
    if top_byte & 0xfe == 0xfc {
        return true;
    }
    // Link-local (RFC 4291): fe80::/10 — first 10 bits 1111111010.
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    false
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

    // ----- SSRF policy: IP classifier -----

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classifier_blocks_ipv4_rfc1918() {
        for s in [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.1.1",
        ] {
            assert!(is_blocked_ip(ip(s)), "should be blocked: {s}");
        }
    }

    #[test]
    fn classifier_blocks_ipv4_loopback_link_local_cgnat() {
        for s in [
            "127.0.0.1",
            "127.255.255.255",
            "169.254.0.1",
            "169.254.169.254", // cloud metadata service
            "100.64.0.1",
            "100.127.255.255",
        ] {
            assert!(is_blocked_ip(ip(s)), "should be blocked: {s}");
        }
    }

    #[test]
    fn classifier_blocks_ipv4_special_ranges() {
        for s in [
            "0.0.0.0",
            "0.1.2.3",
            "255.255.255.255",
            "224.0.0.1",
            "198.18.0.1",
            "198.19.255.255",
            "192.0.2.1", // TEST-NET-1 (documentation)
        ] {
            assert!(is_blocked_ip(ip(s)), "should be blocked: {s}");
        }
    }

    #[test]
    fn classifier_blocks_ipv6_private() {
        for s in [
            "::1",
            "::",
            "fc00::1",
            "fd00::1",
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fe80::1",
            "febf::1",
            "ff00::1",
        ] {
            assert!(is_blocked_ip(ip(s)), "should be blocked: {s}");
        }
    }

    #[test]
    fn classifier_blocks_ipv4_mapped_and_compat() {
        // IPv4-mapped (::ffff:127.0.0.1) and IPv4-compatible (::127.0.0.1)
        // must both be blocked — an attacker shouldn't be able to smuggle
        // an internal v4 destination through a v6 literal.
        assert!(is_blocked_ip(ip("::ffff:127.0.0.1")));
        assert!(is_blocked_ip(ip("::ffff:10.0.0.1")));
        assert!(is_blocked_ip(ip("::7f00:1"))); // ::127.0.0.1
    }

    #[test]
    fn classifier_allows_public_ipv4() {
        for s in ["1.1.1.1", "8.8.8.8", "140.82.121.4"] {
            assert!(!is_blocked_ip(ip(s)), "should be allowed: {s}");
        }
    }

    #[test]
    fn classifier_allows_public_ipv6() {
        for s in ["2001:4860:4860::8888", "2606:4700:4700::1111"] {
            assert!(!is_blocked_ip(ip(s)), "should be allowed: {s}");
        }
    }

    // ----- SSRF policy: resolver gating -----

    #[tokio::test]
    async fn resolve_blocks_private_ipv4_literal() {
        let r = FederationResolver::with_policy(FederationPolicy::strict("our.example".into()))
            .unwrap();
        let err = r.resolve("10.0.0.1").await.unwrap_err();
        match err {
            ResolveError::PrivateIpBlocked { ip, .. } => {
                assert_eq!(ip, "10.0.0.1".parse::<IpAddr>().unwrap());
            }
            other => panic!("expected PrivateIpBlocked, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_blocks_loopback_when_destination_is_not_self() {
        let r = FederationResolver::with_policy(FederationPolicy::strict("our.example".into()))
            .unwrap();
        let err = r.resolve("127.0.0.1:8448").await.unwrap_err();
        assert!(matches!(err, ResolveError::PrivateIpBlocked { .. }));
    }

    #[tokio::test]
    async fn resolve_allows_loopback_for_self_loop() {
        // A test harness or single-host eval that points its own
        // server_name at 127.0.0.1 must keep working.
        let r = FederationResolver::with_policy(FederationPolicy::strict("localhost:8008".into()))
            .unwrap();
        let resolved = r.resolve("localhost:8008").await;
        // DNS for "localhost" resolves to 127.0.0.1 / ::1 in practice; if
        // the test environment has no resolver, the IP list will be empty
        // and no IP check fires either. Either path must succeed.
        assert!(
            resolved.is_ok(),
            "self-loop resolution failed: {resolved:?}"
        );
    }

    #[tokio::test]
    async fn resolve_allows_loopback_for_self_loop_ipv4_literal() {
        let r = FederationResolver::with_policy(FederationPolicy::strict("127.0.0.1:8008".into()))
            .unwrap();
        let resolved = r.resolve("127.0.0.1:8008").await.unwrap();
        assert_eq!(resolved.target_port, 8008);
    }

    #[tokio::test]
    async fn resolve_blocks_via_delegation() {
        // Malicious peer: well-known points us at an RFC 1918 literal.
        let r = FederationResolver::with_policy(FederationPolicy::strict("our.example".into()))
            .unwrap();
        r.seed_well_known("evil.example", Some("192.168.0.1:8448".into()), 60_000);
        let err = r.resolve("evil.example").await.unwrap_err();
        assert!(matches!(err, ResolveError::PrivateIpBlocked { .. }));
    }

    #[tokio::test]
    async fn resolve_respects_allow_list_match() {
        let mut policy = FederationPolicy::strict("our.example".into());
        policy.private_ip_block = false;
        policy.allow_list = vec!["good.example".into(), "trusted.example:8090".into()];
        let r = FederationResolver::with_policy(policy).unwrap();
        // Explicit-port form: step 2 returns immediately with no DNS data
        // needed beyond what the allow-list cares about.
        let resolved = r.resolve("good.example:8090").await.unwrap();
        assert_eq!(resolved.target_host, "good.example");
    }

    #[tokio::test]
    async fn resolve_respects_allow_list_miss() {
        let policy = FederationPolicy {
            private_ip_block: false,
            allow_list: vec!["good.example".into()],
            our_server_name: "our.example".into(),
        };
        let r = FederationResolver::with_policy(policy).unwrap();
        let err = r.resolve("bad.example").await.unwrap_err();
        assert!(matches!(err, ResolveError::NotAllowed(_)));
    }

    #[tokio::test]
    async fn resolve_permissive_policy_passes_loopback() {
        let r = FederationResolver::with_policy(FederationPolicy::permissive()).unwrap();
        let resolved = r.resolve("127.0.0.1:8448").await.unwrap();
        assert_eq!(resolved.target_port, 8448);
    }

    #[test]
    fn host_only_strips_port() {
        assert_eq!(host_only("acme.com"), "acme.com");
        assert_eq!(host_only("acme.com:8448"), "acme.com");
        assert_eq!(host_only("1.2.3.4:8448"), "1.2.3.4");
        assert_eq!(host_only("[::1]:8448"), "[::1]");
        assert_eq!(host_only("[::1]"), "[::1]");
    }

    #[test]
    fn well_known_guard_refuses_private_and_unresolvable() {
        let r = FederationResolver::with_policy(FederationPolicy::strict("our.example".into()))
            .unwrap();
        assert!(r.well_known_ips_permitted("evil.example", &[ip("1.1.1.1")]));
        assert!(!r.well_known_ips_permitted("evil.example", &[ip("127.0.0.1")]));
        assert!(!r.well_known_ips_permitted("evil.example", &[ip("10.0.0.5")]));
        assert!(!r.well_known_ips_permitted("evil.example", &[ip("169.254.169.254")]));
        // Any blocked address in the set refuses the whole host.
        assert!(!r.well_known_ips_permitted("evil.example", &[ip("1.1.1.1"), ip("127.0.0.1")]));
        // Unresolvable (empty) refuses — we can't validate what we can't resolve.
        assert!(!r.well_known_ips_permitted("evil.example", &[]));
    }

    #[test]
    fn well_known_guard_allows_self_loopback_only() {
        let r = FederationResolver::with_policy(FederationPolicy::strict("our.example".into()))
            .unwrap();
        // Our own server_name may point at loopback (single-host eval).
        assert!(r.well_known_ips_permitted("our.example", &[ip("127.0.0.1")]));
        // But a non-loopback private IP for self is still refused.
        assert!(!r.well_known_ips_permitted("our.example", &[ip("10.0.0.5")]));
    }

    #[test]
    fn well_known_guard_off_permits_everything() {
        // private_ip_block off (e.g. Complement's Docker network).
        let r = FederationResolver::with_policy(FederationPolicy::permissive()).unwrap();
        assert!(r.well_known_ips_permitted("anything", &[ip("127.0.0.1")]));
        assert!(r.well_known_ips_permitted("anything", &[]));
    }
}
