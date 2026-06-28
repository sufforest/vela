//! Outbound federation HTTP client.
//!
//! - Signs outbound federation requests with X-Matrix authentication per
//!   `server-server-api.md:287-387`.
//! - Fetches remote server keys via `GET /_matrix/key/v2/server` and validates
//!   the self-signed response per `keys_server.yaml` + v5 signing requirements.
//!
//! No .well-known / SRV resolution in Sprint 3a — we hit
//! `https://{server_name}:8448` directly. Documented in `KNOWN_LIMITATIONS.md`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::http::HeaderValue;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;
use tracing::debug;

use vela_core::events::sign::ServerSigningKey;
use vela_core::federation::keys::{SignatureError, decode_public_key, verify_json_signature};

/// 7-day cap per v5 signing requirements.
pub const KEY_VALIDITY_CAP_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Hard cap on the `valid_until_ts` we'll accept from a server — 100 years
/// into the future is comfortably "not legitimate."
const FAR_FUTURE_CAP_MS: u64 = 100 * 365 * 24 * 60 * 60 * 1000;

/// Hard cap on a `/_matrix/key/v2/server` response body. A legitimate key
/// document is a few keys plus signatures — kilobytes even with a long
/// rotation history — so 256 KiB is hugely generous while stopping a hostile
/// peer from exhausting memory with an unbounded body.
const MAX_KEY_RESPONSE_BYTES: usize = 256 * 1024;

/// Hard cap on a general signed-federation response body (`/state`, `/backfill`,
/// `send_join`, event fetches, transaction replies, …). These are legitimately
/// large for big rooms, so the cap is generous — 100 MiB, matching Synapse's
/// `MAX_RESPONSE_SIZE` — but still bounds memory against a hostile peer.
const MAX_FEDERATION_RESPONSE_BYTES: usize = 100 * 1024 * 1024;

/// Parsed + validated key response, ready for caching.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteKeys {
    /// Map of key_id → unpadded-base64 public key bytes (current keys).
    pub verify_keys: HashMap<String, String>,
    /// Rotated-out keys, key_id → unpadded-base64 public key bytes. Per the S2S
    /// spec these are valid for verifying *events* only, never live federation
    /// requests, so a server that rotated its signing key can still have its
    /// older events validated. The spec's per-key `expired_ts` is intentionally
    /// not stored: it would gate against the event's `origin_server_ts`, which
    /// lives in the signed payload and is therefore attacker-chosen, so the
    /// check adds no integrity — only the key bytes matter. `serde(default)`
    /// keeps documents persisted before this field deserialisable.
    #[serde(default)]
    pub old_verify_keys: HashMap<String, String>,
    /// Effective validity, already capped by `min(response_valid_until, now + 7d)`.
    pub valid_until_ts: u64,
    /// Millisecond POSIX timestamp of when we fetched this.
    pub fetched_at: u64,
}

impl RemoteKeys {
    /// A key in `verify_keys` is still usable at `now` iff `valid_until_ts > now`.
    pub fn is_valid_at(&self, now_ms: u64) -> bool {
        self.valid_until_ts > now_ms
    }

    /// Whether this document can verify a signature made with one of `wanted`
    /// key ids — current or rotated-out. An empty `wanted` means the caller
    /// needs no specific key (any valid document will do), the behaviour of the
    /// plain time-based fetch. Old keys count here so a (legitimate) event
    /// signed with a rotated-out key doesn't keep triggering pointless
    /// re-fetches.
    fn covers_any(&self, wanted: &[&str]) -> bool {
        wanted.is_empty()
            || wanted
                .iter()
                .any(|k| self.verify_keys.contains_key(*k) || self.old_verify_keys.contains_key(*k))
    }

    /// Public key (unpadded base64) for verifying an **event** signed with
    /// `key_id`: a current key, or a rotated-out one from `old_verify_keys`.
    /// Old keys verify events only — the X-Matrix request-auth path looks up
    /// `verify_keys` directly so a live request can never be authed by a key
    /// the server has rotated away.
    pub fn event_verify_key(&self, key_id: &str) -> Option<&str> {
        self.verify_keys
            .get(key_id)
            .or_else(|| self.old_verify_keys.get(key_id))
            .map(String::as_str)
    }
}

/// Errors that can arise while fetching or validating remote keys or signing
/// outbound requests.
#[derive(Debug, Error)]
pub enum FederationClientError {
    #[error("http error: {0}")]
    Http(String),
    #[error("response is not valid JSON: {0}")]
    BadJson(String),
    #[error("key response has wrong server_name: expected {expected}, got {got}")]
    ServerNameMismatch { expected: String, got: String },
    #[error("key response missing or invalid '{0}' field")]
    MissingField(&'static str),
    #[error("key response has no valid self-signature")]
    NoValidSelfSignature,
    #[error("key response valid_until_ts is in the past")]
    ExpiredKeyResponse,
    #[error("key response valid_until_ts is implausibly far in the future")]
    FarFutureKeyResponse,
    #[error("verify_keys entry {key_id} has malformed key: {reason}")]
    MalformedKey { key_id: String, reason: String },
    #[error("signature verify error: {0}")]
    Signature(#[from] SignatureError),
    #[error("federation is disabled in this server's config")]
    FederationDisabled,
}

/// Outbound federation HTTP client.
///
/// Caches one `reqwest::Client` per destination. Each client has its DNS
/// resolution for `tls_server_name` pre-overridden via
/// `ClientBuilder::resolve(tls_server_name, ip:port)`, so the request URL
/// carries `tls_server_name` as host — producing the correct SNI — while the
/// TCP connection goes to the resolved IPs. This is the fix for SRV /
/// `.well-known` delegation: cert validation uses the original server_name.
#[derive(Clone)]
pub struct FederationClient {
    /// Per-destination client, keyed by `tls_server_name:target_port`.
    clients: Arc<dashmap::DashMap<String, reqwest::Client>>,
    /// Fallback client for requests where no pre-resolution is possible
    /// (e.g. testing without a real resolver, or when resolved_ips is empty).
    default_http: reqwest::Client,
    signing_key: Arc<ServerSigningKey>,
    our_server_name: String,
    resolver: Arc<crate::federation::federation_resolver::FederationResolver>,
    /// Extra root CAs to trust for outbound federation, on top of system
    /// roots. Empty in production; used by Complement where both servers'
    /// certs are signed by an ephemeral CA mounted in the container.
    extra_ca_certs: Arc<Vec<reqwest::Certificate>>,
    /// Per-destination base-URL override: if `destination` matches a key,
    /// the request is sent to the given base URL over plain HTTP without
    /// going through the resolver + TLS path. Populated by two callers:
    ///   1. `[federation] http_peers` in vela.toml — real deployments
    ///      (local/self-hosted clusters) that skip TLS by policy.
    ///   2. Integration tests stubbing a remote with wiremock.
    ///
    /// Empty in typical production configs.
    base_url_overrides: Arc<dashmap::DashMap<String, String>>,
    /// When false, every outbound `signed_request` returns
    /// `FederationDisabled` immediately. Belt-and-suspenders for the
    /// federation-disabled mode: the sender already short-circuits, but
    /// some code paths (alias resolution, /key/v2 fetches, federated
    /// invite) call the client directly.
    enabled: bool,
}

fn build_reqwest_client(
    extra_ca_certs: &[reqwest::Certificate],
    dns_overrides: &[(String, std::net::SocketAddr)],
) -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("vela/", env!("CARGO_PKG_VERSION")));
    for cert in extra_ca_certs {
        builder = builder.add_root_certificate(cert.clone());
    }
    for (host, addr) in dns_overrides {
        builder = builder.resolve(host, *addr);
    }
    builder.build()
}

/// Percent-encode every byte of `s` that isn't an URL-unreserved
/// character (`A-Za-z0-9 - _ . ~`). Used when constructing
/// federation URL paths and query parameters: we sign the URL we're
/// about to send, so the encoded form we put on the wire MUST match
/// the encoded form fed into the signing canonical-string. Naive
/// `replace('#', "%23")`-style encoding leaks raw multibyte UTF-8
/// (e.g. unicode aliases) into the URL, which reqwest then re-encodes
/// before sending — breaking the X-Matrix signature at the receiver.
fn url_query_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Read a federation response body into JSON, capped at `max` bytes. Rejects on
/// an advertised `Content-Length` over the cap, and streams with a hard limit
/// as the backstop (the length header may be absent or understated), so a
/// hostile peer can't exhaust memory with an unbounded body.
async fn read_capped_json(
    mut resp: reqwest::Response,
    max: usize,
) -> Result<Value, FederationClientError> {
    if let Some(len) = resp.content_length()
        && len > max as u64
    {
        return Err(FederationClientError::Http(format!(
            "response too large: {len} bytes (cap {max})"
        )));
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| FederationClientError::Http(e.to_string()))?
    {
        if buf.len() + chunk.len() > max {
            return Err(FederationClientError::Http(format!(
                "response exceeds {max}-byte cap"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).map_err(|e| FederationClientError::BadJson(e.to_string()))
}

impl FederationClient {
    pub fn new(
        signing_key: Arc<ServerSigningKey>,
        our_server_name: String,
        resolver: Arc<crate::federation::federation_resolver::FederationResolver>,
        extra_ca_certs: Vec<reqwest::Certificate>,
    ) -> Self {
        Self::new_with_enabled(signing_key, our_server_name, resolver, extra_ca_certs, true)
    }

    pub fn new_with_enabled(
        signing_key: Arc<ServerSigningKey>,
        our_server_name: String,
        resolver: Arc<crate::federation::federation_resolver::FederationResolver>,
        extra_ca_certs: Vec<reqwest::Certificate>,
        enabled: bool,
    ) -> Self {
        let default_http =
            build_reqwest_client(&extra_ca_certs, &[]).expect("reqwest client builds");
        Self {
            clients: Arc::new(dashmap::DashMap::new()),
            default_http,
            signing_key,
            our_server_name,
            resolver,
            extra_ca_certs: Arc::new(extra_ca_certs),
            base_url_overrides: Arc::new(dashmap::DashMap::new()),
            enabled,
        }
    }

    /// Route requests for `destination` (e.g. `remote.example`) to
    /// `base_url` (e.g. `http://10.0.0.5:8008`) instead of resolving.
    /// Populated from `[federation] http_peers` config + integration
    /// tests.
    pub fn set_base_url_override(&self, destination: &str, base_url: &str) {
        self.base_url_overrides
            .insert(destination.to_string(), base_url.to_string());
    }

    /// Return a `reqwest::Client` configured to route requests for
    /// `resolved.tls_server_name` to `resolved.resolved_ips`. Cached per
    /// destination key.
    pub(crate) fn client_for(
        &self,
        resolved: &crate::federation::federation_resolver::ResolvedServer,
    ) -> reqwest::Client {
        // No resolved IPs → fall back to the default client, which does its
        // own (system) DNS. Under `private_ip_block` this branch is now
        // unreachable: `FederationResolver::check_resolved_ips` fails closed
        // on an empty IP set, so `resolve` errors before we get here. It only
        // fires when the SSRF policy is off (tests / Complement), where
        // reaching loopback/private targets is intended.
        if resolved.resolved_ips.is_empty() {
            return self.default_http.clone();
        }

        let key = format!("{}:{}", resolved.tls_server_name, resolved.target_port);
        if let Some(c) = self.clients.get(&key) {
            return c.clone();
        }

        let addrs: Vec<(String, std::net::SocketAddr)> = resolved
            .socket_addrs()
            .into_iter()
            .map(|a| (resolved.tls_server_name.clone(), a))
            .collect();
        let client = build_reqwest_client(self.extra_ca_certs.as_slice(), &addrs)
            .expect("reqwest client builds");
        self.clients.insert(key, client.clone());
        client
    }

    /// Like `fetch_server_keys`, but also returns the raw JSON body
    /// alongside the parsed `RemoteKeys`. The notary endpoint
    /// (`/_matrix/key/v2/query`) needs the raw bundle so it can
    /// preserve the origin server's signatures and add its own;
    /// the parsed form alone is lossy (no signatures, no tls
    /// fingerprints, no extra fields).
    pub async fn fetch_server_keys_with_raw(
        &self,
        server_name: &str,
    ) -> Result<(RemoteKeys, Value), FederationClientError> {
        let body = self.fetch_server_keys_raw_body(server_name).await?;
        let now_ms = now_ms();
        let parsed = validate_key_response(&body, server_name, now_ms)?;
        Ok((parsed, body))
    }

    async fn fetch_server_keys_raw_body(
        &self,
        server_name: &str,
    ) -> Result<Value, FederationClientError> {
        let (url, host_header, client) =
            if let Some(base) = self.base_url_overrides.get(server_name) {
                (
                    format!("{}/_matrix/key/v2/server", base.value()),
                    server_name.to_string(),
                    self.default_http.clone(),
                )
            } else {
                let resolved = self
                    .resolver
                    .resolve(server_name)
                    .await
                    .map_err(|e| FederationClientError::Http(format!("resolve: {e}")))?;
                (
                    format!("{}/_matrix/key/v2/server", resolved.base_url()),
                    resolved.host_header.clone(),
                    self.client_for(&resolved),
                )
            };
        let resp = client
            .get(&url)
            .header("host", &host_header)
            .send()
            .await
            .map_err(|e| FederationClientError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(FederationClientError::Http(format!(
                "status {}",
                resp.status()
            )));
        }
        read_capped_json(resp, MAX_KEY_RESPONSE_BYTES).await
    }

    /// Fetch `GET /_matrix/key/v2/server` from `server_name` and validate.
    pub async fn fetch_server_keys(
        &self,
        server_name: &str,
    ) -> Result<RemoteKeys, FederationClientError> {
        // Check plain-HTTP peer overrides before the resolver — used by
        // local dev clusters and integration tests that bypass TLS.
        let (url, host_header, client) =
            if let Some(base) = self.base_url_overrides.get(server_name) {
                (
                    format!("{}/_matrix/key/v2/server", base.value()),
                    server_name.to_string(),
                    self.default_http.clone(),
                )
            } else {
                let resolved = self
                    .resolver
                    .resolve(server_name)
                    .await
                    .map_err(|e| FederationClientError::Http(format!("resolve: {e}")))?;
                debug!(
                    %server_name,
                    target = %resolved.target_host,
                    port = resolved.target_port,
                    sni = %resolved.tls_server_name,
                    "fetching remote server keys"
                );
                (
                    format!("{}/_matrix/key/v2/server", resolved.base_url()),
                    resolved.host_header.clone(),
                    self.client_for(&resolved),
                )
            };
        let resp = client
            .get(&url)
            .header("host", &host_header)
            .send()
            .await
            .map_err(|e| FederationClientError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(FederationClientError::Http(format!(
                "status {}",
                resp.status()
            )));
        }

        let body = read_capped_json(resp, MAX_KEY_RESPONSE_BYTES).await?;

        let now_ms = now_ms();
        validate_key_response(&body, server_name, now_ms)
    }

    /// Send a signed federation request and return the parsed JSON response.
    ///
    /// Used by the outbound transaction sender and (later) by the outbound
    /// fetch path in `federation_receive`.
    #[tracing::instrument(
        name = "federation.signed_request",
        skip(self, body),
        fields(
            otel.kind = "client",
            http.method = %method,
            peer.service = %destination,
            http.target = %path_and_query,
        )
    )]
    pub async fn signed_request(
        &self,
        method: reqwest::Method,
        destination: &str,
        path_and_query: &str,
        body: Option<Value>,
    ) -> Result<Value, FederationClientError> {
        if !self.enabled {
            return Err(FederationClientError::FederationDisabled);
        }
        // Test override short-circuits the resolve + HTTPS path: when set,
        // we use plain HTTP via the default client to the given base URL.
        let (url, host_header, client) =
            if let Some(base) = self.base_url_overrides.get(destination) {
                (
                    format!("{}{path_and_query}", base.value()),
                    destination.to_string(),
                    self.default_http.clone(),
                )
            } else {
                let resolved = self
                    .resolver
                    .resolve(destination)
                    .await
                    .map_err(|e| FederationClientError::Http(format!("resolve: {e}")))?;
                (
                    format!("{}{}", resolved.base_url(), path_and_query),
                    resolved.host_header.clone(),
                    self.client_for(&resolved),
                )
            };
        let auth_header = self.sign_federation_request(
            method.as_str(),
            path_and_query,
            destination,
            body.as_ref(),
        );

        let mut req = client
            .request(method, &url)
            .header("host", &host_header)
            .header("authorization", auth_header);
        // Inject the W3C `traceparent` header so the receiving server
        // can stitch its handler span into our trace. No-op without
        // the `otel` feature.
        req = crate::trace_context::inject_into_request(req);
        if let Some(ref b) = body {
            req = req.json(b);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| FederationClientError::Http(e.to_string()))?;

        let status = resp.status();
        let resp_body = read_capped_json(resp, MAX_FEDERATION_RESPONSE_BYTES).await?;

        if !status.is_success() {
            return Err(FederationClientError::Http(format!(
                "status {status}: {resp_body}"
            )));
        }

        Ok(resp_body)
    }

    /// Send a transaction to `destination`. `txn_id` must be unique per destination;
    /// the spec requires waiting for a 200 before sending a new txnId to the same
    /// peer. This method makes one request; the sender task handles sequencing.
    pub async fn send_transaction(
        &self,
        destination: &str,
        txn_id: &str,
        body: Value,
    ) -> Result<Value, FederationClientError> {
        let path = format!("/_matrix/federation/v1/send/{txn_id}");
        self.signed_request(reqwest::Method::PUT, destination, &path, Some(body))
            .await
    }

    /// `GET /_matrix/federation/v1/make_join/{roomId}/{userId}?ver=X`
    ///
    /// Returns `{room_version, event}` where `event` is an unsigned template
    /// member event the origin (us) is expected to sign and return via
    /// `send_join`. Called when a local user wants to join a remote room.
    pub async fn make_join(
        &self,
        destination: &str,
        room_id: &str,
        user_id: &str,
        room_versions: &[&str],
    ) -> Result<Value, FederationClientError> {
        let ver_params: Vec<String> = room_versions.iter().map(|v| format!("ver={v}")).collect();
        let query = ver_params.join("&");
        let path = format!("/_matrix/federation/v1/make_join/{room_id}/{user_id}?{query}");
        self.signed_request(reqwest::Method::GET, destination, &path, None)
            .await
    }

    /// `PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}`
    ///
    /// Submit the signed join event. The resident server validates, accepts,
    /// and returns `{auth_chain, state, event}` — the full state of the room
    /// prior to our join plus all events needed to validate them.
    ///
    /// `omit_members = true` opts into MSC3706: the resident may return
    /// a partial-state response (the `state` array omits most member
    /// events, with `partial_state: true` and `servers_in_room: [...]`
    /// flagged in the body). The caller is responsible for handling
    /// the partial-state bookkeeping; a server that doesn't implement
    /// MSC3706 ignores the param and returns full state as before.
    pub async fn send_join_v2(
        &self,
        destination: &str,
        room_id: &str,
        event_id: &str,
        signed_event: Value,
        omit_members: bool,
    ) -> Result<Value, FederationClientError> {
        let mut path = format!("/_matrix/federation/v2/send_join/{room_id}/{event_id}");
        if omit_members {
            path.push_str("?omit_members=true");
        }
        self.signed_request(reqwest::Method::PUT, destination, &path, Some(signed_event))
            .await
    }

    /// `PUT /_matrix/federation/v2/invite/{roomId}/{eventId}`
    ///
    /// Body: `{event, room_version, invite_room_state}`. Remote validates the
    /// invite, optionally adds its own signature, and returns
    /// `{event: <doubly-signed>}`. Per spec the joining server then persists
    /// the returned form.
    /// `GET /_matrix/federation/v1/make_leave/{roomId}/{userId}`
    pub async fn make_leave(
        &self,
        destination: &str,
        room_id: &str,
        user_id: &str,
    ) -> Result<Value, FederationClientError> {
        let path = format!("/_matrix/federation/v1/make_leave/{room_id}/{user_id}");
        self.signed_request(reqwest::Method::GET, destination, &path, None)
            .await
    }

    /// `PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}`
    pub async fn send_leave_v2(
        &self,
        destination: &str,
        room_id: &str,
        event_id: &str,
        signed_event: Value,
    ) -> Result<Value, FederationClientError> {
        let path = format!("/_matrix/federation/v2/send_leave/{room_id}/{event_id}");
        self.signed_request(reqwest::Method::PUT, destination, &path, Some(signed_event))
            .await
    }

    /// `GET /_matrix/federation/v1/make_knock/{roomId}/{userId}?ver=X`
    ///
    /// Fetches a knock template from the resident server, keyed by the
    /// local user. Mirrors `make_join` but produces a `membership=knock`
    /// template and requires the remote room to advertise `join_rule=knock`
    /// (or `knock_restricted`).
    pub async fn make_knock(
        &self,
        destination: &str,
        room_id: &str,
        user_id: &str,
        room_versions: &[&str],
    ) -> Result<Value, FederationClientError> {
        let query = room_versions
            .iter()
            .map(|v| format!("ver={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let path = format!("/_matrix/federation/v1/make_knock/{room_id}/{user_id}?{query}");
        self.signed_request(reqwest::Method::GET, destination, &path, None)
            .await
    }

    /// `PUT /_matrix/federation/v1/send_knock/{roomId}/{eventId}`
    ///
    /// Returns `{knock_room_state: [stripped state events...]}` on success —
    /// spec-defined payload that lets the knocking server render the room
    /// chrome (name, avatar, topic) before being accepted.
    pub async fn send_knock_v1(
        &self,
        destination: &str,
        room_id: &str,
        event_id: &str,
        signed_event: Value,
    ) -> Result<Value, FederationClientError> {
        let path = format!("/_matrix/federation/v1/send_knock/{room_id}/{event_id}");
        self.signed_request(reqwest::Method::PUT, destination, &path, Some(signed_event))
            .await
    }

    pub async fn send_invite_v2(
        &self,
        destination: &str,
        room_id: &str,
        event_id: &str,
        body: Value,
    ) -> Result<Value, FederationClientError> {
        let path = format!("/_matrix/federation/v2/invite/{room_id}/{event_id}");
        self.signed_request(reqwest::Method::PUT, destination, &path, Some(body))
            .await
    }

    /// `GET /_matrix/federation/v1/query/directory?room_alias=...`
    pub async fn query_directory(
        &self,
        destination: &str,
        room_alias: &str,
    ) -> Result<Value, FederationClientError> {
        // Percent-encode every non-unreserved byte. Aliases like
        // `#老虎Â£я🤨👉ඞ:hs1` carry multibyte UTF-8; we sign the URL
        // and reqwest sends it verbatim, so the encoded form we sign
        // MUST match the encoded form on the wire — otherwise the
        // X-Matrix signature breaks at the receiver.
        let encoded = url_query_encode(room_alias);
        let path = format!("/_matrix/federation/v1/query/directory?room_alias={encoded}");
        self.signed_request(reqwest::Method::GET, destination, &path, None)
            .await
    }

    /// `GET /_matrix/federation/v1/query/profile?user_id=...&field=...`
    ///
    /// Used by client-API profile handlers when the target user lives on
    /// another server. `field` is `"displayname"`, `"avatar_url"`, or
    /// `None` for both. Response shape mirrors the spec: a JSON object
    /// containing whichever fields are set on the remote.
    pub async fn query_profile(
        &self,
        destination: &str,
        user_id: &str,
        field: Option<&str>,
    ) -> Result<Value, FederationClientError> {
        let encoded_user = url_query_encode(user_id);
        let path = match field {
            Some(f) => {
                format!("/_matrix/federation/v1/query/profile?user_id={encoded_user}&field={f}")
            }
            None => format!("/_matrix/federation/v1/query/profile?user_id={encoded_user}"),
        };
        self.signed_request(reqwest::Method::GET, destination, &path, None)
            .await
    }

    /// `GET /_matrix/federation/v1/hierarchy/{roomId}` — fetch a
    /// remote space's single-level summary (MSC2946). Caller is
    /// responsible for further recursion across servers.
    pub async fn fetch_hierarchy(
        &self,
        destination: &str,
        room_id: &str,
    ) -> Result<Value, FederationClientError> {
        let path = format!(
            "/_matrix/federation/v1/hierarchy/{}",
            url_query_encode(room_id)
        );
        self.signed_request(reqwest::Method::GET, destination, &path, None)
            .await
    }

    /// `GET /_matrix/federation/v1/event/{eventId}` — fetch a single
    /// PDU we don't have locally. Response is a transaction-shaped
    /// object (`{origin, origin_server_ts, pdus: [event]}`); we
    /// return just the PDU value, leaving validation / persistence
    /// to the caller via `persist_fetched_event`.
    /// `POST /_matrix/federation/v1/publicRooms` — fetch a remote
    /// server's published room directory. Used to back the C2S
    /// `/publicRooms?server=other.example` query so our local
    /// clients can browse another homeserver's directory without
    /// having to talk to it directly. Returns the peer's
    /// `{chunk, total_room_count_estimate, next_batch?, prev_batch?}`
    /// shape verbatim.
    pub async fn fetch_public_rooms(
        &self,
        destination: &str,
        limit: Option<u64>,
        since: Option<&str>,
        search_term: Option<&str>,
    ) -> Result<Value, FederationClientError> {
        let mut body = serde_json::Map::new();
        if let Some(l) = limit {
            body.insert("limit".to_string(), serde_json::json!(l));
        }
        if let Some(s) = since {
            body.insert("since".to_string(), serde_json::json!(s));
        }
        if let Some(term) = search_term {
            body.insert(
                "filter".to_string(),
                serde_json::json!({"generic_search_term": term}),
            );
        }
        self.signed_request(
            reqwest::Method::POST,
            destination,
            "/_matrix/federation/v1/publicRooms",
            Some(Value::Object(body)),
        )
        .await
    }

    pub async fn fetch_event_pdu(
        &self,
        destination: &str,
        event_id: &str,
    ) -> Result<Value, FederationClientError> {
        let encoded = url_query_encode(event_id);
        let path = format!("/_matrix/federation/v1/event/{encoded}");
        let resp = self
            .signed_request(reqwest::Method::GET, destination, &path, None)
            .await?;
        resp.get("pdus")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .cloned()
            .ok_or_else(|| FederationClientError::BadJson("response missing pdus[0]".into()))
    }

    /// MSC2836 `POST /_matrix/federation/unstable/event_relationships`.
    /// Walks the resident server's relations graph from `body.event_id`
    /// and returns `{events, limited, auth_chain}`. Callers persist the
    /// returned events as outliers before re-running their local walk.
    pub async fn event_relationships(
        &self,
        destination: &str,
        body: Value,
    ) -> Result<Value, FederationClientError> {
        self.signed_request(
            reqwest::Method::POST,
            destination,
            "/_matrix/federation/unstable/event_relationships",
            Some(body),
        )
        .await
    }

    /// `GET /_matrix/federation/v1/state/{roomId}?event_id=…`
    ///
    /// Fetch the room's full state at the given event as PDU arrays —
    /// heavier than `state_ids` but lets the caller skip a second
    /// round of `fetch_event_pdu` lookups. Returns the peer's
    /// `{auth_chain: [...], pdu: [...]}` shape. Used by the MSC3706
    /// partial-state filler to materialise the rest of the room's
    /// state after a partial join.
    pub async fn state(
        &self,
        destination: &str,
        room_id: &str,
        event_id: &str,
    ) -> Result<Value, FederationClientError> {
        let path = format!(
            "/_matrix/federation/v1/state/{}?event_id={}",
            url_query_encode(room_id),
            url_query_encode(event_id),
        );
        self.signed_request(reqwest::Method::GET, destination, &path, None)
            .await
    }

    /// `GET /_matrix/federation/v1/state_ids/{roomId}?event_id=…`
    ///
    /// Fetch the room's state at the given event as event_id arrays
    /// (lighter than `/state` which returns full PDUs). Returns the
    /// peer's `{auth_chain_ids: [...], pdu_ids: [...]}` shape; caller
    /// resolves missing events via `fetch_event_pdu` and persists
    /// them as outliers. Used as a last-resort fallback when our
    /// own snapshot chain doesn't anchor for an inbound event (e.g.
    /// gap-fill events whose oldest ancestor's prev isn't a known
    /// snapshot).
    pub async fn state_ids(
        &self,
        destination: &str,
        room_id: &str,
        event_id: &str,
    ) -> Result<Value, FederationClientError> {
        let path = format!(
            "/_matrix/federation/v1/state_ids/{}?event_id={}",
            url_query_encode(room_id),
            url_query_encode(event_id),
        );
        self.signed_request(reqwest::Method::GET, destination, &path, None)
            .await
    }

    /// `GET /_matrix/federation/v1/timestamp_to_event/{roomId}?ts=…&dir=…`
    ///
    /// MSC3030 federation companion. Caller passes "f" or "b" for `dir`.
    /// Returns the peer's `{event_id, origin_server_ts}` response, or an
    /// error if the call failed or the peer has no matching event (404
    /// surfaces as `Http`).
    pub async fn timestamp_to_event(
        &self,
        destination: &str,
        room_id: &str,
        ts: u64,
        dir: &str,
    ) -> Result<Value, FederationClientError> {
        let path = format!(
            "/_matrix/federation/v1/timestamp_to_event/{}?ts={ts}&dir={dir}",
            url_query_encode(room_id)
        );
        self.signed_request(reqwest::Method::GET, destination, &path, None)
            .await
    }

    /// `POST /_matrix/federation/v1/user/keys/query` — fetch device +
    /// cross-signing keys for users on a remote server. Body shape
    /// matches the C2S /keys/query: `{device_keys: {user_id:
    /// [device_id, ...]}}`.
    pub async fn query_user_keys(
        &self,
        destination: &str,
        body: Value,
    ) -> Result<Value, FederationClientError> {
        self.signed_request(
            reqwest::Method::POST,
            destination,
            "/_matrix/federation/v1/user/keys/query",
            Some(body),
        )
        .await
    }

    /// `POST /_matrix/federation/v1/user/keys/claim` — claim one-time
    /// keys for users on a remote server. Body shape matches the C2S
    /// /keys/claim: `{one_time_keys: {user_id: {device_id: algorithm}}}`.
    pub async fn claim_user_keys(
        &self,
        destination: &str,
        body: Value,
    ) -> Result<Value, FederationClientError> {
        self.signed_request(
            reqwest::Method::POST,
            destination,
            "/_matrix/federation/v1/user/keys/claim",
            Some(body),
        )
        .await
    }

    /// `GET /_matrix/federation/v1/backfill/{roomId}?v=...&limit=N`
    ///
    /// Sliding-window history fetch. Caller provides the event IDs to start
    /// walking back from (typically the oldest events we have locally) and
    /// a limit. The response is a transaction-shaped `{pdus: [...]}`.
    pub async fn backfill(
        &self,
        destination: &str,
        room_id: &str,
        event_ids: &[&str],
        limit: usize,
    ) -> Result<Value, FederationClientError> {
        let v_params: Vec<String> = event_ids.iter().map(|id| format!("v={id}")).collect();
        let query = format!("{}&limit={limit}", v_params.join("&"));
        let path = format!("/_matrix/federation/v1/backfill/{room_id}?{query}");
        self.signed_request(reqwest::Method::GET, destination, &path, None)
            .await
    }

    /// Fetch a remote media object via authenticated federation
    /// download (MSC3916). The peer responds with `multipart/mixed`
    /// containing two parts: a JSON metadata block (currently empty)
    /// and the file content with its original `Content-Type`. We
    /// return the file content as `(content_type, bytes)` — the JSON
    /// metadata block is reserved for future spec extensions and is
    /// dropped today.
    pub async fn fetch_media(
        &self,
        destination: &str,
        media_id: &str,
    ) -> Result<MediaResponse, FederationClientError> {
        if !self.enabled {
            return Err(FederationClientError::FederationDisabled);
        }
        let path = format!("/_matrix/federation/v1/media/download/{media_id}");

        let (url, host_header, client) =
            if let Some(base) = self.base_url_overrides.get(destination) {
                (
                    format!("{}{path}", base.value()),
                    destination.to_string(),
                    self.default_http.clone(),
                )
            } else {
                let resolved = self
                    .resolver
                    .resolve(destination)
                    .await
                    .map_err(|e| FederationClientError::Http(format!("resolve: {e}")))?;
                (
                    format!("{}{}", resolved.base_url(), path),
                    resolved.host_header.clone(),
                    self.client_for(&resolved),
                )
            };
        let auth_header =
            self.sign_federation_request(reqwest::Method::GET.as_str(), &path, destination, None);

        let mut req = client
            .request(reqwest::Method::GET, &url)
            .header("host", &host_header)
            .header("authorization", auth_header);
        req = crate::trace_context::inject_into_request(req);

        let resp = req
            .send()
            .await
            .map_err(|e| FederationClientError::Http(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(FederationClientError::Http(format!(
                "media: status {status}"
            )));
        }

        let response_ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        // Capture filename from the top-level Content-Disposition before
        // consuming the response — only used on the non-multipart compat
        // path below, but `resp.bytes()` takes ownership.
        let top_level_filename = resp
            .headers()
            .get(reqwest::header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_filename_from_content_disposition);
        let body = resp
            .bytes()
            .await
            .map_err(|e| FederationClientError::Http(format!("read body: {e}")))?;

        // Spec-compliant peers reply with multipart/mixed (MSC3916).
        // Compatibility carve-out: some servers and Complement mocks
        // return the file directly with its native Content-Type even
        // at this endpoint. When the response isn't multipart/mixed,
        // pass the body through verbatim instead of failing.
        if let Some(boundary) = parse_multipart_boundary(&response_ct) {
            parse_multipart_media(&body, &boundary)
                .map_err(|e| FederationClientError::BadJson(format!("multipart: {e}")))
        } else {
            Ok(MediaResponse {
                content_type: response_ct,
                filename: top_level_filename,
                bytes: body.to_vec(),
            })
        }
    }
}

/// Outcome of a federated `/media/download` fetch. The `filename` is
/// present when the peer's response carried one (either as a multipart
/// part's Content-Disposition or, on the legacy non-multipart path, the
/// top-level Content-Disposition); otherwise `None`. Callers propagate
/// it back to the local-download response so clients see the original
/// filename even when the file came from a remote homeserver.
#[derive(Debug)]
pub struct MediaResponse {
    pub content_type: String,
    pub filename: Option<String>,
    pub bytes: Vec<u8>,
}

/// Pull `boundary=...` out of a `Content-Type: multipart/mixed; boundary=...`
/// header value. Accepts both quoted and unquoted boundary parameters,
/// case-insensitive on the parameter name.
fn parse_multipart_boundary(content_type: &str) -> Option<String> {
    for param in content_type.split(';').skip(1) {
        let param = param.trim();
        let (name, value) = param.split_once('=')?;
        if !name.eq_ignore_ascii_case("boundary") {
            continue;
        }
        let v = value.trim();
        // Strip surrounding quotes if present.
        let v = v
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(v);
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    None
}

/// Parse a `multipart/mixed` body and return the media part —
/// `MediaResponse` — assuming the spec-defined two-part layout
/// (JSON metadata first, file content second). The `filename` field
/// is extracted from the file part's Content-Disposition when present.
/// Returns an error string on any structural mismatch.
fn parse_multipart_media(body: &[u8], boundary: &str) -> Result<MediaResponse, String> {
    let marker = format!("--{boundary}");
    let marker_b = marker.as_bytes();
    let positions: Vec<usize> = (0..body.len())
        .filter(|&i| body[i..].starts_with(marker_b))
        .collect();
    // We need at least three boundary markers: opening before the
    // JSON part, between JSON and file, and closing.
    if positions.len() < 3 {
        return Err(format!(
            "expected at least 3 boundary markers, got {}",
            positions.len()
        ));
    }
    // The file content is between positions[1] and positions[2].
    let part_start = positions[1] + marker_b.len();
    let part_end = positions[2];
    let mut p = part_start;
    // Optional CRLF after boundary.
    if body.get(p..p + 2) == Some(b"\r\n") {
        p += 2;
    }
    // Find header/body terminator (CRLFCRLF).
    let header_terminator = body[p..part_end]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "missing header terminator in media part".to_string())?;
    let headers_bytes = &body[p..p + header_terminator];
    let content_start = p + header_terminator + 4;
    // Drop the trailing CRLF before the next boundary if present.
    let mut content_end = part_end;
    if content_end >= 2 && &body[content_end - 2..content_end] == b"\r\n" {
        content_end -= 2;
    }

    let headers_str =
        std::str::from_utf8(headers_bytes).map_err(|e| format!("non-UTF-8 part headers: {e}"))?;
    let mut content_type = "application/octet-stream".to_string();
    let mut filename: Option<String> = None;
    for line in headers_str.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let n = name.trim();
        if n.eq_ignore_ascii_case("content-type") {
            content_type = value.trim().to_string();
        } else if n.eq_ignore_ascii_case("content-disposition") {
            filename = parse_filename_from_content_disposition(value.trim());
        }
    }

    Ok(MediaResponse {
        content_type,
        filename,
        bytes: body[content_start..content_end].to_vec(),
    })
}

/// Parse `filename` out of an HTTP Content-Disposition header value,
/// preferring `filename*=UTF-8''<percent-encoded>` (RFC 5987) over the
/// plain `filename="..."` form. Returns `None` when no filename is
/// declared. Defensive against malformed or empty values.
fn parse_filename_from_content_disposition(value: &str) -> Option<String> {
    let mut plain: Option<String> = None;
    let mut starred: Option<String> = None;
    for param in value.split(';').skip(1) {
        let param = param.trim();
        let Some((name, raw_value)) = param.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let raw_value = raw_value.trim();
        if name.eq_ignore_ascii_case("filename*") {
            // RFC 5987: charset'language'percent-encoded-value
            let mut parts = raw_value.splitn(3, '\'');
            let charset = parts.next().unwrap_or("");
            let _lang = parts.next().unwrap_or("");
            let encoded = parts.next().unwrap_or("");
            if !charset.eq_ignore_ascii_case("utf-8") || encoded.is_empty() {
                continue;
            }
            let mut decoded = Vec::with_capacity(encoded.len());
            let bytes = encoded.as_bytes();
            let mut i = 0;
            let mut ok = true;
            while i < bytes.len() {
                if bytes[i] == b'%' && i + 2 < bytes.len() {
                    let hi = (bytes[i + 1] as char).to_digit(16);
                    let lo = (bytes[i + 2] as char).to_digit(16);
                    match (hi, lo) {
                        (Some(h), Some(l)) => {
                            decoded.push((h * 16 + l) as u8);
                            i += 3;
                        }
                        _ => {
                            ok = false;
                            break;
                        }
                    }
                } else {
                    decoded.push(bytes[i]);
                    i += 1;
                }
            }
            if ok && let Ok(s) = String::from_utf8(decoded) {
                starred = Some(s);
            }
        } else if name.eq_ignore_ascii_case("filename") {
            let v = raw_value
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(raw_value);
            if !v.is_empty() {
                plain = Some(v.to_string());
            }
        }
    }
    starred.or(plain)
}

#[cfg(test)]
mod multipart_tests {
    use super::{parse_multipart_boundary, parse_multipart_media};

    #[test]
    fn boundary_parsing_handles_quotes_and_case() {
        assert_eq!(
            parse_multipart_boundary("multipart/mixed; boundary=abc").as_deref(),
            Some("abc")
        );
        assert_eq!(
            parse_multipart_boundary("multipart/mixed; BOUNDARY=\"x-y-z\"").as_deref(),
            Some("x-y-z")
        );
        assert_eq!(parse_multipart_boundary("multipart/mixed"), None);
    }

    #[test]
    fn multipart_extracts_media_part_round_trip() {
        let boundary = "vela-test-boundary";
        let body_inner = b"hello world".to_vec();
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
        body.extend_from_slice(b"{}\r\n");
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n\r\n");
        body.extend_from_slice(&body_inner);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

        let media = parse_multipart_media(&body, boundary).unwrap();
        assert_eq!(media.content_type, "text/plain; charset=utf-8");
        assert_eq!(media.bytes, body_inner);
        assert!(media.filename.is_none(), "no Content-Disposition → None");
    }

    #[test]
    fn multipart_extracts_unicode_filename_from_part_content_disposition() {
        let boundary = "vela-unicode";
        let body_inner = b"\xe2\x98\x95".to_vec();
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
        body.extend_from_slice(b"{}\r\n");
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: image/png\r\n");
        body.extend_from_slice(
            b"Content-Disposition: inline; filename=\"\"; filename*=UTF-8''%E2%98%95\r\n\r\n",
        );
        body.extend_from_slice(&body_inner);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

        let media = parse_multipart_media(&body, boundary).unwrap();
        assert_eq!(media.content_type, "image/png");
        assert_eq!(media.filename.as_deref(), Some("☕"));
        assert_eq!(media.bytes, body_inner);
    }

    #[test]
    fn parse_filename_prefers_rfc5987_over_plain() {
        use super::parse_filename_from_content_disposition;
        // plain only
        assert_eq!(
            parse_filename_from_content_disposition("inline; filename=\"hello.txt\""),
            Some("hello.txt".to_string())
        );
        // RFC 5987 wins
        assert_eq!(
            parse_filename_from_content_disposition(
                "inline; filename=\"fallback\"; filename*=UTF-8''%E2%98%95"
            ),
            Some("☕".to_string())
        );
        // No filename at all
        assert!(parse_filename_from_content_disposition("inline").is_none());
    }
}

/// Validate a `/_matrix/key/v2/server` response per spec.
///
/// Checks (in order):
/// 1. Has `server_name` and it matches the queried name.
/// 2. Has `verify_keys` map (non-empty) and `valid_until_ts`.
/// 3. Has a `signatures.{server_name}.{key_id}` entry where `key_id` is in the
///    response's own `verify_keys`, and that signature verifies.
/// 4. `valid_until_ts > now`.
/// 5. Each verify_keys entry decodes to a 32-byte Ed25519 public key.
/// 6. Effective validity is capped at `min(valid_until_ts, now + 7d)`.
pub fn validate_key_response(
    body: &Value,
    expected_server_name: &str,
    now_ms: u64,
) -> Result<RemoteKeys, FederationClientError> {
    let obj = body
        .as_object()
        .ok_or(FederationClientError::BadJson("not an object".into()))?;

    // 1. server_name match
    let server_name = obj
        .get("server_name")
        .and_then(|v| v.as_str())
        .ok_or(FederationClientError::MissingField("server_name"))?;
    if server_name != expected_server_name {
        return Err(FederationClientError::ServerNameMismatch {
            expected: expected_server_name.to_string(),
            got: server_name.to_string(),
        });
    }

    // 2. verify_keys + valid_until_ts present
    let verify_keys_obj = obj
        .get("verify_keys")
        .and_then(|v| v.as_object())
        .ok_or(FederationClientError::MissingField("verify_keys"))?;
    if verify_keys_obj.is_empty() {
        return Err(FederationClientError::MissingField("verify_keys (empty)"));
    }
    let valid_until_ts = obj
        .get("valid_until_ts")
        .and_then(|v| v.as_u64())
        .ok_or(FederationClientError::MissingField("valid_until_ts"))?;

    // 4. valid_until_ts must be in the future and plausibly finite
    if valid_until_ts <= now_ms {
        return Err(FederationClientError::ExpiredKeyResponse);
    }
    if valid_until_ts > now_ms.saturating_add(FAR_FUTURE_CAP_MS) {
        return Err(FederationClientError::FarFutureKeyResponse);
    }

    // 5. Decode each verify_keys entry; reject malformed
    let mut verify_keys_map: HashMap<String, String> = HashMap::new();
    for (key_id, entry) in verify_keys_obj {
        let key_b64 = entry.get("key").and_then(|v| v.as_str()).ok_or_else(|| {
            FederationClientError::MalformedKey {
                key_id: key_id.clone(),
                reason: "missing 'key' field".into(),
            }
        })?;
        decode_public_key(key_b64).map_err(|e| FederationClientError::MalformedKey {
            key_id: key_id.clone(),
            reason: e.to_string(),
        })?;
        verify_keys_map.insert(key_id.clone(), key_b64.to_string());
    }

    // 5b. Old (rotated-out) verify keys: usable for verifying events only.
    //     Best-effort — a malformed entry is skipped rather than failing the
    //     whole response, since current keys (which gate live requests) must
    //     not be held hostage to historical-key cruft. `expired_ts` is ignored
    //     (see `RemoteKeys::old_verify_keys`).
    let mut old_verify_keys_map: HashMap<String, String> = HashMap::new();
    if let Some(old_obj) = obj.get("old_verify_keys").and_then(|v| v.as_object()) {
        for (key_id, entry) in old_obj {
            let Some(key_b64) = entry.get("key").and_then(|v| v.as_str()) else {
                continue;
            };
            if decode_public_key(key_b64).is_err() {
                continue;
            }
            old_verify_keys_map.insert(key_id.clone(), key_b64.to_string());
        }
    }

    // 3. Self-signature: at least one signature under signatures.{server_name}
    //    must use a key_id in verify_keys, and that signature must verify.
    let sigs_root = obj
        .get("signatures")
        .and_then(|v| v.as_object())
        .ok_or(FederationClientError::MissingField("signatures"))?;
    let our_sigs = sigs_root.get(server_name).and_then(|v| v.as_object());
    let our_sigs = match our_sigs {
        Some(s) if !s.is_empty() => s,
        _ => return Err(FederationClientError::NoValidSelfSignature),
    };

    let mut any_verified = false;
    for (key_id, _sig) in our_sigs {
        let Some(pub_b64) = verify_keys_map.get(key_id) else {
            // Signature uses a key_id not in verify_keys — ignore this one.
            continue;
        };
        let public_key = decode_public_key(pub_b64)?;
        match verify_json_signature(obj, server_name, key_id, &public_key) {
            Ok(()) => {
                any_verified = true;
                break;
            }
            Err(_) => continue,
        }
    }
    if !any_verified {
        return Err(FederationClientError::NoValidSelfSignature);
    }

    // 6. Apply 7-day cap
    let capped_valid_until = valid_until_ts.min(now_ms.saturating_add(KEY_VALIDITY_CAP_MS));

    Ok(RemoteKeys {
        verify_keys: verify_keys_map,
        old_verify_keys: old_verify_keys_map,
        valid_until_ts: capped_valid_until,
        fetched_at: now_ms,
    })
}

// ========================================================================
// X-Matrix request signing (3a.3)
// ========================================================================

impl FederationClient {
    /// Build an `Authorization: X-Matrix ...` header for a federation request.
    ///
    /// Per `server-server-api.md:287-387`, the signed JSON is:
    /// ```json
    /// {"method": "GET", "uri": "/_matrix/...", "origin": "us", "destination": "them",
    ///  "content": <body-if-any>}
    /// ```
    /// `content` is omitted entirely for requests without a body (e.g. GET).
    pub fn sign_federation_request(
        &self,
        method: &str,
        uri: &str,
        destination: &str,
        body: Option<&Value>,
    ) -> HeaderValue {
        let header_str = build_x_matrix_header(
            &self.signing_key,
            &self.our_server_name,
            method,
            uri,
            destination,
            body,
        );
        HeaderValue::from_str(&header_str).expect("signed header is ASCII")
    }
}

/// Build the X-Matrix Authorization header value. Extracted as a free function
/// for direct unit testing.
pub fn build_x_matrix_header(
    signing_key: &ServerSigningKey,
    origin: &str,
    method: &str,
    uri: &str,
    destination: &str,
    body: Option<&Value>,
) -> String {
    let mut request_json = Map::new();
    request_json.insert("method".into(), json!(method));
    request_json.insert("uri".into(), json!(uri));
    request_json.insert("origin".into(), json!(origin));
    request_json.insert("destination".into(), json!(destination));
    if let Some(b) = body {
        request_json.insert("content".into(), b.clone());
    }

    // Sign the JSON (strips signatures+unsigned, canonical encodes, signs, reinserts).
    signing_key.sign_json(&mut request_json, origin);

    let sig = request_json["signatures"][origin][signing_key.key_id()]
        .as_str()
        .expect("signing_key.sign_json inserts a string signature")
        .to_string();

    format!(
        "X-Matrix origin=\"{}\",destination=\"{}\",key=\"{}\",sig=\"{}\"",
        origin,
        destination,
        signing_key.key_id(),
        sig,
    )
}

/// Verify an X-Matrix-signed request on the receive side.
///
/// Rebuilds the signed JSON from method + uri + origin + destination + body,
/// then verifies the signature using the given public key.
pub fn verify_federation_request(
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    body: Option<&Value>,
    key_id: &str,
    public_key: &ed25519_dalek::VerifyingKey,
    signature_b64: &str,
) -> Result<(), SignatureError> {
    let mut request_json = Map::new();
    request_json.insert("method".into(), json!(method));
    request_json.insert("uri".into(), json!(uri));
    request_json.insert("origin".into(), json!(origin));
    request_json.insert("destination".into(), json!(destination));
    if let Some(b) = body {
        request_json.insert("content".into(), b.clone());
    }

    // Reconstruct the signatures block as signJson would have produced
    // so we can call verify_json_signature.
    let mut sigs_for_origin = Map::new();
    sigs_for_origin.insert(key_id.to_string(), json!(signature_b64));
    let mut sigs = Map::new();
    sigs.insert(origin.to_string(), Value::Object(sigs_for_origin));
    request_json.insert("signatures".into(), Value::Object(sigs));

    verify_json_signature(&request_json, origin, key_id, public_key)
}

/// Current time in milliseconds since UNIX epoch.
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock sane")
        .as_millis() as u64
}

// ========================================================================
// Remote key cache (3a.2)
// ========================================================================

use dashmap::DashMap;
use vela_store::db::Database;

/// In-memory + persistent cache of remote server keys.
///
/// Two tiers:
/// - DashMap for hot-path lookups (no disk I/O on cache hit).
/// - `server_keys` CF in RocksDB for durability across restarts.
///
/// Population strategy is lazy: `get_or_fetch` consults memory, then disk,
/// then fetches from the remote server. No background refresher in 3a.
pub struct RemoteKeyCache {
    memory: DashMap<String, Arc<RemoteKeys>>,
    db: Arc<Database>,
    client: FederationClient,
}

/// Minimum interval between key (re)fetches for the *same* server triggered by
/// an unknown key id. Signing keys rotate, so a key id we've never seen is
/// normally legitimate and we re-fetch to pick it up — but a hostile peer must
/// not be able to make us hammer a victim's `/_matrix/key/v2/server` by signing
/// requests with random key ids, so a server we fetched within this window is
/// served from cache (the caller then rejects the unverifiable request). 1s
/// bounds the worst case to ~1 key fetch/sec/server while still recovering from
/// a real rotation within a second.
const MIN_KEY_REFETCH_MS: u64 = 1_000;

/// Whether a cached key document is good enough to serve a request signed by
/// one of `wanted`, or whether the caller must (re)fetch.
///
/// Serve the cache iff it is still time-valid **and** either it already has one
/// of the wanted keys, or it was fetched within `min_refetch_ms` (the storm
/// guard above). An expired document, or a valid one missing the wanted key
/// past the cooldown, forces a fetch.
fn cache_suffices(cached: &RemoteKeys, wanted: &[&str], now: u64, min_refetch_ms: u64) -> bool {
    cached.is_valid_at(now)
        && (cached.covers_any(wanted) || now.saturating_sub(cached.fetched_at) < min_refetch_ms)
}

impl RemoteKeyCache {
    pub fn new(db: Arc<Database>, client: FederationClient) -> Self {
        Self {
            memory: DashMap::new(),
            db,
            client,
        }
    }

    /// Return cached keys if present and still valid; otherwise fetch.
    /// On fetch, the result is written to both disk and memory.
    ///
    /// Time-based only: use [`get_or_fetch_signed`](Self::get_or_fetch_signed)
    /// when you know which key id a request/event is signed with, so a rotated
    /// signing key is picked up rather than rejected.
    pub async fn get_or_fetch(
        &self,
        server_name: &str,
    ) -> Result<Arc<RemoteKeys>, FederationClientError> {
        self.get_or_fetch_signed(server_name, &[]).await
    }

    /// Like [`get_or_fetch`](Self::get_or_fetch), but aware of the `wanted` key
    /// ids the request/event is signed with.
    ///
    /// A server can present a *current* signing key id we've never seen — it
    /// rotated to a new key, or (under Complement) a port was reused by a fresh
    /// server — while our cached document for it is still inside its
    /// `valid_until_ts`. The plain time check then hands back a stale document
    /// and we wrongly reject a legitimately-signed request. This variant
    /// re-fetches when a time-valid cache is missing all of `wanted`,
    /// rate-limited by `MIN_KEY_REFETCH_MS` so a peer can't induce a fetch
    /// storm with bogus key ids. (This is what surfaces as the msc3902 flake
    /// under Docker ephemeral-port reuse: a new test server reuses a port with
    /// a fresh key while we still cache the previous occupant's key.)
    pub async fn get_or_fetch_signed(
        &self,
        server_name: &str,
        wanted: &[&str],
    ) -> Result<Arc<RemoteKeys>, FederationClientError> {
        let now = now_ms();

        // 1. Memory
        if let Some(entry) = self.memory.get(server_name) {
            let cached = entry.clone();
            drop(entry);
            if cache_suffices(&cached, wanted, now, MIN_KEY_REFETCH_MS) {
                return Ok(cached);
            }
            if cached.is_valid_at(now) {
                // Time-valid but signed with a key id we don't have and past
                // the cooldown: re-fetch to pick up a rotated key, falling back
                // to the cached document if the fetch fails (it still verifies
                // requests using the keys we already hold).
                return Ok(self.refetch_or(server_name, cached).await);
            }
            // Expired — drop and fall through to disk/network.
            drop(cached);
            self.memory.remove(server_name);
        }

        // 2. Disk
        if let Ok(Some(bytes)) = self.db.load_remote_server_keys(server_name)
            && let Ok(keys) = serde_json::from_slice::<RemoteKeys>(&bytes)
            && keys.is_valid_at(now)
        {
            let arc = Arc::new(keys);
            self.memory.insert(server_name.to_string(), arc.clone());
            if cache_suffices(&arc, wanted, now, MIN_KEY_REFETCH_MS) {
                return Ok(arc);
            }
            return Ok(self.refetch_or(server_name, arc).await);
        }

        // 3. Fetch (cold cache or expired) — propagate the error.
        let arc = Arc::new(self.client.fetch_server_keys(server_name).await?);
        self.store(server_name, &arc);
        Ok(arc)
    }

    /// Re-fetch keys for a server whose cached document lacks the wanted key
    /// id, returning the fresh keys on success or the (cooldown-armed)
    /// `fallback` on failure.
    ///
    /// The cooldown is armed in memory **before** the fetch is awaited. This
    /// coalesces a concurrent burst: requests that arrive while the fetch is in
    /// flight see a recently-refreshed cache and serve from it instead of each
    /// launching their own fetch. That matters because the inbound-auth path
    /// runs this for unauthenticated, attacker-chosen `(origin, key_id)` pairs,
    /// where the fetch targets a third party — without the early stamp a single
    /// connection burst would fan out into one (timeout-prone) fetch per
    /// request. The stamp is memory-only: it is transient, needn't survive a
    /// restart, and keeping it off disk avoids write churn under such a burst.
    async fn refetch_or(&self, server_name: &str, fallback: Arc<RemoteKeys>) -> Arc<RemoteKeys> {
        let stamped = Arc::new(RemoteKeys {
            verify_keys: fallback.verify_keys.clone(),
            old_verify_keys: fallback.old_verify_keys.clone(),
            valid_until_ts: fallback.valid_until_ts,
            fetched_at: now_ms(),
        });
        self.memory.insert(server_name.to_string(), stamped.clone());

        match self.client.fetch_server_keys(server_name).await {
            Ok(keys) => {
                let arc = Arc::new(keys);
                self.store(server_name, &arc);
                arc
            }
            Err(e) => {
                debug!(%server_name, error = %e, "key refetch for unknown key id failed; using cached keys");
                stamped
            }
        }
    }

    /// Write a key document to both disk and the in-memory cache.
    fn store(&self, server_name: &str, arc: &Arc<RemoteKeys>) {
        if let Ok(bytes) = serde_json::to_vec(&**arc) {
            let _ = self.db.store_remote_server_keys(server_name, &bytes);
        }
        self.memory.insert(server_name.to_string(), arc.clone());
    }

    /// Store a pre-fetched RemoteKeys directly. Used by tests (both
    /// `#[cfg(test)]` unit tests and integration tests under `tests/`)
    /// to seed the cache for a stub remote without an HTTP fetch.
    pub fn insert_for_test(&self, server_name: &str, keys: RemoteKeys) {
        let arc = Arc::new(keys);
        if let Ok(bytes) = serde_json::to_vec(&*arc) {
            let _ = self.db.store_remote_server_keys(server_name, &bytes);
        }
        self.memory.insert(server_name.to_string(), arc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn url_query_encode_preserves_unreserved() {
        // RFC 3986 unreserved set: ALPHA / DIGIT / - . _ ~
        assert_eq!(
            url_query_encode("Abc-123_xyz.~"),
            "Abc-123_xyz.~",
            "unreserved chars must NOT be percent-encoded"
        );
    }

    #[test]
    fn url_query_encode_percent_encodes_reserved() {
        // Reserved + sub-delims must encode.
        assert_eq!(url_query_encode("#alias:host"), "%23alias%3Ahost");
        assert_eq!(url_query_encode("@user:host"), "%40user%3Ahost");
        // Space, slash, query.
        assert_eq!(url_query_encode("a b/c?d"), "a%20b%2Fc%3Fd");
    }

    #[test]
    fn url_query_encode_percent_encodes_multibyte_utf8() {
        // The TestRemoteAliasRequestsUnderstandUnicode case: every UTF-8
        // byte gets percent-encoded so the wire URL matches what we
        // signed.
        let alias = "#老虎:hs1";
        let encoded = url_query_encode(alias);
        // No raw multibyte bytes survive.
        assert!(
            encoded.is_ascii(),
            "encoded form must be pure ASCII: {encoded}"
        );
        // Sigil + colon present.
        assert!(encoded.starts_with("%23"));
        assert!(encoded.contains("%3A"));
        // Unicode bytes encoded — `老` (U+8001) is 3 bytes in UTF-8:
        // E8 80 81. Verify those appear in order.
        assert!(encoded.contains("%E8%80%81"));
    }

    fn now_ms_fixed() -> u64 {
        1_700_000_000_000
    }

    fn sign_key_response(key: &ServerSigningKey, server_name: &str, valid_until_ts: u64) -> Value {
        let mut body = Map::new();
        body.insert("server_name".into(), json!(server_name));
        body.insert(
            "verify_keys".into(),
            json!({
                key.key_id(): {"key": key.public_key_base64()}
            }),
        );
        body.insert("old_verify_keys".into(), json!({}));
        body.insert("valid_until_ts".into(), json!(valid_until_ts));
        key.sign_json(&mut body, server_name);
        Value::Object(body)
    }

    /// Build a cached key document with the given key ids present.
    fn keys_doc(valid_until_ts: u64, fetched_at: u64, key_ids: &[&str]) -> RemoteKeys {
        RemoteKeys {
            verify_keys: key_ids
                .iter()
                .map(|k| ((*k).to_string(), "AAAA".to_string()))
                .collect(),
            old_verify_keys: HashMap::new(),
            valid_until_ts,
            fetched_at,
        }
    }

    #[test]
    fn cache_suffices_when_valid_and_has_key() {
        let now = now_ms_fixed();
        let doc = keys_doc(now + 60_000, now - 60_000, &["ed25519:a"]);
        assert!(cache_suffices(
            &doc,
            &["ed25519:a"],
            now,
            MIN_KEY_REFETCH_MS
        ));
    }

    #[test]
    fn cache_refetches_when_valid_but_missing_key_and_cooled_down() {
        let now = now_ms_fixed();
        // Fetched well past the cooldown, signed with a key we don't have:
        // must refetch (this is the rotation / port-reuse case).
        let doc = keys_doc(now + 60_000, now - 60_000, &["ed25519:old"]);
        assert!(!cache_suffices(
            &doc,
            &["ed25519:new"],
            now,
            MIN_KEY_REFETCH_MS
        ));
    }

    #[test]
    fn cache_suffices_when_missing_key_but_within_cooldown() {
        let now = now_ms_fixed();
        // Just fetched: serve the cache even though it lacks the key, so a
        // peer signing with random key ids can't make us hammer the origin.
        let doc = keys_doc(now + 60_000, now - 10, &["ed25519:old"]);
        assert!(cache_suffices(
            &doc,
            &["ed25519:new"],
            now,
            MIN_KEY_REFETCH_MS
        ));
    }

    #[test]
    fn cache_never_suffices_when_expired() {
        let now = now_ms_fixed();
        // Expired forces a fetch even when it holds the wanted key, and even
        // when freshly fetched.
        let doc = keys_doc(now - 1, now, &["ed25519:a"]);
        assert!(!cache_suffices(
            &doc,
            &["ed25519:a"],
            now,
            MIN_KEY_REFETCH_MS
        ));
    }

    #[test]
    fn cache_suffices_with_empty_wanted_mirrors_time_check() {
        let now = now_ms_fixed();
        // No specific key wanted (the plain get_or_fetch path): valid → serve,
        // expired → fetch, regardless of contents.
        assert!(cache_suffices(
            &keys_doc(now + 1, now, &[]),
            &[],
            now,
            MIN_KEY_REFETCH_MS
        ));
        assert!(!cache_suffices(
            &keys_doc(now - 1, now, &[]),
            &[],
            now,
            MIN_KEY_REFETCH_MS
        ));
    }

    #[test]
    fn event_verify_key_uses_current_then_old() {
        let keys = RemoteKeys {
            verify_keys: HashMap::from([("ed25519:cur".to_string(), "CURRENT".to_string())]),
            old_verify_keys: HashMap::from([("ed25519:old".to_string(), "OLDKEY".to_string())]),
            valid_until_ts: 0,
            fetched_at: 0,
        };
        assert_eq!(keys.event_verify_key("ed25519:cur"), Some("CURRENT"));
        assert_eq!(keys.event_verify_key("ed25519:old"), Some("OLDKEY"));
        assert_eq!(keys.event_verify_key("ed25519:nope"), None);
    }

    #[test]
    fn cache_suffices_covers_old_verify_keys() {
        let now = now_ms_fixed();
        let doc = RemoteKeys {
            verify_keys: HashMap::from([("ed25519:cur".to_string(), "C".to_string())]),
            old_verify_keys: HashMap::from([("ed25519:old".to_string(), "O".to_string())]),
            valid_until_ts: now + 60_000,
            fetched_at: now - 60_000,
        };
        // An event signed with the known *old* key must not trigger a refetch...
        assert!(cache_suffices(
            &doc,
            &["ed25519:old"],
            now,
            MIN_KEY_REFETCH_MS
        ));
        // ...but a genuinely unknown key id still does.
        assert!(!cache_suffices(
            &doc,
            &["ed25519:unknown"],
            now,
            MIN_KEY_REFETCH_MS
        ));
    }

    #[test]
    fn validates_response_with_old_verify_keys() {
        let cur = ServerSigningKey::generate();
        let old = ServerSigningKey::generate();
        let old_pub = old.public_key_base64();
        let mut body = sign_key_response(&cur, "them.example", now_ms_fixed() + 60_000);
        // Inject an old_verify_keys entry, then re-sign with the current key so
        // the document still self-verifies over its new contents.
        let obj = body.as_object_mut().unwrap();
        obj.insert(
            "old_verify_keys".into(),
            json!({ old.key_id(): { "key": old_pub, "expired_ts": 1000 } }),
        );
        obj.remove("signatures");
        cur.sign_json(obj, "them.example");

        let parsed =
            validate_key_response(&body, "them.example", now_ms_fixed()).expect("valid response");
        assert!(parsed.verify_keys.contains_key(cur.key_id()));
        assert_eq!(
            parsed.old_verify_keys.get(old.key_id()).map(String::as_str),
            Some(old_pub.as_str()),
            "old_verify_keys must be parsed into the cached document",
        );
    }

    #[test]
    fn validates_well_formed_self_signed_response() {
        let key = ServerSigningKey::generate();
        let body = sign_key_response(&key, "them.example", now_ms_fixed() + 60_000);
        let parsed =
            validate_key_response(&body, "them.example", now_ms_fixed()).expect("valid response");
        assert_eq!(parsed.verify_keys.len(), 1);
        assert!(parsed.verify_keys.contains_key(key.key_id()));
        assert!(parsed.is_valid_at(now_ms_fixed()));
    }

    #[test]
    fn rejects_server_name_mismatch() {
        let key = ServerSigningKey::generate();
        let body = sign_key_response(&key, "them.example", now_ms_fixed() + 60_000);
        let err = validate_key_response(&body, "someone-else.example", now_ms_fixed())
            .expect_err("must reject");
        assert!(matches!(
            err,
            FederationClientError::ServerNameMismatch { .. }
        ));
    }

    #[test]
    fn rejects_tampered_body() {
        let key = ServerSigningKey::generate();
        let mut body = sign_key_response(&key, "them.example", now_ms_fixed() + 60_000);
        // Tamper with a non-signature field after signing.
        body.as_object_mut()
            .unwrap()
            .insert("sneaky".into(), json!("injected"));
        let err =
            validate_key_response(&body, "them.example", now_ms_fixed()).expect_err("must reject");
        assert!(matches!(err, FederationClientError::NoValidSelfSignature));
    }

    #[test]
    fn rejects_expired_response() {
        let key = ServerSigningKey::generate();
        let body = sign_key_response(&key, "them.example", now_ms_fixed() - 1);
        let err =
            validate_key_response(&body, "them.example", now_ms_fixed()).expect_err("must reject");
        assert!(matches!(err, FederationClientError::ExpiredKeyResponse));
    }

    #[test]
    fn rejects_far_future_valid_until_ts() {
        let key = ServerSigningKey::generate();
        let body = sign_key_response(&key, "them.example", u64::MAX);
        let err =
            validate_key_response(&body, "them.example", now_ms_fixed()).expect_err("must reject");
        assert!(matches!(err, FederationClientError::FarFutureKeyResponse));
    }

    #[test]
    fn caps_validity_at_seven_days() {
        let key = ServerSigningKey::generate();
        // Server claims 30 days of validity. We must cap at 7.
        let claimed = now_ms_fixed() + 30 * 24 * 60 * 60 * 1000;
        let body = sign_key_response(&key, "them.example", claimed);
        let parsed = validate_key_response(&body, "them.example", now_ms_fixed()).unwrap();
        let expected_cap = now_ms_fixed() + KEY_VALIDITY_CAP_MS;
        assert_eq!(parsed.valid_until_ts, expected_cap);
    }

    #[test]
    fn rejects_malformed_verify_key() {
        let key = ServerSigningKey::generate();
        let mut body = Map::new();
        body.insert("server_name".into(), json!("them.example"));
        body.insert(
            "verify_keys".into(),
            json!({
                "ed25519:bad": {"key": "not-valid-base64!"}
            }),
        );
        body.insert("valid_until_ts".into(), json!(now_ms_fixed() + 60_000));
        key.sign_json(&mut body, "them.example");
        let err = validate_key_response(&Value::Object(body), "them.example", now_ms_fixed())
            .expect_err("must reject");
        assert!(matches!(err, FederationClientError::MalformedKey { .. }));
    }

    #[test]
    fn rejects_when_no_signature_matches_verify_keys() {
        // Signed by a different key than the one advertised in verify_keys.
        let advertised = ServerSigningKey::generate();
        let different = ServerSigningKey::generate();
        let mut body = Map::new();
        body.insert("server_name".into(), json!("them.example"));
        body.insert(
            "verify_keys".into(),
            json!({
                advertised.key_id(): {"key": advertised.public_key_base64()}
            }),
        );
        body.insert("old_verify_keys".into(), json!({}));
        body.insert("valid_until_ts".into(), json!(now_ms_fixed() + 60_000));
        // Sign with a key NOT in verify_keys.
        different.sign_json(&mut body, "them.example");
        let err = validate_key_response(&Value::Object(body), "them.example", now_ms_fixed())
            .expect_err("must reject");
        assert!(matches!(err, FederationClientError::NoValidSelfSignature));
    }

    // --- X-Matrix signing tests ---

    #[test]
    fn client_cache_keys_by_sni_and_port() {
        // Different destinations get different cached clients; repeat lookups
        // for the same destination reuse the cache. This is what makes the
        // per-destination SNI override efficient — we don't rebuild a TLS
        // config on every request.
        use crate::federation::federation_resolver::{FederationResolver, ResolvedServer};
        use std::net::IpAddr;
        use std::sync::Arc;

        let key = Arc::new(ServerSigningKey::generate());
        let resolver = Arc::new(FederationResolver::new().unwrap());
        let client = FederationClient::new(key, "us.example".into(), resolver, Vec::new());

        let r1 = ResolvedServer {
            target_host: "node1.internal".into(),
            target_port: 8443,
            tls_server_name: "matrix.example.com".into(),
            host_header: "matrix.example.com".into(),
            resolved_ips: vec!["10.0.0.1".parse::<IpAddr>().unwrap()],
        };
        let r2 = ResolvedServer {
            target_host: "node2.internal".into(),
            target_port: 8443,
            tls_server_name: "other.example.com".into(),
            host_header: "other.example.com".into(),
            resolved_ips: vec!["10.0.0.2".parse::<IpAddr>().unwrap()],
        };

        // Different destinations → different entries.
        let _c1 = client.client_for(&r1);
        let _c2 = client.client_for(&r2);
        assert_eq!(client.clients.len(), 2);

        // Same destination → reuses cache.
        let _c1_again = client.client_for(&r1);
        assert_eq!(client.clients.len(), 2, "client_for should memoise");
    }

    #[test]
    fn client_for_falls_back_to_default_on_empty_ips() {
        // IP-literal case has empty resolved_ips (well, populated but empty is
        // also possible on DNS failure). We should return the default client
        // rather than build one without a resolve override.
        use crate::federation::federation_resolver::{FederationResolver, ResolvedServer};
        use std::sync::Arc;

        let key = Arc::new(ServerSigningKey::generate());
        let resolver = Arc::new(FederationResolver::new().unwrap());
        let client = FederationClient::new(key, "us.example".into(), resolver, Vec::new());

        let r = ResolvedServer {
            target_host: "example.com".into(),
            target_port: 8448,
            tls_server_name: "example.com".into(),
            host_header: "example.com".into(),
            resolved_ips: vec![], // DNS failed, empty
        };
        let _ = client.client_for(&r);
        // Cache not populated for the empty-IPs path.
        assert_eq!(client.clients.len(), 0);
    }

    #[test]
    fn build_header_matches_spec_format() {
        let key = ServerSigningKey::generate();
        let header = build_x_matrix_header(
            &key,
            "us.example",
            "GET",
            "/_matrix/key/v2/server",
            "them.example",
            None,
        );
        assert!(header.starts_with("X-Matrix "));
        assert!(header.contains(r#"origin="us.example""#));
        assert!(header.contains(r#"destination="them.example""#));
        assert!(header.contains(&format!(r#"key="{}""#, key.key_id())));
        assert!(header.contains(r#"sig=""#));
    }

    #[test]
    fn sign_verify_roundtrip_get() {
        let key = ServerSigningKey::generate();
        let header = build_x_matrix_header(
            &key,
            "us.example",
            "GET",
            "/_matrix/foo",
            "them.example",
            None,
        );
        // Extract sig from header
        let sig = extract_header_param(&header, "sig").unwrap();
        let result = verify_federation_request(
            "GET",
            "/_matrix/foo",
            "us.example",
            "them.example",
            None,
            key.key_id(),
            &key.verifying_key(),
            &sig,
        );
        assert!(result.is_ok(), "roundtrip should verify: {result:?}");
    }

    #[test]
    fn sign_verify_roundtrip_post_with_body() {
        let key = ServerSigningKey::generate();
        let body = json!({"foo": "bar", "n": 42});
        let header = build_x_matrix_header(
            &key,
            "us.example",
            "POST",
            "/_matrix/bar",
            "them.example",
            Some(&body),
        );
        let sig = extract_header_param(&header, "sig").unwrap();
        let result = verify_federation_request(
            "POST",
            "/_matrix/bar",
            "us.example",
            "them.example",
            Some(&body),
            key.key_id(),
            &key.verifying_key(),
            &sig,
        );
        assert!(result.is_ok(), "roundtrip should verify: {result:?}");
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let key = ServerSigningKey::generate();
        let body = json!({"foo": "bar"});
        let header = build_x_matrix_header(
            &key,
            "us.example",
            "POST",
            "/_matrix/bar",
            "them.example",
            Some(&body),
        );
        let sig = extract_header_param(&header, "sig").unwrap();
        let tampered = json!({"foo": "EVIL"});
        let result = verify_federation_request(
            "POST",
            "/_matrix/bar",
            "us.example",
            "them.example",
            Some(&tampered),
            key.key_id(),
            &key.verifying_key(),
            &sig,
        );
        assert!(matches!(result, Err(SignatureError::VerificationFailed)));
    }

    #[test]
    fn verify_rejects_wrong_destination() {
        let key = ServerSigningKey::generate();
        let header = build_x_matrix_header(
            &key,
            "us.example",
            "GET",
            "/_matrix/foo",
            "them.example",
            None,
        );
        let sig = extract_header_param(&header, "sig").unwrap();
        let result = verify_federation_request(
            "GET",
            "/_matrix/foo",
            "us.example",
            "attacker.example", // different destination
            None,
            key.key_id(),
            &key.verifying_key(),
            &sig,
        );
        assert!(matches!(result, Err(SignatureError::VerificationFailed)));
    }

    fn extract_header_param(header: &str, param: &str) -> Option<String> {
        let prefix = format!("{param}=\"");
        let start = header.find(&prefix)? + prefix.len();
        let rest = &header[start..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    }
}
