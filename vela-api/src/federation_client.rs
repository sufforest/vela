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

/// Parsed + validated key response, ready for caching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteKeys {
    /// Map of key_id → unpadded-base64 public key bytes.
    pub verify_keys: HashMap<String, String>,
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
    resolver: Arc<crate::federation_resolver::FederationResolver>,
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

impl FederationClient {
    pub fn new(
        signing_key: Arc<ServerSigningKey>,
        our_server_name: String,
        resolver: Arc<crate::federation_resolver::FederationResolver>,
        extra_ca_certs: Vec<reqwest::Certificate>,
    ) -> Self {
        Self::new_with_enabled(signing_key, our_server_name, resolver, extra_ca_certs, true)
    }

    pub fn new_with_enabled(
        signing_key: Arc<ServerSigningKey>,
        our_server_name: String,
        resolver: Arc<crate::federation_resolver::FederationResolver>,
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
        resolved: &crate::federation_resolver::ResolvedServer,
    ) -> reqwest::Client {
        // If no resolved IPs (shouldn't happen for valid hostnames post-3c.1,
        // but defensive), fall back to the default client which does its own DNS.
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

        let body: Value = resp
            .json()
            .await
            .map_err(|e| FederationClientError::BadJson(e.to_string()))?;

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
        let resp_body: Value = resp
            .json()
            .await
            .map_err(|e| FederationClientError::BadJson(e.to_string()))?;

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
    pub async fn send_join_v2(
        &self,
        destination: &str,
        room_id: &str,
        event_id: &str,
        signed_event: Value,
    ) -> Result<Value, FederationClientError> {
        let path = format!("/_matrix/federation/v2/send_join/{room_id}/{event_id}");
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

    /// `GET /_matrix/federation/v1/event/{eventId}` — fetch a single
    /// PDU we don't have locally. Response is a transaction-shaped
    /// object (`{origin, origin_server_ts, pdus: [event]}`); we
    /// return just the PDU value, leaving validation / persistence
    /// to the caller via `persist_fetched_event`.
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
    ) -> Result<(String, Vec<u8>), FederationClientError> {
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
            Ok((response_ct, body.to_vec()))
        }
    }
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
/// `(content_type, bytes)` — assuming the spec-defined two-part
/// layout (JSON metadata first, file content second). Returns an
/// error string on any structural mismatch.
fn parse_multipart_media(body: &[u8], boundary: &str) -> Result<(String, Vec<u8>), String> {
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
    let content_type = headers_str
        .split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-type") {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "application/octet-stream".to_string());

    Ok((content_type, body[content_start..content_end].to_vec()))
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

        let (ct, bytes) = parse_multipart_media(&body, boundary).unwrap();
        assert_eq!(ct, "text/plain; charset=utf-8");
        assert_eq!(bytes, body_inner);
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
    pub async fn get_or_fetch(
        &self,
        server_name: &str,
    ) -> Result<Arc<RemoteKeys>, FederationClientError> {
        let now = now_ms();

        // 1. Memory
        if let Some(keys) = self.memory.get(server_name) {
            if keys.is_valid_at(now) {
                return Ok(keys.clone());
            }
            // Stale — drop and refetch
            drop(keys);
            self.memory.remove(server_name);
        }

        // 2. Disk
        if let Ok(Some(bytes)) = self.db.load_remote_server_keys(server_name)
            && let Ok(keys) = serde_json::from_slice::<RemoteKeys>(&bytes)
            && keys.is_valid_at(now)
        {
            let arc = Arc::new(keys);
            self.memory.insert(server_name.to_string(), arc.clone());
            return Ok(arc);
        }

        // 3. Fetch
        let keys = self.client.fetch_server_keys(server_name).await?;
        let arc = Arc::new(keys);

        // Persist
        if let Ok(bytes) = serde_json::to_vec(&*arc) {
            let _ = self.db.store_remote_server_keys(server_name, &bytes);
        }
        self.memory.insert(server_name.to_string(), arc.clone());
        Ok(arc)
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
        use crate::federation_resolver::{FederationResolver, ResolvedServer};
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
        use crate::federation_resolver::{FederationResolver, ResolvedServer};
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
