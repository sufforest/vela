//! Integration-test harness.
//!
//! Spins up the axum router against a fresh RocksDB in a TempDir and
//! drives real HTTP requests through it via `tower::ServiceExt::oneshot`.
//! This is the "middle tier" between in-process unit tests and external
//! Complement: it exercises middleware, routing, and handler wiring
//! without paying Docker's boot cost.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use dashmap::DashMap;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

use vela_api::router::{AppState, ServerConfig, build_router};
use vela_core::events::sign::ServerSigningKey;
use vela_store::db::Database;
use vela_store::media::{FilesystemMediaStore, MediaStore};

pub struct Harness {
    pub state: AppState,
    pub router: Router,
    _tmp: TempDir,
}

/// Per-test config knobs. Defaults match production behaviour
/// (federation on, registration open, 50 MiB upload cap, no
/// auto-encryption).
pub struct ConfigOverrides {
    pub search_all_users: bool,
    pub federation_enabled: bool,
    pub registration_enabled: bool,
    pub registration_token: Option<String>,
    pub max_upload_size: u64,
    pub encrypt_by_default: vela_api::router::EncryptByDefault,
    pub oidc: vela_api::router::OidcConfig,
    pub public_base_url: Option<String>,
}

impl Default for ConfigOverrides {
    fn default() -> Self {
        Self {
            search_all_users: false,
            federation_enabled: true,
            registration_enabled: true,
            registration_token: None,
            max_upload_size: 50 * 1024 * 1024,
            encrypt_by_default: vela_api::router::EncryptByDefault::Off,
            oidc: vela_api::router::OidcConfig::default(),
            public_base_url: None,
        }
    }
}

impl Harness {
    pub fn new() -> Self {
        Self::with_server_name("localhost:8008")
    }

    /// Build a harness with `[user_directory] search_all_users` enabled.
    /// Mirrors what an operator would set in vela.toml for an open
    /// community deployment.
    pub fn with_search_all_users() -> Self {
        Self::build(
            "localhost:8008",
            ConfigOverrides {
                search_all_users: true,
                ..Default::default()
            },
        )
    }

    pub fn with_server_name(server_name: &str) -> Self {
        Self::build(server_name, ConfigOverrides::default())
    }

    /// Build a harness with the given config overrides applied. Defaults
    /// preserve the existing harness behaviour (federation enabled,
    /// registration open, 50 MiB upload cap).
    pub fn with_config(overrides: ConfigOverrides) -> Self {
        Self::build("localhost:8008", overrides)
    }

    /// Build a harness with a specific server_name AND specific
    /// overrides. Use when a test needs both (e.g. well_known
    /// resolution depends on the server_name shape).
    pub fn with_overrides(server_name: &str, overrides: ConfigOverrides) -> Self {
        Self::build(server_name, overrides)
    }

    fn build(server_name: &str, overrides: ConfigOverrides) -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(Database::open(tmp.path()).expect("db open"));
        let media = FilesystemMediaStore::new(&tmp.path().join("media")).expect("media");
        let key = Arc::new(ServerSigningKey::generate());
        let resolver = Arc::new(
            vela_api::federation::federation_resolver::FederationResolver::new().expect("resolver"),
        );
        let client = Arc::new(
            vela_api::federation::federation_client::FederationClient::new_with_enabled(
                key.clone(),
                server_name.to_string(),
                resolver,
                Vec::new(),
                overrides.federation_enabled,
            ),
        );
        let remote_keys = Arc::new(
            vela_api::federation::federation_client::RemoteKeyCache::new(
                db.clone(),
                (*client).clone(),
            ),
        );
        let typing_stream = vela_api::federation::edu::typing::TypingStream::new(
            db.clone(),
            server_name.to_string(),
        );
        let federation_sender = Arc::new(
            vela_api::federation::federation_sender::FederationSender::new_with_enabled(
                db.clone(),
                client.clone(),
                server_name.to_string(),
                vec![
                    vela_api::federation::edu::to_device::ToDeviceStream::new(),
                    vela_api::federation::edu::device_list::DeviceListStream::new(),
                    typing_stream.clone(),
                ],
                overrides.federation_enabled,
            ),
        );
        let appservice_registry =
            Arc::new(vela_api::appservice::AsRegistry::open(db.clone()).expect("as registry"));
        let appservice_outbox =
            vela_api::appservice::outbox::AsOutbox::new(db.clone(), appservice_registry.clone());
        let state = AppState {
            db,
            config: Arc::new(ServerConfig {
                server_name: server_name.to_string(),
                bind_host: "127.0.0.1".into(),
                bind_port: 0,
                public_base_url: overrides.public_base_url.clone(),
                search_all_users: overrides.search_all_users,
                federation_enabled: overrides.federation_enabled,
                registration_enabled: overrides.registration_enabled,
                registration_token: overrides.registration_token,
                max_upload_size: overrides.max_upload_size,
                encrypt_by_default: overrides.encrypt_by_default,
                allow_public_rooms_over_federation: false,
                user_directory_federate: false,
                minimum_room_version: vela_core::events::room_version::RoomVersion::V6,
                voip: vela_api::router::VoipConfig::default(),
                rtc: vela_api::router::RtcConfig::default(),
                oidc: overrides.oidc,
                admin_bot_localpart: vela_api::admin::DEFAULT_BOT_LOCALPART.to_string(),
                presence: vela_api::router::PresenceConfig::default(),
                push: vela_api::router::PushConfig {
                    allow_private_pushers: true,
                },
            }),
            room_locks: Arc::new(DashMap::new()),
            user_locks: Arc::new(DashMap::new()),
            key_backup_user_locks: Arc::new(DashMap::new()),
            room_senders: Arc::new(DashMap::new()),
            typing_state: Arc::new(DashMap::new()),
            typing_change_pos: Arc::new(DashMap::new()),
            last_gap_fill_pos: Arc::new(DashMap::new()),
            typing_stream,
            media_store: Arc::new(media) as Arc<dyn MediaStore>,
            signing_key: key,
            remote_keys,
            federation_sender,
            federation_client: client,
            oidc_introspection: None,
            partial_state_filler: Arc::new(
                vela_api::federation::partial_state_filler::PartialStateFiller::new(),
            ),
            appservice_registry,
            appservice_outbox,
            uia_sessions: vela_api::auth::uia::new_sessions(),
            user_senders: Arc::new(DashMap::new()),
            metrics_renderer: None,
            rate_limiter: vela_api::rate_limit::RateLimiter::defaults(),
            started_at: Arc::new(Instant::now()),
            started_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        };
        let router = build_router(state.clone());
        Harness {
            state,
            router,
            _tmp: tmp,
        }
    }

    pub async fn request(&self, req: Request<Body>) -> Response<Body> {
        self.router.clone().oneshot(req).await.expect("router call")
    }

    /// Register `username` with `password` and return `(user_id, access_token)`.
    pub async fn register(&self, username: &str, password: &str) -> (String, String) {
        let body = json!({
            "username": username,
            "password": password,
            "auth": {"type": "m.login.dummy"},
        });
        let resp = self
            .request(
                Request::post("/_matrix/client/v3/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "register failed");
        let v = read_json(resp).await;
        (
            v["user_id"].as_str().unwrap().to_string(),
            v["access_token"].as_str().unwrap().to_string(),
        )
    }

    pub async fn create_room(&self, token: &str, body: Value) -> String {
        let resp = self
            .request(
                Request::post("/_matrix/client/v3/createRoom")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "createRoom failed");
        read_json(resp).await["room_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    pub async fn send_message(&self, token: &str, room_id: &str, body: &str) -> String {
        let txn = format!("txn-{}", rand_txn());
        let resp = self
            .request(
                Request::put(format!(
                    "/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn}"
                ))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"msgtype": "m.text", "body": body}).to_string(),
                ))
                .unwrap(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "send failed");
        read_json(resp).await["event_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    pub async fn join(&self, token: &str, room_id: &str) {
        let resp = self
            .request(
                Request::post(format!("/_matrix/client/v3/rooms/{room_id}/join"))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "join failed");
    }

    pub async fn set_pusher(&self, token: &str, app_id: &str, pushkey: &str, url: &str) {
        let body = json!({
            "app_id": app_id,
            "pushkey": pushkey,
            "kind": "http",
            "app_display_name": "test",
            "device_display_name": "test-device",
            "lang": "en",
            "data": {"url": url, "format": "event_id_only"},
        });
        let resp = self
            .request(
                Request::post("/_matrix/client/v3/pushers/set")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "set_pusher failed");
    }
}

pub async fn read_json(resp: Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

fn rand_txn() -> String {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{nanos}")
}

// ---- Federation test helpers --------------------------------------------

/// A stub remote server identity for inbound federation tests. Holds a
/// generated ed25519 signing key and exposes helpers to:
/// 1. Seed the harness's RemoteKeyCache so signature verification works.
/// 2. Sign federation request bodies (events) with the remote's key.
/// 3. Mint X-Matrix `Authorization` headers for inbound HTTP requests.
pub struct StubRemote {
    pub server_name: String,
    pub key: vela_core::events::sign::ServerSigningKey,
}

impl StubRemote {
    pub fn new(server_name: &str) -> Self {
        Self {
            server_name: server_name.to_string(),
            key: vela_core::events::sign::ServerSigningKey::generate(),
        }
    }

    /// Install this remote's verify key into the harness so middleware
    /// signature verification accepts requests we sign with `self.key`.
    pub fn install(&self, harness: &Harness) {
        let mut verify_keys = std::collections::HashMap::new();
        verify_keys.insert(self.key.key_id().to_string(), self.key.public_key_base64());
        let keys = vela_api::federation::federation_client::RemoteKeys {
            verify_keys,
            valid_until_ts: u64::MAX / 2,
            fetched_at: 0,
        };
        harness
            .state
            .remote_keys
            .insert_for_test(&self.server_name, keys);
    }

    /// Build an X-Matrix `Authorization` header for `(method, uri)` against
    /// the harness's server_name as destination, optionally including a body.
    pub fn auth_header(
        &self,
        method: &str,
        uri: &str,
        destination: &str,
        body: Option<&Value>,
    ) -> String {
        let mut request = serde_json::Map::new();
        request.insert("method".into(), json!(method));
        request.insert("uri".into(), json!(uri));
        request.insert("origin".into(), json!(self.server_name));
        request.insert("destination".into(), json!(destination));
        if let Some(b) = body {
            request.insert("content".into(), b.clone());
        }
        // Sign over the canonical JSON of the request.
        let mut signed = request.clone();
        self.key.sign_json(&mut signed, &self.server_name);
        let sig = signed
            .get("signatures")
            .and_then(|s| s.get(&self.server_name))
            .and_then(|s| s.get(self.key.key_id()))
            .and_then(|v| v.as_str())
            .expect("sig present after signing");
        format!(
            "X-Matrix origin=\"{origin}\",destination=\"{dest}\",key=\"{key_id}\",sig=\"{sig}\"",
            origin = self.server_name,
            dest = destination,
            key_id = self.key.key_id(),
        )
    }

    /// Sign an event JSON template (in place) and return the computed
    /// event_id. Useful for stubbing inbound `send_join` / `send_knock`
    /// where the event in the body must carry our origin's signature.
    pub fn sign_event(&self, event: &mut serde_json::Map<String, Value>) -> String {
        vela_core::events::hash::add_content_hash(event);
        self.key.sign_event(event, &self.server_name);
        vela_core::events::hash::compute_event_id(event)
            .as_str()
            .to_string()
    }
}
