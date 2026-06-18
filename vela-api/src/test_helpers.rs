//! Shared test helpers for `vela-api`. Compiled only under `#[cfg(test)]`.
//!
//! Put helpers here when more than one test module needs them. Colocated
//! helpers (only used by one module) should stay in that module's `tests`
//! submodule.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tempfile::TempDir;

use crate::federation::federation_client::{FederationClient, RemoteKeyCache};
use crate::federation::federation_resolver::FederationResolver;
use crate::federation::federation_sender::FederationSender;
use crate::router::{AppState, ServerConfig};
use vela_core::events::sign::ServerSigningKey;
use vela_store::db::Database;
use vela_store::media::{FilesystemMediaStore, MediaStore};

/// Construct an `AppState` backed by a fresh RocksDB in a `TempDir`.
///
/// The caller must keep the returned `TempDir` alive for the duration of the
/// test; dropping it unlinks the database directory.
///
/// Default server_name is `example.com`.
pub fn build_test_state() -> (AppState, TempDir) {
    build_test_state_with_name("example.com")
}

/// Variant with configurable server_name. Useful when a test needs to
/// impersonate a specific destination.
pub fn build_test_state_with_name(server_name: &str) -> (AppState, TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(Database::open(tmp.path()).expect("db open"));
    let media = FilesystemMediaStore::new(&tmp.path().join("media")).expect("media");
    let key = Arc::new(ServerSigningKey::generate());
    let resolver = Arc::new(FederationResolver::new().expect("resolver"));
    let client = Arc::new(FederationClient::new(
        key.clone(),
        server_name.to_string(),
        resolver,
        Vec::new(),
    ));
    let remote_keys = Arc::new(RemoteKeyCache::new(db.clone(), (*client).clone()));
    let typing_stream =
        crate::federation::edu::typing::TypingStream::new(db.clone(), server_name.to_string());
    let appservice_registry =
        Arc::new(crate::appservice::AsRegistry::open(db.clone()).expect("as registry"));
    let appservice_outbox =
        crate::appservice::outbox::AsOutbox::new(db.clone(), appservice_registry.clone());
    let federation_sender = Arc::new(FederationSender::new(
        db.clone(),
        client.clone(),
        server_name.to_string(),
        vec![
            crate::federation::edu::to_device::ToDeviceStream::new(),
            crate::federation::edu::device_list::DeviceListStream::new(),
            typing_stream.clone(),
        ],
    ));
    let state = AppState {
        db,
        config: Arc::new(ServerConfig {
            server_name: server_name.to_string(),
            bind_host: "127.0.0.1".to_string(),
            bind_port: 0,
            public_base_url: None,
            search_all_users: false,
            federation_enabled: true,
            registration_enabled: true,
            registration_token: None,
            max_upload_size: 50 * 1024 * 1024,
            encrypt_by_default: crate::router::EncryptByDefault::Off,
            allow_public_rooms_over_federation: false,
            user_directory_federate: false,
            minimum_room_version: vela_core::events::room_version::RoomVersion::V6,
            voip: crate::router::VoipConfig::default(),
            rtc: crate::router::RtcConfig::default(),
            oidc: crate::router::OidcConfig::default(),
            admin_bot_localpart: crate::admin::DEFAULT_BOT_LOCALPART.to_string(),
            presence: crate::router::PresenceConfig::default(),
            // Tests run wiremock servers on 127.0.0.1, so the SSRF
            // guard would refuse the localhost push gateway. Default
            // to permissive in test fixtures; production defaults
            // strict via PushConfig::default().
            push: crate::router::PushConfig {
                allow_private_pushers: true,
            },
            support: crate::router::SupportConfig::default(),
            max_delay_ms: crate::delayed_events::DEFAULT_MAX_DELAY_MS,
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
            crate::federation::partial_state_filler::PartialStateFiller::new(),
        ),
        event_relationships_unsigned_cache: Arc::new(DashMap::new()),
        delayed_events: crate::delayed_events::new_store(),
        delayed_events_scheduler_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        sliding_sync_cache: Arc::new(crate::sync::sliding_sync::SlidingSyncCache::new()),
        appservice_registry,
        appservice_outbox,
        uia_sessions: crate::auth::uia::new_sessions(),
        user_senders: Arc::new(DashMap::new()),
        metrics_renderer: None,
        rate_limiter: crate::rate_limit::RateLimiter::defaults(),
        started_at: Arc::new(Instant::now()),
        started_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        // No plugins in tests; an empty runtime allows everything (and pulls no
        // wasmtime when the feature is off).
        extensions: Arc::new(
            vela_extensions::Runtime::new(vec![]).expect("empty extension runtime"),
        ),
    };
    (state, tmp)
}
