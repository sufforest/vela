use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use dashmap::DashMap;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use vela_core::events::sign::ServerSigningKey;
use vela_core::identifiers::Nid;
use vela_store::db::Database;
use vela_store::media::MediaStore;

use crate::federation_client::{FederationClient, RemoteKeyCache};
use crate::federation_sender::FederationSender;
use crate::middleware::federation_auth::federation_auth;
use crate::{
    account, account_data, capabilities, devices, directory, discovery, federation, filters,
    key_backup, keys, login, logout, media, membership, messages, presence, profile, pushers,
    pushrules, receipts, redaction, refresh, register, relations, room_upgrade, rooms, search,
    send, sliding_sync, state, sync, to_device, typing, whoami,
};

#[derive(Clone)]
pub struct ServerConfig {
    pub server_name: String,
    pub bind_host: String,
    pub bind_port: u16,
    /// When true, `/user_directory/search` may return users the caller
    /// doesn't share a room with. Default is `false`: unrestricted user
    /// enumeration is a privacy leak and an abuse vector (spam, targeted
    /// DM harassment). Operators can flip this on when the deployment
    /// is an invite-only community where directory openness is desirable.
    pub search_all_users: bool,
    /// When false, federation routes are not mounted and outbound
    /// federation calls short-circuit to a no-op. Default true.
    /// Single-server deployments and evaluation sandboxes set this to
    /// false to refuse traffic from / to other Matrix servers.
    pub federation_enabled: bool,
    /// When false, /register returns 403 M_FORBIDDEN. Default true.
    /// Closed-signup deployments flip this off and either invite users
    /// out-of-band or distribute a `registration_token`.
    pub registration_enabled: bool,
    /// When `Some`, /register requires `auth.token` to match. None →
    /// open registration (gated only by `registration_enabled`).
    pub registration_token: Option<String>,
    /// Maximum upload size in bytes. Enforced both at the global body
    /// limit layer and inside the media upload handler. Default 50 MiB.
    pub max_upload_size: u64,
    /// When `/createRoom` is called without `m.room.encryption` in
    /// `initial_state`, vela may auto-inject it for some presets per
    /// this policy. Spec-clean: clients that explicitly include
    /// `m.room.encryption` (with any algorithm value, including empty
    /// to opt out) win — this only fires when the client was silent.
    /// Privacy-first deployments set `EncryptByDefault::PrivateOnly`.
    pub encrypt_by_default: EncryptByDefault,
    /// When false (default), other servers cannot query our published
    /// public-room directory via `GET /_matrix/federation/v1/publicRooms`.
    /// Privacy-first: don't expose the local room list to the rest of
    /// the federated graph. (Today the federation endpoint isn't even
    /// mounted; this knob declares the intent so future work that mounts
    /// it stays opt-in.)
    pub allow_public_rooms_over_federation: bool,
    /// When false (default), `/user_directory/search` will not query
    /// remote servers for users — results are limited to local users
    /// (and, when `search_all_users = false`, further limited to
    /// rooms-in-common). Forces clients to type the full MXID
    /// (`@alice:other.server`) to start a DM with a stranger, which
    /// is the right privacy default.
    pub user_directory_federate: bool,
}

/// Server policy for auto-injecting `m.room.encryption` on
/// `/createRoom` when the client didn't supply one. Public rooms are
/// never auto-encrypted (Megolm's O(N) rekey on member join makes
/// E2EE in megarooms unworkable; the operator should opt rooms in
/// explicitly there).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptByDefault {
    /// Never auto-inject (default). Clients control encryption.
    Off,
    /// Inject for private rooms (preset `private_chat`,
    /// `trusted_private_chat`) only. Public rooms left alone.
    PrivateOnly,
    /// Inject for direct messages only (`is_direct: true` in body).
    /// Subset of PrivateOnly.
    DmOnly,
    /// Inject for everything except `public_chat`. Aggressive default
    /// — only sensible for fully-private deployments.
    All,
}

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub config: Arc<ServerConfig>,
    pub room_locks: Arc<DashMap<Nid, Arc<tokio::sync::Mutex<()>>>>,
    pub user_locks: Arc<DashMap<u64, Arc<tokio::sync::Mutex<()>>>>,
    pub room_senders: Arc<DashMap<Nid, tokio::sync::broadcast::Sender<u64>>>,
    /// In-memory typing state: room_nid → [(user_nid, expires_at_ms)]
    pub typing_state: Arc<DashMap<u64, Vec<(u64, u64)>>>,
    /// Federation outbound typing buffer (also registered in the
    /// federation sender's stream list). Held here as a concrete handle
    /// so the local /typing handler can `enqueue()` on every PUT.
    pub typing_stream: Arc<crate::edu::typing::TypingStream>,
    pub media_store: Arc<dyn MediaStore>,
    pub signing_key: Arc<ServerSigningKey>,
    pub remote_keys: Arc<RemoteKeyCache>,
    pub federation_sender: Arc<FederationSender>,
    pub federation_client: Arc<FederationClient>,
    pub uia_sessions: crate::uia::UiaSessions,
    /// Per-user wake channel: fires whenever the user's membership
    /// changes in ANY room (new invite, join, leave, knock, ban). Sync
    /// long-polls subscribe to this in addition to the per-room channel
    /// so a pending /sync wakes immediately when the user's room list
    /// gains a new room — e.g. after accepting an invite, or being
    /// invited to a DM.
    pub user_senders: Arc<DashMap<u64, tokio::sync::broadcast::Sender<()>>>,
    /// Renders the current metrics snapshot as a text-format string.
    /// Wired up by the binary when a recorder (Prometheus, StatsD, …)
    /// is installed; `None` in tests and in deployments that opt out.
    pub metrics_renderer: Option<crate::metrics::MetricsRenderer>,
    /// Per-IP rate limiter for unauth abuse-surface endpoints
    /// (`/register`, `/login`). See `crate::rate_limit`.
    pub rate_limiter: crate::rate_limit::RateLimiter,
    /// Monotonic timestamp captured when AppState was built. The
    /// `/_health` endpoint reports `uptime_secs` as the elapsed time
    /// since this instant. Held as an `Arc<Instant>` because `AppState`
    /// is `Clone` and we want every clone to share the same start.
    pub started_at: Arc<Instant>,
    /// Wall-clock timestamp (ms since Unix epoch) captured when
    /// AppState was built. Reported alongside `uptime_secs` so probes
    /// can detect process restarts (the value changes) without relying
    /// on a monotonic clock alone.
    pub started_at_ms: u64,
}

pub fn build_router(state: AppState) -> Router {
    let router = Router::new()
        // Discovery (no auth)
        .route("/.well-known/matrix/client", get(discovery::well_known))
        .route("/_matrix/client/versions", get(discovery::versions))
        // Ops — Prometheus scrape (no auth; front with reverse proxy in prod).
        .route("/_vela/metrics", get(crate::metrics::scrape))
        // Ops — health/liveness probe (no auth, intentionally outside
        // /_matrix/* because it's not part of the spec). See
        // `crate::health` for the response shape.
        .route("/_health", get(crate::health::health))
        // Auth (no auth required) — POSTs are rate-limited per IP.
        .route(
            "/_matrix/client/v3/login",
            get(login::get_login_types).post(login::login),
        )
        .route("/_matrix/client/v3/register", post(register::register))
        .route(
            "/_matrix/client/v3/register/available",
            get(register::available),
        )
        .route("/_matrix/client/v3/refresh", post(refresh::refresh))
        .route("/_matrix/client/r0/refresh", post(refresh::refresh))
        .route("/_matrix/client/v3/logout", post(logout::logout))
        .route("/_matrix/client/v3/logout/all", post(logout::logout_all))
        .route("/_matrix/client/r0/logout", post(logout::logout))
        .route("/_matrix/client/r0/logout/all", post(logout::logout_all))
        // r0 aliases — legacy clients (Sytest converters, older SDKs).
        // Spec says servers MAY continue to accept r0 paths indefinitely; we
        // alias the handful Complement's legacy tests still hit.
        .route(
            "/_matrix/client/r0/login",
            get(login::get_login_types).post(login::login),
        )
        .route("/_matrix/client/r0/register", post(register::register))
        .route("/_matrix/client/r0/sync", get(sync::sync))
        .route(
            "/_matrix/client/r0/rooms/{room_id}/messages",
            get(messages::get_messages),
        )
        .route(
            "/_matrix/client/r0/rooms/{room_id}/state",
            get(state::get_all_state),
        )
        .route(
            "/_matrix/client/r0/rooms/{room_id}/event/{event_id}",
            get(messages::get_event),
        )
        .route(
            "/_matrix/client/r0/rooms/{room_id}/send/{event_type}/{txn_id}",
            put(send::send_message),
        )
        // Account
        .route("/_matrix/client/v3/account/whoami", get(whoami::whoami))
        .route(
            "/_matrix/client/v3/account/password",
            post(account::change_password),
        )
        .route(
            "/_matrix/client/v3/account/deactivate",
            post(account::deactivate),
        )
        // Profile
        .route(
            "/_matrix/client/v3/profile/{userId}",
            get(profile::get_profile),
        )
        .route(
            "/_matrix/client/v3/profile/{userId}/displayname",
            get(profile::get_displayname).put(profile::set_displayname),
        )
        .route(
            "/_matrix/client/v3/profile/{userId}/avatar_url",
            get(profile::get_avatar_url).put(profile::set_avatar_url),
        )
        // Account data
        .route(
            "/_matrix/client/v3/user/{userId}/account_data/{type}",
            get(account_data::get_account_data).put(account_data::set_account_data),
        )
        .route(
            "/_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}",
            get(account_data::get_room_account_data).put(account_data::set_room_account_data),
        )
        .route(
            "/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags",
            get(account_data::list_tags),
        )
        .route(
            "/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}",
            axum::routing::delete(account_data::delete_tag).put(account_data::put_tag),
        )
        // Capabilities
        .route(
            "/_matrix/client/v3/capabilities",
            get(capabilities::get_capabilities),
        )
        // Directory (aliases)
        .route(
            "/_matrix/client/v3/directory/room/{roomAlias}",
            get(directory::get_room_alias)
                .put(directory::set_room_alias)
                .delete(directory::delete_room_alias),
        )
        // Rooms
        .route("/_matrix/client/v3/createRoom", post(rooms::create_room))
        .route("/_matrix/client/v3/joined_rooms", get(rooms::joined_rooms))
        // Membership
        .route(
            "/_matrix/client/v3/join/{roomIdOrAlias}",
            post(membership::join_by_id_or_alias),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/join",
            post(membership::join_room),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/leave",
            post(membership::leave_room),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/invite",
            post(membership::invite_user),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/kick",
            post(membership::kick_user),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/ban",
            post(membership::ban_user),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/unban",
            post(membership::unban_user),
        )
        .route(
            "/_matrix/client/v3/knock/{room_id_or_alias}",
            post(membership::knock_room),
        )
        // Room operations
        .route(
            "/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}",
            put(send::send_message),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/messages",
            get(messages::get_messages),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/event/{event_id}",
            get(messages::get_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/redact/{event_id}/{txn_id}",
            put(redaction::redact_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/relations/{event_id}",
            get(relations::relations_with_query),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/relations/{event_id}/{rel_type}",
            get(relations::relations_with_rel_type),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/relations/{event_id}/{rel_type}/{event_type}",
            get(relations::relations_with_rel_and_event_type),
        )
        // /v1/ is the spec-stable path (added in spec v1.3); /v3/ is
        // the older unstable form. Element X uses /v1/ — without
        // these aliases the relations endpoint 404s and Element
        // can't surface poll votes, thread replies, or any other
        // relation-based UI.
        .route(
            "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}",
            get(relations::relations_with_query),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}/{rel_type}",
            get(relations::relations_with_rel_type),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}/{rel_type}/{event_type}",
            get(relations::relations_with_rel_and_event_type),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/read_markers",
            post(receipts::post_read_markers),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/threads",
            get(relations::threads_list),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/threads",
            get(relations::threads_list),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/joined_members",
            get(rooms::joined_members),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/members",
            get(rooms::list_members),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/aliases",
            get(rooms::list_room_aliases),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/forget",
            post(rooms::forget_room),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/upgrade",
            post(room_upgrade::upgrade_room),
        )
        // Search (stub)
        .route("/_matrix/client/v3/search", post(search::post_search))
        // User directory — substring search over local users.
        .route(
            "/_matrix/client/v3/user_directory/search",
            post(crate::user_directory::search),
        )
        // Spaces hierarchy (MSC2946 / stable v1).
        .route(
            "/_matrix/client/v1/rooms/{room_id}/hierarchy",
            get(crate::spaces::hierarchy),
        )
        // Push rules (stub)
        .route(
            "/_matrix/client/v3/pushrules/",
            get(pushrules::get_pushrules),
        )
        .route(
            "/_matrix/client/v3/pushrules/global/",
            get(pushrules::get_global_pushrules),
        )
        .route(
            "/_matrix/client/v3/pushrules/global/{kind}/{rule_id}",
            get(pushrules::get_pushrule)
                .put(pushrules::put_pushrule)
                .delete(pushrules::delete_pushrule),
        )
        .route(
            "/_matrix/client/v3/pushrules/global/{kind}/{rule_id}/enabled",
            get(pushrules::get_pushrule_enabled).put(pushrules::put_pushrule_enabled),
        )
        .route(
            "/_matrix/client/v3/pushrules/global/{kind}/{rule_id}/actions",
            get(pushrules::get_pushrule_actions).put(pushrules::put_pushrule_actions),
        )
        // Presence
        .route(
            "/_matrix/client/v3/presence/{user_id}/status",
            get(presence::get_status).put(presence::put_status),
        )
        // Pushers
        .route("/_matrix/client/v3/pushers", get(pushers::get_pushers))
        .route("/_matrix/client/v3/pushers/set", post(pushers::set_pusher))
        // Sync filters
        .route(
            "/_matrix/client/v3/user/{userId}/filter",
            post(filters::post_filter),
        )
        .route(
            "/_matrix/client/v3/user/{userId}/filter/{filterId}",
            get(filters::get_filter),
        )
        // Device management
        .route("/_matrix/client/v3/devices", get(devices::list_devices))
        .route(
            "/_matrix/client/v3/devices/{device_id}",
            get(devices::get_device)
                .put(devices::rename_device)
                .delete(devices::delete_device),
        )
        // Public rooms / directory visibility
        .route(
            "/_matrix/client/v3/publicRooms",
            get(directory::list_public_rooms).post(directory::search_public_rooms),
        )
        .route(
            "/_matrix/client/v3/directory/list/room/{room_id}",
            get(directory::get_room_visibility).put(directory::put_room_visibility),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/state",
            get(state::get_all_state),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}",
            get(state::get_state_event).put(send::send_state_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/state/{event_type}",
            get(state::get_state_event_no_key).put(send::send_state_event_no_key),
        )
        // Some clients (notably Sytest converters) PUT to
        // `/state/m.room.canonical_alias/` with a trailing slash and an
        // empty state_key. Axum treats this as a distinct path; alias the
        // trailing-slash form to the same handler.
        .route(
            "/_matrix/client/v3/rooms/{room_id}/state/{event_type}/",
            get(state::get_state_event_no_key).put(send::send_state_event_no_key),
        )
        // E2EE
        .route("/_matrix/client/v3/keys/upload", post(keys::upload_keys))
        .route("/_matrix/client/v3/keys/query", post(keys::query_keys))
        .route("/_matrix/client/v3/keys/claim", post(keys::claim_keys))
        .route("/_matrix/client/v3/keys/changes", get(keys::key_changes))
        .route(
            "/_matrix/client/v3/keys/device_signing/upload",
            post(keys::upload_signing_keys),
        )
        .route(
            "/_matrix/client/v3/keys/signatures/upload",
            post(keys::upload_signatures),
        )
        // Key backup
        .route(
            "/_matrix/client/v3/room_keys/version",
            get(key_backup::get_latest_version).post(key_backup::post_version),
        )
        .route(
            "/_matrix/client/v3/room_keys/version/{version}",
            get(key_backup::get_version)
                .put(key_backup::put_version)
                .delete(key_backup::delete_version),
        )
        .route(
            "/_matrix/client/v3/room_keys/keys",
            get(key_backup::get_all_keys)
                .put(key_backup::put_all_keys)
                .delete(key_backup::delete_all_keys),
        )
        .route(
            "/_matrix/client/v3/room_keys/keys/{room_id}",
            get(key_backup::get_room_keys)
                .put(key_backup::put_room_keys)
                .delete(key_backup::delete_room_keys),
        )
        .route(
            "/_matrix/client/v3/room_keys/keys/{room_id}/{session_id}",
            get(key_backup::get_session)
                .put(key_backup::put_session)
                .delete(key_backup::delete_session),
        )
        .route(
            "/_matrix/client/v3/sendToDevice/{eventType}/{txnId}",
            put(to_device::send_to_device),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/timestamp_to_event",
            get(crate::timestamp::timestamp_to_event),
        )
        // Ephemeral
        .route(
            "/_matrix/client/v3/rooms/{room_id}/typing/{userId}",
            put(typing::set_typing),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/receipt/{receiptType}/{eventId}",
            post(receipts::post_receipt),
        )
        // Media
        .route("/_matrix/media/v3/upload", post(media::upload))
        .route("/_matrix/media/v3/config", get(media::config))
        // Legacy unauth download/thumbnail endpoints. Pre-MSC3916
        // surface — many older clients still call these. Spec
        // deprecates them but keeping them serves backward
        // compatibility while the auth'd v1 paths below are the
        // forward direction.
        .route(
            "/_matrix/media/v3/download/{server_name}/{media_id}",
            get(media::download_legacy),
        )
        .route(
            "/_matrix/media/v3/thumbnail/{server_name}/{media_id}",
            get(media::thumbnail_legacy),
        )
        .route(
            "/_matrix/client/v1/media/download/{server_name}/{media_id}",
            get(media::download),
        )
        .route(
            "/_matrix/client/v1/media/thumbnail/{server_name}/{media_id}",
            get(media::thumbnail),
        )
        // Sync
        .route("/_matrix/client/v3/sync", get(sync::sync))
        // Sliding Sync (MSC4186)
        .route(
            "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync",
            post(sliding_sync::sliding_sync),
        )
        // Federation key publication (unauthenticated per spec). Even
        // with federation disabled, this is harmless — peers that
        // happen to query us get the public keys but inbound traffic
        // is rejected below.
        .route("/_matrix/key/v2/server", get(federation::get_server_keys));
    // Federation authenticated routes — require X-Matrix header
    // verification. Skipped entirely when federation is disabled in
    // config: the routes are not mounted, so unrelated middleware
    // doesn't even see federation-shaped traffic.
    let router = if state.config.federation_enabled {
        router.merge(federation_authed_routes(state.clone()))
    } else {
        router
    };
    let max_body = state.config.max_upload_size as usize;

    router
        // Fallback for unmatched /_matrix/* routes — spec wants 404
        // M_UNRECOGNIZED rather than the misleading 401 from federation
        // auth on an endpoint we just don't implement.
        .fallback(unrecognized_endpoint)
        // Middleware (applied bottom-up — TimeoutLayer wraps innermost,
        // CatchPanicLayer outermost). RequestBodyLimit caps inbound at
        // 50 MiB; media uploads have their own limit and run on the
        // same listener for now. Federation transactions can carry up
        // to 50 PDUs (~megabyte each in pathological cases) so 10 MiB
        // is too tight; 50 MiB is a comfortable upper bound that still
        // shuts down obvious DoS vectors at the layer.
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn(crate::metrics::record_request))
        .layer(CorsLayer::very_permissive())
        // axum's per-extractor body limit defaults to 2 MiB; without
        // DefaultBodyLimit::max(...) the Bytes extractor in
        // /media/v3/upload (and any other handler that takes a raw
        // body) rejects with 413 well before the configured upload
        // size matters. The tower-http RequestBodyLimitLayer below is
        // a connection-level cap; this is the extractor-level cap.
        .layer(axum::extract::DefaultBodyLimit::max(max_body))
        .layer(RequestBodyLimitLayer::new(max_body))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            Duration::from_secs(30),
        ))
        .with_state(state)
}

/// Per-IP rate limiter applied to abuse-prone unauth POSTs only. Most
/// requests pass through unconditionally; we look up the path + method
/// against a small allow-list and only consult the limiter for the few
/// endpoints we care about. Cheap by design — the path comparison is
/// the entire check on the hot path.
///
/// Takes `ConnectInfo` out of request extensions manually rather than
/// as an axum extractor arg: the `Option<ConnectInfo>` extractor doesn't
/// satisfy `from_fn_with_state`'s generic bounds, and we want to fall
/// back to a sentinel IP when the extension isn't populated (tower
/// oneshot in tests doesn't attach it).
async fn rate_limit_middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let endpoint = match (req.method().as_str(), req.uri().path()) {
        ("POST", "/_matrix/client/v3/register" | "/_matrix/client/r0/register") => Some("register"),
        ("POST", "/_matrix/client/v3/login" | "/_matrix/client/r0/login") => Some("login"),
        _ => None,
    };
    if let Some(endpoint) = endpoint {
        let ip = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|c| c.0.ip().to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string());
        if let Err(retry_ms) = state.rate_limiter.check(endpoint, &ip) {
            return limit_exceeded_response(retry_ms);
        }
    }
    next.run(req).await
}

/// Build a Matrix-spec `M_LIMIT_EXCEEDED` response carrying the
/// suggested wait. Shared between the per-route limit middlewares so
/// the response shape stays identical across endpoints.
fn limit_exceeded_response(retry_after_ms: u64) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({
            "errcode": "M_LIMIT_EXCEEDED",
            "error": "rate limit exceeded",
            "retry_after_ms": retry_after_ms,
        })),
    )
        .into_response()
}

/// Fire the per-user wake channel for `user_nid`. Called by every code
/// path that changes the user's membership in any room, so their pending
/// `/sync` returns immediately instead of waiting for its timeout.
pub fn notify_user(state: &AppState, user_nid: u64) {
    if let Some(tx) = state.user_senders.get(&user_nid) {
        let _ = tx.send(());
    }
}

/// Apply a membership transition consistently: persist the membership
/// byte, wake the target user's `/sync`, and wake anyone long-polling
/// the room. Every federation-inbound and client-driven path that flips
/// a user's room membership hit exactly these three writes; without a
/// single entry point the ordering (and the room-channel wake) drifted
/// between call sites. Failures from `set_membership` are logged but
/// non-fatal — the event has already persisted, and the membership
/// index is recoverable from room state if corrupted.
///
/// `stream_pos` is what the caller emitted for the transition-bearing
/// event (usually the m.room.member event). Pass 0 if no stream-bearing
/// event was written (rare — membership changes normally have one).
pub fn apply_membership_change(
    state: &AppState,
    room_nid: u64,
    user_nid: u64,
    membership: u8,
    stream_pos: u64,
) {
    if let Err(e) = state.db.set_membership(room_nid, user_nid, membership) {
        tracing::warn!(
            room_nid,
            user_nid,
            membership,
            error = %e,
            "set_membership failed"
        );
    }
    notify_user(state, user_nid);
    if let Some(sender) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender.send(stream_pos);
    }
}

async fn unrecognized_endpoint(uri: axum::http::Uri) -> impl axum::response::IntoResponse {
    use axum::Json;
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "errcode": "M_UNRECOGNIZED",
            "error": format!("unrecognized endpoint: {}", uri.path()),
        })),
    )
}

/// Build the sub-router for federation endpoints that require X-Matrix auth.
fn federation_authed_routes(state: AppState) -> Router<AppState> {
    use crate::federation_fetch;
    Router::new()
        .route(
            "/_matrix/federation/v1/send/{txn_id}",
            put(federation::receive_transaction),
        )
        // Fetch endpoints (read-only)
        .route(
            "/_matrix/federation/v1/event/{event_id}",
            get(federation_fetch::get_event),
        )
        .route(
            "/_matrix/federation/v1/state/{room_id}",
            get(federation_fetch::get_state),
        )
        .route(
            "/_matrix/federation/v1/state_ids/{room_id}",
            get(federation_fetch::get_state_ids),
        )
        .route(
            "/_matrix/federation/v1/event_auth/{room_id}/{event_id}",
            get(federation_fetch::get_event_auth),
        )
        .route(
            "/_matrix/federation/v1/get_missing_events/{room_id}",
            post(federation_fetch::get_missing_events),
        )
        .route(
            "/_matrix/federation/v1/backfill/{room_id}",
            get(federation_fetch::get_backfill),
        )
        .route(
            "/_matrix/federation/v1/query/directory",
            get(federation_fetch::query_directory),
        )
        // Inbound join
        .route(
            "/_matrix/federation/v1/make_join/{room_id}/{user_id}",
            get(crate::federation_join::make_join),
        )
        .route(
            "/_matrix/federation/v1/send_join/{room_id}/{event_id}",
            put(crate::federation_join::send_join_v1),
        )
        .route(
            "/_matrix/federation/v2/send_join/{room_id}/{event_id}",
            put(crate::federation_join::send_join_v2),
        )
        .route(
            "/_matrix/federation/v1/make_leave/{room_id}/{user_id}",
            get(crate::federation_leave::make_leave),
        )
        .route(
            "/_matrix/federation/v1/send_leave/{room_id}/{event_id}",
            put(crate::federation_leave::send_leave_v1),
        )
        .route(
            "/_matrix/federation/v2/send_leave/{room_id}/{event_id}",
            put(crate::federation_leave::send_leave_v2),
        )
        .route(
            "/_matrix/federation/v2/invite/{room_id}/{event_id}",
            put(crate::federation_invite::invite_v2),
        )
        .route(
            "/_matrix/federation/v1/make_knock/{room_id}/{user_id}",
            get(crate::federation_knock::make_knock),
        )
        .route(
            "/_matrix/federation/v1/send_knock/{room_id}/{event_id}",
            put(crate::federation_knock::send_knock_v1),
        )
        .layer(axum::middleware::from_fn_with_state(state, federation_auth))
}
