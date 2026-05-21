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

use crate::auth::{account, account_data, devices, login, logout, refresh, register, whoami};
use crate::directory::{self, discovery, search};
use crate::e2ee::{key_backup, keys, to_device};
use crate::federation;
use crate::federation::federation_client::{FederationClient, RemoteKeyCache};
use crate::federation::federation_sender::FederationSender;
use crate::media;
use crate::membership;
use crate::middleware::federation_auth::federation_auth;
use crate::presence;
use crate::profile::{self, capabilities, openid};
use crate::push::{pushers, pushrules};
use crate::room::{messages, redaction, relations, room_upgrade, rooms, send, state};
use crate::sync::{self, filters, receipts, sliding_sync, thread_subscriptions, typing};
use crate::voip;

#[derive(Clone)]
pub struct ServerConfig {
    pub server_name: String,
    pub bind_host: String,
    pub bind_port: u16,
    /// Public-facing base URL for the client API, as advertised in
    /// `.well-known/matrix/client`. When `None`, vela synthesises
    /// `http://<bind_host>:<bind_port>` — which is wrong for any
    /// reverse-proxied deployment. Operators behind a TLS terminator
    /// (Caddy, Cloudflare, nginx) MUST set this to the public URL
    /// (e.g. `"https://matrix.example.com"`) or clients will follow
    /// the well-known to localhost and fail.
    pub public_base_url: Option<String>,
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
    /// Minimum room version vela accepts on `/createRoom` and on
    /// inbound federated joins. Default v6 — older versions have known
    /// auth-rule issues (v1/v2 float-coerced PLs, sig-failed events
    /// accepted) and aren't supported in this codebase regardless.
    /// Operators wanting "spec-modern only" can set this to "10" or
    /// higher; clients/peers requesting older versions get
    /// M_UNSUPPORTED_ROOM_VERSION.
    pub minimum_room_version: vela_core::events::room_version::RoomVersion,
    /// Classic VoIP (`m.call.*` 1-to-1) TURN config. Empty when the
    /// operator hasn't set up coturn — `/voip/turnServer` then 404s
    /// and clients fall back to direct WebRTC. Populated config means
    /// vela mints time-limited HMAC creds (coturn standard auth) for
    /// each `/voip/turnServer` request.
    pub voip: VoipConfig,
    /// matrix-rtc / Element Call (MSC4143). Empty when no SFU is
    /// configured; clients then either piggy-back on another
    /// participant's focus or fall back to classic VoIP.
    pub rtc: RtcConfig,
    /// MSC3861 / OAuth 2.0 authentication-API discovery posture.
    /// Phase 1 surface only: when `enabled`, `/auth_issuer` and the
    /// `/versions` capability bit advertise that vela is configured
    /// to delegate auth to an external IdP. Token validation against
    /// the IdP is NOT wired up yet — phase 2.
    pub oidc: OidcConfig,
    /// Localpart of the server-internal admin bot. Defaults to
    /// `"admin"` (full MXID `@admin:<server_name>`). The localpart is
    /// reserved on `/register` — operators cannot register an account
    /// at this localpart even with a valid token. See `crate::admin`.
    pub admin_bot_localpart: String,
    /// Presence auto-decay thresholds and sweeper cadence. See
    /// `PresenceConfig` for the timings. Stored presence (the string a
    /// client last set via PUT /presence) does not decay on its own;
    /// vela computes effective presence at read time and a background
    /// sweeper persists transitions so federation peers see them.
    pub presence: PresenceConfig,
}

/// Presence auto-decay configuration.
///
/// vela updates `last_active_ms` on every /sync from the user. When the
/// gap between `last_active_ms` and "now" exceeds `idle_after`, the
/// user's effective presence transitions `online → unavailable`. After
/// `offline_after`, it transitions to `offline`. Explicit
/// client-supplied presence values (`unavailable`, `offline`) are
/// honoured as-is.
///
/// Two layers:
/// - **Read-time** (every /sync, GET /presence) computes the effective
///   presence on the fly. Local clients always see the right answer.
/// - **Sweeper** (background task every `sweep_interval`) persists
///   transitions and broadcasts the federation EDU. Without it,
///   remote servers see stale "online" until something else triggers
///   a fresh EDU.
#[derive(Debug, Clone, Copy)]
pub struct PresenceConfig {
    /// Online → unavailable after this much idle time.
    pub idle_after_ms: u64,
    /// (Online | unavailable) → offline after this much idle time.
    pub offline_after_ms: u64,
    /// How often the sweeper task wakes up to apply transitions.
    pub sweep_interval_ms: u64,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            idle_after_ms: 5 * 60 * 1000,
            offline_after_ms: 30 * 60 * 1000,
            sweep_interval_ms: 60 * 1000,
        }
    }
}

/// Classic `/voip/turnServer` configuration.
#[derive(Clone, Default)]
pub struct VoipConfig {
    pub uris: Vec<String>,
    pub shared_secret: String,
    pub ttl_seconds: u32,
}

/// matrix-rtc (MSC4143) configuration.
#[derive(Clone, Default)]
pub struct RtcConfig {
    pub sfu_url: String,
    pub livekit_api_key: String,
    pub livekit_secret: String,
    pub jwt_ttl_seconds: u32,
}

/// MSC3861 OIDC delegated-auth posture.
///
/// Phase 1 (always available once `enabled = true`): advertise the
/// issuer via `/auth_issuer`, `.well-known/matrix/client`, and
/// `versions.unstable_features["org.matrix.msc3861"]`.
///
/// Phase 2 (token validation against the IdP via RFC7662
/// introspection): activates ONLY when `enabled = true` AND
/// `introspection_endpoint` is set. Operators who already configured
/// Phase 1 keep discovery-only behaviour; they opt into Phase 2 by
/// adding the introspection settings.
#[derive(Clone, Default)]
pub struct OidcConfig {
    pub enabled: bool,
    /// The OIDC issuer URL (e.g. `https://auth.example.com/`).
    pub issuer: String,
    /// `Some` when vela's registered client_id should be exposed to
    /// clients that need it pre-IdP-flow.
    pub client_id: Option<String>,
    /// Optional account-management URL surfaced to clients per MSC3861.
    pub account_management_url: Option<String>,
    /// RFC7662 introspection endpoint (e.g.
    /// `https://auth.example.com/oauth2/introspect`). Presence of this
    /// field is what activates Phase 2 token validation.
    pub introspection_endpoint: Option<String>,
    /// Client credentials vela presents to the IdP on every
    /// introspection request. Both must be `Some` when
    /// `introspection_endpoint` is set; the validator refuses to boot
    /// otherwise.
    pub introspection_client_id: Option<String>,
    pub introspection_client_secret: Option<String>,
    /// How those credentials are presented on the wire. Both are
    /// RFC6749 §2.3 standard; IdPs differ on which they accept.
    pub introspection_auth_method: IntrospectionAuthMethod,
}

/// RFC6749 §2.3 client authentication methods supported on
/// introspection requests. `ClientSecretBasic` is the universal
/// default; `ClientSecretPost` exists for IdPs that prefer
/// form-encoded credentials in the body.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IntrospectionAuthMethod {
    #[default]
    ClientSecretBasic,
    ClientSecretPost,
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
    /// Per-user lock for `/room_keys/*` mutating handlers. Separate
    /// from `user_locks` so backup uploads don't serialize with
    /// device-key uploads. Sessions go to distinct CF rows so cross-
    /// session writes are inherently race-free; this lock protects
    /// the (read, modify, write) cycles on version metadata + stats.
    pub key_backup_user_locks: Arc<DashMap<u64, Arc<tokio::sync::Mutex<()>>>>,
    pub room_senders: Arc<DashMap<Nid, tokio::sync::broadcast::Sender<u64>>>,
    /// In-memory typing state: room_nid → [(user_nid, expires_at_ms)]
    pub typing_state: Arc<DashMap<u64, Vec<(u64, u64)>>>,
    /// Stream position at which `typing_state[room]` last transitioned.
    /// /sync uses this to decide whether to emit an `m.typing` ephemeral
    /// for an incremental sync — we emit only when the user's `since`
    /// predates a transition, otherwise the room would always be marked
    /// "changed" by the always-current EDU and clients would receive
    /// redundant typing events.
    pub typing_change_pos: Arc<DashMap<u64, u64>>,
    /// Stream position of the most recent `/get_missing_events` or
    /// `/state_ids` fetch in each room — i.e. the last time we plugged
    /// a federation gap. /sync's `limited` flag is true on any batch
    /// whose `since` predates this position, signalling that earlier
    /// events in the room may be missing from the local view (per
    /// spec: "homeserver determined the timeline events were
    /// inadequate to render the room state at the start of the
    /// batch"). TestSyncTimelineGap covers this.
    pub last_gap_fill_pos: Arc<DashMap<u64, u64>>,
    /// Federation outbound typing buffer (also registered in the
    /// federation sender's stream list). Held here as a concrete handle
    /// so the local /typing handler can `enqueue()` on every PUT.
    pub typing_stream: Arc<crate::federation::edu::typing::TypingStream>,
    pub media_store: Arc<dyn MediaStore>,
    pub signing_key: Arc<ServerSigningKey>,
    pub remote_keys: Arc<RemoteKeyCache>,
    pub federation_sender: Arc<FederationSender>,
    pub federation_client: Arc<FederationClient>,
    /// MSC3861 Phase 2 introspection plumbing. `Some` when the
    /// operator configured an `introspection_endpoint`; `None`
    /// otherwise (Phase 1 discovery only). The auth extractor uses
    /// this as its gate — `None` means the third OIDC path is not
    /// even attempted, so the middleware behaves identically to
    /// pre-MSC3861-Phase-2 vela.
    pub oidc_introspection: Option<Arc<crate::auth::oidc::IntrospectionState>>,
    /// Registered Application Services. Cheaply cloneable; admin
    /// commands, the interest filter, and the masquerading auth
    /// middleware all reach in via this handle.
    pub appservice_registry: Arc<crate::appservice::AsRegistry>,
    /// Per-AS outbound delivery scheduler. The interest filter
    /// enqueues onto here from the send + federation_receive paths.
    pub appservice_outbox: crate::appservice::outbox::AsOutbox,
    pub uia_sessions: crate::auth::uia::UiaSessions,
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
        // MSC3861 phase 1 — clients probe this to learn whether vela
        // delegates auth to an external OIDC issuer. Returns 200 with
        // the issuer/account URLs when `[auth.oidc] enabled = true`,
        // otherwise 404 M_NOT_FOUND (the spec way of saying "this
        // server runs legacy auth").
        .route(
            "/_matrix/client/v1/auth_issuer",
            get(discovery::auth_issuer),
        )
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
            "/_matrix/client/r0/rooms/{room_id}/joined_members",
            get(rooms::joined_members),
        )
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
        // 3PID list — stubbed empty since vela doesn't track email /
        // phone associations. Suppresses Element's "Unable to load
        // email addresses" error in account settings.
        .route("/_matrix/client/v3/account/3pid", get(account::get_3pids))
        // Classic 1-to-1 VoIP: TURN credentials for clients that
        // still drive m.call.* events over Matrix. Group calls use
        // matrix-rtc below instead.
        .route("/_matrix/client/v3/voip/turnServer", get(voip::turn_server))
        // matrix-rtc / Element Call (MSC4143) — mint a per-room JWT
        // the client uses to connect to the configured SFU.
        .route(
            "/_matrix/client/unstable/org.matrix.msc4143/rtc/{room_id}/transport",
            axum::routing::post(voip::rtc_jwt),
        )
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
            "/_matrix/client/v3/rooms/{room_id}/context/{event_id}",
            get(messages::get_event_context),
        )
        // r0 alias for legacy clients (and TestJumpToDateEndpoint's
        // pagination sub-test, which still issues r0 URIs).
        .route(
            "/_matrix/client/r0/rooms/{room_id}/context/{event_id}",
            get(messages::get_event_context),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/redact/{event_id}/{txn_id}",
            put(redaction::redact_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/report/{event_id}",
            post(crate::admin::report::report_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/report",
            post(crate::admin::report::report_room),
        )
        .route(
            "/_matrix/client/v3/users/{user_id}/report",
            post(crate::admin::report::report_user),
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
            post(crate::directory::user_directory::search),
        )
        // Spaces hierarchy (MSC2946 / stable v1).
        .route(
            "/_matrix/client/v1/rooms/{room_id}/hierarchy",
            get(crate::directory::spaces::hierarchy),
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
        // OpenID — short-lived tokens for SSO into Matrix-aware
        // third-party services. Path userId must match the caller.
        .route(
            "/_matrix/client/v3/user/{userId}/openid/request_token",
            post(openid::request_token),
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
            get(crate::directory::timestamp::timestamp_to_event),
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
        // MSC2246 async upload — POST /create reserves an mxc, PUT to
        // /upload/{server}/{id} fills in bytes later. v1.x clients
        // use this to keep upload UX snappy on large files.
        .route("/_matrix/media/v1/create", post(media::create_media))
        .route(
            "/_matrix/media/v3/upload/{server_name}/{media_id}",
            axum::routing::put(media::upload_to_id),
        )
        .route("/_matrix/media/v3/config", get(media::config))
        .route("/_matrix/media/v3/preview_url", get(media::preview_url))
        .route(
            "/_matrix/client/v1/media/preview_url",
            get(media::preview_url),
        )
        // MSC4306 thread subscriptions.
        .route(
            "/_matrix/client/unstable/io.element.msc4306/rooms/{room_id}/thread/{thread_root_id}/subscription",
            get(thread_subscriptions::get_subscription)
                .put(thread_subscriptions::put_subscription)
                .delete(thread_subscriptions::delete_subscription),
        )
        // Legacy unauth download/thumbnail endpoints. Pre-MSC3916
        // surface — many older clients still call these. Spec
        // deprecates them but keeping them serves backward
        // compatibility while the auth'd v1 paths below are the
        // forward direction.
        .route(
            "/_matrix/media/v3/download/{server_name}/{media_id}",
            get(media::download_legacy),
        )
        // Spec variant with a filename override in the path. The
        // filename overrides any name we recorded at upload time, so
        // clients can serve the same blob under different filenames.
        .route(
            "/_matrix/media/v3/download/{server_name}/{media_id}/{filename}",
            get(media::download_legacy_with_filename),
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
            "/_matrix/client/v1/media/download/{server_name}/{media_id}/{filename}",
            get(media::download_with_filename),
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
        .route("/_matrix/key/v2/server", get(federation::get_server_keys))
        // Notary key-query endpoints (unauthenticated per spec). vela
        // doesn't operate as a notary; the stubs return an empty
        // server_keys array so peers learn the route exists but get
        // no notarised data — the spec-compliant "I'm not a notary"
        // response.
        .route(
            "/_matrix/key/v2/query/{server_name}",
            get(federation::query_keys_single),
        )
        .route("/_matrix/key/v2/query", post(federation::query_keys_batch))
        // Server-version endpoint, unauthenticated per spec. Reports
        // the implementation name + version so other servers can
        // observe deployment heterogeneity.
        .route("/_matrix/federation/v1/version", get(federation::version))
        // OpenID userinfo. Spec marks this unauthenticated — the
        // access_token in the query string is the bearer.
        .route(
            "/_matrix/federation/v1/openid/userinfo",
            get(openid::federation_userinfo),
        );
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
        // Wrong-method on a known route returns 405; spec wants the same
        // M_UNRECOGNIZED JSON body shape as the 404 case (Complement's
        // TestUnknownEndpoints checks for this).
        .method_not_allowed_fallback(method_not_allowed)
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

/// 405 fallback: a known route exists but the request used an
/// unsupported method. Spec wants the same JSON shape as 404
/// M_UNRECOGNIZED — without it, axum returns an empty body and
/// Complement's TestUnknownEndpoints rejects the response.
async fn method_not_allowed(
    method: axum::http::Method,
    uri: axum::http::Uri,
) -> impl axum::response::IntoResponse {
    use axum::Json;
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(serde_json::json!({
            "errcode": "M_UNRECOGNIZED",
            "error": format!("method {} not allowed on {}", method, uri.path()),
        })),
    )
}

/// Build the sub-router for federation endpoints that require X-Matrix auth.
fn federation_authed_routes(state: AppState) -> Router<AppState> {
    use crate::e2ee::federation_devices;
    use crate::federation::federation_fetch;
    use crate::media::federation_media;
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
        // MSC3030 federation companion to the C2S timestamp_to_event.
        .route(
            "/_matrix/federation/v1/timestamp_to_event/{room_id}",
            get(crate::directory::timestamp::federation_timestamp_to_event),
        )
        .route(
            "/_matrix/federation/v1/user/devices/{user_id}",
            get(federation_devices::get_user_devices),
        )
        // Federation key endpoints — peers query these for our local
        // users' device + cross-signing keys, and to claim their
        // one-time keys when starting an Olm session.
        .route(
            "/_matrix/federation/v1/user/keys/query",
            post(keys::federation_query_keys),
        )
        .route(
            "/_matrix/federation/v1/user/keys/claim",
            post(keys::federation_claim_keys),
        )
        // Public-rooms federation directory. Always mounted; the
        // handler returns 404 when
        // `allow_public_rooms_over_federation` is false (default),
        // matching the response a peer would get from a server that
        // doesn't run this endpoint at all.
        .route(
            "/_matrix/federation/v1/publicRooms",
            get(federation_fetch::get_federation_public_rooms)
                .post(federation_fetch::post_federation_public_rooms),
        )
        // MSC2946 spaces hierarchy — single-level summary. Caller
        // recurses across servers themselves.
        .route(
            "/_matrix/federation/v1/hierarchy/{room_id}",
            get(crate::directory::spaces::federation_hierarchy),
        )
        .route(
            "/_matrix/federation/v1/media/download/{media_id}",
            get(federation_media::federation_download),
        )
        .route(
            "/_matrix/federation/v1/media/thumbnail/{media_id}",
            get(federation_media::federation_thumbnail),
        )
        .route(
            "/_matrix/federation/v1/query/directory",
            get(federation_fetch::query_directory),
        )
        .route(
            "/_matrix/federation/v1/query/profile",
            get(federation_fetch::query_profile),
        )
        // Inbound join
        .route(
            "/_matrix/federation/v1/make_join/{room_id}/{user_id}",
            get(crate::membership::federation_join::make_join),
        )
        .route(
            "/_matrix/federation/v1/send_join/{room_id}/{event_id}",
            put(crate::membership::federation_join::send_join_v1),
        )
        .route(
            "/_matrix/federation/v2/send_join/{room_id}/{event_id}",
            put(crate::membership::federation_join::send_join_v2),
        )
        .route(
            "/_matrix/federation/v1/make_leave/{room_id}/{user_id}",
            get(crate::membership::federation_leave::make_leave),
        )
        .route(
            "/_matrix/federation/v1/send_leave/{room_id}/{event_id}",
            put(crate::membership::federation_leave::send_leave_v1),
        )
        .route(
            "/_matrix/federation/v2/send_leave/{room_id}/{event_id}",
            put(crate::membership::federation_leave::send_leave_v2),
        )
        .route(
            "/_matrix/federation/v2/invite/{room_id}/{event_id}",
            put(crate::membership::federation_invite::invite_v2),
        )
        .route(
            "/_matrix/federation/v1/make_knock/{room_id}/{user_id}",
            get(crate::membership::federation_knock::make_knock),
        )
        .route(
            "/_matrix/federation/v1/send_knock/{room_id}/{event_id}",
            put(crate::membership::federation_knock::send_knock_v1),
        )
        .layer(axum::middleware::from_fn_with_state(state, federation_auth))
}
