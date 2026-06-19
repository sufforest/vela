use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use dashmap::DashMap;
use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::Deserialize;
use tracing::{info, warn};

use vela_api::federation::federation_client::{FederationClient, RemoteKeyCache};
use vela_api::federation::federation_resolver::FederationResolver;
use vela_api::federation::federation_sender::FederationSender;
use vela_api::router::{AppState, ServerConfig};
use vela_core::events::sign::ServerSigningKey;
use vela_store::db::Database;

mod backup;
mod retention;

#[derive(Parser)]
#[command(name = "vela", version, about = "Vela Matrix Homeserver")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "vela.toml")]
    config: PathBuf,
    /// Parse and validate the config file, print a short summary, and
    /// exit 0. Does not open the database, bind ports, or start any
    /// background tasks. Intended for ops scripts that want to
    /// pre-flight a new config before swapping binaries.
    #[arg(long)]
    validate_config: bool,
}

#[derive(Debug, Default, Deserialize)]
struct Config {
    #[serde(default)]
    server: ServerSection,
    #[serde(default)]
    database: DatabaseSection,
    #[serde(default)]
    user_directory: UserDirectorySection,
    #[serde(default)]
    directory: DirectorySection,
    #[serde(default)]
    federation: FederationSection,
    #[serde(default)]
    registration: RegistrationSection,
    #[serde(default)]
    media: MediaSection,
    #[serde(default)]
    room_defaults: RoomDefaultsSection,
    #[serde(default)]
    backup: BackupSection,
    #[serde(default)]
    retention: RetentionSection,
    #[serde(default)]
    tracing: TracingSection,
    #[serde(default)]
    rate_limit: RateLimitSection,
    #[serde(default)]
    voip: VoipSection,
    #[serde(default)]
    rtc: RtcSection,
    #[serde(default)]
    auth: AuthSection,
    #[serde(default)]
    admin: AdminSection,
    #[serde(default)]
    presence: PresenceSection,
    #[serde(default)]
    push: PushSection,
    #[serde(default)]
    appservice: AppServiceSection,
    #[serde(default)]
    support: SupportSection,
    #[serde(default)]
    extensions: ExtensionsSection,
}

/// `[support]` section — drives `.well-known/matrix/support` (MSC1929 /
/// spec v1.10). Empty (the default) means the endpoint 404s. Operators
/// publishing abuse/security contacts populate `contacts` and/or
/// `support_page`.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
struct SupportSection {
    contacts: Vec<SupportContactSection>,
    support_page: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
struct SupportContactSection {
    matrix_id: Option<String>,
    email_address: Option<String>,
    /// `m.role.admin` or `m.role.security` per spec.
    role: Option<String>,
}

/// `[appservice]` section. File-based application-service preload.
/// vela's primary AS lifecycle is admin-bot driven (`!as register`),
/// but Complement (and some operator workflows) drop YAML
/// registration files at a known path before the server starts.
/// When `registration_dir` is set, vela scans it for `*.yaml`
/// at boot and registers each one (duplicates are silently skipped
/// so re-boots are idempotent).
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct AppServiceSection {
    registration_dir: Option<String>,
}

/// `[extensions]` section. Sandboxed WASM plugins run at server-discretion
/// points (currently the local send path). Empty by default — no plugins, the
/// runtime is inert. Each `[[extensions.plugin]]` declares one component.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct ExtensionsSection {
    plugin: Vec<ExtensionPluginSection>,
}

#[derive(Debug, Deserialize, Clone)]
struct ExtensionPluginSection {
    /// Operator-facing name, used in errors, logs, and metrics labels.
    name: String,
    /// Path to the compiled `.wasm` component.
    wasm_path: String,
    /// "open" (default) → a failing/trapping plugin allows the event;
    /// "closed" → it blocks. Availability vs. safety.
    #[serde(default = "default_fail_policy")]
    fail_policy: String,
    /// Per-call fuel (≈ instruction) budget.
    #[serde(default = "default_plugin_fuel")]
    fuel: u64,
    /// Per-call wall-clock budget (ms); 0 disables the wall deadline.
    #[serde(default = "default_plugin_wall_ms")]
    wall_ms: u64,
    /// Max linear memory in 64 KiB pages.
    #[serde(default = "default_plugin_memory_pages")]
    memory_pages: u32,
    /// Only invoke for these event types; omitted → all events.
    event_types: Option<Vec<String>>,
    /// Which extension points this plugin binds: "check_event" (sync decision),
    /// "on_event" (async observation), "check_registration" (anti-spam signup).
    /// Defaults to ["check_event"].
    #[serde(default = "default_points")]
    points: Vec<String>,
    /// Host capabilities granted to this plugin (least-privilege; default none).
    /// "emit-event" lets it post events as its `@_ext_<name>` bot. `logging` is
    /// always granted and not listed here.
    #[serde(default)]
    capabilities: Vec<String>,
    /// How much of the client IP a `check_registration` plugin sees:
    /// "none" (default) | "hashed" (a rate-limit token, no PII) | "full" (raw IP).
    #[serde(default = "default_client_ip")]
    client_ip: String,
    /// Opaque JSON handed to the guest verbatim as `plugin_config`.
    #[serde(default)]
    config: serde_json::Value,
}

fn default_fail_policy() -> String {
    "open".to_string()
}
fn default_points() -> Vec<String> {
    vec!["check_event".to_string()]
}
fn default_client_ip() -> String {
    "none".to_string()
}
fn default_plugin_fuel() -> u64 {
    50_000_000
}
fn default_plugin_wall_ms() -> u64 {
    100
}
fn default_plugin_memory_pages() -> u32 {
    256
}

/// `[push]` section. Outbound push gateway posture knobs.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct PushSection {
    /// Allow pusher URLs that resolve to private / loopback /
    /// link-local addresses. False by default (refuses them as
    /// SSRF). Flip to true on docker/k8s deployments where the
    /// gateway lives on an internal network.
    allow_private_pushers: bool,
}

/// `[presence]` section. Auto-decay thresholds + sweeper cadence for
/// the user-presence state machine.
///
/// vela updates a user's `last_active_ms` every time they /sync. After
/// `idle_after` of no activity, the effective presence transitions
/// `online → unavailable`; after `offline_after`, to `offline`. A
/// background sweeper task running every `sweep_interval` persists
/// those transitions and broadcasts the federation EDU so remote
/// servers see the new state. Local /sync responses always compute the
/// effective value at read time, so they're correct even between
/// sweeper ticks.
#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
struct PresenceSection {
    /// Same syntax as backup/retention intervals (`5min`, `300s`, `1h`).
    idle_after: String,
    offline_after: String,
    sweep_interval: String,
}

impl Default for PresenceSection {
    fn default() -> Self {
        Self {
            idle_after: "5min".to_string(),
            offline_after: "30min".to_string(),
            sweep_interval: "60s".to_string(),
        }
    }
}

/// `[admin]` section. Configures the server-internal admin bot + admin
/// room. The bot's localpart defaults to `"admin"` (full MXID
/// `@admin:<server_name>`). Operators can pick a different localpart if
/// `admin` is already taken on their deployment — but the chosen
/// localpart is then reserved on `/register` for safety.
#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
struct AdminSection {
    bot_localpart: String,
}

impl Default for AdminSection {
    fn default() -> Self {
        Self {
            bot_localpart: vela_api::admin::DEFAULT_BOT_LOCALPART.to_string(),
        }
    }
}

/// `[auth]` section. Container for authentication-mode configuration.
/// Today only houses `[auth.oidc]` (MSC3861 phase 1 discovery posture);
/// future auth-related blocks (e.g. SAML, LDAP) would slot in alongside.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AuthSection {
    oidc: OidcSection,
}

/// `[auth.oidc]` section. MSC3861 phase 1: discovery + capability
/// advertisement only. When `enabled = true`, vela tells clients via
/// `/auth_issuer` and `/versions` that it's configured to delegate
/// auth to an external OIDC issuer — but token validation against that
/// IdP is NOT wired up yet (phase 2). Leaving `enabled = false`
/// preserves the legacy `/login` + `/register` flow exactly.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
struct OidcSection {
    enabled: bool,
    /// The OIDC issuer URL, e.g. `https://auth.example.com/`. Required
    /// when `enabled = true`; surfaced verbatim to clients.
    issuer: String,
    /// vela's registered client_id at the issuer. Optional — only
    /// needed for clients that read it from discovery rather than
    /// learning it through dynamic client registration.
    client_id: Option<String>,
    /// Account-management URL per MSC3861. Optional; when set, clients
    /// show it to end users as the place to manage their identity.
    account_management_url: Option<String>,
    /// RFC7662 introspection endpoint. Setting this activates Phase 2:
    /// vela validates incoming Bearer tokens against the IdP. Leave
    /// unset for discovery-only Phase 1 posture.
    introspection_endpoint: Option<String>,
    /// Credentials vela presents to the IdP on introspection requests.
    /// Required together when `introspection_endpoint` is set; the
    /// validator refuses to boot otherwise.
    introspection_client_id: Option<String>,
    introspection_client_secret: Option<String>,
    /// `"client_secret_basic"` (default) or `"client_secret_post"`.
    /// Both are RFC6749 §2.3 standard methods; pick whichever your
    /// IdP requires.
    #[serde(default)]
    introspection_auth_method: OidcIntrospectionAuthMethod,
}

#[derive(Debug, Default, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum OidcIntrospectionAuthMethod {
    #[default]
    ClientSecretBasic,
    ClientSecretPost,
}

impl From<OidcIntrospectionAuthMethod> for vela_api::router::IntrospectionAuthMethod {
    fn from(m: OidcIntrospectionAuthMethod) -> Self {
        match m {
            OidcIntrospectionAuthMethod::ClientSecretBasic => Self::ClientSecretBasic,
            OidcIntrospectionAuthMethod::ClientSecretPost => Self::ClientSecretPost,
        }
    }
}

/// `[voip]` section. Drives the classic 1-to-1 `m.call.*` path by
/// returning TURN credentials from `/_matrix/client/v3/voip/turnServer`.
/// Empty (the default) means we serve a 404 there — clients then fall
/// back to direct WebRTC, which works on permissive networks but
/// dies in restrictive NAT/firewall environments. Group calls don't
/// use this at all; see `[rtc]` for matrix-rtc / Element Call.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
struct VoipSection {
    /// `["turn:turn.example.com:3478", "turns:turn.example.com:5349"]`.
    /// Vela returns these verbatim in the `uris` array of the
    /// `/voip/turnServer` response.
    uris: Vec<String>,
    /// Long-term shared secret matching coturn's `static-auth-secret`
    /// or `use-auth-secret`. Vela mints time-limited username /
    /// password pairs from this so clients get credentials valid for
    /// `ttl` seconds. Empty disables `/voip/turnServer`.
    shared_secret: String,
    /// How long the minted credential is valid for, in seconds.
    /// Default 24h, matching synapse.
    ttl: u32,
}

/// `[rtc]` section. Drives the matrix-rtc / Element Call path
/// (MSC4143). Empty (the default) means we don't advertise an SFU
/// in `.well-known` and the JWT-mint endpoint refuses; clients then
/// fall back to whichever focus another participant brings.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
struct RtcSection {
    /// Public URL of the SFU (LiveKit). Clients use this as the
    /// WebRTC endpoint after we mint them a JWT scoped to a room.
    sfu_url: String,
    /// LiveKit API key (its public side of the JWT issuer pair).
    livekit_api_key: String,
    /// LiveKit API secret. We sign the JWT with HS256 using this.
    livekit_secret: String,
    /// JWT lifetime in seconds. Default 6h — long enough for a
    /// reasonable meeting, short enough that a leaked token isn't
    /// permanently dangerous.
    jwt_ttl: u32,
}

/// `[retention]` section. Drives the periodic retention sweeper.
/// Off by default — operators opt in by setting `enabled = true` and
/// at least one media lifetime. Lifetime values use the same suffix
/// syntax as backup intervals (`365d`, `30d`, `24h`); the literal
/// `"forever"` (or empty string) means "keep forever."
#[derive(Debug, Deserialize)]
#[serde(default)]
struct RetentionSection {
    enabled: bool,
    /// E.g. `"24h"`. Default 24h.
    interval: String,
    media: RetentionMediaSection,
}

impl Default for RetentionSection {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: "24h".to_string(),
            media: RetentionMediaSection::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct RetentionMediaSection {
    /// Local-uploaded media — retain forever by default. Operators
    /// who want cost-driven expiry set this to e.g. `"365d"`.
    local_lifetime: String,
    /// Cached remote media — short-by-default once we start fetching
    /// remote blobs (today vela 404s on remote downloads, so the
    /// field is forward-looking but harmless). 30 days is a sane
    /// default for a fetch-and-cache layer.
    remote_lifetime: String,
}

impl Default for RetentionMediaSection {
    fn default() -> Self {
        Self {
            local_lifetime: "forever".to_string(),
            remote_lifetime: "30d".to_string(),
        }
    }
}

/// `[room_defaults]` section. Server-side policies that tune what
/// `/createRoom` produces when the client is silent. Client explicit
/// `initial_state` always wins.
#[derive(Debug, Deserialize)]
#[serde(default)]
struct RoomDefaultsSection {
    /// `"off"` (default), `"dm_only"`, `"private_only"`, or `"all"`.
    /// When set to anything other than `"off"`, vela injects
    /// `m.room.encryption` (algorithm `m.megolm.v1.aes-sha2`) into
    /// new rooms whose `/createRoom` request didn't include one.
    /// Public rooms are never auto-encrypted regardless of policy.
    /// Privacy-first deployments should set this to `"private_only"`.
    encrypt_by_default: String,
}

impl Default for RoomDefaultsSection {
    fn default() -> Self {
        Self {
            encrypt_by_default: "off".to_string(),
        }
    }
}

fn parse_encrypt_policy(s: &str) -> anyhow::Result<vela_api::router::EncryptByDefault> {
    use vela_api::router::EncryptByDefault::*;
    match s.trim().to_ascii_lowercase().as_str() {
        "off" | "" => Ok(Off),
        "dm_only" | "dm" => Ok(DmOnly),
        "private_only" | "private" => Ok(PrivateOnly),
        "all" => Ok(All),
        other => anyhow::bail!(
            "[room_defaults] encrypt_by_default: unknown {other:?} \
             (expected off | dm_only | private_only | all)"
        ),
    }
}

/// `[backup]` section. Drives the in-process backup scheduler. Default
/// is `enabled = false` — operators must opt in by setting a target.
/// `interval` accepts the same human-readable duration syntax used in
/// other parts of vela's config (`"24h"`, `"30m"`, `"15m"`, etc.).
#[derive(Debug, Deserialize)]
#[serde(default)]
struct BackupSection {
    enabled: bool,
    /// E.g. `"24h"`, `"6h"`. Default 24h.
    interval: String,
    /// `"disk:/path"` or `"s3://bucket/prefix"`.
    target: String,
    /// Number of most-recent backups to retain. 0 = keep forever.
    keep: usize,
    /// Optional S3 credentials when `target` is an `s3://` URL.
    s3: Option<S3BackupSection>,
}

impl Default for BackupSection {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: "24h".to_string(),
            target: String::new(),
            keep: 7,
            s3: None,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct S3BackupSection {
    region: Option<String>,
    endpoint: Option<String>,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    allow_http: bool,
}

/// `[registration]` section. Controls signup admission. Default is
/// open (`enabled = true`, no token) which is wrong for any
/// internet-facing deploy — operators MUST flip these for production.
/// Closed-signup deployments set `enabled = false` and either invite
/// users out-of-band or distribute a `token`.
#[derive(Debug, Deserialize)]
#[serde(default)]
struct RegistrationSection {
    enabled: bool,
    token: Option<String>,
}

impl Default for RegistrationSection {
    fn default() -> Self {
        Self {
            enabled: true,
            token: None,
        }
    }
}

/// `[media]` section. Holds the upload cap and the storage backend
/// selection. Default backend is the local filesystem (rooted at
/// `<database.path>/media`); S3-compatible storage is enabled by
/// setting `backend = "s3"` and providing a `[media.s3]` block.
#[derive(Debug, Deserialize)]
#[serde(default)]
struct MediaSection {
    /// Human-readable size: "50MB", "1GB", "500K", or a bare byte
    /// count ("1024"). Default 50MB.
    max_upload_size: String,
    /// `"fs"` (default) or `"s3"`. Determines which MediaStore impl
    /// is wired into AppState.
    backend: String,
    /// S3 configuration. Only consulted when `backend = "s3"`.
    s3: Option<S3MediaSection>,
}

impl Default for MediaSection {
    fn default() -> Self {
        Self {
            max_upload_size: "50MB".to_string(),
            backend: "fs".to_string(),
            s3: None,
        }
    }
}

/// `[media.s3]` section. Mirrors `vela_store::media::S3Config`. Access
/// keys may also be loaded from environment variables (AWS standard
/// AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) — leave the fields
/// unset to let the SDK pick them up.
#[derive(Debug, Deserialize)]
#[serde(default)]
#[derive(Default)]
struct S3MediaSection {
    bucket: String,
    region: Option<String>,
    /// Override for non-AWS S3-compatible (MinIO, Cloudflare R2,
    /// Backblaze B2). Example: `"https://s3.eu-central-003.backblazeb2.com"`.
    endpoint: Option<String>,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    /// Optional key prefix; "" puts blobs at the bucket root.
    prefix: String,
    /// Allow plain-HTTP endpoints. Required for MinIO with a
    /// dev-mode listener. Default false (production safety).
    allow_http: bool,
}

#[cfg(test)]
mod parse_encrypt_policy_tests {
    use super::parse_encrypt_policy;
    use vela_api::router::EncryptByDefault::*;

    #[test]
    fn known_values() {
        assert_eq!(parse_encrypt_policy("off").unwrap(), Off);
        assert_eq!(parse_encrypt_policy("").unwrap(), Off);
        assert_eq!(parse_encrypt_policy("DM_ONLY").unwrap(), DmOnly);
        assert_eq!(parse_encrypt_policy("dm").unwrap(), DmOnly);
        assert_eq!(parse_encrypt_policy("private_only").unwrap(), PrivateOnly);
        assert_eq!(parse_encrypt_policy("PRIVATE").unwrap(), PrivateOnly);
        assert_eq!(parse_encrypt_policy("all").unwrap(), All);
    }

    #[test]
    fn unknown_rejected() {
        assert!(parse_encrypt_policy("encrypt_everything").is_err());
        assert!(parse_encrypt_policy("yes").is_err());
    }
}

#[cfg(test)]
mod parse_size_tests {
    use super::parse_size;

    #[test]
    fn bare_integer() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("0").unwrap(), 0);
    }

    #[test]
    fn k_m_g_suffixes() {
        assert_eq!(parse_size("50MB").unwrap(), 50 * 1024 * 1024);
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("500K").unwrap(), 500 * 1024);
        assert_eq!(parse_size("2 KiB").unwrap(), 2048);
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(parse_size("50mb").unwrap(), 50 * 1024 * 1024);
        assert_eq!(parse_size("50Mb").unwrap(), 50 * 1024 * 1024);
        assert_eq!(parse_size("50 GIB").unwrap(), 50u64 * 1024 * 1024 * 1024);
    }

    #[test]
    fn whitespace_tolerated() {
        assert_eq!(parse_size(" 50MB ").unwrap(), 50 * 1024 * 1024);
        assert_eq!(parse_size("50 MB").unwrap(), 50 * 1024 * 1024);
    }

    #[test]
    fn malformed_rejected() {
        assert!(parse_size("not_a_number").is_err());
        assert!(parse_size("MB").is_err());
        assert!(parse_size("").is_err());
        assert!(parse_size("-5").is_err());
    }
}

/// Parse a human-readable duration string ("24h", "30m", "15s",
/// or a bare second count). Used for backup intervals.
fn parse_duration(s: &str) -> anyhow::Result<std::time::Duration> {
    let trimmed = s.trim();
    let mult: u64 = if trimmed.ends_with('h') || trimmed.ends_with('H') {
        3600
    } else if trimmed.ends_with('m') || trimmed.ends_with('M') {
        60
    } else if trimmed.ends_with('s') || trimmed.ends_with('S') {
        1
    } else if trimmed.ends_with('d') || trimmed.ends_with('D') {
        86400
    } else {
        1
    };
    let num_str = trimmed
        .trim_end_matches(|c: char| c.is_ascii_alphabetic())
        .trim();
    let n: u64 = num_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid duration {s:?}: {e}"))?;
    Ok(std::time::Duration::from_secs(n.saturating_mul(mult)))
}

#[cfg(test)]
mod parse_duration_tests {
    use super::parse_duration;
    use std::time::Duration;

    #[test]
    fn suffixes() {
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("15s").unwrap(), Duration::from_secs(15));
    }

    #[test]
    fn bare_integer_is_seconds() {
        assert_eq!(parse_duration("60").unwrap(), Duration::from_secs(60));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_duration("not_a_number").is_err());
        assert!(parse_duration("").is_err());
    }
}

/// Parse a human-readable size string into bytes. Accepts:
/// - bare integer ("1024" → 1024)
/// - K / KB / KiB suffix (1024 multiplier)
/// - M / MB / MiB suffix (1024² multiplier)
/// - G / GB / GiB suffix (1024³ multiplier)
///
/// Case-insensitive, whitespace tolerated.
fn parse_size(s: &str) -> anyhow::Result<u64> {
    let trimmed = s.trim();
    let upper = trimmed.to_ascii_uppercase();
    let mult: u64 = if upper.ends_with("GIB") || upper.ends_with("GB") || upper.ends_with('G') {
        1024 * 1024 * 1024
    } else if upper.ends_with("MIB") || upper.ends_with("MB") || upper.ends_with('M') {
        1024 * 1024
    } else if upper.ends_with("KIB") || upper.ends_with("KB") || upper.ends_with('K') {
        1024
    } else {
        1
    };
    let num_str = trimmed
        .trim_end_matches(|c: char| c.is_ascii_alphabetic())
        .trim();
    let n: u64 = num_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid size string {s:?}: {e}"))?;
    Ok(n.saturating_mul(mult))
}

/// `[rate_limit]` section. Controls the per-IP token-bucket limiter
/// applied to abuse-prone unauthenticated POSTs (`/register`, `/login`).
/// Default: enabled with production-safe thresholds (see
/// `RateLimiter::defaults`). Set `enabled = false` in test or
/// Complement deployments where many requests originate from a single
/// IP and would cascade-fail unrelated assertions.
#[derive(Debug, Deserialize)]
#[serde(default)]
struct RateLimitSection {
    enabled: bool,
}

impl Default for RateLimitSection {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// `[tracing]` section. Distributed-tracing controls. Only meaningful
/// when the `otel` feature is compiled in — in builds without it, this
/// section is parsed but ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TracingSection {
    /// OTLP/gRPC collector endpoint (e.g. "http://localhost:4317").
    /// `None` (or empty string) disables export — spans still log via
    /// the fmt layer.
    otlp_endpoint: Option<String>,
}

/// `[federation]` section. `enabled` toggles federation in/out at
/// the router and outbound-client level. `http_peers` carries
/// plain-HTTP peer overrides — a map from a remote `server_name` to
/// the base URL we should use to reach it, bypassing the normal
/// resolve-+-HTTPS path. Intended for local dev / self-hosted
/// clusters where two Vela instances need to talk without real TLS
/// certs. Empty in production.
#[derive(Debug, Deserialize)]
#[serde(default)]
struct FederationSection {
    enabled: bool,
    /// `"server_name" = "http://host:port"` pairs.
    http_peers: std::collections::HashMap<String, String>,
    /// SSRF guard: refuse outbound federation when the destination resolves
    /// to a private / loopback / link-local / etc. address. Default true.
    /// Disable only for containerised test environments (Complement,
    /// docker-compose dev clusters) where peers legitimately live on
    /// RFC 1918 networks.
    private_ip_block: bool,
    /// If non-empty, restrict outbound federation to these `server_name`s.
    /// Empty disables the filter. Per-room ACLs (`m.room.server_acl`)
    /// continue to apply on top of this.
    allow_list: Vec<String>,
}

impl Default for FederationSection {
    fn default() -> Self {
        Self {
            enabled: true,
            http_peers: std::collections::HashMap::new(),
            private_ip_block: true,
            allow_list: Vec::new(),
        }
    }
}

/// `[user_directory]` section. Controls /user_directory/search behaviour.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct UserDirectorySection {
    /// When false (default), search returns only users that share a room
    /// with the caller. Set true on deployments where full-directory
    /// search is desired.
    search_all_users: bool,
    /// When false (default), user_directory search does not query remote
    /// servers — results are local-only. Privacy-first: forces full
    /// MXID input for cross-server DMs to a stranger, no enumeration of
    /// the federated user graph.
    federate: bool,
}

/// `[directory]` section. Controls public-room directory exposure.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct DirectorySection {
    /// When false (default), other servers cannot query our published
    /// public-room directory via `/_matrix/federation/v1/publicRooms`.
    /// Privacy-first; opt-in for community / open-server deployments.
    allow_public_rooms_over_federation: bool,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct ServerSection {
    name: String,
    bind: String,
    port: u16,
    /// Public-facing URL for the client API, advertised in
    /// `.well-known/matrix/client`. Set to e.g.
    /// `"https://matrix.example.com"` when vela sits behind a TLS
    /// terminator (Caddy / Cloudflare / nginx). When unset, vela
    /// publishes `http://<bind>:<port>` — correct only for a
    /// directly-internet-reachable vela, wrong for any reverse-proxied
    /// deploy.
    public_base_url: Option<String>,
    /// Optional TLS listener. When present, Vela additionally serves HTTPS on
    /// `tls.port` using the provided cert/key files. Absent → plain HTTP only
    /// (development and unit-test default).
    tls: Option<TlsSection>,
    /// PEM files whose CAs to trust for OUTBOUND federation TLS, in addition
    /// to system roots. Empty in production; used by Complement where both
    /// servers' certs are signed by a CA mounted in the container.
    extra_ca_certs: Vec<PathBuf>,
    /// Minimum room version vela accepts. Default `"6"`. Operators
    /// who want spec-modern-only deployments set this to `"10"` or
    /// higher. Below v6 is never supported regardless of this setting.
    minimum_room_version: String,
    /// MSC4140 delayed-events upper bound (milliseconds). Default
    /// 7 days. Operators wanting a tighter window can shrink it.
    /// Setting `0` effectively disables the feature — every PUT
    /// with `?org.matrix.msc4140.delay=` fails 400 — which is the
    /// right outcome for deployments that don't want to operate the
    /// scheduler at all.
    #[serde(default = "default_max_delay_ms")]
    max_delay_ms: u64,
}

fn default_max_delay_ms() -> u64 {
    vela_api::delayed_events::DEFAULT_MAX_DELAY_MS
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            name: "localhost".to_string(),
            bind: "0.0.0.0".to_string(),
            port: 8008,
            public_base_url: None,
            tls: None,
            extra_ca_certs: Vec::new(),
            minimum_room_version: "6".to_string(),
            max_delay_ms: default_max_delay_ms(),
        }
    }
}

fn parse_minimum_room_version(
    s: &str,
) -> anyhow::Result<vela_core::events::room_version::RoomVersion> {
    use vela_core::events::room_version::RoomVersion;
    RoomVersion::parse(s.trim()).ok_or_else(|| {
        anyhow::anyhow!(
            "[server] minimum_room_version: {s:?} is not a supported room version (expected 6..12)"
        )
    })
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
struct TlsSection {
    /// HTTPS port. Matrix federation defaults to 8448.
    port: u16,
    /// PEM-encoded certificate file.
    cert_file: PathBuf,
    /// PEM-encoded private key file.
    key_file: PathBuf,
}

impl Default for TlsSection {
    fn default() -> Self {
        Self {
            port: 8448,
            cert_file: PathBuf::from("/conf/server.tls.crt"),
            key_file: PathBuf::from("/conf/server.tls.key"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct DatabaseSection {
    path: String,
}

impl Default for DatabaseSection {
    fn default() -> Self {
        Self {
            path: "./data".to_string(),
        }
    }
}

fn load_extra_ca_certs(paths: &[PathBuf]) -> anyhow::Result<Vec<reqwest::Certificate>> {
    let mut out = Vec::new();
    for path in paths {
        let bytes = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("failed to read CA cert {}: {e}", path.display()))?;
        // from_pem_bundle handles files containing one or more concatenated certs.
        let certs = reqwest::Certificate::from_pem_bundle(&bytes)
            .map_err(|e| anyhow::anyhow!("failed to parse CA cert {}: {e}", path.display()))?;
        info!(path = %path.display(), count = certs.len(), "loaded extra CA cert(s)");
        out.extend(certs);
    }
    Ok(out)
}

/// Build the sandboxed extension runtime from `[extensions]`. An empty section
/// yields an inert runtime (no plugins). A missing wasm file, an unknown
/// fail_policy, or an invalid component aborts startup — a misconfigured policy
/// must not silently no-op. With the `extensions` feature off this still
/// compiles and returns the no-op runtime.
fn build_extension_runtime(
    section: &ExtensionsSection,
    services: vela_extensions::HostServices,
) -> anyhow::Result<vela_extensions::Runtime> {
    let mut configs = Vec::with_capacity(section.plugin.len());
    for p in &section.plugin {
        let wasm = std::fs::read(&p.wasm_path).map_err(|e| {
            anyhow::anyhow!(
                "extension '{}': reading wasm at {}: {e}",
                p.name,
                p.wasm_path
            )
        })?;
        let fail_policy = match p.fail_policy.as_str() {
            "open" => vela_extensions::FailPolicy::Open,
            "closed" => vela_extensions::FailPolicy::Closed,
            other => anyhow::bail!(
                "extension '{}': unknown fail_policy {other:?} (expected \"open\" or \"closed\")",
                p.name
            ),
        };
        let mut points = vela_extensions::Points {
            check_event: false,
            on_event: false,
            check_registration: false,
        };
        for point in &p.points {
            match point.as_str() {
                "check_event" => points.check_event = true,
                "on_event" => points.on_event = true,
                "check_registration" => points.check_registration = true,
                other => anyhow::bail!(
                    "extension '{}': unknown point {other:?} (expected \"check_event\", \"on_event\", or \"check_registration\")",
                    p.name
                ),
            }
        }
        if !points.check_event && !points.on_event && !points.check_registration {
            anyhow::bail!(
                "extension '{}': points is empty — a plugin bound to no point can never run",
                p.name
            );
        }
        let client_ip = match p.client_ip.as_str() {
            "none" => vela_extensions::ClientIpTier::None,
            "hashed" => vela_extensions::ClientIpTier::Hashed,
            "full" => vela_extensions::ClientIpTier::Full,
            other => anyhow::bail!(
                "extension '{}': unknown client_ip {other:?} (expected \"none\", \"hashed\", or \"full\")",
                p.name
            ),
        };
        if client_ip != vela_extensions::ClientIpTier::None && !points.check_registration {
            anyhow::bail!(
                "extension '{}': client_ip is only used by the \"check_registration\" point",
                p.name
            );
        }
        let mut capabilities = vela_extensions::Capabilities::default();
        for cap in &p.capabilities {
            match cap.as_str() {
                "emit-event" => capabilities.emit_event = true,
                "kv" => capabilities.kv = true,
                other => anyhow::bail!(
                    "extension '{}': unknown capability {other:?} (expected \"emit-event\" or \"kv\")",
                    p.name
                ),
            }
        }
        // emit-event is only meaningful from on_event (it can't run on the
        // decision hot path); reject a config that grants it without binding it.
        // (kv works from either point, so it has no such requirement.)
        if capabilities.emit_event && !points.on_event {
            anyhow::bail!(
                "extension '{}': capability \"emit-event\" requires the \"on_event\" point",
                p.name
            );
        }
        configs.push(vela_extensions::PluginConfig {
            name: p.name.clone(),
            wasm,
            fail_policy,
            fuel: p.fuel,
            wall_ms: p.wall_ms,
            memory_pages: p.memory_pages,
            event_types: p.event_types.clone(),
            points,
            capabilities,
            client_ip,
            config: p.config.clone(),
        });
    }
    if !configs.is_empty() {
        info!(count = configs.len(), "extensions: loading plugin(s)");
    }
    vela_extensions::Runtime::with_services(configs, services)
        .map_err(|e| anyhow::anyhow!("extensions: {e}"))
}

/// Re-read `[extensions]` from the config file and build a fresh runtime, for
/// SIGHUP hot-reload. Unlike [`load_config`], a parse/build error is *returned*
/// (not fatal) so the caller keeps the current plugin set. Returns the runtime
/// and the plugin count.
#[cfg(unix)]
fn reload_extension_runtime(
    path: &std::path::Path,
    services: vela_extensions::HostServices,
) -> Result<(vela_extensions::Runtime, usize), String> {
    let config: Config = Figment::new()
        .merge(Toml::file(path))
        .merge(Env::prefixed("VELA_").split("_"))
        .extract()
        .map_err(|e| format!("parsing {}: {e}", path.display()))?;
    let count = config.extensions.plugin.len();
    let runtime =
        build_extension_runtime(&config.extensions, services).map_err(|e| e.to_string())?;
    Ok((runtime, count))
}

#[cfg(all(test, unix))]
mod reload_tests {
    fn write_config(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vela.toml");
        std::fs::write(&path, body).expect("write config");
        (dir, path)
    }

    fn example_wasm() -> String {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../extensions/examples/keyword-filter/keyword-filter.wasm"
        )
        .to_string()
    }

    #[test]
    fn reloads_a_valid_config() {
        let (_dir, path) = write_config(&format!(
            "[[extensions.plugin]]\nname = \"kf\"\nwasm_path = \"{}\"\n\
             config = {{ banned = [\"spam\"] }}\n",
            example_wasm()
        ));
        let (_rt, count) =
            super::reload_extension_runtime(&path, vela_extensions::HostServices::default())
                .expect("valid config reloads");
        assert_eq!(count, 1);
    }

    #[test]
    fn empty_config_reloads_to_zero_plugins() {
        let (_dir, path) = write_config("# nothing here\n");
        let (_rt, count) =
            super::reload_extension_runtime(&path, vela_extensions::HostServices::default())
                .expect("empty config reloads");
        assert_eq!(count, 0);
    }

    #[test]
    fn a_missing_wasm_errors_so_the_caller_keeps_the_old_set() {
        let (_dir, path) = write_config(
            "[[extensions.plugin]]\nname = \"kf\"\nwasm_path = \"/no/such/plugin.wasm\"\n",
        );
        assert!(
            super::reload_extension_runtime(&path, vela_extensions::HostServices::default())
                .is_err(),
            "a bad reload must error, not panic or silently succeed"
        );
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // --validate-config short-circuits before any side-effects: no
    // crypto provider install, no tracing init, no DB open, no listener
    // bind. Print a one-line "OK" plus the parsed summary, exit 0. If
    // validation fails, the anyhow error bubbles up and clap/anyhow
    // print the message and exit non-zero — exactly what an ops script
    // wants for pre-flight.
    if cli.validate_config {
        let config = load_config(&cli.config);
        validate_config(&config)?;
        // Also exercise the field-level parsers (size, duration,
        // retention lifetime). These are the ones operators most often
        // typo and the cheapest to surface here.
        validate_runtime_parsable(&config)?;
        print_config_summary(&cli.config, &config);
        return Ok(());
    }

    // rustls 0.23 requires the process-level crypto provider to be explicitly
    // installed before any TLS operation. We use aws-lc-rs (also what reqwest
    // pulls via `rustls-tls`). This is a no-op if already set (e.g. tests).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Load config: file -> env vars (VELA_ prefix)
    let config = load_config(&cli.config);

    // Initialize tracing — fmt layer + (optionally) an OTLP exporter
    // when the `otel` feature is enabled and a collector endpoint is
    // configured. The returned guard, if any, MUST live until shutdown
    // so in-flight spans flush.
    let _otel_guard = init_tracing(&config.tracing);

    // Validate config at startup — fail loudly with a human-readable
    // message now rather than letting a malformed setting surface as
    // an opaque runtime error later.
    validate_config(&config)?;

    info!(server_name = %config.server.name, "starting vela");

    // Install a metrics recorder if one's enabled at compile time.
    // Feature-gated so alternate deployments can `--no-default-features`
    // and bring their own exporter.
    let metrics_renderer = install_metrics_recorder();

    // Build tokio runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // Captured into the async block for the SIGHUP extension-reload task (unix).
    #[cfg(unix)]
    let config_path = cli.config.clone();
    runtime.block_on(async move {
        // Open database
        let db_path = PathBuf::from(&config.database.path);
        let db = Database::open(&db_path)
            .map_err(|e| anyhow::anyhow!("failed to open database: {e}"))?;

        info!(path = %config.database.path, "database opened");

        // Initialize media store. Filesystem is the single-pod default;
        // S3 (or any S3-compatible: MinIO, Cloudflare R2, B2) is for
        // multi-pod deploys and off-host blob durability.
        let media_store: Arc<dyn vela_store::media::MediaStore> = match config
            .media
            .backend
            .as_str()
        {
            "fs" => {
                let media_path = PathBuf::from(&config.database.path).join("media");
                Arc::new(
                    vela_store::media::FilesystemMediaStore::new(&media_path)
                        .map_err(|e| anyhow::anyhow!("failed to initialize fs media store: {e}"))?,
                )
            }
            "s3" => {
                let s3 = config.media.s3.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("[media] backend = \"s3\" requires a [media.s3] block")
                })?;
                if s3.bucket.is_empty() {
                    anyhow::bail!("[media.s3] bucket must be set");
                }
                let store_cfg = vela_store::media::S3Config {
                    bucket: s3.bucket.clone(),
                    region: s3.region.clone(),
                    endpoint: s3.endpoint.clone(),
                    access_key_id: s3.access_key_id.clone(),
                    secret_access_key: s3.secret_access_key.clone(),
                    prefix: s3.prefix.clone(),
                    allow_http: s3.allow_http,
                };
                Arc::new(
                    vela_store::media::S3MediaStore::new(&store_cfg)
                        .map_err(|e| anyhow::anyhow!("failed to init S3 media store: {e}"))?,
                )
            }
            other => anyhow::bail!("unknown [media] backend {other:?}: must be \"fs\" or \"s3\""),
        };
        info!(backend = %config.media.backend, "media store initialised");

        // Load or generate server signing key
        let signing_key = match db
            .load_signing_key()
            .map_err(|e| anyhow::anyhow!("failed to load signing key: {e}"))?
        {
            Some((key_id, secret)) => {
                info!(key_id = %key_id, "loaded existing signing key");
                ServerSigningKey::from_bytes(key_id, &secret)
            }
            None => {
                let key = ServerSigningKey::generate();
                db.store_signing_key(key.key_id(), key.secret_bytes())
                    .map_err(|e| anyhow::anyhow!("failed to store signing key: {e}"))?;
                info!(key_id = %key.key_id(), "generated new signing key");
                key
            }
        };

        let signing_key = Arc::new(signing_key);
        let db = Arc::new(db);

        let fed_policy = vela_api::federation::federation_resolver::FederationPolicy {
            private_ip_block: config.federation.private_ip_block,
            allow_list: config.federation.allow_list.clone(),
            our_server_name: config.server.name.clone(),
        };
        if !config.federation.private_ip_block {
            tracing::warn!(
                "federation: private-IP block disabled — outbound federation may dial \
                 internal hosts; only safe in trusted-network deployments"
            );
        }
        if !config.federation.allow_list.is_empty() {
            tracing::info!(
                allow_list = ?config.federation.allow_list,
                "federation: outbound restricted to allow-list"
            );
        }
        let resolver = Arc::new(
            FederationResolver::with_policy(fed_policy)
                .map_err(|e| anyhow::anyhow!("failed to init DNS resolver: {e}"))?,
        );
        let extra_ca_certs = load_extra_ca_certs(&config.server.extra_ca_certs)?;
        let federation_client = Arc::new(FederationClient::new_with_enabled(
            signing_key.clone(),
            config.server.name.clone(),
            resolver,
            extra_ca_certs,
            config.federation.enabled,
        ));
        // Plain-HTTP peer overrides: bypasses the resolve-+-HTTPS path for
        // configured server_names. Used by local dev / self-hosted clusters
        // where real TLS certs aren't practical. Empty in production.
        for (peer, url) in &config.federation.http_peers {
            federation_client.set_base_url_override(peer, url);
        }
        if !config.federation.http_peers.is_empty() {
            tracing::info!(
                peers = ?config.federation.http_peers.keys().collect::<Vec<_>>(),
                "federation: plain-HTTP peer overrides installed"
            );
        }
        let remote_keys = Arc::new(RemoteKeyCache::new(
            db.clone(),
            (*federation_client).clone(),
        ));
        let typing_stream = vela_api::federation::edu::typing::TypingStream::new(
            db.clone(),
            config.server.name.clone(),
        );
        let edu_streams: vela_api::federation::edu::EduStreams = vec![
            vela_api::federation::edu::receipts::ReceiptStream::new(config.server.name.clone()),
            vela_api::federation::edu::presence::PresenceStream::new(config.server.name.clone()),
            vela_api::federation::edu::to_device::ToDeviceStream::new(),
            vela_api::federation::edu::device_list::DeviceListStream::new(),
            vela_api::federation::edu::signing_key::SigningKeyUpdateStream::new(),
            typing_stream.clone(),
        ];
        let federation_sender = Arc::new(FederationSender::new_with_enabled(
            db.clone(),
            federation_client.clone(),
            config.server.name.clone(),
            edu_streams,
            config.federation.enabled,
        ));

        // Application Service registry + per-AS outbound delivery
        // scheduler. Workers start in start_all after AppState is
        // built so they see the cleartext hs_tokens that operators
        // re-paste via `!as register` (those are in-memory only).
        let appservice_registry = Arc::new(
            vela_api::appservice::AsRegistry::open(db.clone())
                .map_err(|e| anyhow::anyhow!("as registry open: {e}"))?,
        );
        if let Some(dir) = config.appservice.registration_dir.as_deref() {
            preload_appservice_dir(dir, &appservice_registry);
        }
        let appservice_outbox =
            vela_api::appservice::outbox::AsOutbox::new(db.clone(), appservice_registry.clone());

        // MSC3861 Phase 2 plumbing. Only constructed when the operator
        // supplied an introspection_endpoint; otherwise the extractor's
        // third OIDC path stays dormant.
        let oidc_introspection =
            config
                .auth
                .oidc
                .introspection_endpoint
                .as_deref()
                .map(|endpoint| {
                    let client = vela_api::auth::oidc::IntrospectionClient::new(
                        endpoint.to_string(),
                        config
                            .auth
                            .oidc
                            .introspection_client_id
                            .clone()
                            .unwrap_or_default(),
                        config
                            .auth
                            .oidc
                            .introspection_client_secret
                            .clone()
                            .unwrap_or_default(),
                        config.auth.oidc.introspection_auth_method.into(),
                    );
                    let cache = vela_api::auth::oidc::IntrospectionCache::new(
                        vela_api::auth::oidc::DEFAULT_CACHE_TTL,
                    );
                    Arc::new(vela_api::auth::oidc::IntrospectionState { client, cache })
                });

        // Host services backing the capabilities. The emitter's AppState is
        // wired in after the struct exists (below); the kv store needs only the
        // db. Both injected into the runtime so granted plugins can use them.
        let event_emitter = vela_api::extensions::ApiEventEmitter::new();
        let kv_store = vela_api::extensions::ApiKvStore::new(db.clone());
        let host_services = vela_extensions::HostServices {
            emitter: Some(event_emitter.clone() as std::sync::Arc<dyn vela_extensions::EventEmitter>),
            kv: Some(kv_store.clone() as std::sync::Arc<dyn vela_extensions::KvStore>),
        };
        let extensions = Arc::new(arc_swap::ArcSwap::from_pointee(build_extension_runtime(
            &config.extensions,
            host_services.clone(),
        )?));
        let observe_queue = vela_api::extensions::ObserveQueue::new(&db);

        // SIGHUP → re-read [extensions] from the config file and atomically swap
        // the plugin set in. A bad new config (missing file, invalid component)
        // is logged and the current set is kept — a reload must never disarm
        // moderation. Unix only; other platforms restart to reload.
        #[cfg(unix)]
        {
            let extensions = extensions.clone();
            let config_path = config_path.clone();
            let reload_services = host_services.clone();
            tokio::spawn(async move {
                let mut hup = match tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::hangup(),
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to install SIGHUP handler; extension hot-reload disabled");
                        return;
                    }
                };
                while hup.recv().await.is_some() {
                    match reload_extension_runtime(&config_path, reload_services.clone()) {
                        Ok((runtime, count)) => {
                            extensions.store(Arc::new(runtime));
                            info!(plugins = count, "reloaded extensions on SIGHUP");
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "extension reload failed; keeping the current plugin set");
                        }
                    }
                }
            });
        }

        let state = AppState {
            db: db.clone(),
            config: Arc::new(ServerConfig {
                server_name: config.server.name.clone(),
                bind_host: config.server.bind.clone(),
                bind_port: config.server.port,
                public_base_url: config.server.public_base_url.clone(),
                search_all_users: config.user_directory.search_all_users,
                federation_enabled: config.federation.enabled,
                registration_enabled: config.registration.enabled,
                registration_token: config.registration.token.clone(),
                max_upload_size: parse_size(&config.media.max_upload_size)?,
                encrypt_by_default: parse_encrypt_policy(&config.room_defaults.encrypt_by_default)?,
                allow_public_rooms_over_federation: config
                    .directory
                    .allow_public_rooms_over_federation,
                user_directory_federate: config.user_directory.federate,
                minimum_room_version: parse_minimum_room_version(
                    &config.server.minimum_room_version,
                )?,
                voip: vela_api::router::VoipConfig {
                    uris: config.voip.uris.clone(),
                    shared_secret: config.voip.shared_secret.clone(),
                    ttl_seconds: if config.voip.ttl == 0 {
                        24 * 60 * 60
                    } else {
                        config.voip.ttl
                    },
                },
                rtc: vela_api::router::RtcConfig {
                    sfu_url: config.rtc.sfu_url.clone(),
                    livekit_api_key: config.rtc.livekit_api_key.clone(),
                    livekit_secret: config.rtc.livekit_secret.clone(),
                    jwt_ttl_seconds: if config.rtc.jwt_ttl == 0 {
                        6 * 60 * 60
                    } else {
                        config.rtc.jwt_ttl
                    },
                },
                oidc: vela_api::router::OidcConfig {
                    enabled: config.auth.oidc.enabled,
                    issuer: config.auth.oidc.issuer.clone(),
                    client_id: config.auth.oidc.client_id.clone(),
                    account_management_url: config.auth.oidc.account_management_url.clone(),
                    introspection_endpoint: config.auth.oidc.introspection_endpoint.clone(),
                    introspection_client_id: config.auth.oidc.introspection_client_id.clone(),
                    introspection_client_secret: config
                        .auth
                        .oidc
                        .introspection_client_secret
                        .clone(),
                    introspection_auth_method: config.auth.oidc.introspection_auth_method.into(),
                },
                admin_bot_localpart: if config.admin.bot_localpart.trim().is_empty() {
                    vela_api::admin::DEFAULT_BOT_LOCALPART.to_string()
                } else {
                    config.admin.bot_localpart.trim().to_string()
                },
                presence: vela_api::router::PresenceConfig {
                    idle_after_ms: parse_duration(&config.presence.idle_after)?.as_millis() as u64,
                    offline_after_ms: parse_duration(&config.presence.offline_after)?.as_millis()
                        as u64,
                    sweep_interval_ms: parse_duration(&config.presence.sweep_interval)?.as_millis()
                        as u64,
                },
                push: vela_api::router::PushConfig {
                    allow_private_pushers: config.push.allow_private_pushers,
                },
                support: vela_api::router::SupportConfig {
                    contacts: config
                        .support
                        .contacts
                        .iter()
                        .map(|c| vela_api::router::SupportContact {
                            matrix_id: c.matrix_id.clone(),
                            email_address: c.email_address.clone(),
                            role: c.role.clone(),
                        })
                        .collect(),
                    support_page: config.support.support_page.clone(),
                },
                max_delay_ms: config.server.max_delay_ms,
            }),
            room_locks: Arc::new(DashMap::new()),
            user_locks: Arc::new(DashMap::new()),
            key_backup_user_locks: Arc::new(DashMap::new()),
            room_senders: Arc::new(DashMap::new()),
            typing_state: Arc::new(DashMap::new()),
            typing_change_pos: Arc::new(DashMap::new()),
            last_gap_fill_pos: Arc::new(DashMap::new()),
            typing_stream,
            media_store: media_store.clone(),
            signing_key,
            remote_keys,
            federation_sender,
            federation_client,
            oidc_introspection,
            partial_state_filler: Arc::new(
                vela_api::federation::partial_state_filler::PartialStateFiller::new(),
            ),
            event_relationships_unsigned_cache: Arc::new(DashMap::new()),
            delayed_events: vela_api::delayed_events::new_store(),
            delayed_events_scheduler_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            sliding_sync_cache: Arc::new(vela_api::sync::sliding_sync::SlidingSyncCache::new()),
            appservice_registry,
            appservice_outbox,
            uia_sessions: vela_api::auth::uia::new_sessions(),
            user_senders: Arc::new(DashMap::new()),
            metrics_renderer: metrics_renderer.clone(),
            rate_limiter: if config.rate_limit.enabled {
                vela_api::rate_limit::RateLimiter::defaults()
            } else {
                info!("rate_limit: disabled by config");
                vela_api::rate_limit::RateLimiter::disabled()
            },
            // Captured before listeners bind so the /_health endpoint
            // reports "process up since" rather than "first request
            // received at." Both fields share the same instant.
            started_at: Arc::new(Instant::now()),
            started_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            extensions,
            observe_queue,
        };

        // Wire AppState into the emit service now that it exists (the runtime
        // already holds the emitter; this completes the loop so emit-granted
        // plugins can drive the send path). This forms an intentional Arc cycle
        // (emitter → AppState → runtime → emitter) that lives for the process —
        // AppState never tears down — so it's a one-time allocation, not a leak;
        // don't "fix" it with a Weak.
        event_emitter.set_state(state.clone());

        // Admin bot + admin room bootstrap. Idempotent: creates the
        // bot user + private "Admins" room on first boot, no-ops on
        // subsequent boots. Also seeds the static `[registration]
        // token` into the dynamic-tokens CF when no admin exists yet,
        // so the same lookup path covers bootstrap and post-bootstrap.
        // See `vela_api::admin` for the full design.
        if let Err(e) = vela_api::admin::bootstrap(&state).await {
            anyhow::bail!("admin bootstrap failed: {:?}", e.0);
        }

        // Presence auto-decay sweeper. Persists transitions from
        // `online → unavailable → offline` based on idle time and
        // broadcasts the federation EDU. Local /sync responses already
        // compute the effective presence at read time; the sweeper
        // closes the gap for federation peers and the stored CF.
        // Always on — there's no useful "off" mode (would mean stale
        // presence survives forever, which is the bug this fixes).
        let _presence_sweeper_handle = vela_api::presence::presence_sweeper::spawn(state.clone());

        // Extension async observation worker. Drains the durable observation
        // queue and runs every `on_event`-bound plugin off the request path.
        // Always running (cheap when idle), so a SIGHUP that adds an on_event
        // plugin starts being observed without a restart.
        let _observe_worker_handle = state
            .observe_queue
            .spawn_worker(db.clone(), state.extensions.clone());

        // Extension kv TTL sweeper: periodically reap expired kv entries — the
        // routine space manager for the `kv` capability (so a plugin's
        // short-lived counters/dedup markers don't accumulate). Cheap; runs even
        // when no plugin uses kv (then it sweeps an empty CF).
        {
            let kv_store = kv_store.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
                ticker.tick().await; // the first tick fires immediately — skip it
                loop {
                    ticker.tick().await;
                    // The sweep does blocking RocksDB scans — run it off the
                    // async runtime, like the observation worker.
                    let kv = kv_store.clone();
                    let reaped = tokio::task::spawn_blocking(move || kv.sweep())
                        .await
                        .unwrap_or(0);
                    if reaped > 0 {
                        tracing::debug!(reaped, "extensions: kv sweep reaped expired entries");
                    }
                }
            });
        }

        // Start per-AS outbound delivery workers for every persisted
        // registration. Workers exit cleanly when their AS is
        // unregistered; deliveries that need the cleartext hs_token
        // (which lives only in process memory) wait until the
        // operator re-pastes via `!as register`.
        state.appservice_outbox.start_all();

        // MSC3706 partial-state filler. Cheap no-op if no rooms are
        // flagged partial.
        vela_api::federation::partial_state_filler::ensure_running(&state);

        // MSC4140 delayed events scheduler. Rehydrates the in-memory
        // queue from the `delayed_events` CF and ticks every 100ms.
        vela_api::delayed_events::boot(&state);

        let app = vela_api::router::build_router(state);

        // Periodic backup task. No-op when [backup] enabled = false.
        // The handle is intentionally dropped: we don't need a clean
        // shutdown for the backup loop — if a backup is mid-upload
        // when SIGTERM arrives, the in-progress one is abandoned and
        // the next process picks up at the next interval. No harm
        // beyond a single missed cycle.
        if config.backup.enabled {
            let backup_cfg = backup::BackupConfig {
                enabled: true,
                interval: parse_duration(&config.backup.interval)?,
                target: config.backup.target.clone(),
                keep: config.backup.keep,
                s3: config.backup.s3.as_ref().map(|s| backup::S3BackupConfig {
                    region: s.region.clone(),
                    endpoint: s.endpoint.clone(),
                    access_key_id: s.access_key_id.clone(),
                    secret_access_key: s.secret_access_key.clone(),
                    allow_http: s.allow_http,
                }),
            };
            let _backup_handle = backup::spawn_backup_task(db.clone(), backup_cfg);
        }

        // Retention sweeper. Same shape as the backup task: in-process
        // tokio loop, interval-driven, off by default.
        if config.retention.enabled {
            let retention_cfg = retention::RetentionConfig {
                enabled: true,
                interval: parse_duration(&config.retention.interval)?,
                local_media_lifetime: retention::parse_lifetime(
                    &config.retention.media.local_lifetime,
                )?,
                remote_media_lifetime: retention::parse_lifetime(
                    &config.retention.media.remote_lifetime,
                )?,
                server_name: config.server.name.clone(),
            };
            let _retention_handle =
                retention::spawn_retention_task(db.clone(), media_store.clone(), retention_cfg);
        }

        // Plain HTTP listener (CS-API, and federation fallback when TLS is disabled)
        let http_addr: SocketAddr = format!("{}:{}", config.server.bind, config.server.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid bind address: {e}"))?;
        let http_listener = tokio::net::TcpListener::bind(&http_addr).await?;
        info!(addr = %http_addr, "listening plain HTTP");

        // Optional TLS listener (federation — spec-required). Holds an
        // `axum_server::Handle` so we can ask it to drain in-flight
        // connections on signal.
        let (tls_handle, tls_task) = if let Some(tls_cfg) = &config.server.tls {
            let tls_addr: SocketAddr =
                format!("{}:{}", config.server.bind, tls_cfg.port)
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid TLS bind address: {e}"))?;
            info!(
                addr = %tls_addr,
                cert = ?tls_cfg.cert_file,
                "listening HTTPS"
            );
            let rustls_cfg = RustlsConfig::from_pem_file(&tls_cfg.cert_file, &tls_cfg.key_file)
                .await
                .map_err(|e| anyhow::anyhow!("TLS cert/key load failed: {e}"))?;
            let handle = axum_server::Handle::new();
            let app_tls = app.clone();
            let handle_for_task = handle.clone();
            let task = tokio::spawn(async move {
                axum_server::bind_rustls(tls_addr, rustls_cfg)
                    .handle(handle_for_task)
                    .serve(app_tls.into_make_service_with_connect_info::<SocketAddr>())
                    .await
            });
            (Some(handle), Some(task))
        } else {
            (None, None)
        };

        // axum's `with_graceful_shutdown` takes a future that resolves
        // when shutdown should start. We wait for the signal here, then
        // also tell the TLS server to drain (its own future is bound to
        // an internal channel, not ours).
        let tls_handle_for_signal = tls_handle.clone();
        let http_done = axum::serve(
            http_listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            if let Some(h) = tls_handle_for_signal {
                h.graceful_shutdown(Some(Duration::from_secs(30)));
            }
        });

        http_done.await?;

        if let Some(task) = tls_task {
            // graceful_shutdown was already requested above. Await with
            // a hard cap so a stuck connection can't keep us up forever.
            let _ = tokio::time::timeout(Duration::from_secs(35), task).await;
        }

        info!("shutdown complete");
        Ok::<(), anyhow::Error>(())
    })
}

/// Read every `*.yaml` in `dir` and register the parsed AS with the
/// in-memory registry. Used by the Complement entrypoint (and any
/// operator workflow that drops registration files at a known path).
/// Failures per-file are logged and skipped — a malformed file
/// shouldn't crash the server. Duplicates are silently no-op'd via
/// the `DuplicateId` error path so reboots are idempotent.
fn preload_appservice_dir(dir: &str, registry: &vela_api::appservice::AsRegistry) {
    let path = std::path::Path::new(dir);
    let entries = match std::fs::read_dir(path) {
        Ok(e) => e,
        Err(e) => {
            warn!(%dir, error = %e, "appservice.registration_dir not readable; skipping preload");
            return;
        }
    };
    let mut loaded = 0usize;
    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        let yaml = match std::fs::read_to_string(&p) {
            Ok(s) => s,
            Err(e) => {
                warn!(file = %p.display(), error = %e, "appservice yaml read failed");
                continue;
            }
        };
        let parsed = match vela_api::appservice::registration::parse(&yaml) {
            Ok(p) => p,
            Err(e) => {
                warn!(file = %p.display(), error = %e, "appservice yaml parse failed");
                continue;
            }
        };
        let id = parsed.appservice.id.clone();
        match registry.register(parsed.appservice) {
            Ok(_) => {
                info!(file = %p.display(), %id, "appservice preloaded");
                loaded += 1;
            }
            Err(vela_api::appservice::RegistryError::DuplicateId(_)) => {
                // Already registered (re-boot of a persisted registry).
                // No-op so the entrypoint can pass the same dir on every
                // start without operator intervention.
            }
            Err(e) => warn!(file = %p.display(), error = %e, "appservice register failed"),
        }
    }
    if loaded > 0 {
        info!(%dir, count = loaded, "appservice preload complete");
    }
}

/// Wait for either SIGINT (Ctrl+C, dev) or SIGTERM (Docker / k8s /
/// systemd, production). Both are graceful-stop signals; we treat them
/// identically. SIGKILL bypasses this entirely — the OS terminates the
/// process and RocksDB recovers from its WAL on next start.
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("received SIGINT, shutting down"),
        _ = term.recv() => info!("received SIGTERM, shutting down"),
    }
}

/// Install the compile-time-selected metrics exporter, if any. Returns
/// the renderer closure the `/_vela/metrics` HTTP handler will call.
/// `None` means "no exporter compiled in"; `/_vela/metrics` will return
/// 503 and `metrics::` macros across the codebase stay no-ops.
/// Stand-in for the OTLP shutdown handle when the feature isn't
/// compiled in. Holding a value of this type is a no-op; the binding
/// in `main` exists only so the code paths look identical with and
/// without `--features otel`.
#[cfg(not(feature = "otel"))]
struct OtelGuard;

/// Initialise the global tracing subscriber. Always wires the `fmt`
/// layer (matching today's stderr-formatted output). When the `otel`
/// feature is enabled AND `[tracing] otlp_endpoint` is set, also
/// bridges spans into an OpenTelemetry tracer that exports via OTLP
/// over gRPC. Returns a guard whose Drop flushes pending spans — bind
/// it in `main` for the program lifetime, drop on shutdown.
#[cfg(feature = "otel")]
fn init_tracing(cfg: &TracingSection) -> Option<OtelShutdownGuard> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,vela=debug".parse().unwrap());
    let fmt_layer = tracing_subscriber::fmt::layer();

    let endpoint = cfg
        .otlp_endpoint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let Some(endpoint) = endpoint else {
        // otel compiled in but operator didn't set an endpoint —
        // fall back to fmt-only.
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
        info!("tracing: otel feature on, no otlp_endpoint configured (fmt only)");
        return None;
    };

    // Install the W3C trace-context propagator globally so vela-api's
    // inject/extract helpers (used in signed_request and the federation
    // auth middleware) round-trip the `traceparent` header.
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    // Provider construction lives in vela-api so the OTLP export path is
    // covered by an integration test (vela-api/tests/otlp_export.rs).
    let provider = vela_api::otel::build_tracer_provider(endpoint);
    opentelemetry::global::set_tracer_provider(provider.clone());
    let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, "vela");
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();
    info!(%endpoint, "tracing: OTLP exporter installed");

    Some(OtelShutdownGuard { provider })
}

#[cfg(not(feature = "otel"))]
fn init_tracing(_cfg: &TracingSection) -> Option<OtelGuard> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,vela=debug".parse().unwrap()),
        )
        .init();
    None
}

/// Held in `main` while the program runs; on Drop, flushes the OTLP
/// batch exporter so spans queued at shutdown make it to the
/// collector.
#[cfg(feature = "otel")]
struct OtelShutdownGuard {
    provider: opentelemetry_sdk::trace::SdkTracerProvider,
}

#[cfg(feature = "otel")]
impl Drop for OtelShutdownGuard {
    fn drop(&mut self) {
        // Best-effort: shutdown returns Result but there's nothing
        // useful we can do about a flush failure on process exit.
        let _ = self.provider.shutdown();
    }
}

#[cfg(feature = "prometheus")]
fn install_metrics_recorder() -> Option<vela_api::metrics::MetricsRenderer> {
    use std::sync::Arc;
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("prometheus recorder installed");
    info!("metrics: prometheus recorder installed");
    Some(Arc::new(move || handle.render()))
}

#[cfg(not(feature = "prometheus"))]
fn install_metrics_recorder() -> Option<vela_api::metrics::MetricsRenderer> {
    info!("metrics: no exporter compiled in (use --features prometheus to enable)");
    None
}

/// Load the TOML config file plus `VELA_` environment overrides.
/// A parse error (unknown field, type mismatch, malformed TOML) is
/// surfaced to stderr and the process exits 1 — previously these
/// errors were silently swallowed and the binary booted with full
/// defaults, leaving operators wondering why `server.bind = "..."`
/// didn't take effect. Missing file remains a soft default: figment's
/// `Toml::file()` is best-effort on absence, so a server with no
/// config file boots on `0.0.0.0:8008` as before.
fn load_config(path: &std::path::Path) -> Config {
    Figment::new()
        .merge(Toml::file(path))
        .merge(Env::prefixed("VELA_").split("_"))
        .extract()
        .unwrap_or_else(|e| {
            eprintln!("error: failed to parse {}: {e}", path.display());
            eprintln!("hint: run with `--validate-config` to inspect parser output");
            std::process::exit(1);
        })
}

/// Run the field-level parsers (size, duration, retention lifetime)
/// against the parsed config so syntax errors get caught at validation
/// time rather than at startup. `validate_config` only checks
/// inter-field invariants; this function exercises the parsers we use
/// later in `main` so a bad `"50MBz"` or `"24hh"` is surfaced now.
fn validate_runtime_parsable(config: &Config) -> anyhow::Result<()> {
    parse_size(&config.media.max_upload_size)
        .map_err(|e| anyhow::anyhow!("[media] max_upload_size: {e}"))?;
    if config.backup.enabled {
        parse_duration(&config.backup.interval)
            .map_err(|e| anyhow::anyhow!("[backup] interval: {e}"))?;
    }
    if config.retention.enabled {
        parse_duration(&config.retention.interval)
            .map_err(|e| anyhow::anyhow!("[retention] interval: {e}"))?;
        retention::parse_lifetime(&config.retention.media.local_lifetime)
            .map_err(|e| anyhow::anyhow!("[retention.media] local_lifetime: {e}"))?;
        retention::parse_lifetime(&config.retention.media.remote_lifetime)
            .map_err(|e| anyhow::anyhow!("[retention.media] remote_lifetime: {e}"))?;
    }
    Ok(())
}

/// Operator-facing summary printed when `--validate-config` succeeds.
/// Stays small and stable so ops scripts can grep it. We deliberately
/// don't print secrets (registration token, S3 keys) — the field is
/// either present or absent, not its value.
fn print_config_summary(path: &std::path::Path, config: &Config) {
    println!("config OK: {}", path.display());
    println!("  server.name             = {}", config.server.name);
    println!(
        "  server.bind             = {}:{}",
        config.server.bind, config.server.port
    );
    if let Some(tls) = &config.server.tls {
        println!(
            "  server.tls              = port {} cert {}",
            tls.port,
            tls.cert_file.display()
        );
    } else {
        println!("  server.tls              = disabled");
    }
    println!("  database.path           = {}", config.database.path);
    println!("  federation.enabled      = {}", config.federation.enabled);
    println!(
        "  registration.enabled    = {} (token: {})",
        config.registration.enabled,
        if config.registration.token.is_some() {
            "set"
        } else {
            "unset"
        }
    );
    println!("  media.backend           = {}", config.media.backend);
    println!(
        "  media.max_upload_size   = {} ({} bytes)",
        config.media.max_upload_size,
        parse_size(&config.media.max_upload_size).unwrap_or(0)
    );
    println!("  backup.enabled          = {}", config.backup.enabled);
    println!("  retention.enabled       = {}", config.retention.enabled);
    println!("  rate_limit.enabled      = {}", config.rate_limit.enabled);
    println!("  auth.oidc.enabled       = {}", config.auth.oidc.enabled);
}

/// Validate config before we touch the database. Failures here return
/// early with a human-readable error so operators see the problem in
/// systemd/journalctl without having to grep stack traces. Only checks
/// things we can cheaply verify up front — the DB open itself catches
/// permission / path errors.
fn validate_config(config: &Config) -> anyhow::Result<()> {
    // server.name: non-empty, no whitespace. Matrix's formal grammar
    // is stricter but we don't need to re-implement it here — this
    // catches the common fat-finger cases.
    let name = &config.server.name;
    if name.is_empty() {
        anyhow::bail!("config: [server] name must be set");
    }
    if name.chars().any(|c| c.is_whitespace()) {
        anyhow::bail!("config: [server] name contains whitespace: {name:?}");
    }
    // TLS: if declared, cert and key files must actually exist on
    // disk. Loading them happens later under tokio; early-fail gives a
    // clearer signal.
    if let Some(tls) = &config.server.tls {
        if !tls.cert_file.exists() {
            anyhow::bail!(
                "config: [server.tls] cert_file does not exist: {}",
                tls.cert_file.display()
            );
        }
        if !tls.key_file.exists() {
            anyhow::bail!(
                "config: [server.tls] key_file does not exist: {}",
                tls.key_file.display()
            );
        }
    }
    // Extra CA certs: same early-existence check, same reasoning.
    for path in &config.server.extra_ca_certs {
        if !path.exists() {
            anyhow::bail!(
                "config: [server] extra_ca_certs entry does not exist: {}",
                path.display()
            );
        }
    }
    // Federation http_peers: each URL must parse as http(s)://. This
    // is a config-level typo catcher; the actual request will still
    // fail loudly at federation time if the remote is unreachable.
    for (peer, url) in &config.federation.http_peers {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            anyhow::bail!(
                "config: [federation] http_peers[{peer}] must start with http:// or https:// (got {url:?})"
            );
        }
    }
    // OIDC discovery: when delegation is on the issuer URL is what
    // clients consume verbatim. An empty value would let `/auth_issuer`
    // serve `{"issuer": ""}`, which is worse than 404 — Element X would
    // try to talk to an unresolvable IdP. Fail early instead.
    if config.auth.oidc.enabled && config.auth.oidc.issuer.trim().is_empty() {
        anyhow::bail!("config: [auth.oidc] issuer must be set when enabled = true");
    }
    // Phase 2 validity: if introspection_endpoint is set, both client
    // credentials must be set too. Otherwise the operator would boot a
    // server that 401s every IdP-authenticated request silently.
    if config.auth.oidc.introspection_endpoint.is_some() {
        if !config.auth.oidc.enabled {
            anyhow::bail!(
                "config: [auth.oidc] introspection_endpoint set but enabled = false; \
                 set enabled = true or remove the endpoint"
            );
        }
        let has_id = config
            .auth
            .oidc
            .introspection_client_id
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty());
        let has_secret = config
            .auth
            .oidc
            .introspection_client_secret
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty());
        if !has_id || !has_secret {
            anyhow::bail!(
                "config: [auth.oidc] introspection_endpoint requires \
                 introspection_client_id + introspection_client_secret"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod validate_config_tests {
    use super::*;

    /// `validate_runtime_parsable` accepts a default config (the same
    /// shape `Config::default()` produces — `"50MB"`, `"24h"`, etc.).
    /// This is the smoke-test path `vela --validate-config` exercises
    /// against a freshly-stamped TOML.
    #[test]
    fn default_config_passes_runtime_parsers() {
        let cfg = Config::default();
        validate_runtime_parsable(&cfg).expect("default must parse");
    }

    /// A garbage `max_upload_size` is the canonical "operator typo"
    /// case — it's parsed cheaply but only at startup, not at TOML
    /// parse time. `--validate-config` should surface it now, with a
    /// human-readable error pointing at the field.
    #[test]
    fn rejects_malformed_max_upload_size() {
        let mut cfg = Config::default();
        cfg.media.max_upload_size = "not-a-size".to_string();
        let err = validate_runtime_parsable(&cfg).unwrap_err();
        assert!(
            err.to_string().contains("max_upload_size"),
            "error should name the offending field: {err}"
        );
    }

    /// Retention parsers are skipped when `retention.enabled = false`
    /// (consistent with how `main` only calls them under the same
    /// gate). A malformed lifetime in a disabled section is fine: an
    /// operator who flips the gate on later will see the error then.
    #[test]
    fn skips_disabled_retention_parsers() {
        let mut cfg = Config::default();
        cfg.retention.enabled = false;
        cfg.retention.media.local_lifetime = "garbage".to_string();
        validate_runtime_parsable(&cfg).expect("disabled retention shouldn't parse lifetimes");
    }

    /// Conversely, a malformed lifetime IS caught when retention is
    /// enabled. Mirrors the gate `main` uses to actually call the
    /// parsers.
    #[test]
    fn rejects_malformed_lifetime_when_retention_enabled() {
        let mut cfg = Config::default();
        cfg.retention.enabled = true;
        cfg.retention.media.local_lifetime = "garbage".to_string();
        let err = validate_runtime_parsable(&cfg).unwrap_err();
        assert!(
            err.to_string().contains("local_lifetime"),
            "error should name the offending field: {err}"
        );
    }

    /// `validate_config` is the inter-field invariant check. Empty
    /// server.name is the canonical fat-finger that `Config::default()`
    /// avoids but a stripped-down operator TOML can hit.
    #[test]
    fn validate_config_rejects_empty_server_name() {
        let mut cfg = Config::default();
        cfg.server.name = String::new();
        assert!(validate_config(&cfg).is_err());
    }

    /// Phase 2: introspection_endpoint without credentials is a boot
    /// error — otherwise the operator gets silent 401s on every
    /// IdP-authenticated request.
    #[test]
    fn validate_config_rejects_introspection_endpoint_without_credentials() {
        let mut cfg = Config::default();
        cfg.auth.oidc.enabled = true;
        cfg.auth.oidc.issuer = "https://idp.example.com".into();
        cfg.auth.oidc.introspection_endpoint =
            Some("https://idp.example.com/oauth2/introspect".into());
        // client_id + client_secret intentionally missing.
        let err = validate_config(&cfg).unwrap_err();
        assert!(
            err.to_string().contains("introspection_client_id"),
            "error should name the missing field: {err}",
        );
    }

    /// `introspection_endpoint` without `enabled = true` is an
    /// operator misconfiguration — Phase 2 implies Phase 1.
    #[test]
    fn validate_config_rejects_introspection_endpoint_without_enabled() {
        let mut cfg = Config::default();
        cfg.auth.oidc.enabled = false;
        cfg.auth.oidc.introspection_endpoint =
            Some("https://idp.example.com/oauth2/introspect".into());
        cfg.auth.oidc.introspection_client_id = Some("vela".into());
        cfg.auth.oidc.introspection_client_secret = Some("secret".into());
        assert!(validate_config(&cfg).is_err());
    }

    /// Phase 1 alone (discovery, no introspection) keeps working:
    /// `enabled = true` + `issuer` set is the legacy posture.
    #[test]
    fn validate_config_accepts_phase1_only() {
        let mut cfg = Config::default();
        cfg.auth.oidc.enabled = true;
        cfg.auth.oidc.issuer = "https://idp.example.com".into();
        validate_config(&cfg).expect("phase 1 alone must validate");
    }

    /// Phase 2 with full credentials validates cleanly.
    #[test]
    fn validate_config_accepts_phase2_with_credentials() {
        let mut cfg = Config::default();
        cfg.auth.oidc.enabled = true;
        cfg.auth.oidc.issuer = "https://idp.example.com".into();
        cfg.auth.oidc.introspection_endpoint =
            Some("https://idp.example.com/oauth2/introspect".into());
        cfg.auth.oidc.introspection_client_id = Some("vela".into());
        cfg.auth.oidc.introspection_client_secret = Some("secret".into());
        validate_config(&cfg).expect("phase 2 with credentials must validate");
    }
}
