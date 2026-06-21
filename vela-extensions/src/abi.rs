//! Host-facing types for the extension contract. These are plain Rust types
//! with no runtime dependency, so they compile whether or not the
//! `wasmtime-runtime` feature is on. The gated runtime module converts between
//! these and the Component-Model bindings generated from `wit/extension.wit`.
//!
//! The wire contract itself lives in `wit/extension.wit` and is versioned by
//! the WIT package version — there is no hand-rolled ABI version here.

use serde_json::Value;

/// Where an event originated. A [`Verdict::Block`] is a hard reject for
/// [`Origin::Local`] (we refuse to originate the event) but MUST be a soft-fail
/// for [`Origin::Federation`] — rejecting an event peers accepted would hole our
/// DAG. PR1 only dispatches local sends; the field exists so the contract is
/// stable and the runtime is origin-aware from the start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Local,
    Federation,
}

/// The per-event data the host shares across all interested plugins at a
/// decision point. Borrowed so the hot path can serialize the event once and
/// lend it to every plugin without copying.
pub struct EventContext<'a> {
    /// The full event as a JSON value; serialized to canonical JSON when handed
    /// to a plugin.
    pub event: &'a Value,
    pub room_id: &'a str,
    pub sender: &'a str,
    pub event_type: &'a str,
    pub origin: Origin,
}

/// The signup metadata the host hands the runtime at the registration decision
/// point, before the account is created. Borrowed, like [`EventContext`]. The
/// host supplies BOTH IP forms it knows; each plugin is shown only the one its
/// `client_ip` tier permits (none / hashed / full), so the per-plugin privacy
/// choice is applied at marshal time.
pub struct RegistrationContext<'a> {
    /// Requested localpart, e.g. `"alice"`.
    pub username: &'a str,
    /// Registration method: `"open"`, `"token"`, `"oidc"`, `"guest"`,
    /// `"appservice"`.
    pub kind: &'a str,
    /// The raw client IP, if the host has it. Shown only to `full`-tier plugins.
    pub client_ip_full: Option<&'a str>,
    /// A non-reversible HMAC of the IP (a rate-limit key, no PII), if computed.
    /// Shown to `hashed`-tier plugins.
    pub client_ip_hashed: Option<&'a str>,
}

/// The media-upload metadata the host hands a plugin, after the bytes are stored
/// but before the upload is downloadable. v1 carries no raw content — the upload
/// streams, so only an in-stream hash + metadata are available. Borrowed.
pub struct MediaContext<'a> {
    /// Client-declared MIME type.
    pub content_type: &'a str,
    /// Original filename, or empty.
    pub filename: &'a str,
    /// Size in bytes.
    pub size: u64,
    /// The uploading user's id.
    pub uploader: &'a str,
    /// Lowercase hex SHA-256 of the content.
    pub sha256: &'a str,
}

/// Which profile field a user is setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileField {
    DisplayName,
    AvatarUrl,
}

/// A user setting their own display name or avatar, handed to a plugin before the
/// change is persisted or propagated. Borrowed.
pub struct ProfileUpdate<'a> {
    /// The user changing their own profile.
    pub user_id: &'a str,
    /// Which field is being set.
    pub field: ProfileField,
    /// The proposed new value; `None` means the user is clearing the field. For
    /// `AvatarUrl` this is the mxc:// URI, not the image.
    pub value: Option<&'a str>,
}

/// A user creating a room, handed to a plugin before anything is persisted.
/// Borrowed.
pub struct RoomCreate<'a> {
    /// The creating user, `@user:server`.
    pub creator: &'a str,
    /// The room id the server derived for this creation.
    pub room_id: &'a str,
    pub room_version: &'a str,
    /// Resolved preset: `public_chat` / `private_chat` / `trusted_private_chat`.
    pub preset: &'a str,
    /// Requested directory visibility (`public` / `private`), or `None`.
    pub visibility: Option<&'a str>,
    pub name: Option<&'a str>,
    pub topic: Option<&'a str>,
    /// Requested alias localpart (e.g. `foo` for `#foo:server`), or `None`.
    pub alias_localpart: Option<&'a str>,
    /// Users invited at creation time.
    pub invite: &'a [String],
    pub is_direct: bool,
}

/// The login metadata the host hands a plugin at `/login`, before the password is
/// verified. Mirrors [`RegistrationContext`] (same privacy-tiered IP). Borrowed.
pub struct LoginContext<'a> {
    /// The requested username/localpart (may not exist).
    pub username: &'a str,
    /// The login type, e.g. `"m.login.password"`.
    pub login_type: &'a str,
    /// The raw client IP, if the host has it. Shown only to `full`-tier plugins.
    pub client_ip_full: Option<&'a str>,
    /// A non-reversible HMAC of the IP (a rate-limit key, no PII), if computed.
    /// Shown to `hashed`-tier plugins.
    pub client_ip_hashed: Option<&'a str>,
}

/// A timeline event being considered for one viewer's `/sync`, handed to a
/// read-path filter plugin. Borrowed. `event` is canonical JSON.
pub struct SyncEvent<'a> {
    /// The user doing the `/sync` — whose visibility is being decided.
    pub viewer: &'a str,
    pub room_id: &'a str,
    /// Canonical JSON of the event.
    pub event: &'a str,
    /// The event's `type`, e.g. `m.room.message`.
    pub event_type: &'a str,
    pub sender: &'a str,
}

/// What a plugin returns from a decision point. Converted from the generated
/// Component-Model `verdict` variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block { errcode: String, reason: String },
}

impl Verdict {
    /// The default block when a plugin blocks without naming an errcode.
    pub fn forbidden(reason: impl Into<String>) -> Self {
        Verdict::Block {
            errcode: "M_FORBIDDEN".to_string(),
            reason: reason.into(),
        }
    }
}
