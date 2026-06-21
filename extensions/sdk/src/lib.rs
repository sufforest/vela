//! SDK for writing sandboxed WASM extensions for the [vela](https://github.com/sufforest/vela)
//! Matrix homeserver.
//!
//! Implement [`Plugin`] for your type, return a [`Decision`], and export it with
//! [`export_plugin!`]. Build to a `wasm32-unknown-unknown` cdylib and
//! componentize with `wasm-tools component new`; an operator then loads the
//! resulting `.wasm` via `[[extensions.plugin]]` in `vela.toml`.
//!
//! ```ignore
//! use vela_extension_sdk::{export_plugin, Decision, Event, Plugin};
//!
//! struct Hello;
//! impl Plugin for Hello {
//!     fn check_event(ev: &Event) -> Decision {
//!         match ev.message_body() {
//!             Some(b) if b.contains("spam") => Decision::block("no spam"),
//!             _ => Decision::allow(),
//!         }
//!     }
//! }
//! export_plugin!(Hello);
//! ```

use serde::de::DeserializeOwned;
use serde_json::Value;

/// Generated Component-Model bindings from the WIT. The WIT is vendored under
/// `wit/` so the crate is self-contained and publishable; a test in
/// `vela-extensions` asserts it stays byte-identical to the host's canonical
/// copy, so the contract can't drift. Hidden: callers use the ergonomic surface
/// below; only [`export_plugin!`] reaches in here.
#[doc(hidden)]
pub mod bindings {
    wit_bindgen::generate!({
        path: "wit/extension.wit",
        world: "plugin",
        pub_export_macro: true,
    });
}

/// Where an event originated. A [`Decision::Block`] on a [`Origin::Federation`]
/// event is soft-failed by the host (never hard-rejected) — your plugin just
/// reports a verdict; the host applies origin policy.
pub use bindings::exports::vela::extension::decision::Origin;

/// What a plugin returns from a decision point. `#[non_exhaustive]` so future
/// verdicts (e.g. redact/quarantine) can be added without a breaking change —
/// construct via the methods below, not a literal.
#[non_exhaustive]
pub enum Decision {
    /// Permit the event.
    Allow,
    /// Reject it (for a local send, the client sees this as an error).
    Block { errcode: String, reason: String },
}

impl Decision {
    /// Allow the event.
    pub fn allow() -> Self {
        Decision::Allow
    }

    /// Block with the default `M_FORBIDDEN` errcode and the given reason.
    pub fn block(reason: impl Into<String>) -> Self {
        Decision::Block {
            errcode: "M_FORBIDDEN".to_string(),
            reason: reason.into(),
        }
    }

    /// Block with a custom Matrix errcode (e.g. an `IO.YOURORG.*` extension code).
    pub fn block_with(errcode: impl Into<String>, reason: impl Into<String>) -> Self {
        Decision::Block {
            errcode: errcode.into(),
            reason: reason.into(),
        }
    }
}

/// An ergonomic view over the event handed to a plugin. The raw event JSON is
/// parsed once on construction; the accessors borrow from it.
pub struct Event {
    raw: bindings::exports::vela::extension::decision::EventContext,
    event: Value,
}

impl Event {
    fn new(raw: bindings::exports::vela::extension::decision::EventContext) -> Self {
        let event = serde_json::from_str(&raw.event).unwrap_or(Value::Null);
        Event { raw, event }
    }

    /// The room the event is in.
    pub fn room_id(&self) -> &str {
        &self.raw.room_id
    }

    /// The sender's user ID.
    pub fn sender(&self) -> &str {
        &self.raw.sender
    }

    /// The event type, e.g. `"m.room.message"`.
    pub fn event_type(&self) -> &str {
        &self.raw.event_type
    }

    /// Where the event came from.
    pub fn origin(&self) -> Origin {
        self.raw.origin
    }

    /// The full event as parsed JSON (`Value::Null` if it wasn't valid JSON).
    pub fn event(&self) -> &Value {
        &self.event
    }

    /// `content.body` as a string, if present — the common case for message
    /// moderation. `None` for events without a textual body.
    pub fn message_body(&self) -> Option<&str> {
        self.event.get("content")?.get("body")?.as_str()
    }

    /// This plugin's operator-supplied config, deserialized into `T`.
    ///
    /// - **No config set** (the empty string) → `T::default()`.
    /// - **Config present but invalid** for `T` → **panics**, which traps the
    ///   call. The host resolves the trap via the plugin's `fail_policy`, so a
    ///   config typo surfaces loudly (logs/metrics) instead of silently
    ///   disarming the plugin. Derive `#[serde(deny_unknown_fields)]` on `T` to
    ///   catch mistyped keys too.
    ///
    /// Use [`Event::try_config`] to handle the malformed case yourself.
    pub fn config<T: DeserializeOwned + Default>(&self) -> T {
        if self.raw.plugin_config.is_empty() {
            return T::default();
        }
        serde_json::from_str(&self.raw.plugin_config)
            .expect("plugin config is present but invalid for the requested type")
    }

    /// This plugin's config as `T`, distinguishing the three cases the lenient
    /// [`Event::config`] collapses:
    /// - no config set → `Ok(None)`
    /// - present and valid → `Ok(Some(T))`
    /// - present but invalid → `Err`
    pub fn try_config<T: DeserializeOwned>(&self) -> Result<Option<T>, serde_json::Error> {
        if self.raw.plugin_config.is_empty() {
            return Ok(None);
        }
        serde_json::from_str(&self.raw.plugin_config).map(Some)
    }

    /// This plugin's key→value store (needs the `kv` capability) — lets a
    /// `check_event` decision be stateful (rate-limit, dedup, count). See [`Kv`].
    pub fn kv(&self) -> Kv {
        Kv::new()
    }
}

/// A handle to your plugin's private key→value store (the `kv` capability).
/// Reachable from **every** hook: the decision contexts expose it via `kv()`
/// (e.g. [`RoomCreate::kv`], [`Event::kv`]) and [`Caps`] via [`Caps::kv`], so a
/// `check_*` decision can be stateful (rate-limit, dedup, count) just like an
/// observer. Operations call the host directly and return
/// [`KvError::NotPermitted`] if the operator didn't grant `kv`. Keys are
/// namespaced to your plugin by the host — you can't read another plugin's.
#[derive(Clone, Copy)]
pub struct Kv {
    _seal: (),
}

impl Kv {
    fn new() -> Self {
        Kv { _seal: () }
    }

    /// Read a key. `None` if absent or expired. Bytes are whatever you stored.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        bindings::vela::extension::kv::get(key).map_err(KvError::from)
    }

    /// Write a key with no expiry. The host caps key/value size and enforces a
    /// per-plugin byte quota ([`KvError::QuotaExceeded`] when full).
    pub fn set(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        bindings::vela::extension::kv::set(key, value, None).map_err(KvError::from)
    }

    /// Write a key with a time-to-live in milliseconds — it disappears after
    /// `ttl_ms`. The right tool for rate-limit counters and dedup markers (they
    /// self-clean, so the store doesn't fill up).
    pub fn set_ttl(&self, key: &[u8], value: &[u8], ttl_ms: u64) -> Result<(), KvError> {
        bindings::vela::extension::kv::set(key, value, Some(ttl_ms)).map_err(KvError::from)
    }

    /// Delete a key. Idempotent.
    pub fn delete(&self, key: &[u8]) -> Result<(), KvError> {
        bindings::vela::extension::kv::delete(key).map_err(KvError::from)
    }

    /// [`get`](Self::get) + JSON-decode. `None` if absent or the stored bytes
    /// don't decode as `T` (it's your own data; treat as a cache miss).
    pub fn get_json<T: DeserializeOwned>(&self, key: &[u8]) -> Result<Option<T>, KvError> {
        Ok(self.get(key)?.and_then(|b| serde_json::from_slice(&b).ok()))
    }

    /// JSON-encode + [`set_ttl`](Self::set_ttl) (`ttl_ms = 0` → no expiry).
    pub fn set_json<T: serde::Serialize>(
        &self,
        key: &[u8],
        value: &T,
        ttl_ms: u64,
    ) -> Result<(), KvError> {
        let bytes = serde_json::to_vec(value).map_err(|_| KvError::Internal)?;
        if ttl_ms == 0 {
            self.set(key, &bytes)
        } else {
            self.set_ttl(key, &bytes, ttl_ms)
        }
    }
}

/// Host capabilities granted to a plugin — the only way for plugin code to reach
/// out of the sandbox. v1 grants **logging** (write a line to vela's log,
/// attributed to your plugin). `emit-event` and `kv` are *added here* in later
/// stages, so a plugin's [`Plugin::on_event`] signature never has to change as
/// capabilities grow. `#[non_exhaustive]` so adding methods isn't a breaking
/// change.
#[non_exhaustive]
pub struct Caps {}

impl Caps {
    /// Write an info-level line to vela's log, tagged with your plugin's name.
    /// The host truncates very long messages and rate-limits a tight log loop,
    /// so this is safe to call freely. Pure output — no events, no I/O.
    pub fn log(&self, message: impl AsRef<str>) {
        self.log_at(bindings::vela::extension::logging::LogLevel::Info, message);
    }

    /// Log at trace level.
    pub fn trace(&self, message: impl AsRef<str>) {
        self.log_at(bindings::vela::extension::logging::LogLevel::Trace, message);
    }

    /// Log at debug level.
    pub fn debug(&self, message: impl AsRef<str>) {
        self.log_at(bindings::vela::extension::logging::LogLevel::Debug, message);
    }

    /// Log at warn level.
    pub fn warn(&self, message: impl AsRef<str>) {
        self.log_at(bindings::vela::extension::logging::LogLevel::Warn, message);
    }

    /// Log at error level.
    pub fn error(&self, message: impl AsRef<str>) {
        self.log_at(bindings::vela::extension::logging::LogLevel::Error, message);
    }

    fn log_at(
        &self,
        level: bindings::vela::extension::logging::LogLevel,
        message: impl AsRef<str>,
    ) {
        bindings::vela::extension::logging::log(level, message.as_ref());
    }

    /// Post an event into a room as this plugin's `@_ext_<name>` bot user, and
    /// return the new event's id. Requires the operator-granted `emit-event`
    /// capability and is only available from [`Plugin::on_event`] — otherwise
    /// you get [`EmitError::NotPermitted`].
    ///
    /// The event goes through normal room authorization: the bot must be a
    /// member of the room with sufficient power level (the operator invites it),
    /// or this returns [`EmitError::Unauthorized`]. v1 allows `m.room.message`,
    /// `m.reaction`, and `m.room.redaction`; emits are rate-limited per plugin.
    pub fn emit(
        &self,
        room_id: &str,
        event_type: &str,
        content: &Value,
    ) -> Result<String, EmitError> {
        let ev = bindings::vela::extension::emit::NewEvent {
            room_id: room_id.to_string(),
            event_type: event_type.to_string(),
            content: content.to_string(),
            state_key: None,
        };
        bindings::vela::extension::emit::emit_event(&ev).map_err(EmitError::from)
    }

    /// Convenience over [`emit`](Self::emit): send a plain-text `m.room.message`.
    pub fn send_text(&self, room_id: &str, body: &str) -> Result<String, EmitError> {
        let content = serde_json::json!({ "msgtype": "m.text", "body": body });
        self.emit(room_id, "m.room.message", &content)
    }

    /// This plugin's private key→value store (needs the `kv` capability) — the
    /// same store the decision contexts reach via `kv()`. See [`Kv`].
    pub fn kv(&self) -> Kv {
        Kv::new()
    }

    /// Read a key. Shorthand for `self.kv().get(key)`.
    pub fn kv_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        self.kv().get(key)
    }

    /// Write a key with no expiry. Shorthand for `self.kv().set(key, value)`.
    pub fn kv_set(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        self.kv().set(key, value)
    }

    /// Write a key with a TTL in ms. Shorthand for `self.kv().set_ttl(...)`.
    pub fn kv_set_ttl(&self, key: &[u8], value: &[u8], ttl_ms: u64) -> Result<(), KvError> {
        self.kv().set_ttl(key, value, ttl_ms)
    }

    /// Delete a key. Shorthand for `self.kv().delete(key)`.
    pub fn kv_delete(&self, key: &[u8]) -> Result<(), KvError> {
        self.kv().delete(key)
    }

    /// [`kv_get`](Self::kv_get) + JSON-decode. Shorthand for `self.kv().get_json(key)`.
    pub fn kv_get_json<T: DeserializeOwned>(&self, key: &[u8]) -> Result<Option<T>, KvError> {
        self.kv().get_json(key)
    }

    /// JSON-encode + set with TTL. Shorthand for `self.kv().set_json(...)`.
    pub fn kv_set_json<T: serde::Serialize>(
        &self,
        key: &[u8],
        value: &T,
        ttl_ms: u64,
    ) -> Result<(), KvError> {
        self.kv().set_json(key, value, ttl_ms)
    }
}

/// Why a [`Caps`] kv op failed. `#[non_exhaustive]` — match with a `_` arm.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KvError {
    /// Not granted, or the key/value exceeded a per-op size cap.
    NotPermitted(String),
    /// This plugin is over its byte budget — free space (delete / shorter TTL).
    QuotaExceeded,
    /// Internal host failure (logged server-side), or a JSON encode error.
    Internal,
}

impl From<bindings::vela::extension::kv::KvError> for KvError {
    fn from(e: bindings::vela::extension::kv::KvError) -> Self {
        use bindings::vela::extension::kv::KvError as W;
        match e {
            W::NotPermitted(m) => KvError::NotPermitted(m),
            W::QuotaExceeded => KvError::QuotaExceeded,
            W::Internal => KvError::Internal,
        }
    }
}

/// Why an [`Caps::emit`] failed. `#[non_exhaustive]` — match with a `_` arm.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitError {
    /// The bot isn't joined / lacks power level in that room (invite it).
    Unauthorized,
    /// Not granted, called outside `on_event`, a disallowed event type, or
    /// malformed content.
    NotPermitted(String),
    /// This plugin's emit rate cap tripped — back off and retry later.
    RateLimited,
    /// Internal host failure (logged server-side).
    Internal,
}

impl From<bindings::vela::extension::emit::EmitError> for EmitError {
    fn from(e: bindings::vela::extension::emit::EmitError) -> Self {
        use bindings::vela::extension::emit::EmitError as W;
        match e {
            W::Unauthorized => EmitError::Unauthorized,
            W::NotPermitted(m) => EmitError::NotPermitted(m),
            W::RateLimited => EmitError::RateLimited,
            W::Internal => EmitError::Internal,
        }
    }
}

/// An ergonomic view over the signup metadata at the registration point.
pub struct Registration {
    raw: bindings::exports::vela::extension::decision::RegistrationContext,
}

impl Registration {
    fn new(raw: bindings::exports::vela::extension::decision::RegistrationContext) -> Self {
        Registration { raw }
    }

    /// The requested localpart, e.g. `"alice"`.
    pub fn username(&self) -> &str {
        &self.raw.username
    }

    /// How they're registering: `"open"`, `"token"`, `"oidc"`, `"guest"`,
    /// `"appservice"`.
    pub fn kind(&self) -> &str {
        &self.raw.kind
    }

    /// An opaque IP token for rate-limiting (per the operator's `client_ip`
    /// tier), or `None` if not exposed. Treat it as an opaque key — only as a
    /// real address if your plugin was granted the `full` tier.
    pub fn client_ip(&self) -> Option<&str> {
        self.raw.client_ip.as_deref()
    }

    /// This plugin's operator-supplied config as `T` — see [`Event::config`] for
    /// the default-vs-panic semantics.
    pub fn config<T: DeserializeOwned + Default>(&self) -> T {
        if self.raw.plugin_config.is_empty() {
            return T::default();
        }
        serde_json::from_str(&self.raw.plugin_config)
            .expect("plugin config is present but invalid for the requested type")
    }

    /// This plugin's config as `T`, distinguishing absent / valid / invalid.
    pub fn try_config<T: DeserializeOwned>(&self) -> Result<Option<T>, serde_json::Error> {
        if self.raw.plugin_config.is_empty() {
            return Ok(None);
        }
        serde_json::from_str(&self.raw.plugin_config).map(Some)
    }

    /// This plugin's key→value store (needs the `kv` capability) — a stateful
    /// per-IP signup rate-limiter is a few lines. See [`Kv`].
    pub fn kv(&self) -> Kv {
        Kv::new()
    }
}

/// An ergonomic view over the media-upload metadata at the media point. v1 has
/// no raw content — uploads stream, so only a hash + metadata are available.
pub struct Media {
    raw: bindings::exports::vela::extension::decision::MediaContext,
}

impl Media {
    fn new(raw: bindings::exports::vela::extension::decision::MediaContext) -> Self {
        Media { raw }
    }

    /// Client-declared MIME type, e.g. `"image/png"`.
    pub fn content_type(&self) -> &str {
        &self.raw.content_type
    }

    /// Original filename, or `""`.
    pub fn filename(&self) -> &str {
        &self.raw.filename
    }

    /// Size in bytes.
    pub fn size(&self) -> u64 {
        self.raw.size
    }

    /// The uploading user's id.
    pub fn uploader(&self) -> &str {
        &self.raw.uploader
    }

    /// Lowercase hex SHA-256 of the content — match against a known-bad-hash list.
    pub fn sha256(&self) -> &str {
        &self.raw.sha256
    }

    /// This plugin's key→value store (needs the `kv` capability) — e.g. a hash
    /// blocklist or per-uploader quota. See [`Kv`].
    pub fn kv(&self) -> Kv {
        Kv::new()
    }

    /// This plugin's operator-supplied config as `T` — see [`Event::config`].
    pub fn config<T: DeserializeOwned + Default>(&self) -> T {
        if self.raw.plugin_config.is_empty() {
            return T::default();
        }
        serde_json::from_str(&self.raw.plugin_config)
            .expect("plugin config is present but invalid for the requested type")
    }
}

/// Which profile field a user is setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileField {
    DisplayName,
    AvatarUrl,
}

/// An ergonomic view over a profile update at the `check_profile_update` point —
/// a user setting their own display name or avatar, before it's persisted.
pub struct Profile {
    raw: bindings::exports::vela::extension::decision::ProfileContext,
}

impl Profile {
    fn new(raw: bindings::exports::vela::extension::decision::ProfileContext) -> Self {
        Profile { raw }
    }

    /// The user changing their own profile.
    pub fn user_id(&self) -> &str {
        &self.raw.user_id
    }

    /// Which field is being set.
    pub fn field(&self) -> ProfileField {
        use bindings::exports::vela::extension::decision::ProfileField as Wit;
        match self.raw.field {
            Wit::DisplayName => ProfileField::DisplayName,
            Wit::AvatarUrl => ProfileField::AvatarUrl,
        }
    }

    /// The proposed new value, or `None` if the user is clearing the field. For
    /// [`ProfileField::AvatarUrl`] this is the mxc:// URI, not the image (image
    /// scanning is `check_media_upload`'s job).
    pub fn value(&self) -> Option<&str> {
        self.raw.value.as_deref()
    }

    /// This plugin's key→value store (needs the `kv` capability) — e.g. per-user
    /// display-name churn limits. See [`Kv`].
    pub fn kv(&self) -> Kv {
        Kv::new()
    }

    /// This plugin's operator-supplied config as `T` — see [`Event::config`].
    pub fn config<T: DeserializeOwned + Default>(&self) -> T {
        if self.raw.plugin_config.is_empty() {
            return T::default();
        }
        serde_json::from_str(&self.raw.plugin_config)
            .expect("plugin config is present but invalid for the requested type")
    }
}

/// An ergonomic view over a room creation at the `check_room_create` point — a
/// user creating a room, before anything is persisted.
pub struct RoomCreate {
    raw: bindings::exports::vela::extension::decision::RoomCreateContext,
}

impl RoomCreate {
    fn new(raw: bindings::exports::vela::extension::decision::RoomCreateContext) -> Self {
        RoomCreate { raw }
    }

    /// The creating user, `@user:server`.
    pub fn creator(&self) -> &str {
        &self.raw.creator
    }

    /// The room id the server derived for this creation.
    pub fn room_id(&self) -> &str {
        &self.raw.room_id
    }

    /// The room version.
    pub fn room_version(&self) -> &str {
        &self.raw.room_version
    }

    /// The resolved preset, normally `public_chat` / `private_chat` /
    /// `trusted_private_chat`. Client-supplied and not validated against that set,
    /// so key a "no public rooms" rule on [`RoomCreate::visibility`], not this.
    pub fn preset(&self) -> &str {
        &self.raw.preset
    }

    /// Requested directory visibility (`public` / `private`), or `None`. A
    /// "no public rooms" rule keys on this.
    pub fn visibility(&self) -> Option<&str> {
        self.raw.visibility.as_deref()
    }

    /// Requested room name, or `None`.
    pub fn name(&self) -> Option<&str> {
        self.raw.name.as_deref()
    }

    /// Requested room topic, or `None`.
    pub fn topic(&self) -> Option<&str> {
        self.raw.topic.as_deref()
    }

    /// Requested alias localpart (e.g. `foo` for `#foo:server`), or `None`.
    pub fn alias_localpart(&self) -> Option<&str> {
        self.raw.alias_localpart.as_deref()
    }

    /// Users invited at creation time (an invite-bomb signal / target list).
    pub fn invite(&self) -> &[String] {
        &self.raw.invite
    }

    /// Whether the client marked this a direct (1:1) room.
    pub fn is_direct(&self) -> bool {
        self.raw.is_direct
    }

    /// This plugin's key→value store (needs the `kv` capability) — e.g. a
    /// per-creator "rooms created today" counter for a rate limit. See [`Kv`].
    pub fn kv(&self) -> Kv {
        Kv::new()
    }

    /// This plugin's operator-supplied config as `T` — see [`Event::config`].
    pub fn config<T: DeserializeOwned + Default>(&self) -> T {
        if self.raw.plugin_config.is_empty() {
            return T::default();
        }
        serde_json::from_str(&self.raw.plugin_config)
            .expect("plugin config is present but invalid for the requested type")
    }
}

/// Implement this for your plugin type, then `export_plugin!(YourType)`. A plugin
/// can implement any of the hooks — [`Plugin::check_event`] (decision on events),
/// [`Plugin::on_event`] (async observation), [`Plugin::check_registration`]
/// (decision at signup), [`Plugin::check_media_upload`] (decision at upload),
/// [`Plugin::check_profile_update`] (decision at a profile change),
/// [`Plugin::check_room_create`] (decision at room creation) — the unused
/// ones default to allow/no-op, and the operator's `points` config decides which
/// the host invokes.
pub trait Plugin {
    /// Decide whether to allow or block one event (sync, on the hot path).
    /// Default: allow.
    fn check_event(_event: &Event) -> Decision {
        Decision::allow()
    }

    /// Observe an event asynchronously (off the hot path). No return — an
    /// observer cannot block. Default: no-op. Override to audit, emit metrics,
    /// or (with future capabilities via `caps`) act.
    fn on_event(_event: &Event, _caps: &Caps) {}

    /// Decide whether to allow or block a signup, at `/register` before the
    /// account is created. Default: allow. The `kv` capability works here, so a
    /// stateful rate-limit is natural.
    fn check_registration(_reg: &Registration) -> Decision {
        Decision::allow()
    }

    /// Decide whether to allow or block a media upload, after the bytes are
    /// stored but before the upload is downloadable. Default: allow. A block
    /// deletes the stored bytes. v1 sees a hash + metadata (match `sha256()`
    /// against a blocklist, or filter by MIME/size/filename).
    fn check_media_upload(_media: &Media) -> Decision {
        Decision::allow()
    }

    /// Decide whether to allow or block a profile update — a user setting their
    /// own display name or avatar, before it's persisted. Default: allow. Use it
    /// for anti-impersonation and name/avatar policy; the `kv` capability works
    /// here, so per-user churn limits are natural.
    fn check_profile_update(_profile: &Profile) -> Decision {
        Decision::allow()
    }

    /// Decide whether to allow or block a room creation, at `createRoom` before
    /// anything is persisted. Default: allow. Use it for anti-spam, invite-bomb
    /// caps, no-public-rooms, and alias policy; the `kv` capability works here, so
    /// per-creator rate limits are natural.
    fn check_room_create(_room: &RoomCreate) -> Decision {
        Decision::allow()
    }
}

/// Bridge from the raw decision entry point to [`Plugin::check_event`].
/// Called by [`export_plugin!`]; not for direct use.
#[doc(hidden)]
pub fn dispatch<P: Plugin>(
    ctx: bindings::exports::vela::extension::decision::EventContext,
) -> bindings::exports::vela::extension::decision::Verdict {
    use bindings::exports::vela::extension::decision as wit;
    let event = Event::new(ctx);
    match P::check_event(&event) {
        Decision::Allow => wit::Verdict::Allow,
        Decision::Block { errcode, reason } => {
            wit::Verdict::Block(wit::BlockReason { errcode, reason })
        }
    }
}

/// Bridge from the raw observation entry point to [`Plugin::on_event`].
/// Called by [`export_plugin!`]; not for direct use.
#[doc(hidden)]
pub fn dispatch_on_event<P: Plugin>(
    ctx: bindings::exports::vela::extension::decision::EventContext,
) {
    let event = Event::new(ctx);
    P::on_event(&event, &Caps {});
}

/// Bridge from the raw registration entry point to [`Plugin::check_registration`].
/// Called by [`export_plugin!`]; not for direct use.
#[doc(hidden)]
pub fn dispatch_check_registration<P: Plugin>(
    ctx: bindings::exports::vela::extension::decision::RegistrationContext,
) -> bindings::exports::vela::extension::decision::Verdict {
    use bindings::exports::vela::extension::decision as wit;
    let reg = Registration::new(ctx);
    match P::check_registration(&reg) {
        Decision::Allow => wit::Verdict::Allow,
        Decision::Block { errcode, reason } => {
            wit::Verdict::Block(wit::BlockReason { errcode, reason })
        }
    }
}

/// Bridge from the raw media entry point to [`Plugin::check_media_upload`].
/// Called by [`export_plugin!`]; not for direct use.
#[doc(hidden)]
pub fn dispatch_check_media_upload<P: Plugin>(
    ctx: bindings::exports::vela::extension::decision::MediaContext,
) -> bindings::exports::vela::extension::decision::Verdict {
    use bindings::exports::vela::extension::decision as wit;
    let media = Media::new(ctx);
    match P::check_media_upload(&media) {
        Decision::Allow => wit::Verdict::Allow,
        Decision::Block { errcode, reason } => {
            wit::Verdict::Block(wit::BlockReason { errcode, reason })
        }
    }
}

/// Bridge from the raw profile entry point to [`Plugin::check_profile_update`].
/// Called by [`export_plugin!`]; not for direct use.
#[doc(hidden)]
pub fn dispatch_check_profile_update<P: Plugin>(
    ctx: bindings::exports::vela::extension::decision::ProfileContext,
) -> bindings::exports::vela::extension::decision::Verdict {
    use bindings::exports::vela::extension::decision as wit;
    let profile = Profile::new(ctx);
    match P::check_profile_update(&profile) {
        Decision::Allow => wit::Verdict::Allow,
        Decision::Block { errcode, reason } => {
            wit::Verdict::Block(wit::BlockReason { errcode, reason })
        }
    }
}

/// Bridge from the raw room-create entry point to [`Plugin::check_room_create`].
/// Called by [`export_plugin!`]; not for direct use.
#[doc(hidden)]
pub fn dispatch_check_room_create<P: Plugin>(
    ctx: bindings::exports::vela::extension::decision::RoomCreateContext,
) -> bindings::exports::vela::extension::decision::Verdict {
    use bindings::exports::vela::extension::decision as wit;
    let room = RoomCreate::new(ctx);
    match P::check_room_create(&room) {
        Decision::Allow => wit::Verdict::Allow,
        Decision::Block { errcode, reason } => {
            wit::Verdict::Block(wit::BlockReason { errcode, reason })
        }
    }
}

/// Export your [`Plugin`] implementation as the component's entry point. Call
/// this exactly once at the crate root.
#[macro_export]
macro_rules! export_plugin {
    ($plugin:ty) => {
        struct __VelaPluginGlue;
        impl $crate::bindings::exports::vela::extension::decision::Guest for __VelaPluginGlue {
            fn check_event(
                ctx: $crate::bindings::exports::vela::extension::decision::EventContext,
            ) -> $crate::bindings::exports::vela::extension::decision::Verdict {
                $crate::dispatch::<$plugin>(ctx)
            }
            fn check_registration(
                ctx: $crate::bindings::exports::vela::extension::decision::RegistrationContext,
            ) -> $crate::bindings::exports::vela::extension::decision::Verdict {
                $crate::dispatch_check_registration::<$plugin>(ctx)
            }
            fn check_media_upload(
                ctx: $crate::bindings::exports::vela::extension::decision::MediaContext,
            ) -> $crate::bindings::exports::vela::extension::decision::Verdict {
                $crate::dispatch_check_media_upload::<$plugin>(ctx)
            }
            fn check_profile_update(
                ctx: $crate::bindings::exports::vela::extension::decision::ProfileContext,
            ) -> $crate::bindings::exports::vela::extension::decision::Verdict {
                $crate::dispatch_check_profile_update::<$plugin>(ctx)
            }
            fn check_room_create(
                ctx: $crate::bindings::exports::vela::extension::decision::RoomCreateContext,
            ) -> $crate::bindings::exports::vela::extension::decision::Verdict {
                $crate::dispatch_check_room_create::<$plugin>(ctx)
            }
        }
        impl $crate::bindings::exports::vela::extension::observation::Guest for __VelaPluginGlue {
            fn on_event(
                ctx: $crate::bindings::exports::vela::extension::observation::EventContext,
            ) {
                $crate::dispatch_on_event::<$plugin>(ctx)
            }
        }
        $crate::bindings::export!(__VelaPluginGlue with_types_in $crate::bindings);
    };
}
