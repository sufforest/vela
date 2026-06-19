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

    /// Read a key from this plugin's private kv store (needs the `kv`
    /// capability). `None` if absent or expired. Bytes are whatever you stored.
    pub fn kv_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        bindings::vela::extension::kv::get(key).map_err(KvError::from)
    }

    /// Write a key with no expiry. The host caps key/value size and enforces a
    /// per-plugin byte quota (`KvError::QuotaExceeded` when full).
    pub fn kv_set(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        bindings::vela::extension::kv::set(key, value, None).map_err(KvError::from)
    }

    /// Write a key with a time-to-live in milliseconds — it disappears after
    /// `ttl_ms`. The right tool for rate-limit counters and dedup markers (they
    /// self-clean, so the store doesn't fill up).
    pub fn kv_set_ttl(&self, key: &[u8], value: &[u8], ttl_ms: u64) -> Result<(), KvError> {
        bindings::vela::extension::kv::set(key, value, Some(ttl_ms)).map_err(KvError::from)
    }

    /// Delete a key. Idempotent.
    pub fn kv_delete(&self, key: &[u8]) -> Result<(), KvError> {
        bindings::vela::extension::kv::delete(key).map_err(KvError::from)
    }

    /// [`kv_get`](Self::kv_get) + JSON-decode. `None` if absent or the stored
    /// bytes don't decode as `T` (it's your own data; treat as a cache miss).
    pub fn kv_get_json<T: DeserializeOwned>(&self, key: &[u8]) -> Result<Option<T>, KvError> {
        Ok(self
            .kv_get(key)?
            .and_then(|b| serde_json::from_slice(&b).ok()))
    }

    /// JSON-encode + [`kv_set_ttl`](Self::kv_set_ttl) (`ttl_ms = 0` → no expiry).
    pub fn kv_set_json<T: serde::Serialize>(
        &self,
        key: &[u8],
        value: &T,
        ttl_ms: u64,
    ) -> Result<(), KvError> {
        let bytes = serde_json::to_vec(value).map_err(|_| KvError::Internal)?;
        if ttl_ms == 0 {
            self.kv_set(key, &bytes)
        } else {
            self.kv_set_ttl(key, &bytes, ttl_ms)
        }
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

/// Implement this for your plugin type, then `export_plugin!(YourType)`. A plugin
/// can implement the **decision** hook ([`Plugin::check_event`]), the async
/// **observation** hook ([`Plugin::on_event`]), or both — the unused one defaults
/// to a no-op, and the operator's `points` config decides which the host invokes.
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
