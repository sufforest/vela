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

/// Host capabilities granted to a plugin. **Empty in v1** — a forward-compatible
/// seam: `log`, `emit-event`, and `kv` are *added here* in later stages, so a
/// plugin's [`Plugin::on_event`] signature never has to change as capabilities
/// grow. `#[non_exhaustive]` so adding methods isn't a breaking change.
#[non_exhaustive]
pub struct Caps {}

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
