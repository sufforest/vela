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
