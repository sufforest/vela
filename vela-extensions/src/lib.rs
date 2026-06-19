//! Sandboxed, language-agnostic WASM extension runtime for vela.
//!
//! Operators run **untrusted** policy logic (moderation today, automation
//! later) at the Matrix spec's server-discretion points, in any language that
//! compiles to a WASM component, isolated and resource-limited. See `DESIGN.md`
//! and `wit/extension.wit` for the architecture and the host↔guest contract.
//!
//! The runtime is gated behind the default-on `wasmtime-runtime` feature. With
//! it off, the types and a no-op [`Runtime`] (which allows everything) still
//! compile with zero wasmtime dependencies, so vela can build without WASM.

mod abi;
mod config;
mod emit;
mod kv;
mod runtime;

#[cfg(feature = "wasmtime-runtime")]
mod plugin;

pub use abi::{EventContext, Origin, Verdict};
pub use config::{Capabilities, FailPolicy, PluginConfig, Points};
pub use emit::{EmitError, EmitRequest, EventEmitter};
pub use kv::{KvError, KvStore};
pub use runtime::{Decision, Runtime, RuntimeError};

/// The host services injected into a [`Runtime`] — the implementations of the
/// capabilities that call back into the homeserver. vela-api fills these in and
/// hands them to `Runtime::with_services`; each future internals-touching
/// capability adds a field. `Default` (all `None`) = nothing injected, for tests
/// and wasmtime-free embedders.
#[derive(Clone, Default)]
pub struct HostServices {
    pub emitter: Option<std::sync::Arc<dyn EventEmitter>>,
    pub kv: Option<std::sync::Arc<dyn KvStore>>,
}
