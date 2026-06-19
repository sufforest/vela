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
mod runtime;

#[cfg(feature = "wasmtime-runtime")]
mod plugin;

pub use abi::{EventContext, Origin, Verdict};
pub use config::{Capabilities, FailPolicy, PluginConfig, Points};
pub use emit::{EmitError, EmitRequest, EventEmitter};
pub use runtime::{Decision, Runtime, RuntimeError};
