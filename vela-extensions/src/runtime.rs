//! The dispatcher. Holds the loaded plugins and runs a decision point across
//! them. The public surface (`Runtime`, `Decision`) compiles in both feature
//! states; with `wasmtime-runtime` off it degrades to a no-op that allows
//! everything, so call sites in vela-api never need `#[cfg]`.

use crate::abi::EventContext;
use crate::config::PluginConfig;

/// The aggregate outcome of a decision point across all plugins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block { errcode: String, reason: String },
}

/// Errors from building a runtime (e.g. a plugin component failed to load).
#[derive(Debug)]
pub struct RuntimeError(pub String);

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RuntimeError {}

// ----------------------------------------------------------------------------
// Real runtime (wasmtime-runtime feature on)
// ----------------------------------------------------------------------------

#[cfg(feature = "wasmtime-runtime")]
mod imp {
    use super::*;
    use crate::abi::{Origin, Verdict};
    use crate::config::FailPolicy;
    use crate::plugin::Plugin;

    /// Loads and dispatches across sandboxed plugins.
    pub struct Runtime {
        plugins: Vec<Plugin>,
    }

    impl Runtime {
        /// Compile every configured plugin. Fails if any component is invalid —
        /// a misconfigured server should refuse to start, not silently run with
        /// a missing policy.
        pub fn new(configs: Vec<PluginConfig>) -> Result<Self, RuntimeError> {
            let engine = Plugin::new_engine().map_err(|e| RuntimeError(e.to_string()))?;
            let mut plugins = Vec::with_capacity(configs.len());
            for cfg in configs {
                let name = cfg.name.clone();
                let plugin = Plugin::load(&engine, cfg)
                    .map_err(|e| RuntimeError(format!("plugin '{name}': {e}")))?;
                plugins.push(plugin);
            }
            Ok(Runtime { plugins })
        }

        /// True if no plugins are loaded at all — lets the hot path skip
        /// serializing the event when there's nothing to dispatch to. (This is
        /// the coarse gate; per-event scope filtering happens in `check_event`.)
        pub fn is_empty(&self) -> bool {
            self.plugins.is_empty()
        }

        /// Run the decision point. Semantics:
        /// - **block-if-any**: the first plugin that blocks wins (logical AND of
        ///   allows). A failed/fail-open plugin never overrides another's block.
        /// - **scoped activation**: a plugin whose `event_types` doesn't match is
        ///   skipped without instantiation.
        /// - **fail policy**: on trap/fuel-out/error, fail-open → treat as allow,
        ///   fail-closed → treat as block.
        pub fn check_event(&self, ctx: &EventContext<'_>) -> Decision {
            for plugin in &self.plugins {
                if !scoped_in(&plugin.cfg, ctx.event_type) {
                    continue;
                }
                let verdict = match plugin.check_event(ctx) {
                    Ok(v) => v,
                    Err(e) => match plugin.cfg.fail_policy {
                        FailPolicy::Open => {
                            tracing::warn!(
                                plugin = %plugin.cfg.name,
                                error = %e,
                                "extension failed; failing open (allow)"
                            );
                            continue;
                        }
                        FailPolicy::Closed => {
                            tracing::warn!(
                                plugin = %plugin.cfg.name,
                                error = %e,
                                "extension failed; failing closed (block)"
                            );
                            return Decision::Block {
                                errcode: "M_FORBIDDEN".to_string(),
                                reason: "extension policy unavailable".to_string(),
                            };
                        }
                    },
                };

                if let Verdict::Block { errcode, reason } = verdict {
                    // INVARIANT (carried by the caller, not enforced here): a
                    // Block on a federated event must be SOFT-failed, never
                    // hard-rejected — hard-rejecting an event peers accepted
                    // would hole our DAG. This crate returns a pure verdict; the
                    // origin-aware translation lives at the call site.
                    // TODO(PR2): the federation call site must map Block→soft-fail
                    // for Origin::Federation. The debug_assert below is only a
                    // dev tripwire (compiled out in release) — it is NOT the
                    // enforcement. PR1 constructs Origin::Local exclusively.
                    debug_assert!(
                        ctx.origin == Origin::Local,
                        "block on a federation event must be soft-failed by the caller"
                    );
                    return Decision::Block { errcode, reason };
                }
            }
            Decision::Allow
        }
    }

    /// A plugin with no `event_types` filter runs for everything; otherwise only
    /// for the listed types.
    fn scoped_in(cfg: &PluginConfig, event_type: &str) -> bool {
        match &cfg.event_types {
            None => true,
            Some(types) => types.iter().any(|t| t == event_type),
        }
    }
}

// ----------------------------------------------------------------------------
// No-op runtime (wasmtime-runtime feature off) — zero wasmtime deps
// ----------------------------------------------------------------------------

#[cfg(not(feature = "wasmtime-runtime"))]
mod imp {
    use super::*;

    /// Stub runtime for wasmtime-free builds: holds nothing, allows everything.
    pub struct Runtime;

    impl Runtime {
        pub fn new(_configs: Vec<PluginConfig>) -> Result<Self, RuntimeError> {
            Ok(Runtime)
        }

        pub fn is_empty(&self) -> bool {
            true
        }

        pub fn check_event(&self, _ctx: &EventContext<'_>) -> Decision {
            Decision::Allow
        }
    }
}

pub use imp::Runtime;
