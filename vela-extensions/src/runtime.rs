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
    use std::sync::Arc;

    use super::*;
    use crate::HostServices;
    use crate::abi::Verdict;
    use crate::config::FailPolicy;
    use crate::emit::EventEmitter;
    use crate::plugin::{EpochTicker, Plugin};

    /// Loads and dispatches across sandboxed plugins.
    pub struct Runtime {
        plugins: Vec<Plugin>,
        /// Drives wall-clock deadlines; `None` if no plugin sets `wall_ms`.
        /// Held only for its `Drop` (stops the ticker thread).
        _ticker: Option<EpochTicker>,
    }

    impl Runtime {
        /// Compile every configured plugin with no host services injected —
        /// every capability-granted plugin's calls fail. Used by tests and
        /// wasmtime-free embedders; vela-server uses [`with_services`].
        pub fn new(configs: Vec<PluginConfig>) -> Result<Self, RuntimeError> {
            Self::with_services(configs, HostServices::default())
        }

        /// Compile every configured plugin, injecting only the `emit-event`
        /// service. Convenience over [`with_services`] for emit-only callers.
        pub fn with_emitter(
            configs: Vec<PluginConfig>,
            emitter: Option<Arc<dyn EventEmitter>>,
        ) -> Result<Self, RuntimeError> {
            Self::with_services(
                configs,
                HostServices {
                    emitter,
                    ..Default::default()
                },
            )
        }

        /// Compile every configured plugin, injecting the host capability
        /// services (emit, kv, …). Fails if any component is invalid — a
        /// misconfigured server should refuse to start, not silently run with a
        /// missing policy.
        pub fn with_services(
            configs: Vec<PluginConfig>,
            services: HostServices,
        ) -> Result<Self, RuntimeError> {
            let engine = Plugin::new_engine().map_err(|e| RuntimeError(e.to_string()))?;
            // Only run the epoch ticker if some plugin actually uses a
            // wall-clock budget — no idle thread otherwise.
            let needs_ticker = configs.iter().any(|c| c.wall_ms > 0);
            let mut plugins = Vec::with_capacity(configs.len());
            for cfg in configs {
                let name = cfg.name.clone();
                let plugin = Plugin::load(&engine, cfg, &services)
                    .map_err(|e| RuntimeError(format!("plugin '{name}': {e}")))?;
                plugins.push(plugin);
            }
            let ticker = needs_ticker.then(|| EpochTicker::spawn(&engine));
            Ok(Runtime {
                plugins,
                _ticker: ticker,
            })
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
            // Serialize the event once, shared across every interested plugin
            // (the JSON marshaling — not wasm execution — is the real cost).
            // Computed lazily so a fully-scoped-out event pays nothing.
            let mut event_json: Option<String> = None;
            for plugin in &self.plugins {
                if !plugin.cfg.points.check_event || !scoped_in(&plugin.cfg, ctx.event_type) {
                    continue;
                }
                let event_json = event_json.get_or_insert_with(|| ctx.event.to_string());
                let verdict = match plugin.check_event(event_json, ctx) {
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
                    // This crate returns a pure verdict; the origin-aware
                    // translation lives at the call site. INVARIANT (enforced
                    // there): a Block on a `local` event is a hard reject (we
                    // refuse to originate it); a Block on a `federation` event is
                    // a SOFT-fail (store it, hide it from local clients) — never
                    // a hard reject, which would hole our DAG vs. peers.
                    return Decision::Block { errcode, reason };
                }
            }
            Decision::Allow
        }

        /// True if any plugin binds the async observation point — lets the host
        /// skip enqueuing for observation when there are no observers.
        pub fn binds_on_event(&self) -> bool {
            self.plugins.iter().any(|p| p.cfg.points.on_event)
        }

        /// Run the async observation point: every `on_event`-bound, scoped plugin
        /// sees the event. No verdict (an observer cannot block); a failing
        /// observer is logged and skipped — `fail_policy` does not apply (there
        /// is nothing to fail open/closed). Called off the hot path.
        pub fn on_event(&self, ctx: &EventContext<'_>) {
            let mut event_json: Option<String> = None;
            for plugin in &self.plugins {
                if !plugin.cfg.points.on_event || !scoped_in(&plugin.cfg, ctx.event_type) {
                    continue;
                }
                let event_json = event_json.get_or_insert_with(|| ctx.event.to_string());
                if let Err(e) = plugin.on_event(event_json, ctx) {
                    tracing::warn!(
                        plugin = %plugin.cfg.name,
                        error = %e,
                        "extension on_event failed"
                    );
                }
            }
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
        /// Mirrors the real runtime's signatures; injected services are ignored
        /// (no plugins run without wasmtime).
        pub fn with_services(
            configs: Vec<PluginConfig>,
            _services: crate::HostServices,
        ) -> Result<Self, RuntimeError> {
            Self::new(configs)
        }

        pub fn with_emitter(
            configs: Vec<PluginConfig>,
            _emitter: Option<std::sync::Arc<dyn crate::emit::EventEmitter>>,
        ) -> Result<Self, RuntimeError> {
            Self::new(configs)
        }

        pub fn new(configs: Vec<PluginConfig>) -> Result<Self, RuntimeError> {
            // Loud warning rather than silent no-op: an operator who configured
            // plugins but built without the `extensions` feature would otherwise
            // see their policy silently ignored (everything allowed).
            if !configs.is_empty() {
                tracing::warn!(
                    count = configs.len(),
                    "extension plugins are configured but this build lacks the \
                     `extensions` feature — they will NOT run and all events are \
                     allowed; rebuild with `--features extensions` to enable them"
                );
            }
            Ok(Runtime)
        }

        pub fn is_empty(&self) -> bool {
            true
        }

        pub fn check_event(&self, _ctx: &EventContext<'_>) -> Decision {
            Decision::Allow
        }

        pub fn binds_on_event(&self) -> bool {
            false
        }

        pub fn on_event(&self, _ctx: &EventContext<'_>) {}
    }
}

pub use imp::Runtime;
