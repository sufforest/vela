//! The wasmtime-backed plugin: load a component, instantiate it under fuel +
//! memory limits, run `check-event`, convert the verdict. Entirely gated behind
//! the `wasmtime-runtime` feature — nothing here compiles in a wasmtime-free
//! build.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use serde_json::Value;
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

use crate::abi::{EventContext, Origin, Verdict};
use crate::config::PluginConfig;

/// How often the epoch ticker advances the engine's epoch. This is the
/// resolution of the per-plugin `wall_ms` deadline.
const EPOCH_TICK_MS: u64 = 10;

/// Longest plugin log message the host will emit; longer is truncated. Bounds
/// the log *volume* a `log` call produces — not the transient host allocation of
/// lifting the guest string, which the Component Model materializes in full
/// before truncation (bounded instead by the guest's own linear-memory cap).
const MAX_LOG_LEN: usize = 2048;

/// Most `log` calls the host honors per single plugin invocation; further calls
/// are dropped. `HostState` is fresh per call, so this resets every event —
/// it bounds a tight log loop within one `on_event`/`check_event` (fuel bounds
/// the total, this bounds the line count).
const MAX_LOG_CALLS: u32 = 64;

mod bindings {
    wasmtime::component::bindgen!({
        path: "wit/extension.wit",
        world: "plugin",
    });
}

use bindings::exports::vela::extension::decision as wit;
use bindings::vela::extension::logging::{Host as LoggingHost, LogLevel};

/// Per-store host state. Holds the resource limiter so memory growth is capped
/// per instantiation; fuel lives on the store itself. Also carries the plugin
/// name (to attribute its log lines) and a per-invocation log-call counter.
struct HostState {
    limits: StoreLimits,
    name: String,
    log_calls: u32,
}

/// Truncate `s` to at most `max` bytes without splitting a UTF-8 char.
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

impl LoggingHost for HostState {
    /// A plugin calling the `logging` capability. Forwarded to vela's `tracing`
    /// at a fixed target (`vela::extensions::plugin`) so operators can filter
    /// all plugin output, tagged with the plugin name so it's attributable.
    /// Bounded: message truncated to [`MAX_LOG_LEN`], at most [`MAX_LOG_CALLS`]
    /// lines per invocation. The message is passed as an *argument*, never a
    /// format string, so a plugin can't inject formatting.
    fn log(&mut self, level: LogLevel, message: String) {
        const TARGET: &str = "vela::extensions::plugin";
        if self.log_calls >= MAX_LOG_CALLS {
            if self.log_calls == MAX_LOG_CALLS {
                self.log_calls += 1;
                tracing::warn!(target: TARGET, plugin = %self.name, "plugin exceeded its per-call log budget; suppressing further lines");
            }
            return;
        }
        self.log_calls += 1;
        let msg = truncate_on_char_boundary(&message, MAX_LOG_LEN);
        let plugin = &*self.name;
        match level {
            LogLevel::Error => tracing::error!(target: TARGET, plugin, "{}", msg),
            LogLevel::Warn => tracing::warn!(target: TARGET, plugin, "{}", msg),
            LogLevel::Info => tracing::info!(target: TARGET, plugin, "{}", msg),
            LogLevel::Debug => tracing::debug!(target: TARGET, plugin, "{}", msg),
            LogLevel::Trace => tracing::trace!(target: TARGET, plugin, "{}", msg),
        }
    }
}

/// A loaded, ready-to-instantiate plugin. The component is compiled once at
/// load (via `PluginPre`), so per-call work is instantiation only — not
/// recompilation. Each call still builds a fresh store + instance, keeping
/// plugins stateless; a warm instance pool is a possible future optimization.
pub(crate) struct Plugin {
    engine: Engine,
    pre: bindings::PluginPre<HostState>,
    pub(crate) cfg: PluginConfig,
}

/// Why a plugin invocation failed. The runtime maps these onto the plugin's
/// fail policy (open → allow, closed → block).
#[derive(Debug)]
pub(crate) enum PluginError {
    /// Compilation or linking of the component failed at load time.
    Load(String),
    /// The guest trapped, ran out of fuel, or hit the memory cap.
    Trap(String),
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginError::Load(m) => write!(f, "plugin load failed: {m}"),
            PluginError::Trap(m) => write!(f, "plugin trapped: {m}"),
        }
    }
}

impl Plugin {
    /// Build the shared engine. One engine backs every plugin (cloning an
    /// `Engine` shares its inner state), as wasmtime intends — per-plugin
    /// engines would duplicate the compiler/type context for no reason.
    pub(crate) fn new_engine() -> Result<Engine, PluginError> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        // Wall-clock backstop: the epoch is advanced by a ticker thread (see
        // `EpochTicker`); a store sets a deadline in ticks.
        config.epoch_interruption(true);
        Engine::new(&config).map_err(|e| PluginError::Load(e.to_string()))
    }

    /// Compile a plugin component against the shared engine and resolve its
    /// imports once. Returns an error if the bytes aren't a valid component or
    /// its world doesn't match.
    pub(crate) fn load(engine: &Engine, cfg: PluginConfig) -> Result<Self, PluginError> {
        let component =
            Component::new(engine, &cfg.wasm).map_err(|e| PluginError::Load(e.to_string()))?;

        // Grant host capabilities by adding them to the linker. A plugin that
        // doesn't import `logging` simply ignores it; one that does gets it.
        let mut linker: Linker<HostState> = Linker::new(engine);
        bindings::vela::extension::logging::add_to_linker::<_, HasSelf<HostState>>(
            &mut linker,
            |s| s,
        )
        .map_err(|e| PluginError::Load(e.to_string()))?;
        let pre = linker
            .instantiate_pre(&component)
            .and_then(bindings::PluginPre::new)
            .map_err(|e| PluginError::Load(e.to_string()))?;

        Ok(Plugin {
            engine: engine.clone(),
            pre,
            cfg,
        })
    }

    /// Build a fresh, bounded store, instantiate the component, and marshal the
    /// wire event context — shared by `check_event` and `on_event`. A fresh
    /// instance per call keeps plugins stateless; fuel/memory/wall are bounded
    /// per config. `event_json` is serialized once by the runtime and shared
    /// across plugins (not re-serialized per plugin).
    fn prepare(
        &self,
        event_json: &str,
        ctx: &EventContext<'_>,
    ) -> Result<(Store<HostState>, bindings::Plugin, wit::EventContext), PluginError> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.cfg.memory_pages as usize * 64 * 1024)
            .build();
        let mut store = Store::new(
            &self.engine,
            HostState {
                limits,
                name: self.cfg.name.clone(),
                log_calls: 0,
            },
        );
        store.limiter(|s| &mut s.limits);
        store
            .set_fuel(self.cfg.fuel)
            .map_err(|e| PluginError::Trap(e.to_string()))?;
        // With epoch_interruption enabled, a store's default deadline traps
        // immediately — so we must always set one. `wall_ms == 0` → an
        // effectively-infinite deadline (no wall limit); otherwise trap (the
        // default deadline behavior) after this many epoch ticks.
        let deadline = if self.cfg.wall_ms > 0 {
            self.cfg.wall_ms.div_ceil(EPOCH_TICK_MS).max(1)
        } else {
            u64::MAX
        };
        store.set_epoch_deadline(deadline);

        let instance = self
            .pre
            .instantiate(&mut store)
            .map_err(|e| PluginError::Trap(e.to_string()))?;

        let wire = wit::EventContext {
            event: event_json.to_string(),
            room_id: ctx.room_id.to_string(),
            sender: ctx.sender.to_string(),
            event_type: ctx.event_type.to_string(),
            origin: match ctx.origin {
                Origin::Local => wit::Origin::Local,
                Origin::Federation => wit::Origin::Federation,
            },
            plugin_config: config_json(&self.cfg.config),
        };
        Ok((store, instance, wire))
    }

    /// Run the decision hook (sync, critical path) for one event → a verdict.
    pub(crate) fn check_event(
        &self,
        event_json: &str,
        ctx: &EventContext<'_>,
    ) -> Result<Verdict, PluginError> {
        let (mut store, instance, wire) = self.prepare(event_json, ctx)?;
        let verdict = instance
            .vela_extension_decision()
            .call_check_event(&mut store, &wire)
            .map_err(|e| PluginError::Trap(e.to_string()))?;
        Ok(match verdict {
            wit::Verdict::Allow => Verdict::Allow,
            wit::Verdict::Block(r) => Verdict::Block {
                errcode: r.errcode,
                reason: r.reason,
            },
        })
    }

    /// Run the observation hook (async, off the hot path) for one event. No
    /// verdict — an observer cannot block. Same per-call bounds as check_event.
    pub(crate) fn on_event(
        &self,
        event_json: &str,
        ctx: &EventContext<'_>,
    ) -> Result<(), PluginError> {
        let (mut store, instance, wire) = self.prepare(event_json, ctx)?;
        instance
            .vela_extension_observation()
            .call_on_event(&mut store, &wire)
            .map_err(|e| PluginError::Trap(e.to_string()))?;
        Ok(())
    }
}

/// Plugin config is handed to the guest as a JSON string; `null`/absent → "".
fn config_json(v: &Value) -> String {
    if v.is_null() {
        String::new()
    } else {
        v.to_string()
    }
}

/// Background timer that advances the shared engine's epoch every
/// `EPOCH_TICK_MS`, so per-call wall-clock deadlines (`set_epoch_deadline`)
/// fire. One ticker per runtime; it stops and joins on drop.
pub(crate) struct EpochTicker {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl EpochTicker {
    pub(crate) fn spawn(engine: &Engine) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let engine = engine.clone();
        let handle = thread::Builder::new()
            .name("vela-ext-epoch".into())
            .spawn(move || {
                while !stop_thread.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
                    engine.increment_epoch();
                }
            })
            .expect("spawn epoch ticker");
        EpochTicker {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_respects_char_boundaries_and_cap() {
        // Under the cap: returned whole.
        assert_eq!(truncate_on_char_boundary("hello", 64), "hello");
        // ASCII over the cap: cut exactly at the cap.
        let s = "a".repeat(100);
        assert_eq!(truncate_on_char_boundary(&s, 10).len(), 10);
        // Multibyte over the cap: cut backwards to a char boundary, never mid-char
        // (so the result is always valid UTF-8 and never panics).
        let m = "é".repeat(100); // each 'é' is 2 bytes
        let cut = truncate_on_char_boundary(&m, 5); // 5 lands mid-char → backs to 4
        assert_eq!(cut.len(), 4);
        assert!(cut.chars().all(|c| c == 'é'));
    }
}
