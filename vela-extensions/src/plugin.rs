//! The wasmtime-backed plugin: load a component, instantiate it under fuel +
//! memory limits, run `check-event`, convert the verdict. Entirely gated behind
//! the `wasmtime-runtime` feature — nothing here compiles in a wasmtime-free
//! build.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use serde_json::Value;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

use crate::abi::{EventContext, Origin, Verdict};
use crate::config::PluginConfig;

/// How often the epoch ticker advances the engine's epoch. This is the
/// resolution of the per-plugin `wall_ms` deadline.
const EPOCH_TICK_MS: u64 = 10;

mod bindings {
    wasmtime::component::bindgen!({
        path: "wit/extension.wit",
        world: "plugin",
    });
}

use bindings::exports::vela::extension::decision as wit;

/// Per-store host state. Holds the resource limiter so memory growth is capped
/// per instantiation; fuel lives on the store itself.
struct HostState {
    limits: StoreLimits,
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

        // PR1 grants no host capabilities, so the linker is empty.
        let linker: Linker<HostState> = Linker::new(engine);
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

    /// Run the decision hook for one event. A fresh instance per call keeps
    /// plugins stateless; fuel, memory, and wall-clock are bounded per config.
    /// `event_json` is the event serialized once by the runtime and shared
    /// across all plugins at this decision point (not re-serialized per plugin).
    pub(crate) fn check_event(
        &self,
        event_json: &str,
        ctx: &EventContext<'_>,
    ) -> Result<Verdict, PluginError> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.cfg.memory_pages as usize * 64 * 1024)
            .build();
        let mut store = Store::new(&self.engine, HostState { limits });
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
