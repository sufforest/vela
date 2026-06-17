//! The wasmtime-backed plugin: load a component, instantiate it under fuel +
//! memory limits, run `check-event`, convert the verdict. Entirely gated behind
//! the `wasmtime-runtime` feature — nothing here compiles in a wasmtime-free
//! build.

use serde_json::Value;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

use crate::abi::{EventContext, Origin, Verdict};
use crate::config::PluginConfig;

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
/// plugins stateless; a warm instance pool is a planned PR2 optimization.
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
    /// plugins stateless; fuel and memory are bounded per the plugin's config.
    pub(crate) fn check_event(&self, ctx: &EventContext<'_>) -> Result<Verdict, PluginError> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.cfg.memory_pages as usize * 64 * 1024)
            .build();
        let mut store = Store::new(&self.engine, HostState { limits });
        store.limiter(|s| &mut s.limits);
        store
            .set_fuel(self.cfg.fuel)
            .map_err(|e| PluginError::Trap(e.to_string()))?;

        let instance = self
            .pre
            .instantiate(&mut store)
            .map_err(|e| PluginError::Trap(e.to_string()))?;

        let wire = wit::EventContext {
            event: ctx.event.to_string(),
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
