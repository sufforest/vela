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

use crate::HostServices;
use crate::abi::{EventContext, Origin, RegistrationContext, Verdict};
use crate::config::{ClientIpTier, PluginConfig};
use crate::emit::{EmitLimiter, EmitRequest, EventEmitter, emit_type_allowed};
use crate::kv::KvStore;

/// How often the epoch ticker advances the engine's epoch. This is the
/// resolution of the per-plugin `wall_ms` deadline.
const EPOCH_TICK_MS: u64 = 10;

/// Per-op size caps for the `kv` capability. Bound a single key/value; total
/// footprint is bounded by the per-plugin quota (enforced in the store).
const MAX_KV_KEY: usize = 256;
const MAX_KV_VALUE: usize = 64 * 1024;

/// Per-plugin emit rate cap (token bucket): sustained rate and burst. A
/// legitimate bot emits in occasional bursts; this bounds a runaway/loop far
/// below what would flood a room, surfaced to the guest as `rate-limited`.
const EMIT_RATE_PER_SEC: f64 = 1.0;
const EMIT_BURST: f64 = 20.0;

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
use bindings::vela::extension::emit::{
    EmitError as WitEmitError, Host as EmitHost, NewEvent as WitNewEvent,
};
use bindings::vela::extension::kv::{Host as KvHost, KvError as WitKvError};
use bindings::vela::extension::logging::{Host as LoggingHost, LogLevel};

/// Per-store host state. Holds the resource limiter so memory growth is capped
/// per instantiation; fuel lives on the store itself. Also carries the plugin
/// name (to attribute its log lines), a per-invocation log-call counter, and —
/// only for an `on_event` invocation of an emit-granted plugin — the emit
/// context backing the `emit-event` capability.
struct HostState {
    limits: StoreLimits,
    name: String,
    log_calls: u32,
    emit: Option<EmitCtx>,
    kv: Option<KvCtx>,
}

/// Backs the `kv` capability for one invocation. Present for any kv-granted
/// plugin (both points — kv is synchronous, so a stateful `check_event` is fine,
/// unlike emit which is on_event-only). The store is shared (`Arc`).
struct KvCtx {
    store: Arc<dyn KvStore>,
    plugin: String,
}

impl KvHost for HostState {
    fn get(&mut self, key: Vec<u8>) -> Result<Option<Vec<u8>>, WitKvError> {
        let ctx = self.kv.as_ref().ok_or_else(kv_not_granted)?;
        if key.len() > MAX_KV_KEY {
            return Err(WitKvError::NotPermitted("key too large".into()));
        }
        ctx.store.get(&ctx.plugin, &key).map_err(Into::into)
    }

    fn set(&mut self, key: Vec<u8>, value: Vec<u8>, ttl_ms: Option<u64>) -> Result<(), WitKvError> {
        let ctx = self.kv.as_ref().ok_or_else(kv_not_granted)?;
        if key.len() > MAX_KV_KEY {
            return Err(WitKvError::NotPermitted("key too large".into()));
        }
        if value.len() > MAX_KV_VALUE {
            return Err(WitKvError::NotPermitted("value too large".into()));
        }
        ctx.store
            .set(&ctx.plugin, &key, &value, ttl_ms)
            .map_err(Into::into)
    }

    fn delete(&mut self, key: Vec<u8>) -> Result<(), WitKvError> {
        let ctx = self.kv.as_ref().ok_or_else(kv_not_granted)?;
        ctx.store.delete(&ctx.plugin, &key).map_err(Into::into)
    }
}

fn kv_not_granted() -> WitKvError {
    WitKvError::NotPermitted("the kv capability is not granted to this plugin".into())
}

impl From<crate::kv::KvError> for WitKvError {
    fn from(e: crate::kv::KvError) -> Self {
        match e {
            crate::kv::KvError::NotPermitted(m) => WitKvError::NotPermitted(m),
            crate::kv::KvError::QuotaExceeded => WitKvError::QuotaExceeded,
            crate::kv::KvError::Internal => WitKvError::Internal,
        }
    }
}

/// Backs the `emit-event` capability for one invocation. Present only when the
/// plugin is emit-granted *and* this is an `on_event` call (emit drives async
/// host work via `block_on`, which is illegal on the `check_event` request
/// path). The emitter + limiter are shared (`Arc`) across the plugin's calls.
struct EmitCtx {
    emitter: Arc<dyn EventEmitter>,
    limiter: Arc<EmitLimiter>,
    plugin: String,
}

impl EmitHost for HostState {
    /// A plugin calling `emit-event`. Enforces, in order: capability present
    /// (else not-permitted), allowlisted non-state event type, content is a JSON
    /// object, per-plugin rate cap — then hands off to the injected emitter,
    /// which resolves the plugin's bot and emits through normal room
    /// authorization. The bot, not this code, is what room auth gates.
    fn emit_event(&mut self, event: WitNewEvent) -> Result<String, WitEmitError> {
        let Some(ctx) = self.emit.as_ref() else {
            return Err(WitEmitError::NotPermitted(
                "emit-event is only available from on_event with the emit-event capability".into(),
            ));
        };
        if event.state_key.is_some() {
            return Err(WitEmitError::NotPermitted(
                "state events cannot be emitted in this version".into(),
            ));
        }
        if !emit_type_allowed(&event.event_type) {
            return Err(WitEmitError::NotPermitted(format!(
                "event type {:?} is not permitted to emit",
                event.event_type
            )));
        }
        let content = match serde_json::from_str(&event.content) {
            Ok(Value::Object(map)) => Value::Object(map),
            _ => {
                return Err(WitEmitError::NotPermitted(
                    "content must be a JSON object".into(),
                ));
            }
        };
        if !ctx.limiter.try_acquire() {
            return Err(WitEmitError::RateLimited);
        }
        let req = EmitRequest {
            room_id: event.room_id,
            event_type: event.event_type,
            content,
            state_key: None,
        };
        ctx.emitter.emit(&ctx.plugin, req).map_err(Into::into)
    }
}

impl From<crate::emit::EmitError> for WitEmitError {
    fn from(e: crate::emit::EmitError) -> Self {
        match e {
            crate::emit::EmitError::Unauthorized => WitEmitError::Unauthorized,
            crate::emit::EmitError::NotPermitted(m) => WitEmitError::NotPermitted(m),
            crate::emit::EmitError::RateLimited => WitEmitError::RateLimited,
            crate::emit::EmitError::Internal => WitEmitError::Internal,
        }
    }
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
    /// The host emit service, present only when this plugin was granted
    /// `emit-event` *and* an emitter was injected into the runtime.
    emitter: Option<Arc<dyn EventEmitter>>,
    /// Per-plugin emit rate cap, shared across invocations.
    emit_limiter: Arc<EmitLimiter>,
    /// The host kv service, present only when granted `kv` *and* a store was
    /// injected.
    kv: Option<Arc<dyn KvStore>>,
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
    /// its world doesn't match. `emitter` is the host's emit service (injected
    /// at runtime construction); a plugin only gets it if it's also granted.
    pub(crate) fn load(
        engine: &Engine,
        cfg: PluginConfig,
        services: &HostServices,
    ) -> Result<Self, PluginError> {
        let component =
            Component::new(engine, &cfg.wasm).map_err(|e| PluginError::Load(e.to_string()))?;

        // Grant host capabilities by adding them to the linker. `logging` is
        // always linked (harmless). `emit` and `kv` are linked ONLY when the
        // operator granted them — so an ungranted plugin that imports one fails
        // to instantiate (the enforcement), and one that doesn't import it is
        // unaffected.
        let mut linker: Linker<HostState> = Linker::new(engine);
        bindings::vela::extension::logging::add_to_linker::<_, HasSelf<HostState>>(
            &mut linker,
            |s| s,
        )
        .map_err(|e| PluginError::Load(e.to_string()))?;
        if cfg.capabilities.emit_event {
            bindings::vela::extension::emit::add_to_linker::<_, HasSelf<HostState>>(
                &mut linker,
                |s| s,
            )
            .map_err(|e| PluginError::Load(e.to_string()))?;
        }
        if cfg.capabilities.kv {
            bindings::vela::extension::kv::add_to_linker::<_, HasSelf<HostState>>(
                &mut linker,
                |s| s,
            )
            .map_err(|e| PluginError::Load(e.to_string()))?;
        }
        let pre = linker
            .instantiate_pre(&component)
            .and_then(bindings::PluginPre::new)
            .map_err(|e| PluginError::Load(e.to_string()))?;

        // Only hold a service when the plugin is actually granted it — a belt to
        // the linker's suspenders (the host fns also check their ctx).
        let emitter = cfg
            .capabilities
            .emit_event
            .then(|| services.emitter.clone())
            .flatten();
        let kv = cfg.capabilities.kv.then(|| services.kv.clone()).flatten();
        Ok(Plugin {
            engine: engine.clone(),
            pre,
            cfg,
            emitter,
            emit_limiter: Arc::new(EmitLimiter::new(EMIT_RATE_PER_SEC, EMIT_BURST)),
            kv,
        })
    }

    /// Build a fresh, bounded store and instantiate the component — the per-call
    /// setup shared by every point. A fresh instance per call keeps plugins
    /// stateless; fuel/memory/wall are bounded per config. `allow_emit` gates the
    /// emit capability (only the off-request-path `on_event`); kv is wired
    /// whenever granted (it's synchronous, fine on any path).
    fn make_store(
        &self,
        allow_emit: bool,
    ) -> Result<(Store<HostState>, bindings::Plugin), PluginError> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.cfg.memory_pages as usize * 64 * 1024)
            .build();
        // Wire the emit capability only for an on_event call of a granted plugin
        // (`allow_emit`) with an injected emitter. The decision paths run inline
        // on the async request thread where emit's `block_on` would panic.
        let emit = match (allow_emit, &self.emitter) {
            (true, Some(emitter)) => Some(EmitCtx {
                emitter: emitter.clone(),
                limiter: self.emit_limiter.clone(),
                plugin: self.cfg.name.clone(),
            }),
            _ => None,
        };
        let kv = self.kv.as_ref().map(|store| KvCtx {
            store: store.clone(),
            plugin: self.cfg.name.clone(),
        });
        let mut store = Store::new(
            &self.engine,
            HostState {
                limits,
                name: self.cfg.name.clone(),
                log_calls: 0,
                emit,
                kv,
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
        Ok((store, instance))
    }

    /// `make_store` + marshal the event wire context — shared by `check_event`
    /// and `on_event`. `event_json` is serialized once by the runtime and shared
    /// across plugins (not re-serialized per plugin).
    fn prepare(
        &self,
        event_json: &str,
        ctx: &EventContext<'_>,
        allow_emit: bool,
    ) -> Result<(Store<HostState>, bindings::Plugin, wit::EventContext), PluginError> {
        let (store, instance) = self.make_store(allow_emit)?;
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
        // No emit on the decision path — it runs inline on the async request
        // thread, where the capability's `block_on` would panic.
        let (mut store, instance, wire) = self.prepare(event_json, ctx, false)?;
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
        // on_event runs on a blocking worker thread, so emit's `block_on` is
        // legal here — wire the capability (granted plugins only).
        let (mut store, instance, wire) = self.prepare(event_json, ctx, true)?;
        instance
            .vela_extension_observation()
            .call_on_event(&mut store, &wire)
            .map_err(|e| PluginError::Trap(e.to_string()))?;
        Ok(())
    }

    /// Run the registration decision hook for one signup → a verdict. Like
    /// `check_event` it's on the request path (no emit), but kv is available
    /// (stateful signup rate limits).
    pub(crate) fn check_registration(
        &self,
        ctx: &RegistrationContext<'_>,
    ) -> Result<Verdict, PluginError> {
        let (mut store, instance) = self.make_store(false)?;
        // Apply this plugin's IP tier at marshal time: it sees only the form its
        // operator-granted tier permits.
        let client_ip = match self.cfg.client_ip {
            ClientIpTier::None => None,
            ClientIpTier::Hashed => ctx.client_ip_hashed,
            ClientIpTier::Full => ctx.client_ip_full,
        };
        let wire = wit::RegistrationContext {
            username: ctx.username.to_string(),
            kind: ctx.kind.to_string(),
            client_ip: client_ip.map(|s| s.to_string()),
            plugin_config: config_json(&self.cfg.config),
        };
        let verdict = instance
            .vela_extension_decision()
            .call_check_registration(&mut store, &wire)
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
