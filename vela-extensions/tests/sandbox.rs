//! Adversarial sandbox + dispatch tests for the extension runtime, driven by
//! one committed fixture component (`fixtures/spam_guest.wasm`) that switches
//! behavior by config. These exercise the security-critical promises: untrusted
//! code can't burn unbounded CPU or memory, and the dispatcher's block-if-any /
//! scoping / fail-policy semantics hold.
//!
//! Gated on the runtime feature — with it off, `Runtime` is a no-op.
#![cfg(feature = "wasmtime-runtime")]

use serde_json::{Value, json};
use vela_extensions::{
    Capabilities, Decision, EventContext, FailPolicy, Origin, PluginConfig, Points, Runtime,
};

const FIXTURE: &[u8] = include_bytes!("fixtures/spam_guest.wasm");

/// A plugin config over the shared fixture. `mode` selects guest behavior;
/// generous fuel/memory unless a test overrides them.
fn plugin(name: &str, mode: &str) -> PluginConfig {
    PluginConfig {
        name: name.to_string(),
        wasm: FIXTURE.to_vec(),
        fail_policy: FailPolicy::Open,
        fuel: 100_000_000,
        memory_pages: 256, // 16 MiB cap; comfortably above the guest's baseline
        wall_ms: 0,        // wall-clock deadline off unless a test sets it
        event_types: None,
        points: Points::default(), // decision-only unless a test overrides
        capabilities: Capabilities::default(), // no caps unless a test overrides
        config: json!({ "mode": mode }),
    }
}

fn message(body: &str) -> Value {
    json!({
        "type": "m.room.message",
        "sender": "@alice:example.org",
        "content": { "msgtype": "m.text", "body": body },
    })
}

fn run(plugins: Vec<PluginConfig>, event: &Value, event_type: &str) -> Decision {
    let rt = Runtime::new(plugins).expect("runtime loads");
    let ctx = EventContext {
        event,
        room_id: "!room:example.org",
        sender: "@alice:example.org",
        event_type,
        origin: Origin::Local,
    };
    rt.check_event(&ctx)
}

// --- happy path -------------------------------------------------------------

#[test]
fn allows_a_clean_message() {
    let d = run(
        vec![plugin("p", "allow")],
        &message("hello world"),
        "m.room.message",
    );
    assert_eq!(d, Decision::Allow);
}

#[test]
fn blocks_on_content() {
    let d = run(
        vec![plugin("p", "allow")],
        &message("this is SPAM"),
        "m.room.message",
    );
    assert!(matches!(d, Decision::Block { .. }));
}

#[test]
fn block_carries_errcode_and_reason() {
    match run(vec![plugin("p", "block")], &message("hi"), "m.room.message") {
        Decision::Block { errcode, reason } => {
            assert_eq!(errcode, "M_FORBIDDEN");
            assert!(!reason.is_empty());
        }
        Decision::Allow => panic!("expected block"),
    }
}

// --- multi-plugin block-if-any ---------------------------------------------

#[test]
fn block_if_any_regardless_of_order() {
    let ev = message("clean");
    // allow then block, and block then allow — both must block.
    assert!(matches!(
        run(
            vec![plugin("a", "allow"), plugin("b", "block")],
            &ev,
            "m.room.message"
        ),
        Decision::Block { .. }
    ));
    assert!(matches!(
        run(
            vec![plugin("b", "block"), plugin("a", "allow")],
            &ev,
            "m.room.message"
        ),
        Decision::Block { .. }
    ));
}

#[test]
fn all_allow_means_allow() {
    let ev = message("clean");
    let d = run(
        vec![plugin("a", "allow"), plugin("b", "allow")],
        &ev,
        "m.room.message",
    );
    assert_eq!(d, Decision::Allow);
}

// --- scoped activation ------------------------------------------------------

#[test]
fn scoped_plugin_is_skipped_for_other_event_types() {
    let mut p = plugin("blocker", "block");
    p.event_types = Some(vec!["m.room.message".to_string()]);
    // A blocking plugin scoped to messages must not fire on a membership event.
    let d = run(vec![p], &message("hi"), "m.room.member");
    assert_eq!(d, Decision::Allow);
}

// --- adversarial: resource limits ------------------------------------------

#[test]
fn infinite_loop_is_trapped_by_fuel_then_fails_open() {
    let mut p = plugin("looper", "loop");
    p.fuel = 1_000_000; // small CPU budget; the spin loop must exhaust it
    p.fail_policy = FailPolicy::Open;
    let d = run(vec![p], &message("hi"), "m.room.message");
    assert_eq!(d, Decision::Allow, "fuel-trapped plugin should fail open");
}

#[test]
fn infinite_loop_can_fail_closed() {
    let mut p = plugin("looper", "loop");
    p.fuel = 1_000_000;
    p.fail_policy = FailPolicy::Closed;
    assert!(matches!(
        run(vec![p], &message("hi"), "m.room.message"),
        Decision::Block { .. }
    ));
}

#[test]
fn memory_bomb_is_trapped_by_the_cap() {
    let mut p = plugin("bomb", "membomb");
    p.memory_pages = 64; // 4 MiB cap; the unbounded grow must hit it
    p.fuel = 10_000_000_000; // plenty of fuel so memory (not fuel) traps first
    p.fail_policy = FailPolicy::Open;
    let d = run(vec![p], &message("hi"), "m.room.message");
    assert_eq!(d, Decision::Allow, "memory-capped plugin should fail open");
}

// --- a failing plugin never overrides another's allow-vs-block correctly ----

#[test]
fn fail_open_plugin_does_not_mask_a_real_block() {
    // looper fails open (→ skipped), blocker blocks → overall block.
    let mut looper = plugin("looper", "loop");
    looper.fuel = 1_000_000;
    looper.fail_policy = FailPolicy::Open;
    let d = run(
        vec![looper, plugin("blocker", "block")],
        &message("hi"),
        "m.room.message",
    );
    assert!(matches!(d, Decision::Block { .. }));
}

// --- negative space: concurrency + bad input -------------------------------

#[test]
fn runtime_is_shareable_across_threads() {
    use std::sync::Arc;
    use std::thread;

    // One runtime, many concurrent callers. A fresh store per call means no
    // shared mutable state; this pins Send + Sync and the stateless contract.
    let rt = Arc::new(Runtime::new(vec![plugin("p", "allow")]).expect("loads"));
    let handles: Vec<_> = (0..16)
        .map(|i| {
            let rt = Arc::clone(&rt);
            thread::spawn(move || {
                let spam = i % 2 == 0;
                let ev = message(if spam { "buy SPAM now" } else { "hello" });
                let ctx = EventContext {
                    event: &ev,
                    room_id: "!room:example.org",
                    sender: "@alice:example.org",
                    event_type: "m.room.message",
                    origin: Origin::Local,
                };
                match rt.check_event(&ctx) {
                    Decision::Block { .. } => assert!(spam),
                    Decision::Allow => assert!(!spam),
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("thread panicked");
    }
}

#[test]
fn invalid_component_fails_to_load_naming_the_plugin() {
    let mut p = plugin("bogus", "allow");
    p.wasm = b"this is not a wasm component".to_vec();
    let err = match Runtime::new(vec![p]) {
        Ok(_) => panic!("should refuse to start with invalid component"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("bogus"), "error names the plugin");
}

#[test]
fn core_module_is_rejected_as_not_a_component() {
    // A valid *core* module is not a component; the runtime must reject it
    // rather than mis-instantiate.
    let mut p = plugin("coremod", "allow");
    p.wasm = wat::parse_str("(module)").expect("valid wat");
    assert!(Runtime::new(vec![p]).is_err());
}

// --- adversarial: stack + traps beyond fuel --------------------------------

#[test]
fn unbounded_recursion_is_trapped_by_the_stack_limit() {
    // Ample fuel so it's the *stack* limit, not fuel, that stops the recursion.
    let mut p = plugin("recurser", "recurse");
    p.fuel = 10_000_000_000;
    p.fail_policy = FailPolicy::Open;
    let d = run(vec![p], &message("hi"), "m.room.message");
    assert_eq!(d, Decision::Allow, "stack-trapped plugin should fail open");
}

#[test]
fn wall_clock_deadline_traps_independently_of_fuel() {
    // Effectively unlimited fuel, so only the wall-clock budget can stop the
    // spin loop. Proves the epoch backstop, not fuel, is doing the work.
    let mut p = plugin("slowloop", "loop");
    p.fuel = u64::MAX / 2;
    p.wall_ms = 50;
    p.fail_policy = FailPolicy::Open;
    let start = std::time::Instant::now();
    let d = run(vec![p], &message("hi"), "m.room.message");
    assert_eq!(
        d,
        Decision::Allow,
        "wall-clock-trapped plugin should fail open"
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "must trap on the wall deadline, not run toward fuel exhaustion"
    );
}

#[test]
fn explicit_trap_respects_fail_closed() {
    let mut p = plugin("trapper", "trap");
    p.fail_policy = FailPolicy::Closed;
    assert!(matches!(
        run(vec![p], &message("hi"), "m.room.message"),
        Decision::Block { .. }
    ));
}

#[test]
fn instances_are_stateless_across_calls() {
    // One runtime, the same plugin called twice. The "counter" guest blocks only
    // if a module-global survived a prior call; a fresh instance per call means
    // both calls must Allow.
    let rt = Runtime::new(vec![plugin("c", "counter")]).expect("loads");
    let ev = message("hi");
    let ctx = EventContext {
        event: &ev,
        room_id: "!room:example.org",
        sender: "@alice:example.org",
        event_type: "m.room.message",
        origin: Origin::Local,
    };
    assert_eq!(rt.check_event(&ctx), Decision::Allow, "first call");
    assert_eq!(
        rt.check_event(&ctx),
        Decision::Allow,
        "second call must see a fresh instance, not leaked state"
    );
}

// --- federation origin ------------------------------------------------------

#[test]
fn federation_origin_allows_normally() {
    // A clean event from federation passes like any other; origin only matters
    // when a Block must be soft-failed (the caller's job, PR2).
    let rt = Runtime::new(vec![plugin("p", "allow")]).expect("loads");
    let ev = message("hello");
    let ctx = EventContext {
        event: &ev,
        room_id: "!room:example.org",
        sender: "@bob:remote.example",
        event_type: "m.room.message",
        origin: Origin::Federation,
    };
    assert_eq!(rt.check_event(&ctx), Decision::Allow);
}

#[test]
fn federation_block_returns_block_for_the_caller_to_soft_fail() {
    // The runtime returns a pure Block for a federated event too — no panic. The
    // origin-aware caller (federation receive) maps that Block to a soft-fail
    // (store + hide), never a hard reject. This pins that the runtime itself is
    // origin-agnostic and leaves the local-vs-federation policy to the caller.
    let rt = Runtime::new(vec![plugin("b", "block")]).expect("loads");
    let ev = message("hi");
    let ctx = EventContext {
        event: &ev,
        room_id: "!room:example.org",
        sender: "@bob:remote.example",
        event_type: "m.room.message",
        origin: Origin::Federation,
    };
    assert!(matches!(rt.check_event(&ctx), Decision::Block { .. }));
}

// --- adversarial under concurrency -----------------------------------------

#[test]
fn traps_stay_isolated_under_concurrency() {
    use std::sync::Arc;
    use std::thread;

    // 16 concurrent callers, each tripping a different resource trap that fails
    // open. A trap in one store must not corrupt another; all must Allow.
    let rt = Arc::new(
        Runtime::new(vec![{
            let mut p = plugin("looper", "loop");
            p.fuel = 1_000_000;
            p
        }])
        .expect("loads"),
    );
    let bomb_rt = Arc::new(
        Runtime::new(vec![{
            let mut p = plugin("bomb", "membomb");
            p.memory_pages = 64;
            p.fuel = 10_000_000_000;
            p
        }])
        .expect("loads"),
    );

    let handles: Vec<_> = (0..16)
        .map(|i| {
            let rt = if i % 2 == 0 {
                Arc::clone(&rt)
            } else {
                Arc::clone(&bomb_rt)
            };
            thread::spawn(move || {
                let ev = message("hi");
                let ctx = EventContext {
                    event: &ev,
                    room_id: "!room:example.org",
                    sender: "@alice:example.org",
                    event_type: "m.room.message",
                    origin: Origin::Local,
                };
                assert_eq!(rt.check_event(&ctx), Decision::Allow);
            })
        })
        .collect();
    for h in handles {
        h.join().expect("thread panicked");
    }
}

// --- observation point (on_event) + points routing -------------------------

/// An observer-only plugin: binds `on_event`, not `check_event`.
fn observer(name: &str, mode: &str) -> PluginConfig {
    let mut p = plugin(name, mode);
    p.points = Points {
        check_event: false,
        on_event: true,
    };
    p
}

fn ctx_for<'a>(event: &'a Value, event_type: &'a str) -> EventContext<'a> {
    EventContext {
        event,
        room_id: "!room:example.org",
        sender: "@alice:example.org",
        event_type,
        origin: Origin::Local,
    }
}

#[test]
fn observer_only_plugin_is_skipped_by_check_event() {
    // Binds on_event, not check_event. Even in block mode it must NOT affect a
    // decision — check_event skips it → Allow.
    let rt = Runtime::new(vec![observer("obs", "block")]).expect("loads");
    assert_eq!(
        rt.check_event(&ctx_for(&message("hi"), "m.room.message")),
        Decision::Allow
    );
    assert!(rt.binds_on_event());
}

#[test]
fn decision_only_plugin_is_skipped_by_on_event() {
    // Default points = decision-only. A loop-mode decision plugin would hang
    // on_event if it were invoked there — it isn't, so on_event returns fast.
    let mut p = plugin("dec", "loop");
    p.fuel = 1_000_000;
    let rt = Runtime::new(vec![p]).expect("loads");
    assert!(!rt.binds_on_event());
    let start = std::time::Instant::now();
    rt.on_event(&ctx_for(&message("hi"), "m.room.message"));
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "on_event must not invoke a decision-only plugin"
    );
}

#[test]
fn on_event_is_fuel_bounded() {
    // An observer that spins must be fuel-bounded: on_event returns promptly
    // rather than hanging the worker. (No verdict — observation can't block.)
    let mut p = observer("looper", "loop");
    p.fuel = 1_000_000;
    let rt = Runtime::new(vec![p]).expect("loads");
    let start = std::time::Instant::now();
    rt.on_event(&ctx_for(&message("hi"), "m.room.message"));
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "on_event must be fuel-bounded, not hang"
    );
}

#[test]
fn on_event_completes_for_a_normal_event() {
    // Smoke: a well-behaved observer returns cleanly.
    let rt = Runtime::new(vec![observer("obs", "allow")]).expect("loads");
    rt.on_event(&ctx_for(&message("hello"), "m.room.message"));
}

#[test]
fn a_plugin_can_bind_both_points() {
    // points = both → check_event decides AND on_event observes.
    let mut p = plugin("both", "block");
    p.points = Points {
        check_event: true,
        on_event: true,
    };
    let rt = Runtime::new(vec![p]).expect("loads");
    assert!(matches!(
        rt.check_event(&ctx_for(&message("hi"), "m.room.message")),
        Decision::Block { .. }
    ));
    assert!(rt.binds_on_event());
    rt.on_event(&ctx_for(&message("hi"), "m.room.message")); // no-op observe, returns
}

// --- logging capability (the first host import) ----------------------------

/// Minimal tracing subscriber that counts events at a target — proves the
/// `logging` host import reaches vela's log, with no dev-dependency. Span
/// methods are stubs; only `event` is observed.
struct LogCounter {
    target: &'static str,
    count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl tracing::Subscriber for LogCounter {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if event.metadata().target() == self.target {
            self.count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

fn count_plugin_logs(rt: &Runtime, ctx: &EventContext<'_>) -> usize {
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sub = LogCounter {
        target: "vela::extensions::plugin",
        count: count.clone(),
    };
    tracing::subscriber::with_default(sub, || rt.on_event(ctx));
    count.load(std::sync::atomic::Ordering::Relaxed)
}

#[test]
fn on_event_logging_capability_reaches_velas_log() {
    // The guest calls back into the host via the `logging` import; the line must
    // arrive at vela's plugin log target. The "log" fixture emits one per level.
    let rt = Runtime::new(vec![observer("logger", "log")]).expect("loads");
    let n = count_plugin_logs(&rt, &ctx_for(&message("hello"), "m.room.message"));
    assert_eq!(n, 5, "one line per level should reach the log");
}

#[test]
fn on_event_log_flood_is_host_bounded() {
    // A plugin that calls the logging cap 10k× must not flood the log: the host
    // caps lines per invocation, so far fewer than 10k reach tracing.
    let rt = Runtime::new(vec![observer("flooder", "logflood")]).expect("loads");
    let n = count_plugin_logs(&rt, &ctx_for(&message("hello"), "m.room.message"));
    assert!(n > 0, "some lines should be emitted");
    // The exact contract: at most MAX_LOG_CALLS (64) honored + 1 suppression
    // notice. 10k calls collapse to ≤65 — pin it tightly, not just "< a lot".
    assert!(n <= 65, "the host must bound a log flood to 64+1, got {n}");
}

// --- emit-event capability (host import + injected service) -----------------

use std::sync::Mutex;
use vela_extensions::{EmitError, EmitRequest, EventEmitter};

const EMIT_FIXTURE: &[u8] = include_bytes!("fixtures/emit_guest.wasm");

/// Records every emit the host forwarded — so a test can assert the host's
/// pre-emit gates (grant, allowlist, state rejection, rate cap) let through
/// exactly what they should.
#[derive(Default)]
struct MockEmitter {
    calls: Mutex<Vec<EmitRequest>>,
}

impl EventEmitter for MockEmitter {
    fn emit(&self, _plugin: &str, req: EmitRequest) -> Result<String, EmitError> {
        self.calls.lock().unwrap().push(req);
        Ok("$mockevent:example.org".to_string())
    }
}

fn emit_config(mode: &str, granted: bool) -> PluginConfig {
    PluginConfig {
        name: "emitter".into(),
        wasm: EMIT_FIXTURE.to_vec(),
        fail_policy: FailPolicy::Open,
        fuel: 50_000_000,
        wall_ms: 0,
        memory_pages: 256,
        event_types: None,
        points: Points {
            check_event: false,
            on_event: true,
        },
        capabilities: Capabilities {
            emit_event: granted,
        },
        config: json!({ "mode": mode }),
    }
}

fn emit_runtime(mode: &str, mock: std::sync::Arc<MockEmitter>) -> Runtime {
    Runtime::with_emitter(
        vec![emit_config(mode, true)],
        Some(mock as std::sync::Arc<dyn EventEmitter>),
    )
    .expect("emit-granted runtime loads")
}

#[test]
fn emit_posts_through_the_injected_emitter_when_granted() {
    let mock = std::sync::Arc::new(MockEmitter::default());
    let rt = emit_runtime("emit_message", mock.clone());
    rt.on_event(&ctx_for(&message("hi"), "m.room.message"));
    let calls = mock.calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "one message should reach the emitter");
    assert_eq!(calls[0].event_type, "m.room.message");
    assert_eq!(calls[0].room_id, "!room:example.org");
}

#[test]
fn emit_rejects_state_events_before_the_emitter() {
    let mock = std::sync::Arc::new(MockEmitter::default());
    let rt = emit_runtime("emit_state", mock.clone());
    rt.on_event(&ctx_for(&message("hi"), "m.room.message"));
    assert!(
        mock.calls.lock().unwrap().is_empty(),
        "a state-event emit must be rejected by the host, never reach the emitter"
    );
}

#[test]
fn emit_rejects_non_allowlisted_types_before_the_emitter() {
    let mock = std::sync::Arc::new(MockEmitter::default());
    let rt = emit_runtime("emit_member", mock.clone());
    rt.on_event(&ctx_for(&message("hi"), "m.room.message"));
    assert!(
        mock.calls.lock().unwrap().is_empty(),
        "a disallowed event type must be rejected by the host"
    );
}

#[test]
fn emit_is_rate_capped_per_plugin() {
    let mock = std::sync::Arc::new(MockEmitter::default());
    let rt = emit_runtime("emit_flood", mock.clone());
    rt.on_event(&ctx_for(&message("hi"), "m.room.message"));
    let n = mock.calls.lock().unwrap().len();
    assert!(
        n > 0 && n <= 20,
        "a 100-emit flood must be capped at the burst (20), got {n}"
    );
}

#[test]
fn ungranted_plugin_importing_emit_fails_to_load() {
    // The emit fixture imports `emit`; without the grant the host doesn't link
    // that interface, so the component can't instantiate — the enforcement that
    // an ungranted plugin simply cannot acquire the capability.
    assert!(
        Runtime::new(vec![emit_config("emit_message", false)]).is_err(),
        "an ungranted plugin that imports emit must fail to load"
    );
}
