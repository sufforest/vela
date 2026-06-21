//! A single test-fixture plugin that switches behavior by its `plugin-config`,
//! so one committed component drives every host test (allow, block, fuel trap,
//! memory cap). Behavior is selected by a substring in `plugin-config` — crude
//! on purpose, to keep the component tiny and free of a JSON dependency.
//!
//! Modes (substring in plugin-config):
//!   "loop"    → spin forever              → host fuel limit traps it
//!   "membomb" → allocate without bound    → host memory limit traps it
//!   "recurse" → unbounded recursion       → host wasm-stack limit traps it
//!   "trap"    → panic                     → wasm trap (panic = "abort")
//!   "counter" → Block only if instance state survived a prior call; since each
//!               call is a fresh instance it must always Allow — proves the
//!               stateless contract behaviorally
//!   "block"   → always Block
//!   "log"     → (on_event) emit one line at each level via the logging cap
//!   "logflood"→ (on_event) call the logging cap 10k× → host must bound it
//!   (default) → Block iff the event JSON contains "SPAM", else Allow

use core::sync::atomic::{AtomicU32, Ordering};

wit_bindgen::generate!({
    path: "../../../wit/extension.wit",
    world: "plugin",
});

use exports::vela::extension::decision::{BlockReason, EventContext, Guest, Verdict};

struct Component;

impl Guest for Component {
    // Read-path sync filter unused by this fixture — show everything.
    fn filter_sync_event(
        _ctx: exports::vela::extension::decision::SyncEventContext,
    ) -> bool {
        true
    }

    // Room-create point unused by this fixture — default allow.
    fn check_room_create(
        _ctx: exports::vela::extension::decision::RoomCreateContext,
    ) -> Verdict {
        Verdict::Allow
    }

    // Profile point unused by this fixture — default allow.
    fn check_profile_update(
        _ctx: exports::vela::extension::decision::ProfileContext,
    ) -> Verdict {
        Verdict::Allow
    }

    fn check_media_upload(
        _ctx: exports::vela::extension::decision::MediaContext,
    ) -> Verdict {
        Verdict::Allow
    }

    // Registration point unused by this fixture — default allow.
    fn check_registration(
        _ctx: exports::vela::extension::decision::RegistrationContext,
    ) -> Verdict {
        Verdict::Allow
    }

    fn check_event(ctx: EventContext) -> Verdict {
        let cfg = ctx.plugin_config.as_str();

        if cfg.contains("loop") {
            // Unbounded CPU: the host's fuel budget must trap this.
            #[allow(clippy::empty_loop)]
            loop {
                core::hint::spin_loop();
            }
        }

        if cfg.contains("membomb") {
            // Unbounded memory: the host's memory cap must trap the grow.
            let mut sink: Vec<u8> = Vec::new();
            loop {
                sink.extend(core::iter::repeat(0u8).take(64 * 1024));
                // Keep the optimizer from eliding the allocation.
                core::hint::black_box(sink.last());
            }
        }

        if cfg.contains("recurse") {
            // Unbounded recursion (non-tail, so frames pile up): the host's
            // wasm-stack limit must trap this even with ample fuel.
            return recurse(core::hint::black_box(u64::MAX));
        }

        if cfg.contains("trap") {
            // panic = "abort" makes this a hard wasm trap, not an unwind.
            panic!("test plugin trapping on purpose");
        }

        if cfg.contains("counter") {
            // A module-global that increments per call. A fresh instance per
            // call resets it to 0, so `prev` is always 0 → Allow. If state ever
            // leaked across calls, the second call would see 1 → Block.
            static SEEN: AtomicU32 = AtomicU32::new(0);
            let prev = SEEN.fetch_add(1, Ordering::Relaxed);
            return if prev == 0 {
                Verdict::Allow
            } else {
                blocked("plugin state leaked across calls")
            };
        }

        if cfg.contains("block") {
            return blocked("blocked unconditionally by test plugin");
        }

        if ctx.event.contains("SPAM") {
            blocked("message looks like spam")
        } else {
            Verdict::Allow
        }
    }
}

#[inline(never)]
fn recurse(n: u64) -> Verdict {
    if n == 0 {
        Verdict::Allow
    } else {
        // Use the result after the call so it isn't a tail call.
        let v = recurse(n - 1);
        core::hint::black_box(&v);
        v
    }
}

fn blocked(reason: &str) -> Verdict {
    Verdict::Block(BlockReason {
        errcode: "M_FORBIDDEN".to_string(),
        reason: reason.to_string(),
    })
}

// Observation hook. Exercises the sandbox-bound trap modes (so on_event's
// fuel/memory/wall bounds are testable) and the `logging` host capability.
impl exports::vela::extension::observation::Guest for Component {
    fn on_event(ctx: exports::vela::extension::observation::EventContext) {
        run_log_modes(&ctx.plugin_config);
        run_trap_modes(&ctx.plugin_config);
    }
}

// Exercise the `logging` host import (a host capability — the guest calling back
// into vela). "logflood" calls it far past the host's per-call budget to prove
// the host bounds it; "log" emits one line at each level.
fn run_log_modes(cfg: &str) {
    use vela::extension::logging::{log, LogLevel};
    if cfg.contains("logflood") {
        for i in 0..10_000u32 {
            log(LogLevel::Info, "flood");
            core::hint::black_box(i);
        }
        return;
    }
    if cfg.contains("log") {
        log(LogLevel::Error, "observed event (error)");
        log(LogLevel::Warn, "observed event (warn)");
        log(LogLevel::Info, "observed event (info)");
        log(LogLevel::Debug, "observed event (debug)");
        log(LogLevel::Trace, "observed event (trace)");
    }
}

fn run_trap_modes(cfg: &str) {
    if cfg.contains("loop") {
        #[allow(clippy::empty_loop)]
        loop {
            core::hint::spin_loop();
        }
    }
    if cfg.contains("membomb") {
        let mut sink: Vec<u8> = Vec::new();
        loop {
            sink.extend(core::iter::repeat(0u8).take(64 * 1024));
            core::hint::black_box(sink.last());
        }
    }
    if cfg.contains("recurse") {
        let _ = recurse(core::hint::black_box(u64::MAX));
    }
    if cfg.contains("trap") {
        panic!("test plugin trapping on purpose");
    }
}

export!(Component);
