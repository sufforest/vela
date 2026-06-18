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
//!   (default) → Block iff the event JSON contains "SPAM", else Allow

use core::sync::atomic::{AtomicU32, Ordering};

wit_bindgen::generate!({
    path: "../../../wit/extension.wit",
    world: "plugin",
});

use exports::vela::extension::decision::{BlockReason, EventContext, Guest, Verdict};

struct Component;

impl Guest for Component {
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

export!(Component);
