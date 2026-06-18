//! Feature-agnostic contract tests — NOT gated on `wasmtime-runtime`, so they
//! run in both the full build and the wasmtime-free (`--no-default-features`)
//! build. They pin the behavior that must hold regardless of the runtime:
//! an empty runtime allows everything and reports itself empty.
//!
//! With the feature OFF, `Runtime` is the no-op stub (always Allow); with it ON,
//! a runtime with zero plugins also allows. Both must agree here.

use serde_json::json;
use vela_extensions::{Decision, EventContext, Origin, Runtime};

#[test]
fn empty_runtime_allows_and_reports_empty() {
    let rt = Runtime::new(vec![]).expect("empty runtime loads");
    assert!(rt.is_empty());

    let ev = json!({ "type": "m.room.message" });
    let ctx = EventContext {
        event: &ev,
        room_id: "!room:example.org",
        sender: "@alice:example.org",
        event_type: "m.room.message",
        origin: Origin::Local,
    };
    assert_eq!(rt.check_event(&ctx), Decision::Allow);
}
