//! Proves an SDK-built example plugin loads and runs in the host runtime — the
//! end-to-end SDK→host contract over the shared WIT. The component is the
//! committed `keyword-filter` example, built from `extensions/`.
#![cfg(feature = "wasmtime-runtime")]

use serde_json::{Value, json};
use vela_extensions::{Decision, EventContext, FailPolicy, Origin, PluginConfig, Runtime};

const KEYWORD_FILTER: &[u8] =
    include_bytes!("../../extensions/examples/keyword-filter/keyword-filter.wasm");

fn runtime(config: Value) -> Runtime {
    Runtime::new(vec![PluginConfig {
        name: "keyword-filter".into(),
        wasm: KEYWORD_FILTER.to_vec(),
        // Fail closed in tests so an unexpected trap surfaces as a block rather
        // than being masked by fail-open.
        fail_policy: FailPolicy::Closed,
        fuel: 50_000_000,
        wall_ms: 0,
        memory_pages: 256,
        event_types: None,
        config,
    }])
    .expect("example plugin loads in the host runtime")
}

fn message(body: &str) -> Value {
    json!({ "type": "m.room.message", "content": { "msgtype": "m.text", "body": body } })
}

fn check(rt: &Runtime, event: &Value, event_type: &str) -> Decision {
    rt.check_event(&EventContext {
        event,
        room_id: "!r:example.org",
        sender: "@a:example.org",
        event_type,
        origin: Origin::Local,
    })
}

#[test]
fn blocks_configured_banned_terms_case_insensitively() {
    let rt = runtime(json!({ "banned": ["spam", "buy now"] }));
    assert!(matches!(
        check(&rt, &message("cheap SPAM here"), "m.room.message"),
        Decision::Block { .. }
    ));
    assert!(matches!(
        check(&rt, &message("BUY NOW!!!"), "m.room.message"),
        Decision::Block { .. }
    ));
}

#[test]
fn allows_clean_messages() {
    let rt = runtime(json!({ "banned": ["spam"] }));
    assert_eq!(
        check(&rt, &message("hello friends"), "m.room.message"),
        Decision::Allow
    );
}

#[test]
fn empty_config_allows_everything() {
    let rt = runtime(json!({}));
    assert_eq!(
        check(&rt, &message("spam spam spam"), "m.room.message"),
        Decision::Allow
    );
}

#[test]
fn non_message_events_pass_through() {
    // The plugin only inspects message bodies; a topic change has no body.
    let rt = runtime(json!({ "banned": ["spam"] }));
    let topic = json!({ "type": "m.room.topic", "content": { "topic": "spam" } });
    assert_eq!(check(&rt, &topic, "m.room.topic"), Decision::Allow);
}

#[test]
fn honors_a_custom_errcode() {
    let rt = runtime(json!({ "banned": ["spam"], "errcode": "IO.EXAMPLE.BLOCKED" }));
    match check(&rt, &message("spam"), "m.room.message") {
        Decision::Block { errcode, .. } => assert_eq!(errcode, "IO.EXAMPLE.BLOCKED"),
        Decision::Allow => panic!("expected a block"),
    }
}

#[test]
fn malformed_config_traps_and_is_resolved_by_fail_policy() {
    // `banned` must be a list; a string is invalid. The SDK's `config()` panics
    // on invalid config → the guest traps → the host applies fail_policy. This is
    // the point: a config mistake surfaces (here as a block / a logged trap),
    // never a silent "blocklist is empty, allow everything".
    let bad = json!({ "banned": "not-a-list" });

    // fail_policy = closed (the helper default) → trap becomes a block.
    let rt = runtime(bad.clone());
    assert!(matches!(
        check(&rt, &message("hi"), "m.room.message"),
        Decision::Block { .. }
    ));

    // fail_policy = open → trap becomes an allow, but the operator still sees it
    // via trap metrics/logs (not a silent config default).
    let rt_open = Runtime::new(vec![PluginConfig {
        name: "keyword-filter".into(),
        wasm: KEYWORD_FILTER.to_vec(),
        fail_policy: FailPolicy::Open,
        fuel: 50_000_000,
        wall_ms: 0,
        memory_pages: 256,
        event_types: None,
        config: bad,
    }])
    .expect("loads");
    assert_eq!(
        check(&rt_open, &message("hi"), "m.room.message"),
        Decision::Allow
    );
}
