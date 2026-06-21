//! Proves the `room-policy` example plugin enforces declarative config rules over
//! `check_room_create`, including the kv-backed per-creator rate limit — which
//! exercises the SDK's kv-from-decision-points path (`RoomCreate::kv`). The
//! component references `kv`, so it's loaded with the capability granted and a
//! store wired. Build it first: `extensions/build-examples.sh` (CI does).
#![cfg(feature = "wasmtime-runtime")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use vela_extensions::{
    Capabilities, ClientIpTier, Decision, FailPolicy, HostServices, KvError, KvStore, PluginConfig,
    Points, RoomCreate, Runtime,
};

const ROOM_POLICY: &[u8] = include_bytes!("../../extensions/examples/room-policy/room-policy.wasm");

/// `(plugin name, key)` → value.
type KvMap = HashMap<(String, Vec<u8>), Vec<u8>>;

/// HashMap-backed kv store so the rate-limit counter persists across calls.
/// Ignores TTL/quota (the store's job, tested in vela-store).
#[derive(Default)]
struct MockKv {
    store: Mutex<KvMap>,
}

impl KvStore for MockKv {
    fn get(&self, plugin: &str, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        Ok(self
            .store
            .lock()
            .unwrap()
            .get(&(plugin.to_string(), key.to_vec()))
            .cloned())
    }
    fn set(
        &self,
        plugin: &str,
        key: &[u8],
        value: &[u8],
        _ttl: Option<u64>,
    ) -> Result<(), KvError> {
        self.store
            .lock()
            .unwrap()
            .insert((plugin.to_string(), key.to_vec()), value.to_vec());
        Ok(())
    }
    fn delete(&self, plugin: &str, key: &[u8]) -> Result<(), KvError> {
        self.store
            .lock()
            .unwrap()
            .remove(&(plugin.to_string(), key.to_vec()));
        Ok(())
    }
}

fn plugin_config(rules: Value, kv_granted: bool) -> PluginConfig {
    PluginConfig {
        name: "room-policy".into(),
        wasm: ROOM_POLICY.to_vec(),
        fail_policy: FailPolicy::Closed,
        fuel: 50_000_000,
        wall_ms: 0,
        memory_pages: 256,
        event_types: None,
        points: Points {
            check_event: false,
            on_event: false,
            check_registration: false,
            check_media_upload: false,
            check_profile_update: false,
            check_room_create: true,
            filter_sync_event: false,
            check_login: false,
        },
        capabilities: Capabilities {
            kv: kv_granted,
            ..Default::default()
        },
        client_ip: ClientIpTier::default(),
        config: rules,
    }
}

fn runtime(rules: Value) -> Runtime {
    Runtime::with_services(
        vec![plugin_config(rules, true)],
        HostServices {
            kv: Some(Arc::new(MockKv::default()) as Arc<dyn KvStore>),
            ..Default::default()
        },
    )
    .expect("room-policy loads")
}

fn ctx<'a>(
    creator: &'a str,
    visibility: Option<&'a str>,
    alias: Option<&'a str>,
    invite: &'a [String],
) -> RoomCreate<'a> {
    RoomCreate {
        creator,
        room_id: "!r:example.org",
        room_version: "12",
        preset: if visibility == Some("public") {
            "public_chat"
        } else {
            "private_chat"
        },
        visibility,
        name: None,
        topic: None,
        alias_localpart: alias,
        invite,
        is_direct: false,
    }
}

#[test]
fn denies_public_rooms() {
    let rt = runtime(json!({ "deny_public": true }));
    assert!(matches!(
        rt.check_room_create(&ctx("@a:x", Some("public"), None, &[])),
        Decision::Block { .. }
    ));
    assert_eq!(
        rt.check_room_create(&ctx("@a:x", Some("private"), None, &[])),
        Decision::Allow
    );
}

#[test]
fn caps_invites() {
    let rt = runtime(json!({ "max_invites": 2 }));
    let many = vec!["@b:x".to_string(), "@c:x".to_string(), "@d:x".to_string()];
    assert!(matches!(
        rt.check_room_create(&ctx("@a:x", None, None, &many)),
        Decision::Block { .. }
    ));
    let few = vec!["@b:x".to_string(), "@c:x".to_string()];
    assert_eq!(
        rt.check_room_create(&ctx("@a:x", None, None, &few)),
        Decision::Allow
    );
}

#[test]
fn blocks_banned_alias() {
    let rt = runtime(json!({ "banned_alias_substrings": ["admin"] }));
    // Case-insensitive substring match.
    assert!(matches!(
        rt.check_room_create(&ctx("@a:x", None, Some("TeamAdmins"), &[])),
        Decision::Block { .. }
    ));
    assert_eq!(
        rt.check_room_create(&ctx("@a:x", None, Some("lounge"), &[])),
        Decision::Allow
    );
}

#[test]
fn rate_limits_creations_per_creator() {
    let rt = runtime(json!({ "max_rooms_per_user_per_day": 2 }));
    // The kv counter persists across calls: first two allowed, third blocked.
    assert_eq!(
        rt.check_room_create(&ctx("@a:x", None, None, &[])),
        Decision::Allow
    );
    assert_eq!(
        rt.check_room_create(&ctx("@a:x", None, None, &[])),
        Decision::Allow
    );
    assert!(matches!(
        rt.check_room_create(&ctx("@a:x", None, None, &[])),
        Decision::Block { .. }
    ));
    // A different creator has its own counter — still allowed.
    assert_eq!(
        rt.check_room_create(&ctx("@b:x", None, None, &[])),
        Decision::Allow
    );
}

#[test]
fn fails_to_load_without_kv_grant() {
    // room-policy references the kv store, so its component imports `kv` — loading
    // it without the grant must error (vela aborts startup on a plugin it can't
    // instantiate), never silently run. Pins the "kv is mandatory" contract.
    let cfg = plugin_config(json!({ "deny_public": true }), false);
    assert!(
        Runtime::new(vec![cfg]).is_err(),
        "room-policy imports kv; it must fail to load without capabilities = [\"kv\"]"
    );
}
