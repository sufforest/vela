# room-policy

A first-party example plugin that enforces **room-creation policy from
declarative config** — no server-side rule engine. It binds the
`check_room_create` point and reads every rule from the operator's `config`
block, so an admin gets config-driven policy without writing any WASM.

This is the pattern vela uses instead of a built-in rule engine: common policy is
a known, audited plugin plus its config; custom logic is your own plugin. One
mechanism, all sandboxed.

## Configure

```toml
[[extensions.plugin]]
name = "room-policy"
wasm_path = "/etc/vela/plugins/room-policy.wasm"
points = ["check_room_create"]
capabilities = ["kv"]                 # required — this plugin uses the kv store
config = {
    deny_public = true,               # block rooms requesting public visibility
    max_rooms_per_user_per_day = 10,  # per-creator rolling-24h cap (needs kv)
    max_invites = 50,                 # invite-bomb guard
    banned_alias_substrings = ["official", "admin"],  # case-insensitive
}
```

Every config field is optional — omit one to turn that rule off. A blocked
creation is rejected before anything is persisted (no room, no alias), with HTTP
403.

**`capabilities = ["kv"]` is required**, not optional: this plugin references the
`kv` store (for the rate-limit counter), so its component imports the `kv`
capability and won't load without the grant — vela aborts startup on a plugin it
can't instantiate. (If you want a kv-free subset, drop the
`max_rooms_per_user_per_day` rule from your own build of this plugin so the kv
import goes away.)

The `max_rooms_per_user_per_day` rule keeps a per-creator counter in `kv` with a
24-hour TTL. A blocked attempt doesn't bump the counter, so it can't extend its
own lockout — the window is 24h from the last *successful* create.

## Build

```sh
cargo build --release --target wasm32-unknown-unknown
wasm-tools component new \
    target/wasm32-unknown-unknown/release/room_policy.wasm \
    -o room-policy.wasm
```

Or, from the repo, `extensions/build-examples.sh` builds it alongside the other
examples. See the [SDK README](../../sdk/README.md) for the plugin API.
