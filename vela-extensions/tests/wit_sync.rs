//! The SDK vendors its own copy of the WIT (so it's a self-contained,
//! publishable crate). This guards against the two copies drifting — a silent
//! host↔guest ABI mismatch would be the worst kind of bug. If this fails,
//! re-copy: `cp vela-extensions/wit/extension.wit extensions/sdk/wit/extension.wit`.

const HOST_WIT: &str = include_str!("../wit/extension.wit");
const SDK_WIT: &str = include_str!("../../extensions/sdk/wit/extension.wit");

#[test]
fn sdk_wit_is_identical_to_host_wit() {
    assert_eq!(
        HOST_WIT, SDK_WIT,
        "extensions/sdk/wit/extension.wit drifted from vela-extensions/wit/extension.wit"
    );
}
