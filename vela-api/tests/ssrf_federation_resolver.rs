//! Federation outbound SSRF guard: a peer that points at an RFC 1918
//! literal must not coerce vela into dialing the operator's internal
//! network. End-to-end check: build a real `FederationClient` against a
//! strict-policy resolver, ask it to talk to `192.168.0.1`, and assert
//! the request is refused before any TCP connection is attempted.

use std::sync::Arc;

use vela_api::federation::federation_client::{FederationClient, FederationClientError};
use vela_api::federation::federation_resolver::{FederationPolicy, FederationResolver};
use vela_core::events::sign::ServerSigningKey;

fn strict_client(our_server_name: &str) -> FederationClient {
    let key = Arc::new(ServerSigningKey::generate());
    let policy = FederationPolicy::strict(our_server_name.to_string());
    let resolver = Arc::new(FederationResolver::with_policy(policy).expect("resolver"));
    FederationClient::new(key, our_server_name.to_string(), resolver, Vec::new())
}

#[tokio::test]
async fn signed_request_refuses_private_ipv4_destination() {
    let client = strict_client("vela.test");
    let err = client
        .signed_request(
            reqwest::Method::GET,
            "192.168.0.1",
            "/_matrix/federation/v1/version",
            None,
        )
        .await
        .expect_err("must refuse");
    match err {
        FederationClientError::Http(msg) => {
            assert!(
                msg.contains("private") || msg.contains("blocked"),
                "expected SSRF refusal, got {msg:?}"
            );
        }
        other => panic!("expected Http(..) wrapping the SSRF refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn signed_request_refuses_loopback_for_non_self_destination() {
    let client = strict_client("vela.test");
    let err = client
        .signed_request(
            reqwest::Method::GET,
            "127.0.0.1",
            "/_matrix/federation/v1/version",
            None,
        )
        .await
        .expect_err("must refuse");
    assert!(matches!(err, FederationClientError::Http(_)));
}

#[tokio::test]
async fn fetch_server_keys_refuses_private_ipv4() {
    let client = strict_client("vela.test");
    let err = client
        .fetch_server_keys("10.0.0.1")
        .await
        .expect_err("must refuse");
    if let FederationClientError::Http(msg) = err {
        assert!(
            msg.contains("private") || msg.contains("blocked"),
            "{msg:?}"
        );
    } else {
        panic!("expected Http(..)");
    }
}
