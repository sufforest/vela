//! X-Matrix request authentication middleware for inbound federation.
//!
//! Applied to `/_matrix/federation/v1/*` routes. The Matrix key endpoint
//! (`/_matrix/key/v2/server`) is unauthenticated per spec and must NOT go
//! through this layer.
//!
//! Pipeline (per `server-server-api.md:274-387`):
//! 1. Read `Authorization: X-Matrix ...` header. Missing / malformed → 401.
//! 2. If the header specifies `destination`, it must equal our server_name. 401 otherwise.
//! 3. Buffer the request body (10 MiB cap). 413 if over.
//! 4. Reconstruct the signed JSON (method + uri + origin + destination + content).
//! 5. Fetch origin's keys via the cache (may trigger an outbound request). 401 on failure.
//! 6. Verify signature. 401 on failure.
//! 7. Insert `XMatrixOrigin(origin)` into request extensions. Forward to handler.

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use tracing::{debug, warn};

use crate::federation::federation_client::verify_federation_request;
use crate::federation::parse_x_matrix_auth;
use crate::router::AppState;
use vela_core::federation::keys::decode_public_key;

/// Max bytes we'll buffer from a federation request body.
/// 10 MiB gives comfortable headroom for transactions with 50 PDUs.
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Origin server name extracted from a verified X-Matrix request.
/// Handlers downstream of the middleware can pull this from request extensions.
#[derive(Debug, Clone)]
pub struct XMatrixOrigin(pub String);

/// Pre-parsed JSON body attached to request extensions by the federation auth
/// middleware. Handlers use `Extension<VerifiedBody>` to read the body without
/// re-parsing and without hitting axum's default 2 MiB Json limit (our
/// middleware already enforces its own 10 MiB cap).
///
/// `Option<Value>` because GET / DELETE requests may have no body.
#[derive(Debug, Clone)]
pub struct VerifiedBody(pub Option<Value>);

/// axum middleware. Install via
/// `Router::layer(axum::middleware::from_fn_with_state(state, federation_auth))`.
pub async fn federation_auth(State(state): State<AppState>, req: Request, next: Next) -> Response {
    match verify_request(&state, req).await {
        Ok(req) => next.run(req).await,
        Err(code) => code.into_response(),
    }
}

/// Inner verification. Returns the (possibly-body-replaced) request on success,
/// or a response with an appropriate status code on failure.
async fn verify_request(state: &AppState, req: Request) -> Result<Request, StatusCode> {
    let (mut parts, body) = req.into_parts();

    // 1. Authorization header
    let header = parts
        .headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let auth = parse_x_matrix_auth(header).ok_or(StatusCode::UNAUTHORIZED)?;

    // 2. Destination check. Per spec: if present, MUST equal our server_name.
    if let Some(dest) = &auth.destination
        && dest != &state.config.server_name
    {
        warn!(origin = %auth.origin, dest = %dest, "X-Matrix destination mismatch");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Method + URI (path+query) captured from parts.
    let method = parts.method.as_str().to_string();
    let uri = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| parts.uri.path().to_string());

    // 3. Buffer the body. Even GET requests go through this — to_bytes handles
    //    empty bodies cleanly.
    let body_bytes = to_bytes(body, MAX_BODY_BYTES).await.map_err(|e| {
        warn!(error = %e, "failed to buffer federation request body");
        // Differentiate between size limit (413) and other failures (400).
        // reqwest/axum don't give us a clean way to detect size overflow here,
        // so any error is treated as PAYLOAD_TOO_LARGE for safety.
        StatusCode::PAYLOAD_TOO_LARGE
    })?;

    // 4. Parse body as JSON iff non-empty. Federation requests are JSON.
    //    A GET with no body produces empty bytes — we pass None to the verifier.
    let body_json: Option<Value> = if body_bytes.is_empty() {
        None
    } else {
        match serde_json::from_slice::<Value>(&body_bytes) {
            Ok(v) => Some(v),
            Err(e) => {
                warn!(error = %e, "federation request body is not valid JSON");
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    };

    // 5. Fetch origin's keys. Pass the key id the request is signed with so a
    //    rotated signing key (or, in Complement, a port-reused server with a
    //    fresh key) is re-fetched rather than rejected against a stale cache.
    let keys = state
        .remote_keys
        .get_or_fetch_signed(&auth.origin, &[auth.key.as_str()])
        .await
        .map_err(|e| {
            warn!(origin = %auth.origin, error = %e, "failed to fetch origin keys");
            StatusCode::UNAUTHORIZED
        })?;

    // Pick the public key the request claims to use.
    let pub_b64 = keys.verify_keys.get(&auth.key).ok_or_else(|| {
        warn!(origin = %auth.origin, key = %auth.key, "origin does not publish this key_id");
        StatusCode::UNAUTHORIZED
    })?;
    let public_key = decode_public_key(pub_b64).map_err(|e| {
        warn!(error = %e, "invalid public key in cache");
        StatusCode::UNAUTHORIZED
    })?;

    // 6. Verify signature.
    verify_federation_request(
        &method,
        &uri,
        &auth.origin,
        &state.config.server_name,
        body_json.as_ref(),
        &auth.key,
        &public_key,
        &auth.sig,
    )
    .map_err(|e| {
        warn!(origin = %auth.origin, error = %e, "X-Matrix signature verification failed");
        StatusCode::UNAUTHORIZED
    })?;

    debug!(origin = %auth.origin, uri = %uri, "X-Matrix signature verified");

    // Stitch this request's span under the remote-originated trace, if
    // any. No-op without the `otel` feature. Done after signature
    // verification so an unauthenticated peer can't spoof a parent
    // span into our trace.
    crate::trace_context::set_current_parent_from_headers(&parts.headers);

    // 7. Attach the parsed body and origin to request extensions. Handlers
    //    use `Extension<VerifiedBody>` instead of `Json<_>` — this avoids
    //    the axum default 2 MiB Json limit (the middleware has already
    //    enforced its own 10 MiB cap) and avoids double-parsing the JSON.
    parts.extensions.insert(XMatrixOrigin(auth.origin));
    parts.extensions.insert(VerifiedBody(body_json));
    let req = Request::from_parts(parts, Body::from(body_bytes));
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};

    #[test]
    fn xmatrix_origin_is_cloneable_and_debug() {
        let o = XMatrixOrigin("them.example".into());
        let o2 = o.clone();
        assert_eq!(o.0, o2.0);
        let s = format!("{:?}", o);
        assert!(s.contains("them.example"));
    }

    // Plumbing for middleware tests — exercise verify_request against a
    // controlled AppState + a synthetic signed request.
    #[tokio::test]
    async fn rejects_request_missing_authorization() {
        let (state, _tmp) = crate::test_helpers::build_test_state();
        let req = Request::builder()
            .method(Method::GET)
            .uri("/_matrix/federation/v1/whatever")
            .body(Body::empty())
            .unwrap();
        let err = verify_request(&state, req).await.expect_err("must reject");
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_wrong_destination() {
        let (state, _tmp) = crate::test_helpers::build_test_state();
        // Our server_name in test state is "example.com"; sign a request
        // claiming destination = "other.example".
        let remote_key = vela_core::events::sign::ServerSigningKey::generate();
        let header = crate::federation::federation_client::build_x_matrix_header(
            &remote_key,
            "remote.example",
            "GET",
            "/_matrix/federation/v1/whatever",
            "other.example", // wrong destination
            None,
        );
        let req = Request::builder()
            .method(Method::GET)
            .uri("/_matrix/federation/v1/whatever")
            .header("authorization", header)
            .body(Body::empty())
            .unwrap();
        let err = verify_request(&state, req).await.expect_err("must reject");
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn accepts_valid_signed_get_request_when_keys_cached() {
        let (state, _tmp) = crate::test_helpers::build_test_state();

        // Prepare a remote server's keys and pre-seed the cache so the
        // middleware doesn't attempt an outbound HTTP call.
        let remote_key = vela_core::events::sign::ServerSigningKey::generate();
        let now = crate::federation::federation_client::now_ms();
        let mut verify_keys = std::collections::HashMap::new();
        verify_keys.insert(
            remote_key.key_id().to_string(),
            remote_key.public_key_base64(),
        );
        let remote_keys = crate::federation::federation_client::RemoteKeys {
            verify_keys,
            old_verify_keys: Default::default(),
            valid_until_ts: now + 60_000,
            fetched_at: now,
        };
        state
            .remote_keys
            .insert_for_test("remote.example", remote_keys);

        let header = crate::federation::federation_client::build_x_matrix_header(
            &remote_key,
            "remote.example",
            "GET",
            "/_matrix/federation/v1/whatever",
            "example.com", // our server_name from build_test_state
            None,
        );
        let req = Request::builder()
            .method(Method::GET)
            .uri("/_matrix/federation/v1/whatever")
            .header("authorization", header)
            .body(Body::empty())
            .unwrap();
        let verified = verify_request(&state, req).await.expect("must accept");
        let origin = verified
            .extensions()
            .get::<XMatrixOrigin>()
            .expect("origin attached");
        assert_eq!(origin.0, "remote.example");
    }

    #[tokio::test]
    async fn rejects_valid_header_but_unknown_origin_server() {
        let (state, _tmp) = crate::test_helpers::build_test_state();
        let remote_key = vela_core::events::sign::ServerSigningKey::generate();
        let header = crate::federation::federation_client::build_x_matrix_header(
            &remote_key,
            "unreachable.example", // we haven't cached keys; fetch will attempt live and fail
            "GET",
            "/_matrix/federation/v1/whatever",
            "example.com",
            None,
        );
        let req = Request::builder()
            .method(Method::GET)
            .uri("/_matrix/federation/v1/whatever")
            .header("authorization", header)
            .body(Body::empty())
            .unwrap();
        // The middleware will try to fetch keys from unreachable.example and fail.
        let err = verify_request(&state, req).await.expect_err("must reject");
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_request_signed_with_rotated_out_key() {
        let (state, _tmp) = crate::test_helpers::build_test_state();

        // The remote's key is in old_verify_keys only (rotated out). Per spec it
        // verifies historical events but MUST NOT authenticate a live request.
        let remote_key = vela_core::events::sign::ServerSigningKey::generate();
        let now = crate::federation::federation_client::now_ms();
        let mut old_verify_keys = std::collections::HashMap::new();
        old_verify_keys.insert(
            remote_key.key_id().to_string(),
            remote_key.public_key_base64(),
        );
        let remote_keys = crate::federation::federation_client::RemoteKeys {
            verify_keys: Default::default(),
            old_verify_keys,
            valid_until_ts: now + 60_000,
            fetched_at: now,
        };
        state
            .remote_keys
            .insert_for_test("remote.example", remote_keys);

        let header = crate::federation::federation_client::build_x_matrix_header(
            &remote_key,
            "remote.example",
            "GET",
            "/_matrix/federation/v1/whatever",
            "example.com",
            None,
        );
        let req = Request::builder()
            .method(Method::GET)
            .uri("/_matrix/federation/v1/whatever")
            .header("authorization", header)
            .body(Body::empty())
            .unwrap();
        let err = verify_request(&state, req).await.expect_err("must reject");
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }
}
