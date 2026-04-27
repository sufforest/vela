//! Federation endpoints.
//!
//! - GET /_matrix/key/v2/server — return self-signed server keys
//! - PUT /_matrix/federation/v1/send/{txnId} — receive transactions (stub)

use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
use serde_json::{Map, Value, json};
use tracing::{debug, info, warn};
use vela_core::events::sign::ServerSigningKey;

use crate::edu::inbound::dispatch_edu;
use crate::middleware::federation_auth::{VerifiedBody, XMatrixOrigin};
use crate::router::AppState;

/// Build the `/_matrix/key/v2/server` response body, self-signed.
/// Extracted for testability; `get_server_keys` is a thin axum wrapper.
pub fn build_server_key_response(
    signing_key: &ServerSigningKey,
    server_name: &str,
    now_ms: u64,
) -> Map<String, Value> {
    // valid_until_ts: 7 days from now (spec maximum that servers will trust)
    let valid_until_ts = now_ms + 7 * 24 * 60 * 60 * 1000;

    let key_id = signing_key.key_id();
    let public_key_b64 = signing_key.public_key_base64();

    let mut response = Map::new();
    response.insert("server_name".into(), json!(server_name));
    response.insert(
        "verify_keys".into(),
        json!({
            key_id: {
                "key": public_key_b64
            }
        }),
    );
    response.insert("old_verify_keys".into(), json!({}));
    response.insert("valid_until_ts".into(), json!(valid_until_ts));

    signing_key.sign_json(&mut response, server_name);
    response
}

/// GET /_matrix/key/v2/server
///
/// Returns the server's published signing keys, self-signed per spec.
pub async fn get_server_keys(State(state): State<AppState>) -> Json<Value> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let response = build_server_key_response(&state.signing_key, &state.config.server_name, now_ms);

    Json(Value::Object(response))
}

/// Parsed X-Matrix Authorization header parameters.
#[derive(Debug)]
pub struct XMatrixAuth {
    pub origin: String,
    pub destination: Option<String>,
    pub key: String,
    pub sig: String,
}

/// Parse an Authorization header with the X-Matrix scheme.
///
/// Format: `X-Matrix origin="...",destination="...",key="...",sig="..."`
/// Per spec: values may or may not be quoted, names are case-insensitive,
/// order doesn't matter. Backslash-escaped characters in quoted values
/// must be unescaped.
pub fn parse_x_matrix_auth(header: &str) -> Option<XMatrixAuth> {
    let header = header.trim();
    // Must start with "X-Matrix " (case-insensitive scheme)
    if header.len() < 9 || !header[..8].eq_ignore_ascii_case("X-Matrix") {
        return None;
    }

    let params_str = header[8..].trim_start();
    let mut origin = None;
    let mut destination = None;
    let mut key = None;
    let mut sig = None;

    for part in split_auth_params(params_str) {
        let (name, value) = part?;
        match name.to_ascii_lowercase().as_str() {
            "origin" => origin = Some(value),
            "destination" => destination = Some(value),
            "key" => key = Some(value),
            // Spec uses "sig" in examples but also defines "signature"
            "sig" | "signature" => sig = Some(value),
            _ => {} // Unknown parameters are ignored per spec
        }
    }

    Some(XMatrixAuth {
        origin: origin?,
        destination,
        key: key?,
        sig: sig?,
    })
}

/// Split auth parameters, handling quoted values with backslash escapes.
/// Returns an iterator of Option<(name, value)>; None signals a parse error.
fn split_auth_params(s: &str) -> Vec<Option<(String, String)>> {
    let mut results = Vec::new();
    let mut remaining = s.trim();

    while !remaining.is_empty() {
        // Find '='
        let eq_pos = match remaining.find('=') {
            Some(p) => p,
            None => {
                results.push(None);
                return results;
            }
        };
        let name = remaining[..eq_pos].trim().to_string();
        remaining = remaining[eq_pos + 1..].trim_start();

        let (value, rest) = if let Some(after_quote) = remaining.strip_prefix('"') {
            // Quoted value — parse with backslash unescaping
            let mut chars = after_quote.chars();
            let mut value = String::new();
            let mut found_end = false;
            let mut consumed = 1; // opening quote
            while let Some(ch) = chars.next() {
                consumed += ch.len_utf8();
                if ch == '\\' {
                    if let Some(escaped) = chars.next() {
                        consumed += escaped.len_utf8();
                        value.push(escaped);
                    }
                } else if ch == '"' {
                    found_end = true;
                    break;
                } else {
                    value.push(ch);
                }
            }
            if !found_end {
                results.push(None);
                return results;
            }
            (value, &remaining[consumed..])
        } else {
            // Unquoted value — extends to next comma or end
            // Per spec compatibility, allow colons in unquoted values
            match remaining.find(',') {
                Some(p) => (remaining[..p].trim_end().to_string(), &remaining[p..]),
                None => (remaining.trim_end().to_string(), ""),
            }
        };

        results.push(Some((name, value)));

        // Skip comma and surrounding whitespace
        remaining = rest.trim_start();
        if remaining.starts_with(',') {
            remaining = remaining[1..].trim_start();
        }
    }

    results
}

/// PUT /_matrix/federation/v1/send/{txnId}
///
/// Receives a federation transaction. Runs each PDU through the receive
/// pipeline (format → signatures → hashes → auth#4 → auth#5 → auth#6 with
/// soft-fail). Returns a per-PDU success/error map per spec.
///
/// This handler runs behind the `federation_auth` middleware which has:
/// - Verified the X-Matrix header signature.
/// - Parsed the request body (up to 10 MiB) and attached it as `VerifiedBody`.
/// - Attached the origin as `XMatrixOrigin`.
///
/// Using `Extension<VerifiedBody>` instead of `Json<Value>` sidesteps axum's
/// default 2 MiB Json body limit — the middleware has already enforced our own
/// 10 MiB cap and done the parse.
#[tracing::instrument(
    name = "federation.receive_transaction",
    skip(state, _headers, body),
    fields(
        otel.kind = "server",
        txn_id = %txn_id,
        origin = %origin.0,
    )
)]
pub async fn receive_transaction(
    State(state): State<AppState>,
    Path(txn_id): Path<String>,
    _headers: HeaderMap,
    Extension(origin): Extension<XMatrixOrigin>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Json<Value> {
    use crate::federation_receive::{MAX_PDUS_PER_TRANSACTION, process_pdu};

    // Body is Some(Value) for PUT transactions; a missing body would be a
    // malformed federation call (empty-body PUT would fail the middleware's
    // JSON parse long before us).
    let body = match body {
        Some(b) => b,
        None => {
            return Json(json!({
                "errcode": "M_BAD_JSON",
                "error": "empty transaction body"
            }));
        }
    };

    let pdus: Vec<Value> = body
        .get("pdus")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();

    if pdus.len() > MAX_PDUS_PER_TRANSACTION {
        warn!(txn_id = %txn_id, pdu_count = pdus.len(), "transaction exceeds PDU limit");
        // Per spec, oversize transactions are malformed. Return per-PDU error
        // response for clarity rather than 400 — the spec's response is always
        // 200 with per-PDU detail.
    }

    info!(txn_id = %txn_id, pdus = pdus.len(), "processing federation transaction");

    let mut results = serde_json::Map::new();
    for pdu_json in pdus.iter().take(MAX_PDUS_PER_TRANSACTION) {
        let (event_id, outcome) = process_pdu(&state, pdu_json).await;
        // Log at debug for the common (accepted) path; bump to warn
        // when the PDU was rejected outright so operators see federation
        // errors without enabling debug logging globally.
        match &outcome {
            crate::federation_receive::PduOutcome::Accepted => {
                debug!(%txn_id, %event_id, outcome = "accepted", "pdu outcome");
            }
            crate::federation_receive::PduOutcome::SoftFailed => {
                debug!(%txn_id, %event_id, outcome = "soft_failed", "pdu outcome");
            }
            crate::federation_receive::PduOutcome::Rejected(reason) => {
                warn!(%txn_id, %event_id, %reason, "pdu rejected");
            }
        }
        results.insert(event_id, outcome.to_json());
    }

    // EDU dispatch. Per spec, each EDU has an `edu_type` and `content`.
    // We dispatch by type; unknown types are dropped silently (spec
    // explicitly permits this — receivers are not required to act on
    // any particular EDU type). The sending server is `origin.0`,
    // verified by the federation_auth middleware via X-Matrix
    // signature.
    if let Some(edus) = body.get("edus").and_then(|p| p.as_array()) {
        for edu in edus {
            dispatch_edu(&state, &origin.0, edu).await;
        }
    }

    Json(json!({ "pdus": results }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vela_core::federation::keys::verify_json_signature;

    #[test]
    fn server_key_response_is_self_signed() {
        let key = ServerSigningKey::generate();
        let response = build_server_key_response(&key, "example.com", 1_700_000_000_000);

        // Required fields per spec
        assert_eq!(response["server_name"], json!("example.com"));
        assert!(response.contains_key("verify_keys"));
        assert!(response.contains_key("old_verify_keys"));
        assert!(response.contains_key("valid_until_ts"));
        assert!(response.contains_key("signatures"));

        // verify_keys contains our key
        let verify_keys = response["verify_keys"].as_object().unwrap();
        let entry = verify_keys.get(key.key_id()).unwrap();
        assert_eq!(entry["key"], json!(key.public_key_base64()));

        // valid_until_ts = now + 7 days
        let expected_vut = 1_700_000_000_000u64 + 7 * 24 * 60 * 60 * 1000;
        assert_eq!(response["valid_until_ts"], json!(expected_vut));

        // Signature verifies with our key
        let result =
            verify_json_signature(&response, "example.com", key.key_id(), &key.verifying_key());
        assert!(result.is_ok(), "self-signature should verify: {result:?}");
    }

    #[test]
    fn parse_standard_x_matrix() {
        let h = r#"X-Matrix origin="example.com",destination="dest.com",key="ed25519:abc",sig="SIGNATURE""#;
        let parsed = parse_x_matrix_auth(h).unwrap();
        assert_eq!(parsed.origin, "example.com");
        assert_eq!(parsed.destination.as_deref(), Some("dest.com"));
        assert_eq!(parsed.key, "ed25519:abc");
        assert_eq!(parsed.sig, "SIGNATURE");
    }

    #[test]
    fn parse_reorders_params() {
        let h = r#"X-Matrix sig="S",key="ed25519:x",origin="o.com",destination="d.com""#;
        let parsed = parse_x_matrix_auth(h).unwrap();
        assert_eq!(parsed.origin, "o.com");
        assert_eq!(parsed.key, "ed25519:x");
        assert_eq!(parsed.sig, "S");
    }

    #[test]
    fn parse_case_insensitive_names() {
        let h = r#"X-Matrix ORIGIN="o.com",Key="ed25519:x",SIG="S""#;
        let parsed = parse_x_matrix_auth(h).unwrap();
        assert_eq!(parsed.origin, "o.com");
        assert_eq!(parsed.key, "ed25519:x");
        assert_eq!(parsed.sig, "S");
    }

    #[test]
    fn parse_scheme_case_insensitive() {
        let h = r#"x-matrix origin="o.com",key="ed25519:x",sig="S""#;
        assert!(parse_x_matrix_auth(h).is_some());
    }

    #[test]
    fn parse_backslash_escape_in_quoted_value() {
        let h = r#"X-Matrix origin="o.com",key="ed25519:x",sig="S\"X""#;
        let parsed = parse_x_matrix_auth(h).unwrap();
        assert_eq!(parsed.sig, "S\"X");
    }

    #[test]
    fn parse_accepts_signature_alias() {
        // Spec uses both `sig` and (in some places) `signature`.
        let h = r#"X-Matrix origin="o.com",key="ed25519:x",signature="S""#;
        let parsed = parse_x_matrix_auth(h).unwrap();
        assert_eq!(parsed.sig, "S");
    }

    #[test]
    fn parse_unquoted_values_with_colon() {
        // Compatibility: allow colons in unquoted values
        let h = "X-Matrix origin=o.com,key=ed25519:abc,sig=SIGNATURE";
        let parsed = parse_x_matrix_auth(h).unwrap();
        assert_eq!(parsed.origin, "o.com");
        assert_eq!(parsed.key, "ed25519:abc");
        assert_eq!(parsed.sig, "SIGNATURE");
    }

    #[test]
    fn parse_ignores_unknown_parameters() {
        let h = r#"X-Matrix origin="o.com",key="ed25519:x",sig="S",foo="bar""#;
        assert!(parse_x_matrix_auth(h).is_some());
    }

    #[test]
    fn parse_rejects_non_xmatrix_scheme() {
        assert!(parse_x_matrix_auth("Bearer tok").is_none());
    }

    #[test]
    fn parse_rejects_missing_required() {
        let h = r#"X-Matrix origin="o.com",key="ed25519:x""#; // no sig
        assert!(parse_x_matrix_auth(h).is_none());
    }

    #[test]
    fn parse_destination_optional() {
        let h = r#"X-Matrix origin="o.com",key="ed25519:x",sig="S""#;
        let parsed = parse_x_matrix_auth(h).unwrap();
        assert!(parsed.destination.is_none());
    }

    // --- Adversarial inputs ----------------------------------------------
    //
    // Federation peers can send any bytes they want in the Authorization
    // header. The parser must reject malformed input deterministically
    // without panicking, looping, or allocating unbounded memory.

    #[test]
    fn parse_empty_input() {
        assert!(parse_x_matrix_auth("").is_none());
    }

    #[test]
    fn parse_only_scheme() {
        assert!(parse_x_matrix_auth("X-Matrix").is_none());
        assert!(parse_x_matrix_auth("X-Matrix ").is_none());
    }

    #[test]
    fn parse_unterminated_quoted_value() {
        // Missing closing quote — must not loop or panic.
        let h = r#"X-Matrix origin="o.com,key="ed25519:x",sig="S""#;
        assert!(parse_x_matrix_auth(h).is_none());
    }

    #[test]
    fn parse_trailing_backslash_in_quoted_value() {
        // Backslash with nothing after — escape escape consumes nothing.
        let h = r#"X-Matrix origin="o.com",key="ed25519:x",sig="S\"#;
        let _ = parse_x_matrix_auth(h);
        // Must not panic. Whether it succeeds or fails is an
        // implementation detail; we only assert it terminates.
    }

    #[test]
    fn parse_value_with_null_byte() {
        // Null byte inside a value — must not crash.
        let h = "X-Matrix origin=\"o.com\",key=\"ed25519:x\",sig=\"\0SIG\"";
        let _ = parse_x_matrix_auth(h);
    }

    #[test]
    fn parse_extremely_long_input() {
        // 1 MiB of `a=b,` repeated — should terminate without panicking
        // or eating huge memory. Whether it parses successfully is fine
        // either way; we only care it terminates.
        let big = "a=b,".repeat(250_000);
        let h = format!("X-Matrix {big}origin=\"o.com\",key=\"ed25519:x\",sig=\"S\"");
        let _ = parse_x_matrix_auth(&h);
    }

    #[test]
    fn parse_value_with_internal_equals() {
        // Quoted value containing `=` — should be accepted as part of the
        // value (e.g. base64-encoded sig with padding).
        let h = r#"X-Matrix origin="o.com",key="ed25519:x",sig="abcd==""#;
        let parsed = parse_x_matrix_auth(h).unwrap();
        assert_eq!(parsed.sig, "abcd==");
    }

    #[test]
    fn parse_only_commas() {
        // Pathological: just commas. Must not loop.
        assert!(parse_x_matrix_auth("X-Matrix ,,,,,,,,").is_none());
    }

    #[test]
    fn parse_param_without_equals() {
        // No `=` separator between name and value.
        assert!(parse_x_matrix_auth("X-Matrix origin").is_none());
    }

    #[test]
    fn parse_lots_of_unknown_params() {
        // 1000 unknown params — should still find the required ones.
        let mut h = String::from("X-Matrix ");
        for i in 0..1000 {
            h.push_str(&format!("p{i}=\"v\","));
        }
        h.push_str(r#"origin="o.com",key="ed25519:x",sig="S""#);
        let parsed = parse_x_matrix_auth(&h).unwrap();
        assert_eq!(parsed.origin, "o.com");
    }

    #[test]
    fn parse_unicode_in_values() {
        // Non-ASCII bytes in a quoted value. Spec doesn't say either way
        // explicitly; we accept since the values just get fed back to the
        // signature verifier which will reject mismatches.
        let h = "X-Matrix origin=\"o.com\",key=\"ed25519:x\",sig=\"sig with 🎉\"";
        let parsed = parse_x_matrix_auth(h).unwrap();
        assert!(parsed.sig.contains("🎉"));
    }

    #[test]
    fn parse_repeated_required_param() {
        // Two `origin=` entries — last one wins (no spec guidance, just
        // must terminate deterministically).
        let h = r#"X-Matrix origin="first.com",origin="second.com",key="ed25519:x",sig="S""#;
        let parsed = parse_x_matrix_auth(h).unwrap();
        assert_eq!(parsed.origin, "second.com");
    }
}
