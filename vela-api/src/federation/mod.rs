//! Federation transport + machinery: keys, transaction in/out, state
//! resolution helpers, backfill, fetch endpoints, ACL enforcement,
//! and the per-destination outbound sender. Membership flows that
//! happen to be federated (`/make_join`, `/send_knock`, etc.) live
//! under `membership/` instead — domain ownership follows behaviour,
//! not URL prefix.

pub mod edu;
pub mod federation_backfill;
pub mod federation_client;
pub mod federation_fetch;
pub mod federation_receive;
pub mod federation_resolver;
pub mod federation_sender;
pub mod federation_state;
pub mod partial_state_filler;
pub mod server_acl;

use std::time::{SystemTime, UNIX_EPOCH};

use crate::middleware::json::Json;
use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
use serde_json::{Map, Value, json};
use tracing::{debug, info, warn};
use vela_core::events::sign::ServerSigningKey;

use crate::federation::edu::inbound::dispatch_edu;
use crate::middleware::federation_auth::{VerifiedBody, XMatrixOrigin};
use crate::router::AppState;

/// Build the `/_matrix/key/v2/server` response body, self-signed.
/// `old_verify_keys` is a list of `(key_id, public_key_b64, expired_ts_ms)`
/// for keys vela has rotated out — peers use these to validate
/// signatures on events authored before the rotation.
/// Extracted for testability; `get_server_keys` is a thin axum wrapper.
pub fn build_server_key_response(
    signing_key: &ServerSigningKey,
    server_name: &str,
    now_ms: u64,
    old_verify_keys: &[(String, String, u64)],
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
    let mut old_map = Map::new();
    for (kid, pub_b64, expired_ts) in old_verify_keys {
        old_map.insert(
            kid.clone(),
            json!({
                "key": pub_b64,
                "expired_ts": expired_ts,
            }),
        );
    }
    response.insert("old_verify_keys".into(), Value::Object(old_map));
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

    let old_keys = state.db.load_rotated_signing_keys().unwrap_or_default();
    let response = build_server_key_response(
        &state.signing_key,
        &state.config.server_name,
        now_ms,
        &old_keys,
    );

    Json(Value::Object(response))
}

/// GET /_matrix/federation/v1/version
///
/// Unauthenticated. Reports the implementation name + version so peers
/// can log deployment heterogeneity.
pub async fn version() -> Json<Value> {
    Json(json!({
        "server": {
            "name": "vela",
            "version": env!("CARGO_PKG_VERSION"),
        }
    }))
}

/// GET /_matrix/key/v2/query/{serverName}
///
/// Notary single-server key query. When the caller asks about a
/// server we ARE, return our self-signed bundle. For any other
/// server, fetch their `/key/v2/server` response, add our signature
/// alongside the origin's (the "notary" assertion: we vouched for
/// these keys at this time), and return. Fetch failures yield an
/// empty `server_keys` — the spec leaves it implementation-defined,
/// and an empty body is friendlier than a 500 to callers that
/// only need their own keys.
pub async fn query_keys_single(
    State(state): State<AppState>,
    Path(server_name): Path<String>,
) -> Json<Value> {
    let entry = build_notary_entry_for(&state, &server_name).await;
    match entry {
        Some(e) => Json(json!({ "server_keys": [e] })),
        None => Json(json!({ "server_keys": [] })),
    }
}

/// POST /_matrix/key/v2/query
///
/// Notary batch key query. Request body shape per spec:
/// `{ "server_keys": { "<server>": { "<key_id>": { ... } } } }`. We
/// notary-sign one entry per asked-about server. The per-key map
/// inside each server entry is currently ignored — `key_v2/server`
/// returns the full key list, and the spec lets the notary return
/// more than was strictly asked. The `minimum_valid_until_ts` hint
/// is also ignored; we rely on the validator's freshness check.
pub async fn query_keys_batch(
    State(state): State<AppState>,
    Json(req): Json<Value>,
) -> Json<Value> {
    let mut server_keys = Vec::new();
    if let Some(asked) = req.get("server_keys").and_then(|v| v.as_object()) {
        for server in asked.keys() {
            if let Some(entry) = build_notary_entry_for(&state, server).await {
                server_keys.push(entry);
            }
        }
    }
    Json(json!({ "server_keys": server_keys }))
}

/// Produce one `server_keys[]` entry for `server_name`: self-signed
/// when it's us, notary-signed when it's anyone else. Returns `None`
/// when the upstream fetch fails — caller decides whether to drop
/// or 5xx; today we drop (empty array), matching Synapse.
async fn build_notary_entry_for(state: &AppState, server_name: &str) -> Option<Value> {
    if server_name == state.config.server_name {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let old_keys = state.db.load_rotated_signing_keys().unwrap_or_default();
        let entry = build_server_key_response(
            &state.signing_key,
            &state.config.server_name,
            now_ms,
            &old_keys,
        );
        return Some(Value::Object(entry));
    }
    match state
        .federation_client
        .fetch_server_keys_with_raw(server_name)
        .await
    {
        Ok((_parsed, raw)) => Some(notary_sign_entry(
            raw,
            &state.signing_key,
            &state.config.server_name,
        )),
        Err(e) => {
            tracing::debug!(
                target = %server_name,
                error = %e,
                "notary key fetch failed; returning empty entry"
            );
            None
        }
    }
}

/// Insert our signature alongside the origin server's signatures on
/// a `/key/v2/server` bundle. Per Matrix spec §"Notary queries":
/// the notary signs the bundle with `signatures` and `unsigned`
/// stripped (same scheme `sign_json` already implements), and the
/// resulting signature lives under `signatures.<notary>.<key_id>`
/// alongside the existing `signatures.<origin>.<their_key_id>`.
/// Origin signatures are preserved verbatim so callers can verify
/// the underlying server's claim.
fn notary_sign_entry(mut bundle: Value, our_key: &ServerSigningKey, our_server: &str) -> Value {
    if let Some(obj) = bundle.as_object_mut() {
        our_key.sign_json(obj, our_server);
    }
    bundle
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

/// Log and persist the per-PDU outcome from a federation transaction.
///
/// Pulled out of the receive_transaction loop so the inline per-room
/// task can reuse it without duplicating the rejection-bookkeeping.
/// Called immediately after `process_pdu` so the next event in the
/// same room sees the rejection via `is_event_rejected`.
fn record_outcome(
    state: &AppState,
    txn_id: &str,
    event_id: &str,
    outcome: &crate::federation::federation_receive::PduOutcome,
) {
    use crate::federation::federation_receive::PduOutcome;
    match outcome {
        PduOutcome::Accepted => {
            debug!(%txn_id, %event_id, outcome = "accepted", "pdu outcome");
        }
        PduOutcome::SoftFailed => {
            debug!(%txn_id, %event_id, outcome = "soft_failed", "pdu outcome");
        }
        PduOutcome::Rejected(reason) => {
            warn!(%txn_id, %event_id, %reason, "pdu rejected");
            // Persist the rejection so descendant events that
            // reference this one in `auth_events` can cascade-
            // reject without needing to re-derive WHY the
            // ancestor was rejected.
            //
            // EXCEPT for transient state-incompleteness rejections:
            // a PDU broadcast that races our own outbound-join
            // bootstrap on the same room gets rejected with
            // "unknown room" (we haven't created the room nid
            // yet) or with "no m.room.create in state" (we
            // haven't promoted state yet). Marking those would
            // poison any later PDU whose auth chain references
            // them — even after our state is fully populated and
            // the re-delivered PDU would otherwise be accepted
            // (TestUnbanViaInvite: ban PDU cascade-rejected off
            // alice's own join, which got marked rejected while
            // her outbound_join was still in flight).
            let is_transient =
                reason == "unknown room" || reason.contains("no m.room.create in state");
            if !event_id.is_empty()
                && !is_transient
                && let Err(e) = state.db.mark_event_rejected(event_id, reason)
            {
                warn!(%txn_id, %event_id, error = %e, "mark_event_rejected failed");
            }
        }
    }
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
    use crate::federation::federation_receive::{MAX_PDUS_PER_TRANSACTION, process_pdu};

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

    // Group PDUs by room_id so independent rooms can be processed in
    // parallel. Per Matrix federation semantics every PDU's auth checks
    // and state writes are scoped to its own room — cross-room
    // dependencies don't exist on the inbound persist path, so room A's
    // batch never has to wait for room B's auth_chain fetch or DB
    // writes. Synapse, Dendrite, and Conduwuit all do this: vela was
    // the only serial-by-room implementation, which made TFRI-shape
    // transactions (many subtests, mixed rooms per txn) head-of-line-
    // block under load and tip into the 5s MustSyncUntil deadline. The
    // per-room lock inside `process_pdu` still serialises writes
    // within a room, so concurrency is bounded and safe.
    use std::collections::HashMap;
    let mut by_room: HashMap<String, Vec<(usize, Value)>> = HashMap::new();
    for (idx, pdu_json) in pdus.into_iter().take(MAX_PDUS_PER_TRANSACTION).enumerate() {
        let room_id = pdu_json
            .get("room_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        by_room.entry(room_id).or_default().push((idx, pdu_json));
    }

    // Process each room's PDUs serially inside the room (preserves the
    // sender-asserted topological order Synapse/Dendrite rely on AND
    // the cascade-rejection contract — a sent_event_N's rejection
    // must be persisted before the next event in the same room can
    // observe it via is_event_rejected in its prev_events check),
    // multiple rooms concurrently across the txn. JoinSet over
    // tokio::spawn so the tokio runtime can pull tasks across worker
    // threads — process_pdu mixes HTTP fetches and RocksDB writes, so
    // the CPU phases benefit from true parallelism (not just I/O
    // interleaving). Fast path when the txn is single-room: skip the
    // spawn entirely.
    //
    // run_room_serial inlines the rejection bookkeeping that used to
    // live in the outer loop. Inlining is load-bearing —
    // TestInboundFederationRejectsEventsWithRejectedAuthEvents drives
    // a txn where event_N+1 references event_N as a prev_event, and
    // the state-at-event resolver depends on event_N's rejection
    // being persisted before event_N+1 runs.
    let mut indexed_results: Vec<(
        usize,
        String,
        crate::federation::federation_receive::PduOutcome,
    )> = Vec::with_capacity(MAX_PDUS_PER_TRANSACTION);
    if by_room.len() <= 1 {
        for (_room_id, pdus_in_room) in by_room {
            for (idx, pdu) in pdus_in_room {
                let (event_id, outcome) = process_pdu(&state, &pdu).await;
                record_outcome(&state, &txn_id, &event_id, &outcome);
                indexed_results.push((idx, event_id, outcome));
            }
        }
    } else {
        let mut set = tokio::task::JoinSet::new();
        for (_room_id, pdus_in_room) in by_room {
            let state_clone = state.clone();
            let txn_id_clone = txn_id.clone();
            set.spawn(async move {
                let mut out: Vec<(
                    usize,
                    String,
                    crate::federation::federation_receive::PduOutcome,
                )> = Vec::with_capacity(pdus_in_room.len());
                for (idx, pdu) in pdus_in_room {
                    let (event_id, outcome) = process_pdu(&state_clone, &pdu).await;
                    record_outcome(&state_clone, &txn_id_clone, &event_id, &outcome);
                    out.push((idx, event_id, outcome));
                }
                out
            });
        }
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(group) => indexed_results.extend(group),
                Err(e) => warn!(%txn_id, error = %e, "per-room process task panicked"),
            }
        }
    }
    // Restore the txn's original PDU order in the response so peers
    // see outcomes in the same sequence they sent — spec doesn't
    // require this, but it's the principle of least surprise and
    // avoids a regression for any peer that relies on it.
    indexed_results.sort_by_key(|(idx, _, _)| *idx);

    let mut results = serde_json::Map::new();
    for (_idx, event_id, outcome) in indexed_results {
        results.insert(event_id, outcome.to_json());
    }

    // EDU dispatch. Per spec, each EDU has an `edu_type` and `content`.
    // We dispatch by type; unknown types are dropped silently (spec
    // explicitly permits this — receivers are not required to act on
    // any particular EDU type). The sending server is `origin.0`,
    // verified by the federation_auth middleware via X-Matrix
    // signature.
    //
    // Runs after PDUs so EDUs that reference newly-persisted state
    // (e.g. a typing EDU for a room the same txn just created via
    // PDU) see consistent state. Conduwuit + Dendrite use the same
    // two-phase order.
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
        let response = build_server_key_response(&key, "example.com", 1_700_000_000_000, &[]);

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

        // No rotated keys → old_verify_keys is an empty object
        assert_eq!(response["old_verify_keys"], json!({}));

        // valid_until_ts = now + 7 days
        let expected_vut = 1_700_000_000_000u64 + 7 * 24 * 60 * 60 * 1000;
        assert_eq!(response["valid_until_ts"], json!(expected_vut));

        // Signature verifies with our key
        let result =
            verify_json_signature(&response, "example.com", key.key_id(), &key.verifying_key());
        assert!(result.is_ok(), "self-signature should verify: {result:?}");
    }

    #[test]
    fn server_key_response_emits_old_verify_keys() {
        let key = ServerSigningKey::generate();
        let old = vec![
            (
                "ed25519:retired1".to_string(),
                "AAAA".to_string(),
                1_600_000_000_000u64,
            ),
            (
                "ed25519:retired2".to_string(),
                "BBBB".to_string(),
                1_650_000_000_000u64,
            ),
        ];
        let response = build_server_key_response(&key, "example.com", 1_700_000_000_000, &old);

        let old_map = response["old_verify_keys"].as_object().unwrap();
        assert_eq!(old_map.len(), 2);
        let r1 = old_map.get("ed25519:retired1").unwrap();
        assert_eq!(r1["key"], json!("AAAA"));
        assert_eq!(r1["expired_ts"], json!(1_600_000_000_000u64));
        let r2 = old_map.get("ed25519:retired2").unwrap();
        assert_eq!(r2["key"], json!("BBBB"));
        assert_eq!(r2["expired_ts"], json!(1_650_000_000_000u64));

        // Response is still self-signed by the CURRENT key only.
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

    /// Notary signing preserves the origin server's signature and
    /// adds the notary's alongside it. Both must verify against
    /// their respective keys. This is the cryptographic invariant
    /// the notary path relies on: callers can trust EITHER
    /// signature (the origin's authoritative claim, or the notary's
    /// vouching of freshness).
    #[test]
    fn notary_sign_entry_preserves_origin_signature() {
        use base64::Engine;
        // 1. Build a remote-signed bundle.
        let remote_key = ServerSigningKey::generate();
        let remote_bundle =
            build_server_key_response(&remote_key, "remote.example", 1_700_000_000_000, &[]);
        // Sanity: the origin signature is present.
        let origin_sig_b64 = remote_bundle["signatures"]["remote.example"][remote_key.key_id()]
            .as_str()
            .expect("origin signature should be set")
            .to_string();

        // 2. Notary signs the bundle.
        let our_key = ServerSigningKey::generate();
        let signed =
            notary_sign_entry(Value::Object(remote_bundle.clone()), &our_key, "us.example");
        let signed_obj = signed.as_object().unwrap();

        // 3. Origin signature is untouched.
        assert_eq!(
            signed_obj["signatures"]["remote.example"][remote_key.key_id()],
            json!(origin_sig_b64),
            "origin's signature must survive notary signing verbatim",
        );

        // 4. Notary's signature is present and valid.
        let our_sig_b64 = signed_obj["signatures"]["us.example"][our_key.key_id()]
            .as_str()
            .expect("notary signature must be added");
        assert!(!our_sig_b64.is_empty());
        let our_pub = our_key.public_key_base64();
        let pub_bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&our_pub)
            .unwrap();
        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(&pub_bytes);
        let pub_key = ed25519_dalek::VerifyingKey::from_bytes(&pub_arr).unwrap();
        // The signature is over canonical-JSON-minus-signatures, which
        // is what verify_json_signature already does.
        assert!(
            verify_json_signature(signed_obj, "us.example", our_key.key_id(), &pub_key).is_ok(),
            "notary signature must verify against our own pubkey",
        );

        // 5. Origin's signature still verifies too (against its key).
        let remote_pub = remote_key.public_key_base64();
        let remote_pub_bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&remote_pub)
            .unwrap();
        let mut remote_pub_arr = [0u8; 32];
        remote_pub_arr.copy_from_slice(&remote_pub_bytes);
        let remote_pub_key = ed25519_dalek::VerifyingKey::from_bytes(&remote_pub_arr).unwrap();
        assert!(
            verify_json_signature(
                signed_obj,
                "remote.example",
                remote_key.key_id(),
                &remote_pub_key,
            )
            .is_ok(),
            "origin's signature must still verify after notary signing",
        );
    }

    /// End-to-end notary flow: stub a remote homeserver via wiremock,
    /// route federation_client's HTTPS fetch at it via the test base-URL
    /// override, and assert `build_notary_entry_for` returns a bundle
    /// signed by BOTH the remote and us. Catches integration bugs the
    /// unit test (which constructs the bundle in-process) misses —
    /// e.g. a JSON-shape mismatch between what `/key/v2/server`
    /// returns on the wire and what `fetch_server_keys_with_raw`
    /// hands the notary signer.
    #[tokio::test]
    async fn notary_end_to_end_signs_remote_bundle() {
        use base64::Engine;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let remote_name = "remote.example";

        // The mocked remote returns a bundle self-signed by `remote_key`.
        let remote_key = ServerSigningKey::generate();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let remote_bundle = build_server_key_response(&remote_key, remote_name, now_ms, &[]);
        Mock::given(method("GET"))
            .and(path("/_matrix/key/v2/server"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(Value::Object(remote_bundle.clone())),
            )
            .mount(&server)
            .await;

        let (state, _tmp) = crate::test_helpers::build_test_state();
        // Plumb the wiremock URL through the federation_client's
        // plaintext base-URL override — same path test_helpers uses for
        // peer stubs elsewhere.
        state
            .federation_client
            .set_base_url_override(remote_name, &server.uri());

        let entry = build_notary_entry_for(&state, remote_name)
            .await
            .expect("notary build must succeed");
        let obj = entry.as_object().unwrap();

        // Remote's signature survived.
        assert_eq!(
            obj["server_name"], remote_name,
            "server_name preserved from upstream bundle"
        );
        assert!(
            obj["signatures"][remote_name][remote_key.key_id()].is_string(),
            "remote signature must be present after notary signing",
        );

        // Vela's signature was added and verifies against vela's key.
        let our_key_id = state.signing_key.key_id();
        let our_sig = obj["signatures"]["example.com"][our_key_id]
            .as_str()
            .expect("notary signature missing");
        assert!(!our_sig.is_empty());
        let our_pub_b64 = state.signing_key.public_key_base64();
        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&our_pub_b64)
            .unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let our_pub = ed25519_dalek::VerifyingKey::from_bytes(&arr).unwrap();
        assert!(
            verify_json_signature(obj, "example.com", our_key_id, &our_pub).is_ok(),
            "notary signature must verify against vela's key",
        );
    }
}
