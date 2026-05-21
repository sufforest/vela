//! AS HTTP delivery. Renders a `Transaction` into the AS spec's
//! request shape and POSTs it. The outbox worker calls `deliver`
//! repeatedly with the same Transaction on retry — idempotency is
//! the AS's responsibility (it sees the same `txn_id`).

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;

use vela_store::db::Database;

use crate::appservice::{AppService, Transaction};

/// Outcome of one delivery attempt. The outbox worker translates
/// these into retry / drop decisions.
#[derive(Debug, Error)]
pub enum DeliveryError {
    /// Transient — schedule a backoff and try again with the same
    /// transaction.
    #[error("retryable: {0}")]
    Retryable(String),
    /// Permanent — drop this transaction. The AS rejected the
    /// payload or returned an unrecoverable status.
    #[error("permanent: {0}")]
    Permanent(String),
}

/// Build the spec-shaped transaction body and POST it to the AS.
/// Loads each event's JSON from the `events` CF on demand so the
/// outbox row stays small.
pub async fn deliver(
    client: &reqwest::Client,
    db: &Arc<Database>,
    appservice: &AppService,
    cleartext_hs_token: Option<&str>,
    txn: &Transaction,
) -> Result<(), DeliveryError> {
    // Without the cleartext hs_token we can't sign the request.
    // Operators only have the cleartext at registration time; if
    // that's been lost, the AS is unreachable — surface a Permanent
    // so we drop and log loudly.
    let hs_token = match cleartext_hs_token {
        Some(t) => t,
        None => {
            return Err(DeliveryError::Permanent(
                "cleartext hs_token unavailable; re-register the AS".into(),
            ));
        }
    };

    // Build the events array. Spec: each entry is the event JSON
    // exactly as it landed in the room, with `room_id` annotated.
    let mut events = Vec::with_capacity(txn.event_nids.len());
    for (idx, &nid) in txn.event_nids.iter().enumerate() {
        let (_h, bytes) = match db.get_event(nid) {
            Ok(Some(v)) => v,
            Ok(None) => continue,
            Err(e) => return Err(DeliveryError::Retryable(format!("db: {e}"))),
        };
        let mut ev: Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => return Err(DeliveryError::Permanent(format!("event json: {e}"))),
        };
        // Annotate `room_id` at the top level. Many AS spec bodies
        // already have it on the event; we ensure it for consistency.
        if let Some(obj) = ev.as_object_mut()
            && let Some(rid) = txn.room_ids.get(idx)
        {
            obj.entry("room_id".to_string())
                .or_insert_with(|| Value::String(rid.clone()));
        }
        events.push(ev);
    }

    // Per AS spec, the transaction body carries `events` (PDUs) and
    // `ephemeral` (EDUs typing/receipts) alongside each other. Omit
    // the `ephemeral` key when empty so legacy bridges that reject
    // unknown fields aren't poked needlessly.
    let mut body_map = serde_json::Map::new();
    body_map.insert("events".into(), Value::Array(events));
    if !txn.ephemeral.is_empty() {
        body_map.insert("ephemeral".into(), Value::Array(txn.ephemeral.clone()));
    }
    let body = Value::Object(body_map);
    let primary = format!(
        "{}/_matrix/app/v1/transactions/{}",
        appservice.config.url.trim_end_matches('/'),
        encode_txn_id(&txn.txn_id)
    );
    match send_one(client, &primary, hs_token, &body).await {
        Ok(()) => Ok(()),
        Err(e) => {
            // Legacy fallback per spec: drop /_matrix/app/v1 prefix.
            // Only retry the fallback for 404/405 to avoid hitting
            // the AS twice on every failure.
            if matches!(&e, DeliveryError::Permanent(reason) if reason.starts_with("status:404")
                || reason.starts_with("status:405"))
            {
                let legacy = format!(
                    "{}/transactions/{}",
                    appservice.config.url.trim_end_matches('/'),
                    encode_txn_id(&txn.txn_id)
                );
                return send_one(client, &legacy, hs_token, &body).await;
            }
            Err(e)
        }
    }
}

/// Percent-encode the txn_id for path use. Our txn_ids today are
/// always ASCII alphanumeric + hyphen (`evt-12345`); encoding is
/// defensive against future schemes.
fn encode_txn_id(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            write!(&mut out, "%{:02X}", b).unwrap();
        }
    }
    out
}

async fn send_one(
    client: &reqwest::Client,
    url: &str,
    hs_token: &str,
    body: &Value,
) -> Result<(), DeliveryError> {
    let resp = client
        .put(url)
        .bearer_auth(hs_token)
        .json(body)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| DeliveryError::Retryable(format!("network: {e}")))?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    // Spec: 404/405 mean fall back to legacy URL. The caller handles
    // that — we surface as Permanent with status prefix so the
    // dispatcher can detect it.
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::METHOD_NOT_ALLOWED
    {
        return Err(DeliveryError::Permanent(format!(
            "status:{}",
            status.as_u16()
        )));
    }
    // 4xx other than 404/405 → AS rejected the payload. Permanent.
    if status.is_client_error() {
        return Err(DeliveryError::Permanent(format!(
            "status:{}",
            status.as_u16()
        )));
    }
    // 5xx → transient.
    Err(DeliveryError::Retryable(format!(
        "status:{}",
        status.as_u16()
    )))
}
