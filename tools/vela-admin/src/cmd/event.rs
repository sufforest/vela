//! `vela-admin event <event_id>` — dump one event exactly as vela stores
//! it: the header fields (nids, ts, depth) plus the full persisted PDU
//! JSON, including `auth_events` / `prev_events` / signatures.
//!
//! This is the ground-truth view for federation triage: when a remote
//! server rejects one of our events, the question is always "what did we
//! actually put on the wire?" — and the stored JSON is that answer.

use anyhow::Result;
use serde_json::Value;
use vela_store::db::Database;

pub fn run(db: &Database, event_id: &str) -> Result<()> {
    let Some(event_nid) = db
        .get_event_nid_by_id(event_id)
        .map_err(anyhow::Error::msg)?
    else {
        anyhow::bail!("event {event_id} not found");
    };
    let Some((header, json)) = db.get_event(event_nid).map_err(anyhow::Error::msg)? else {
        anyhow::bail!("event {event_id}: nid {event_nid} has no stored record");
    };

    println!("event_id        {event_id}  (nid={event_nid})");
    println!(
        "type            {}",
        db.resolve_nid(header.type_nid)
            .ok()
            .flatten()
            .unwrap_or_else(|| format!("<nid {}>", header.type_nid))
    );
    println!(
        "sender          {}",
        db.resolve_nid(header.sender_nid)
            .ok()
            .flatten()
            .unwrap_or_else(|| format!("<nid {}>", header.sender_nid))
    );
    println!("origin_ts       {}", header.origin_server_ts);
    println!("depth           {}", header.depth);
    println!();

    match serde_json::from_slice::<Value>(&json) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v)?),
        Err(e) => {
            println!("!! stored JSON does not parse ({e}); raw bytes:");
            println!("{}", String::from_utf8_lossy(&json));
        }
    }
    Ok(())
}
