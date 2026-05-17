//! `vela-admin diagnose-membership <room_id> <user_id>` — print both
//! sides of the membership picture for one user in one room, and flag
//! any drift between them.
//!
//! Background: vela tracks membership in two CFs that are supposed to
//! agree.
//!
//!   - `memberships[(room_nid, user_nid)]` → u8 (the pre-check on
//!     send/leave/etc reads this).
//!   - `room_state[(room_nid, m.room.member_type_nid, user_state_key_nid)]`
//!     → event_nid of the current m.room.member state event for that
//!     user (the spec auth rule engine consults this via auth_events).
//!
//! When these disagree — typically when one code path writes to one CF
//! without writing the other in the same atomic batch — the symptom is
//! "PUT /send/... returns 403 'sender is not joined'" because the
//! pre-check passes (memberships says JOIN) but the rule engine
//! consults the stale `room_state` member event.
//!
//! This command prints both sides verbatim so the operator can see the
//! disagreement and we can audit the producing code path.

use anyhow::Result;
use serde_json::Value;
use vela_store::db::Database;

pub fn run(db: &Database, room_id: &str, user_id: &str) -> Result<()> {
    let Some(room_nid) = db.get_nid(room_id).map_err(anyhow::Error::msg)? else {
        anyhow::bail!("room {room_id} not found (no NID)");
    };
    let Some(user_nid) = db.get_nid(user_id).map_err(anyhow::Error::msg)? else {
        anyhow::bail!("user {user_id} not found (no NID)");
    };

    println!("room_id   {room_id}  (nid={room_nid})");
    println!("user_id   {user_id}  (nid={user_nid})");
    println!();

    // --- memberships CF ---
    let mem_byte = db
        .get_membership(room_nid, user_nid)
        .map_err(anyhow::Error::msg)?;
    let mem_label = mem_byte
        .map(membership_label)
        .unwrap_or_else(|| "absent".into());
    println!("memberships[room, user] = {mem_label}");

    // --- room_state CF for the matching m.room.member event ---
    let member_type_nid = db
        .get_nid("m.room.member")
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("m.room.member type NID not allocated yet"))?;
    let state_member_event_nid = db
        .get_state_event_nid(room_nid, member_type_nid, user_nid)
        .map_err(anyhow::Error::msg)?;

    match state_member_event_nid {
        None => {
            println!("room_state[m.room.member, user]  = absent");
        }
        Some(event_nid) => {
            let (header, bytes) = db
                .get_event(event_nid)
                .map_err(anyhow::Error::msg)?
                .ok_or_else(|| anyhow::anyhow!("dangling event_nid {event_nid} in room_state"))?;
            let event_id = db
                .get_event_id_by_nid(event_nid)
                .ok()
                .flatten()
                .unwrap_or_else(|| format!("nid:{event_nid}"));
            let content_membership = serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|v| v.get("content").and_then(|c| c.get("membership")).cloned())
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "<unparseable>".into());
            println!("room_state[m.room.member, user]  = {content_membership}");
            println!("    event_id  {event_id}");
            println!("    depth     {}", header.depth);
            println!("    origin_ts {}", header.origin_server_ts);
        }
    }

    println!();
    let drifted = drifts(mem_byte, state_member_event_nid, db)?;
    if drifted {
        println!("DRIFT: memberships and room_state disagree.");
        println!("  Effect: spec auth check (sender-must-be-joined) will fail");
        println!("  for any non-state event sent by this user in this room,");
        println!("  even though the pre-check in send.rs would pass.");
    } else {
        println!("consistent");
    }

    Ok(())
}

fn drifts(
    mem_byte: Option<u8>,
    state_member_event_nid: Option<u64>,
    db: &Database,
) -> Result<bool> {
    let mem = mem_byte
        .map(membership_label)
        .unwrap_or_else(|| "absent".into());
    let state_membership = match state_member_event_nid {
        None => "absent".to_string(),
        Some(event_nid) => {
            let (_, bytes) = db
                .get_event(event_nid)
                .map_err(anyhow::Error::msg)?
                .ok_or_else(|| anyhow::anyhow!("dangling event_nid in room_state"))?;
            serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|v| v.get("content").and_then(|c| c.get("membership")).cloned())
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "<unparseable>".into())
        }
    };
    Ok(mem != state_membership)
}

fn membership_label(b: u8) -> String {
    match b {
        0 => "leave".into(),
        1 => "join".into(),
        2 => "invite".into(),
        3 => "ban".into(),
        4 => "knock".into(),
        other => format!("unknown({other})"),
    }
}
