//! `vela-admin rooms` — list rooms with member counts + names.
//! `vela-admin room <id>` — dump the room's current state.
//!
//! `rooms` is the daily-driver "what's on this server?" command.
//! `room` is for when the operator wants to inspect a specific
//! room's configuration before doing something destructive.

use anyhow::Result;
use serde_json::Value;
use vela_store::db::Database;

pub fn run(db: &Database) -> Result<()> {
    let mut rows: Vec<(String, u64, Option<String>)> = Vec::new();
    let rooms = db.list_room_ids().map_err(anyhow::Error::msg)?;
    for rid in rooms {
        let Some(nid) = db.get_nid(&rid).map_err(anyhow::Error::msg)? else {
            continue;
        };
        let members = db.count_room_members_by_membership(nid, 1).unwrap_or(0);
        let name = read_state_str(db, nid, "m.room.name", "", "/content/name");
        rows.push((rid, members, name));
    }
    rows.sort_by_key(|r| std::cmp::Reverse(r.1));
    println!("{:<8} {:<60} name", "members", "room_id");
    for (rid, members, name) in rows {
        println!(
            "{:<8} {:<60} {}",
            members,
            rid,
            name.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

pub fn run_one(db: &Database, room_id: &str) -> Result<()> {
    let Some(nid) = db.get_nid(room_id).map_err(anyhow::Error::msg)? else {
        anyhow::bail!("room {room_id} not found");
    };
    let state_nids = db
        .get_all_state_event_nids(nid)
        .map_err(anyhow::Error::msg)?;
    println!("room_id  {room_id}");
    println!("nid      {nid}");
    println!("state    {} events", state_nids.len());
    println!();
    for state_nid in state_nids {
        let Some((header, bytes)) = db.get_event(state_nid).map_err(anyhow::Error::msg)? else {
            continue;
        };
        let typ = db
            .resolve_nid(header.type_nid)
            .ok()
            .flatten()
            .unwrap_or_else(|| format!("nid:{}", header.type_nid));
        let skey = db
            .resolve_nid(header.state_key_nid)
            .ok()
            .flatten()
            .unwrap_or_else(|| format!("nid:{}", header.state_key_nid));
        let content = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|v| v.get("content").cloned())
            .unwrap_or(Value::Null);
        // Compact one-line summary: type | state_key | content. Long
        // content (e.g. power_levels) is fine — the operator can
        // grep / pipe to jq.
        println!(
            "{:<32} {:<40} {}",
            typ,
            skey,
            serde_json::to_string(&content).unwrap_or_default()
        );
    }
    Ok(())
}

fn read_state_str(
    db: &Database,
    room_nid: u64,
    event_type: &str,
    state_key: &str,
    pointer: &str,
) -> Option<String> {
    let type_nid = db.get_nid(event_type).ok().flatten()?;
    let skey_nid = db.get_nid(state_key).ok().flatten()?;
    let event_nid = db
        .get_state_event_nid(room_nid, type_nid, skey_nid)
        .ok()
        .flatten()?;
    let (_, bytes) = db.get_event(event_nid).ok().flatten()?;
    let json: Value = serde_json::from_slice(&bytes).ok()?;
    json.pointer(pointer)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}
