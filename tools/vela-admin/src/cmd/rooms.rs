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

/// Top rooms by most-recent activity (`room_bump` timestamp).
/// `room_bump` is updated by every Live event persistence in
/// `vela-store/src/db.rs::update_room_bump`, so this orders rooms
/// by "when was the last thing said here." Rooms with no activity
/// at all (typically just-created with no messages) sort to the
/// bottom and may not appear within `limit`.
pub fn run_top(db: &Database, limit: usize) -> Result<()> {
    let mut rows: Vec<(String, u64, u64, Option<String>)> = Vec::new();
    let rooms = db.list_room_ids().map_err(anyhow::Error::msg)?;
    for rid in rooms {
        let Some(nid) = db.get_nid(&rid).map_err(anyhow::Error::msg)? else {
            continue;
        };
        let bump = db.get_room_bump(nid).unwrap_or(None).unwrap_or(0);
        let members = db.count_room_members_by_membership(nid, 1).unwrap_or(0);
        let name = read_state_str(db, nid, "m.room.name", "", "/content/name");
        rows.push((rid, members, bump, name));
    }
    // Most recent first; rooms with no bump (ts=0) fall to the bottom.
    rows.sort_by_key(|r| std::cmp::Reverse(r.2));
    rows.truncate(limit);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    println!("{:<10} {:<8} {:<60} name", "active", "members", "room_id");
    for (rid, members, bump, name) in rows {
        let active = if bump == 0 {
            "—".to_string()
        } else if bump > now_ms {
            // Federation clock skew. Surface it instead of camouflaging
            // a "5 minutes in the future" bump as `0s` — that would
            // look indistinguishable from real ongoing activity.
            "future".to_string()
        } else {
            format_age(now_ms - bump)
        };
        println!(
            "{:<10} {:<8} {:<60} {}",
            active,
            members,
            rid,
            name.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

/// Render an age in milliseconds as a compact relative string:
/// `45s`, `12m`, `3h`, `5d`, `2w`. Days resolution covers the
/// 1-13d range so "5 days ago" stays meaningful; the flip to weeks
/// kicks in at 14d, where day-precision starts to feel busy.
/// Operator output, not a machine interface — keep it grep-friendly.
fn format_age(ms: u64) -> String {
    let secs = ms / 1000;
    if secs < 60 {
        return format!("{secs}s");
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins}m");
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours}h");
    }
    let days = hours / 24;
    if days < 14 {
        return format!("{days}d");
    }
    let weeks = days / 7;
    format!("{weeks}w")
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
    // The meta record's version drives every version-gated code path
    // (auth selection, redaction shape, event-id format); print it raw
    // so drift from the create event's `room_version` is visible.
    println!(
        "version  {}",
        db.get_room_version(nid)
            .map_err(anyhow::Error::msg)?
            .unwrap_or_else(|| "<missing from room_meta>".to_string())
    );
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

#[cfg(test)]
mod tests {
    use super::format_age;

    #[test]
    fn format_age_picks_largest_unit_under_each_threshold() {
        assert_eq!(format_age(0), "0s");
        assert_eq!(format_age(59_000), "59s");
        assert_eq!(format_age(60_000), "1m");
        assert_eq!(format_age(59 * 60_000), "59m");
        assert_eq!(format_age(60 * 60_000), "1h");
        assert_eq!(format_age(23 * 3_600_000), "23h");
        assert_eq!(format_age(24 * 3_600_000), "1d");
        assert_eq!(format_age(13 * 24 * 3_600_000), "13d");
        // 14 days flips to weeks.
        assert_eq!(format_age(14 * 24 * 3_600_000), "2w");
        assert_eq!(format_age(52 * 7 * 24 * 3_600_000), "52w");
    }

    #[test]
    fn format_age_handles_extreme_input() {
        // No unit larger than weeks — just keep going. A homeserver
        // that's been running 10 years would show ~520w. Reads as
        // "ancient" to an operator, which is the point.
        let ten_years_ms: u64 = 10 * 365 * 24 * 3_600_000;
        assert_eq!(format_age(ten_years_ms), "521w");
    }
}
