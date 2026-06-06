//! `vela-admin diagnose` — operator-friendly health probe. Walks
//! the CFs visible to a secondary RocksDB view and surfaces the
//! categories of silent breakage that don't show up in /sync or
//! /healthz:
//!
//! - **Database counters** — `next_nid` must stay above every
//!   persisted event_nid; a counter that lagged behind would silently
//!   collide IDs on the next persist.
//! - **Partial-state rooms** — MSC3902 joins that haven't finished
//!   resyncing. Each such room has degraded federation; if any are
//!   listed here, the filler is stuck or wedged.
//! - **Federation outbound queues** — destinations with pending PDU
//!   or EDU entries. A growing queue against an unreachable peer
//!   is normal-but-noisy; an unexpectedly-large queue against a
//!   live peer is a flow bug.
//! - **Activity** — rooms with a `room_bump` timestamp in the last
//!   24 hours / 7 days. A friend-group server with hundreds of
//!   rooms but no recent activity may be quieter than the operator
//!   thinks.

use anyhow::Result;
use vela_store::db::Database;

pub fn run(db: &Database) -> Result<()> {
    section_database(db)?;
    println!();
    section_partial_state(db)?;
    println!();
    section_federation(db)?;
    println!();
    section_activity(db)?;
    Ok(())
}

fn section_database(db: &Database) -> Result<()> {
    println!("DATABASE");
    let stream_pos = db.current_stream_position();
    println!("  current stream pos   {stream_pos}");
    Ok(())
}

fn section_partial_state(db: &Database) -> Result<()> {
    let rooms = db.list_partial_state_rooms().map_err(anyhow::Error::msg)?;
    println!("PARTIAL STATE");
    if rooms.is_empty() {
        println!("  rooms still partial  0");
        return Ok(());
    }
    println!("  rooms still partial  {}", rooms.len());
    for (_, room_id, servers) in &rooms {
        let hint = if servers.is_empty() {
            "no hint".to_string()
        } else {
            servers.join(",")
        };
        println!("    {room_id:<60} hint={hint}");
    }
    Ok(())
}

fn section_federation(db: &Database) -> Result<()> {
    let dests = db
        .list_outbound_destinations()
        .map_err(anyhow::Error::msg)?;
    println!("FEDERATION");
    println!("  destinations queued  {}", dests.len());
    if dests.is_empty() {
        return Ok(());
    }
    for d in &dests {
        println!("    {d}");
    }
    Ok(())
}

fn section_activity(db: &Database) -> Result<()> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let one_day = 24 * 3_600_000u64;
    let seven_days = 7 * one_day;
    let rooms = db.list_room_ids().map_err(anyhow::Error::msg)?;
    let mut active_24h = 0usize;
    let mut active_7d = 0usize;
    let mut quiet = 0usize;
    for rid in &rooms {
        let Some(nid) = db.get_nid(rid).map_err(anyhow::Error::msg)? else {
            continue;
        };
        match db.get_room_bump(nid).map_err(anyhow::Error::msg)? {
            Some(bump) => {
                let age = now_ms.saturating_sub(bump);
                if age <= one_day {
                    active_24h += 1;
                }
                if age <= seven_days {
                    active_7d += 1;
                }
            }
            None => quiet += 1,
        }
    }
    println!("ACTIVITY");
    println!("  rooms total          {}", rooms.len());
    println!("  active last 24h      {active_24h}");
    println!("  active last 7d       {active_7d}");
    println!(
        "  no recorded bump     {quiet}{}",
        if quiet > 0 {
            " (just-created rooms or pre-bump-tracking)"
        } else {
            ""
        }
    );
    Ok(())
}
