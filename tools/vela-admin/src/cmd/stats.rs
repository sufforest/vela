//! `vela-admin stats` — global counts for a quick "what's in this
//! server?" view. Each count is one CF scan, so this is O(rows) but
//! that's the right shape for the friend-group target size; ~10k
//! events is sub-second.

use anyhow::Result;
use vela_store::db::Database;

pub fn run(db: &Database) -> Result<()> {
    let rooms = db.list_room_ids().map_err(anyhow::Error::msg)?;
    let media = db.list_media_metadata().map_err(anyhow::Error::msg)?;

    let total_media_bytes: u64 = media
        .iter()
        .filter_map(|(_, v)| v.get("size").and_then(|s| s.as_u64()))
        .sum();
    let mut total_members: u64 = 0;
    for rid in &rooms {
        if let Some(nid) = db.get_nid(rid).ok().flatten()
            && let Ok(c) = db.count_room_members_by_membership(nid, 1)
        {
            total_members += c;
        }
    }

    println!("rooms           {}", rooms.len());
    println!(
        "memberships     {} (sum of joined members across all rooms; users in N rooms count N times)",
        total_members
    );
    println!("media objects   {}", media.len());
    println!(
        "media bytes     {} ({:.1} MiB)",
        total_media_bytes,
        total_media_bytes as f64 / (1024.0 * 1024.0)
    );
    Ok(())
}
