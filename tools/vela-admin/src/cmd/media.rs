//! `vela-admin media` — paginated list of stored media objects.
//! Cheap to run; capped at `--limit` so a server with millions of
//! files doesn't try to print them all.

use anyhow::Result;
use vela_store::db::Database;

pub fn run(db: &Database, limit: usize) -> Result<()> {
    let mut rows = db.list_media_metadata().map_err(anyhow::Error::msg)?;
    // Newest first when `created_at` is present; falls back to
    // alphabetic for entries that never recorded a timestamp.
    rows.sort_by(|a, b| {
        let ta = a.1.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
        let tb = b.1.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
        tb.cmp(&ta).then(b.0.cmp(&a.0))
    });
    let total = rows.len();
    let shown = rows.len().min(limit);
    println!(
        "{:<32} {:<12} {:<32} content_type",
        "media_id", "size", "uploader"
    );
    for (id, meta) in rows.into_iter().take(limit) {
        let size = meta.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
        let uploader = meta
            .get("uploader")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let ct = meta
            .get("content_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        println!("{:<32} {:<12} {:<32} {}", id, size, uploader, ct);
    }
    if shown < total {
        println!(
            "\n…and {} more (pass `--limit {}` to widen)",
            total - shown,
            total
        );
    }
    Ok(())
}
