//! NID allocator: maps string identifiers to compact u64 numeric IDs.
//! All string IDs (user_id, room_id, event_type, state_key) get a NID on first encounter.

use rocksdb::DB;

use crate::keys::{decode_u64, encode_u64};

/// Get or create a NID for a string identifier.
/// Uses global_nids CF for string→NID and nid_reverse CF for NID→string.
pub fn get_or_create_nid(
    db: &DB,
    nid_counter: &std::sync::atomic::AtomicU64,
    string: &str,
) -> Result<u64, rocksdb::Error> {
    let cf_map = db.cf_handle("nid_map").expect("nid_map CF missing");

    // Check if already exists
    if let Some(bytes) = db.get_cf(&cf_map, string.as_bytes())? {
        return Ok(decode_u64(&bytes));
    }

    // Allocate new NID
    let nid = nid_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nid_bytes = encode_u64(nid);

    let cf_reverse = db.cf_handle("nid_reverse").expect("nid_reverse CF missing");

    // Write both mappings atomically
    let mut batch = rocksdb::WriteBatch::default();
    batch.put_cf(&cf_map, string.as_bytes(), nid_bytes);
    batch.put_cf(&cf_reverse, nid_bytes, string.as_bytes());
    db.write(batch)?;

    Ok(nid)
}

/// Look up a NID for a string, returning None if not found.
pub fn get_nid(db: &DB, string: &str) -> Result<Option<u64>, rocksdb::Error> {
    let cf = db.cf_handle("nid_map").expect("nid_map CF missing");
    match db.get_cf(&cf, string.as_bytes())? {
        Some(bytes) => Ok(Some(decode_u64(&bytes))),
        None => Ok(None),
    }
}

/// Resolve a NID back to its string.
pub fn resolve_nid(db: &DB, nid: u64) -> Result<Option<String>, rocksdb::Error> {
    let cf = db.cf_handle("nid_reverse").expect("nid_reverse CF missing");
    match db.get_cf(&cf, encode_u64(nid))? {
        Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).to_string())),
        None => Ok(None),
    }
}
