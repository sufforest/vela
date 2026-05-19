//! `m.receipt` EDU stream — durable, RocksDB-backed.
//!
//! Backed by the `receipts_stream` column family, which is appended to
//! atomically with each locally-originated receipt write (see
//! `Database::set_local_receipt`). Per destination, we maintain a
//! cursor and emit at most one `m.receipt` EDU per scan, aggregating
//! every (room, type, user) entry past the cursor into the spec's
//! nested `content` map.
//!
//! Cursor advances past entries we *considered* — including ones we
//! skipped because the destination doesn't share the room. This is
//! intentional: skipped entries don't accumulate unbounded work, and a
//! peer that joins a room later catches up via the next receipt write,
//! not by re-scanning historical entries we already passed over.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Value, json};

use vela_store::db::Database;

use crate::federation::edu::EduStream;

/// Soft cap on receipt entries collapsed into a single outbound EDU.
/// One `m.receipt` EDU can carry many receipts in its nested map; we
/// bound it to keep transaction sizes reasonable. Excess entries
/// remain in the stream for the next scan.
const MAX_RECEIPTS_PER_EDU: usize = 100;

/// Hard cap on stream entries scanned per call. Bounds work even when
/// most entries are filtered out (destination not in room).
const MAX_STREAM_ENTRIES_PER_SCAN: usize = 512;

pub struct ReceiptStream {
    pub our_server_name: String,
}

impl ReceiptStream {
    pub fn new(our_server_name: String) -> Arc<Self> {
        Arc::new(Self { our_server_name })
    }
}

impl EduStream for ReceiptStream {
    fn name(&self) -> &'static str {
        "receipts"
    }

    fn scan_since(
        &self,
        destination: &str,
        cursor: u64,
        _limit: usize,
        db: &Database,
    ) -> Result<(Vec<Value>, u64), rocksdb::Error> {
        let (entries, mut new_cursor) =
            db.scan_receipts_stream(cursor, MAX_STREAM_ENTRIES_PER_SCAN)?;
        if entries.is_empty() {
            return Ok((Vec::new(), new_cursor));
        }

        // Aggregate by (room_id → receipt_type → user_id), latest wins
        // (entries are scanned in monotonic order, so the loop's last
        // write per key is the freshest).
        type Inner = BTreeMap<String, BTreeMap<String, BTreeMap<String, Value>>>;
        let mut content: Inner = BTreeMap::new();
        let mut included = 0usize;

        for (pos, entry) in entries {
            new_cursor = pos;
            if included >= MAX_RECEIPTS_PER_EDU {
                // Stop *before* advancing past the unprocessed entry
                // so the next scan picks it up.
                new_cursor = pos.saturating_sub(1).max(cursor);
                break;
            }

            let Some(obj) = entry.as_object() else {
                continue;
            };
            let Some(room_nid) = obj.get("room").and_then(|v| v.as_u64()) else {
                continue;
            };
            let Some(receipt_type) = obj.get("type").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(user_nid) = obj.get("user").and_then(|v| v.as_u64()) else {
                continue;
            };
            let Some(event_id) = obj.get("event_id").and_then(|v| v.as_str()) else {
                continue;
            };
            let ts = obj.get("ts").and_then(|v| v.as_u64()).unwrap_or(0);
            // MSC4102: thread_id rides on the EDU under data.thread_id when
            // the receipt was scoped to a thread. Pull it out of the
            // stream entry (set_local_receipt persists it there).
            let thread_id = obj
                .get("thread_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // Filter: only fan out to destinations that share this room.
            // Spec: "Read receipts […] sent to all servers in the room."
            let servers = match db.get_remote_servers_in_room(room_nid, &self.our_server_name) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if !servers.iter().any(|s| s == destination) {
                continue;
            }

            let Some(room_id) = nid_to_string(db, room_nid) else {
                continue;
            };
            let Some(user_id) = nid_to_string(db, user_nid) else {
                continue;
            };

            let mut data = serde_json::Map::new();
            data.insert("ts".into(), json!(ts));
            if let Some(tid) = &thread_id {
                data.insert("thread_id".into(), json!(tid));
            }
            // MSC4102: the federation EDU shape only carries one receipt
            // per (room, type, user), so when the user has both a
            // threaded and unthreaded receipt for the same room+type the
            // unthreaded one is the room-wide anchor and must win.
            // Tested by TestThreadReceiptsInSyncMSC4102: alice posts
            // threaded then unthreaded; the test asserts bob (federated)
            // sees the unthreaded receipt down /sync. Without this guard
            // the latest-write-wins aggregation drops the unthreaded
            // receipt under the threaded one.
            let user_slot = content
                .entry(room_id)
                .or_default()
                .entry(receipt_type.to_string())
                .or_default()
                .entry(user_id)
                .or_insert_with(|| {
                    json!({
                        "event_ids": [event_id],
                        "data": Value::Object(data.clone()),
                    })
                });
            let existing_threaded = user_slot
                .pointer("/data/thread_id")
                .and_then(|v| v.as_str())
                .is_some();
            let new_unthreaded = thread_id.is_none();
            // Overwrite when:
            //   - the existing slot is threaded and the new entry is
            //     unthreaded (MSC4102 priority)
            //   - both have the same threading shape (latest wins)
            // Skip when the new entry is threaded but the existing one
            // is unthreaded — preserve the unthreaded anchor.
            if (existing_threaded && new_unthreaded) || (existing_threaded == thread_id.is_some()) {
                *user_slot = json!({
                    "event_ids": [event_id],
                    "data": Value::Object(data),
                });
            }
            included += 1;
        }

        if content.is_empty() {
            return Ok((Vec::new(), new_cursor));
        }

        let edu = json!({
            "edu_type": "m.receipt",
            "content": content,
        });
        Ok((vec![edu], new_cursor))
    }
}

fn nid_to_string(db: &Database, nid: u64) -> Option<String> {
    db.resolve_nid(nid).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Build a Database with a room that has Alice (local) and one
    /// joined member from each named remote server, so
    /// `get_remote_servers_in_room` returns those servers.
    fn setup_db_with_room(servers: &[&str]) -> (Arc<Database>, tempfile::TempDir, u64, u64) {
        let tmp = tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let room_nid = db.get_or_create_nid("!room:us.example").unwrap();
        let alice_nid = db.get_or_create_nid("@alice:us.example").unwrap();

        // Membership byte 1 = "join" per get_room_members's filter.
        const JOIN: u8 = 1;
        for server in servers {
            let user = format!("@bob:{}", server);
            let user_nid = db.get_or_create_nid(&user).unwrap();
            db.set_membership(room_nid, user_nid, JOIN).unwrap();
        }
        (db, tmp, room_nid, alice_nid)
    }

    #[test]
    fn scan_returns_aggregated_edu_for_destination_in_room() {
        let (db, _tmp, room_nid, alice_nid) = setup_db_with_room(&["peer.example"]);

        // Two locally-originated receipts for the same user — latest wins.
        db.set_local_receipt(room_nid, "m.read", alice_nid, "$msg1", 100, None)
            .unwrap();
        db.set_local_receipt(room_nid, "m.read", alice_nid, "$msg2", 200, None)
            .unwrap();

        let stream = ReceiptStream {
            our_server_name: "us.example".into(),
        };
        let (edus, cursor) = stream.scan_since("peer.example", 0, 25, &db).unwrap();

        assert_eq!(edus.len(), 1, "single aggregated EDU");
        assert!(cursor > 0, "cursor advances past scanned entries");

        let edu = &edus[0];
        assert_eq!(edu["edu_type"], "m.receipt");
        let users = &edu["content"]["!room:us.example"]["m.read"];
        // Latest-wins: $msg2 should be the survivor.
        assert_eq!(
            users["@alice:us.example"]["event_ids"][0], "$msg2",
            "later receipt supersedes earlier"
        );
        assert_eq!(users["@alice:us.example"]["data"]["ts"], 200);
    }

    #[test]
    fn scan_filters_destinations_not_in_room() {
        let (db, _tmp, room_nid, alice_nid) = setup_db_with_room(&["peer.example"]);

        db.set_local_receipt(room_nid, "m.read", alice_nid, "$msg", 100, None)
            .unwrap();

        let stream = ReceiptStream {
            our_server_name: "us.example".into(),
        };
        // other.example does NOT share the room; should get nothing,
        // but cursor still advances (we don't keep re-scanning).
        let (edus, cursor) = stream.scan_since("other.example", 0, 25, &db).unwrap();
        assert!(edus.is_empty(), "no EDU when destination is not in room");
        assert!(cursor > 0, "cursor advances past skipped entries");
    }

    #[test]
    fn scan_strictly_after_cursor() {
        let (db, _tmp, room_nid, alice_nid) = setup_db_with_room(&["peer.example"]);

        let pos1 = db
            .set_local_receipt(room_nid, "m.read", alice_nid, "$msg1", 100, None)
            .unwrap();
        db.set_local_receipt(room_nid, "m.read", alice_nid, "$msg2", 200, None)
            .unwrap();

        let stream = ReceiptStream {
            our_server_name: "us.example".into(),
        };
        // Cursor at pos1 → only the second entry should be visible.
        let (edus, cursor) = stream.scan_since("peer.example", pos1, 25, &db).unwrap();
        assert_eq!(edus.len(), 1);
        assert_eq!(
            edus[0]["content"]["!room:us.example"]["m.read"]["@alice:us.example"]["event_ids"][0],
            "$msg2"
        );
        assert!(cursor > pos1);
    }
}
