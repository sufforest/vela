//! `m.typing` EDU stream — in-memory, ephemeral.
//!
//! Typing has no source-of-truth log: it's a 30-second TTL state with
//! clobber semantics, and the spec calls EDUs "non-persistent." We
//! match that on the federation boundary with an in-memory ring of
//! pending typing-state changes per destination, keyed by
//! `(room_id, user_id)` so repeated start/stop for the same user
//! collapses to the latest before sending.
//!
//! ## Loss semantics
//!
//! Drains on scan. If the federation transaction containing these
//! EDUs fails, those entries are LOST — they don't roll back into the
//! buffer. This is spec-aligned: typing self-corrects on the next
//! state change (the c2s spec mandates client re-sends every 20–30s
//! while typing), and a missed transition heals within seconds. For
//! receipts/presence, where loss matters more, the durable RocksDB
//! streams provide stronger semantics.
//!
//! ## Wire shape (s2s)
//!
//! Per `data/api/server-server/definitions/event-schemas/m.typing.yaml`:
//! ```json
//! {
//!   "edu_type": "m.typing",
//!   "content": { "room_id": "...", "user_id": "...", "typing": true }
//! }
//! ```
//! One EDU per (room, user) state change — *not* a list. We emit one
//! per buffered entry on each scan.

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use serde_json::{Value, json};
use tracing::warn;

use vela_store::db::Database;

use crate::federation::edu::EduStream;

/// Soft cap on entries flushed to a single transaction. The federation
/// sender already enforces the spec's 100-EDU/transaction cap across
/// all streams, but we cap typing per-scan so a single noisy
/// destination's buffer can't starve other streams' room in the txn.
const MAX_TYPING_ENTRIES_PER_SCAN: usize = 50;

#[derive(Clone, Copy, Debug)]
struct TypingEntry {
    typing: bool,
}

pub struct TypingStream {
    /// Per-destination buffer. Outer key = destination server name;
    /// inner key = `(room_id, user_id)` for clobber.
    buffers: DashMap<String, HashMap<(String, String), TypingEntry>>,
    our_server_name: String,
    db: Arc<Database>,
}

impl TypingStream {
    pub fn new(db: Arc<Database>, our_server_name: String) -> Arc<Self> {
        Arc::new(Self {
            buffers: DashMap::new(),
            our_server_name,
            db,
        })
    }

    /// Record a typing-state change locally and stage one EDU per
    /// remote server in the room. Caller is responsible for waking
    /// the federation senders (typically via the same call site that
    /// updated `typing_state`).
    pub fn enqueue(&self, room_id: &str, user_id: &str, room_nid: u64, typing: bool) {
        let servers = match self
            .db
            .get_remote_servers_in_room(room_nid, &self.our_server_name)
        {
            Ok(s) => s,
            Err(e) => {
                warn!(room_nid, error = %e, "typing enqueue: get_remote_servers_in_room failed");
                return;
            }
        };
        if servers.is_empty() {
            return;
        }
        // If WE are denied by the room's server_acl, don't waste a
        // round-trip — every recipient will reject the EDU on their
        // inbound check anyway. Sender_domain in check_server_acl is
        // tested against the deny list; passing our own server name
        // gives us the right answer.
        if crate::federation::server_acl::check_server_acl_db(
            &self.db,
            room_nid,
            &self.our_server_name,
        )
        .is_some()
        {
            return;
        }
        let key = (room_id.to_string(), user_id.to_string());
        for dest in servers {
            self.buffers
                .entry(dest)
                .or_default()
                .insert(key.clone(), TypingEntry { typing });
        }
    }
}

impl EduStream for TypingStream {
    fn name(&self) -> &'static str {
        "typing"
    }

    fn scan_since(
        &self,
        destination: &str,
        cursor: u64,
        _limit: usize,
        _db: &Database,
    ) -> Result<(Vec<Value>, u64), rocksdb::Error> {
        // Drain semantics: take everything we have for this destination
        // and let the caller send it. On send failure these entries are
        // gone — see module-level loss semantics note.
        let mut bucket = match self.buffers.get_mut(destination) {
            Some(b) if !b.is_empty() => b,
            _ => return Ok((Vec::new(), cursor)),
        };

        let to_send: Vec<((String, String), TypingEntry)> =
            bucket.drain().take(MAX_TYPING_ENTRIES_PER_SCAN).collect();
        // If we hit the cap, the remaining entries were already
        // drained from the iterator above — they're lost. The cap is
        // a soft limit (typing self-corrects), so we accept this
        // tradeoff over carrying state across calls.

        if to_send.is_empty() {
            return Ok((Vec::new(), cursor));
        }

        let edus: Vec<Value> = to_send
            .into_iter()
            .map(|((room_id, user_id), entry)| {
                json!({
                    "edu_type": "m.typing",
                    "content": {
                        "room_id": room_id,
                        "user_id": user_id,
                        "typing": entry.typing,
                    },
                })
            })
            .collect();

        // Cursor is meaningless for the in-memory ring (no persistence),
        // but the trait contract says: non-empty batch → strictly
        // greater cursor. Bump by one. The federation sender will
        // persist this advance to RocksDB on success — harmless;
        // restart wipes the buffer anyway.
        Ok((edus, cursor.saturating_add(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn setup_with_room_and_remote(remote_user: &str) -> (Arc<Database>, tempfile::TempDir, u64) {
        let tmp = tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let room = db.get_or_create_nid("!r:us.example").unwrap();
        let bob = db.get_or_create_nid(remote_user).unwrap();
        db.set_membership(room, bob, 1).unwrap();
        (db, tmp, room)
    }

    #[test]
    fn enqueue_emits_per_destination_in_room() {
        let (db, _tmp, room_nid) = setup_with_room_and_remote("@bob:peer.example");
        let stream = TypingStream::new(db.clone(), "us.example".into());

        stream.enqueue("!r:us.example", "@alice:us.example", room_nid, true);

        let (edus, cursor) = stream.scan_since("peer.example", 0, 25, &db).unwrap();
        assert_eq!(edus.len(), 1);
        assert!(cursor > 0);
        assert_eq!(edus[0]["edu_type"], "m.typing");
        assert_eq!(edus[0]["content"]["room_id"], "!r:us.example");
        assert_eq!(edus[0]["content"]["user_id"], "@alice:us.example");
        assert_eq!(edus[0]["content"]["typing"], true);
    }

    #[test]
    fn drain_empties_buffer() {
        let (db, _tmp, room_nid) = setup_with_room_and_remote("@bob:peer.example");
        let stream = TypingStream::new(db.clone(), "us.example".into());

        stream.enqueue("!r", "@alice:us.example", room_nid, true);
        let (first, _) = stream.scan_since("peer.example", 0, 25, &db).unwrap();
        assert_eq!(first.len(), 1);

        // Second scan with no further enqueues → empty.
        let (second, _) = stream.scan_since("peer.example", 1, 25, &db).unwrap();
        assert!(second.is_empty());
    }

    #[test]
    fn clobber_collapses_repeated_state_for_same_user() {
        let (db, _tmp, room_nid) = setup_with_room_and_remote("@bob:peer.example");
        let stream = TypingStream::new(db.clone(), "us.example".into());

        // Three rapid PUTs: typing→typing→not typing.
        stream.enqueue("!r", "@alice:us.example", room_nid, true);
        stream.enqueue("!r", "@alice:us.example", room_nid, true);
        stream.enqueue("!r", "@alice:us.example", room_nid, false);

        let (edus, _) = stream.scan_since("peer.example", 0, 25, &db).unwrap();
        assert_eq!(edus.len(), 1, "clobber to single entry per (room, user)");
        assert_eq!(edus[0]["content"]["typing"], false, "latest state wins");
    }

    #[test]
    fn skips_destinations_not_in_room() {
        let (db, _tmp, room_nid) = setup_with_room_and_remote("@bob:peer.example");
        let stream = TypingStream::new(db.clone(), "us.example".into());

        stream.enqueue("!r", "@alice:us.example", room_nid, true);

        let (edus, cursor) = stream.scan_since("other.example", 0, 25, &db).unwrap();
        assert!(edus.is_empty());
        assert_eq!(cursor, 0, "empty batch leaves cursor unchanged");
    }
}
