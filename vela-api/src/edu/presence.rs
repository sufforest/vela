//! `m.presence` EDU stream — durable, RocksDB-backed.
//!
//! Backed by `presence_stream`, which is appended to atomically with
//! each locally-originated presence change. Per destination, we
//! maintain a cursor and emit at most one `m.presence` EDU per scan,
//! containing the *current* presence record for each user whose
//! latest stream entry the destination cares about.
//!
//! Spec: "Servers should only send presence updates for users that
//! the receiving server would be interested in. Such as the
//! receiving server sharing a room with a given user." We filter by
//! "destination shares any joined room with this user."
//!
//! Cursor advances past skipped entries (same shape as receipts) —
//! work is bounded even when most updates are for users a peer doesn't
//! care about.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde_json::{Value, json};

use vela_store::db::Database;

use crate::edu::EduStream;

/// Soft cap on user presence entries collapsed into a single EDU.
const MAX_PRESENCE_ENTRIES_PER_EDU: usize = 100;

/// Hard cap on stream entries scanned per call.
const MAX_STREAM_ENTRIES_PER_SCAN: usize = 512;

pub struct PresenceStream {
    pub our_server_name: String,
}

impl PresenceStream {
    pub fn new(our_server_name: String) -> Arc<Self> {
        Arc::new(Self { our_server_name })
    }
}

impl EduStream for PresenceStream {
    fn name(&self) -> &'static str {
        "presence"
    }

    fn scan_since(
        &self,
        destination: &str,
        cursor: u64,
        _limit: usize,
        db: &Database,
    ) -> Result<(Vec<Value>, u64), rocksdb::Error> {
        let (entries, mut new_cursor) =
            db.scan_presence_stream(cursor, MAX_STREAM_ENTRIES_PER_SCAN)?;
        if entries.is_empty() {
            return Ok((Vec::new(), new_cursor));
        }

        // Last-write-wins per user: dedupe by user_nid keeping the
        // highest stream position. Iteration is in monotonic order so
        // the loop's last insert per key is the freshest.
        let mut latest_per_user: HashMap<u64, u64> = HashMap::new();
        for (pos, user_nid) in entries {
            new_cursor = pos;
            latest_per_user.insert(user_nid, pos);
        }

        // Resolve which of these users the destination is "interested
        // in" (shares any joined room). Cache room→servers lookups
        // within this scan to avoid duplicate work for users in the
        // same rooms.
        let mut interested: HashMap<u64, String> = HashMap::new(); // user_nid → user_id
        let mut considered = 0usize;
        let mut room_servers_cache: HashMap<u64, HashSet<String>> = HashMap::new();
        for user_nid in latest_per_user.keys() {
            if considered >= MAX_PRESENCE_ENTRIES_PER_EDU {
                break;
            }
            let rooms = match db.get_user_joined_rooms(*user_nid) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let shares = rooms.iter().any(|room_nid| {
                room_servers_cache
                    .entry(*room_nid)
                    .or_insert_with(|| {
                        db.get_remote_servers_in_room(*room_nid, &self.our_server_name)
                            .unwrap_or_default()
                            .into_iter()
                            .collect()
                    })
                    .contains(destination)
            });
            if !shares {
                continue;
            }
            let Some(user_id) = db.resolve_nid(*user_nid).ok().flatten() else {
                continue;
            };
            interested.insert(*user_nid, user_id);
            considered += 1;
        }

        if interested.is_empty() {
            return Ok((Vec::new(), new_cursor));
        }

        // Build the `push` array: one entry per user with their
        // current presence record reshaped into spec wire form.
        let mut push: Vec<Value> = Vec::with_capacity(interested.len());
        for (user_nid, user_id) in interested {
            let Some(rec) = db.get_presence(user_nid).ok().flatten() else {
                continue;
            };
            push.push(format_presence_for_wire(&user_id, &rec));
        }

        if push.is_empty() {
            return Ok((Vec::new(), new_cursor));
        }

        let edu = json!({
            "edu_type": "m.presence",
            "content": { "push": push },
        });
        Ok((vec![edu], new_cursor))
    }
}

/// Reshape a stored presence record into the s2s wire format. Stored:
/// `{presence, status_msg?, last_active_ms}`. Wire (per spec
/// `m.presence`): `{user_id, presence, last_active_ago, currently_active, status_msg?}`.
pub fn format_presence_for_wire(user_id: &str, rec: &Value) -> Value {
    let presence = rec
        .get("presence")
        .and_then(|v| v.as_str())
        .unwrap_or("offline");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let last_active_ms = rec
        .get("last_active_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(now);
    let last_active_ago = now.saturating_sub(last_active_ms);
    let currently_active = presence == "online" && last_active_ago < 5 * 60 * 1000;

    let mut out = serde_json::Map::new();
    out.insert("user_id".into(), json!(user_id));
    out.insert("presence".into(), json!(presence));
    out.insert("last_active_ago".into(), json!(last_active_ago));
    out.insert("currently_active".into(), json!(currently_active));
    if let Some(msg) = rec.get("status_msg").and_then(|v| v.as_str())
        && !msg.is_empty()
    {
        out.insert("status_msg".into(), json!(msg));
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn setup() -> (Arc<Database>, tempfile::TempDir) {
        let tmp = tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        (db, tmp)
    }

    #[test]
    fn format_for_wire_includes_required_fields() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let rec = json!({
            "presence": "online",
            "status_msg": "hi",
            "last_active_ms": now,
        });
        let v = format_presence_for_wire("@alice:us.example", &rec);
        assert_eq!(v["user_id"], "@alice:us.example");
        assert_eq!(v["presence"], "online");
        assert_eq!(v["status_msg"], "hi");
        assert_eq!(v["currently_active"], true);
        assert!(v["last_active_ago"].as_u64().unwrap() < 1000);
    }

    #[test]
    fn scan_skips_users_destination_does_not_share_room_with() {
        let (db, _tmp) = setup();
        let alice = db.get_or_create_nid("@alice:us.example").unwrap();
        // No joined rooms for alice → no peer is interested.
        db.set_local_presence(alice, &json!({"presence": "online", "last_active_ms": 0}))
            .unwrap();

        let stream = PresenceStream {
            our_server_name: "us.example".into(),
        };
        let (edus, cursor) = stream.scan_since("peer.example", 0, 25, &db).unwrap();
        assert!(edus.is_empty(), "no shared rooms → no EDU");
        assert!(cursor > 0, "cursor advances past skipped entry");
    }

    #[test]
    fn scan_emits_for_destination_sharing_a_room() {
        let (db, _tmp) = setup();
        let room = db.get_or_create_nid("!r:us.example").unwrap();
        let alice = db.get_or_create_nid("@alice:us.example").unwrap();
        let bob = db.get_or_create_nid("@bob:peer.example").unwrap();
        // Alice and Bob both joined to the same room.
        db.set_membership(room, alice, 1).unwrap();
        db.set_membership(room, bob, 1).unwrap();

        db.set_local_presence(
            alice,
            &json!({"presence": "online", "last_active_ms": 0, "status_msg": "hi"}),
        )
        .unwrap();

        let stream = PresenceStream {
            our_server_name: "us.example".into(),
        };
        let (edus, _) = stream.scan_since("peer.example", 0, 25, &db).unwrap();
        assert_eq!(edus.len(), 1);
        assert_eq!(edus[0]["edu_type"], "m.presence");
        let push = &edus[0]["content"]["push"];
        assert_eq!(push.as_array().unwrap().len(), 1);
        assert_eq!(push[0]["user_id"], "@alice:us.example");
        assert_eq!(push[0]["presence"], "online");
        assert_eq!(push[0]["status_msg"], "hi");
    }

    #[test]
    fn scan_collapses_repeated_updates_to_latest() {
        let (db, _tmp) = setup();
        let room = db.get_or_create_nid("!r:us.example").unwrap();
        let alice = db.get_or_create_nid("@alice:us.example").unwrap();
        let bob = db.get_or_create_nid("@bob:peer.example").unwrap();
        db.set_membership(room, alice, 1).unwrap();
        db.set_membership(room, bob, 1).unwrap();

        db.set_local_presence(alice, &json!({"presence": "online", "last_active_ms": 0}))
            .unwrap();
        db.set_local_presence(
            alice,
            &json!({"presence": "unavailable", "last_active_ms": 0}),
        )
        .unwrap();
        db.set_local_presence(alice, &json!({"presence": "offline", "last_active_ms": 0}))
            .unwrap();

        let stream = PresenceStream {
            our_server_name: "us.example".into(),
        };
        let (edus, _) = stream.scan_since("peer.example", 0, 25, &db).unwrap();
        assert_eq!(edus.len(), 1);
        let push = &edus[0]["content"]["push"];
        assert_eq!(
            push.as_array().unwrap().len(),
            1,
            "repeated updates for one user collapse to one entry"
        );
        assert_eq!(
            push[0]["presence"], "offline",
            "current state is the latest write"
        );
    }
}
