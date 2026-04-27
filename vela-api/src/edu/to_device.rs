//! `m.direct_to_device` EDU stream — durable, RocksDB-backed.
//!
//! Each entry is a complete EDU `content` block (already shaped per
//! spec: sender, type, message_id, messages map). The federation
//! sender wraps it with `edu_type: m.direct_to_device` and ships it.
//!
//! Per spec, message_id is unique per call, and receivers MUST dedupe
//! to handle retries safely. Senders MAY retry the same EDU verbatim
//! after transient failures — the stream-cursor model gives us this
//! for free: if the txn doesn't ack, the cursor doesn't advance and
//! the next scan returns the same payload.

use std::sync::Arc;

use serde_json::{Value, json};

use vela_store::db::Database;

use crate::edu::EduStream;

const MAX_TO_DEVICE_PER_SCAN: usize = 50;

pub struct ToDeviceStream;

impl ToDeviceStream {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl EduStream for ToDeviceStream {
    fn name(&self) -> &'static str {
        "to_device"
    }

    fn scan_since(
        &self,
        destination: &str,
        cursor: u64,
        _limit: usize,
        db: &Database,
    ) -> Result<(Vec<Value>, u64), rocksdb::Error> {
        let (entries, new_cursor) =
            db.scan_to_device_outbound(destination, cursor, MAX_TO_DEVICE_PER_SCAN)?;
        if entries.is_empty() {
            return Ok((Vec::new(), new_cursor));
        }
        let edus = entries
            .into_iter()
            .map(|(_pos, content)| {
                json!({
                    "edu_type": "m.direct_to_device",
                    "content": content,
                })
            })
            .collect();
        Ok((edus, new_cursor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn enqueue_and_scan_round_trip() {
        let tmp = tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());

        let content = json!({
            "sender": "@alice:us.example",
            "type": "m.room_key_request",
            "message_id": "msg-1",
            "messages": { "@bob:peer.example": { "DEV1": {"k": "v"} } },
        });
        db.enqueue_to_device_outbound("peer.example", &content)
            .unwrap();

        let stream = ToDeviceStream;
        let (edus, cursor) = stream.scan_since("peer.example", 0, 25, &db).unwrap();
        assert_eq!(edus.len(), 1);
        assert!(cursor > 0);
        assert_eq!(edus[0]["edu_type"], "m.direct_to_device");
        assert_eq!(edus[0]["content"]["message_id"], "msg-1");
    }

    #[test]
    fn scan_strictly_after_cursor_skips_delivered() {
        let tmp = tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let c1 = json!({"sender": "x", "type": "y", "message_id": "1", "messages": {}});
        let c2 = json!({"sender": "x", "type": "y", "message_id": "2", "messages": {}});
        let pos1 = db.enqueue_to_device_outbound("peer", &c1).unwrap();
        db.enqueue_to_device_outbound("peer", &c2).unwrap();

        let stream = ToDeviceStream;
        // Treat pos1 as already delivered — scan should return only c2.
        let (edus, _) = stream.scan_since("peer", pos1, 25, &db).unwrap();
        assert_eq!(edus.len(), 1);
        assert_eq!(edus[0]["content"]["message_id"], "2");
    }

    #[test]
    fn other_destinations_isolated() {
        let tmp = tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let c = json!({"sender": "x", "type": "y", "message_id": "1", "messages": {}});
        db.enqueue_to_device_outbound("peer.a", &c).unwrap();

        let stream = ToDeviceStream;
        let (edus, _) = stream.scan_since("peer.b", 0, 25, &db).unwrap();
        assert!(edus.is_empty(), "peer.b should not see peer.a's queue");
    }
}
