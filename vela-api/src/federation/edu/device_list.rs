//! `m.device_list_update` EDU stream — durable, RocksDB-backed.
//!
//! Drains the `device_list_outbound` queue (per-destination prefix,
//! same shape as to-device). Each entry is a complete EDU `content`
//! block with a per-user `stream_id` so the receiver can detect gaps.
//!
//! For now we don't track `prev_id` — the spec permits its absence
//! ("May be missing or empty for the first EDU in a sequence"), and
//! receivers respond to a missing prev_id by refetching keys via
//! `/user/keys/query`. That's correct behaviour, just slightly more
//! work for the receiver. A future revision can populate prev_id from
//! a per-(user, destination) last-emitted-stream-id table once the
//! plumbing is stable.

use std::sync::Arc;

use serde_json::{Value, json};

use vela_store::db::Database;

use crate::federation::edu::EduStream;

const MAX_DEVICE_LIST_PER_SCAN: usize = 50;

pub struct DeviceListStream;

impl DeviceListStream {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl EduStream for DeviceListStream {
    fn name(&self) -> &'static str {
        "device_list"
    }

    fn scan_since(
        &self,
        destination: &str,
        cursor: u64,
        _limit: usize,
        db: &Database,
    ) -> Result<(Vec<Value>, u64), rocksdb::Error> {
        let (entries, new_cursor) =
            db.scan_device_list_outbound(destination, cursor, MAX_DEVICE_LIST_PER_SCAN)?;
        if entries.is_empty() {
            return Ok((Vec::new(), new_cursor));
        }
        let edus = entries
            .into_iter()
            .map(|(_pos, content)| {
                json!({
                    "edu_type": "m.device_list_update",
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
    fn enqueue_and_scan_yields_expected_edu() {
        let tmp = tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());

        let content = json!({
            "user_id":   "@alice:us.example",
            "device_id": "DEV1",
            "stream_id": 7,
            "deleted":   false,
        });
        db.enqueue_device_list_outbound("peer.example", &content)
            .unwrap();

        let stream = DeviceListStream;
        let (edus, cursor) = stream.scan_since("peer.example", 0, 25, &db).unwrap();
        assert_eq!(edus.len(), 1);
        assert!(cursor > 0);
        assert_eq!(edus[0]["edu_type"], "m.device_list_update");
        assert_eq!(edus[0]["content"]["user_id"], "@alice:us.example");
        assert_eq!(edus[0]["content"]["device_id"], "DEV1");
        assert_eq!(edus[0]["content"]["stream_id"], 7);
    }
}
