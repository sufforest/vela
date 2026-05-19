//! `m.signing_key_update` EDU stream — durable, RocksDB-backed.
//!
//! Drains the `signing_key_update_outbound` queue (per-destination
//! prefix, same shape as `device_list_outbound`). Each entry is a
//! complete EDU `content` block (`{user_id, master_key,
//! self_signing_key}`) — peers reading it persist the cross-signing
//! keys directly without a follow-up `/keys/query`.
//!
//! The user_signing_key is intentionally NEVER federated; per spec
//! it's private to the user and stays inside their server.

use std::sync::Arc;

use serde_json::{Value, json};

use vela_store::db::Database;

use crate::federation::edu::EduStream;

const MAX_PER_SCAN: usize = 50;

pub struct SigningKeyUpdateStream;

impl SigningKeyUpdateStream {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl EduStream for SigningKeyUpdateStream {
    fn name(&self) -> &'static str {
        "signing_key_update"
    }

    fn scan_since(
        &self,
        destination: &str,
        cursor: u64,
        _limit: usize,
        db: &Database,
    ) -> Result<(Vec<Value>, u64), rocksdb::Error> {
        let (entries, new_cursor) =
            db.scan_signing_key_update_outbound(destination, cursor, MAX_PER_SCAN)?;
        if entries.is_empty() {
            return Ok((Vec::new(), new_cursor));
        }
        let edus = entries
            .into_iter()
            .map(|(_pos, content)| {
                json!({
                    "edu_type": "m.signing_key_update",
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
            "user_id": "@alice:us.example",
            "master_key": {"keys": {"ed25519:abc": "AAA"}},
            "self_signing_key": {"keys": {"ed25519:def": "BBB"}},
        });
        db.enqueue_signing_key_update_outbound("peer.example", &content)
            .unwrap();

        let stream = SigningKeyUpdateStream;
        let (edus, cursor) = stream.scan_since("peer.example", 0, 25, &db).unwrap();
        assert_eq!(edus.len(), 1);
        assert!(cursor > 0);
        assert_eq!(edus[0]["edu_type"], "m.signing_key_update");
        assert_eq!(edus[0]["content"]["user_id"], "@alice:us.example");
        assert_eq!(
            edus[0]["content"]["master_key"]["keys"]["ed25519:abc"],
            "AAA"
        );
    }
}
