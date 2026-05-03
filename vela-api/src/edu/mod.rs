//! Federated EDU (Ephemeral Data Unit) infrastructure.
//!
//! Per the Matrix server-server spec, EDUs (`m.typing`, `m.receipt`,
//! `m.presence`, etc.) are non-persistent fan-out messages that ride
//! alongside PDUs in `/send/{txnId}` transactions. The spec calls them
//! "non-persistent" twice — there is no retry contract, and senders
//! MAY drop them under load.
//!
//! ## Shape
//!
//! Each logical EDU type is an [`EduStream`] — a source the federation
//! sender drains during transaction assembly. Implementations encode
//! the right semantics for their data:
//!
//! - **RocksDB-backed streams** (receipts, presence) scan a monotonic
//!   stream column family from a per-destination cursor. Newer state
//!   for the same `(room, user)` key supersedes older entries on the
//!   receiver naturally.
//! - **In-memory streams** (typing) keep a clobber-keyed ring with no
//!   disk footprint. Spec-aligned: typing has 30s TTL and self-corrects.
//!
//! The federation sender code is unaware of which kind it's draining.
//! Per-destination cursors live in `federation_edu_cursor` CF and are
//! advanced only after the corresponding transaction is acknowledged
//! by the peer. A crash between cursor advance and ack is safe — EDUs
//! are idempotent on the receiver, and one duplicate transaction does
//! no harm.

use serde_json::Value;
use std::sync::Arc;

use vela_store::db::Database;

/// A source of EDUs to be federated to a destination.
///
/// One implementation per logical EDU type. Registered with
/// [`crate::federation_sender::FederationSender`] at composition time
/// (in `vela-server::main`) — the sender doesn't construct streams,
/// only consumes them.
pub trait EduStream: Send + Sync {
    /// Stable identifier for this stream. Used as part of the cursor
    /// key in the `federation_edu_cursor` column family, so it MUST
    /// remain constant across versions — renaming it abandons every
    /// peer's cursor.
    fn name(&self) -> &'static str;

    /// Scan forward from `cursor` and return up to `limit` EDUs that
    /// should be sent to `destination`, plus the new cursor position.
    ///
    /// The new cursor MUST equal `cursor` if no EDUs are returned, and
    /// MUST be strictly greater than `cursor` if any are returned. The
    /// caller persists the new cursor only after the transaction
    /// containing these EDUs is acknowledged.
    fn scan_since(
        &self,
        destination: &str,
        cursor: u64,
        limit: usize,
        db: &Database,
    ) -> Result<(Vec<Value>, u64), rocksdb::Error>;
}

/// Convenience alias for the registered stream list.
pub type EduStreams = Vec<Arc<dyn EduStream>>;

pub mod device_list;
pub mod inbound;
pub mod presence;
pub mod receipts;
pub mod signing_key;
pub mod to_device;
pub mod typing;
