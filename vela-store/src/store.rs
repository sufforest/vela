//! The storage-layer abstraction.
//!
//! `MatrixStore` is the slow-burn refactor of `Database`'s surface into
//! a backend-agnostic trait. The goal is *option value*: when (or if)
//! we need to run Vela on a different backend (Postgres, FoundationDB,
//! sharded RocksDB), the API crate shouldn't need to change — it
//! already depends on the trait.
//!
//! **Scope discipline.** The trait is not a carbon copy of `Database`.
//! We only add a method here once:
//!
//!   1. Its domain shape is stable (the method name and signature read
//!      naturally at the call site, without RocksDB vocabulary leaking
//!      through).
//!   2. At least one caller benefits — either a test wants to mock it
//!      or a new backend implements it.
//!
//! Methods that haven't earned their place stay on `Database` as
//! inherent impls. Callers keep using `&Database` directly for those.
//! This keeps the trait honest and lets us evolve the surface without
//! committing to misshapen abstractions up front.
//!
//! **Error type.** `StoreError` is currently a type alias for
//! `rocksdb::Error` — a temporary concession so the trait can ship
//! without forcing every caller to adopt a new error type today. When
//! an alternate backend lands, `StoreError` becomes a real enum and
//! `rocksdb::Error` turns into a `From` impl.

use std::sync::Arc;

use serde_json::Value;

use crate::db::{Database, EventHeader};

pub type StoreError = rocksdb::Error;
pub type StoreResult<T> = Result<T, StoreError>;

/// Read-path interface into Vela's persistent state.
///
/// Methods are chosen for stability — each has been called from
/// multiple API modules for several sessions without its signature
/// changing. New methods land when they meet the scope-discipline bar
/// (see module docs).
///
/// Object-safe: callers hold `Arc<dyn MatrixStore>` in `AppState`.
pub trait MatrixStore: Send + Sync + 'static {
    // --- String interning (nids) ---

    /// Return the numeric id for an already-interned string, or None.
    fn get_nid(&self, s: &str) -> StoreResult<Option<u64>>;

    /// Resolve a previously-minted nid back to its string.
    fn resolve_nid(&self, nid: u64) -> StoreResult<Option<String>>;

    // --- User directory ---

    fn get_user(&self, user_nid: u64) -> StoreResult<Option<Value>>;
    fn user_is_deactivated(&self, user_nid: u64) -> StoreResult<bool>;

    // --- Membership index ---

    fn get_membership(&self, room_nid: u64, user_nid: u64) -> StoreResult<Option<u8>>;
    fn get_room_members(&self, room_nid: u64) -> StoreResult<Vec<u64>>;
    fn get_user_joined_rooms(&self, user_nid: u64) -> StoreResult<Vec<u64>>;

    // --- Room state ---

    fn get_state_event_nid(
        &self,
        room_nid: u64,
        type_nid: u64,
        state_key_nid: u64,
    ) -> StoreResult<Option<u64>>;
    fn get_all_state_event_nids(&self, room_nid: u64) -> StoreResult<Vec<u64>>;

    // --- Events ---

    fn get_event(&self, event_nid: u64) -> StoreResult<Option<(EventHeader, Vec<u8>)>>;
    fn get_event_nid_by_id(&self, event_id: &str) -> StoreResult<Option<u64>>;
    fn get_event_id_by_nid(&self, event_nid: u64) -> StoreResult<Option<String>>;
    fn get_extremities(&self, room_nid: u64) -> StoreResult<Vec<u64>>;

    // --- Redactions ---

    fn get_redacted_by(&self, target_event_nid: u64) -> StoreResult<Option<u64>>;
}

/// Blanket impl: every `Database` is a `MatrixStore`. Forwards verbatim
/// to inherent impls — this is 1:1 with no semantic change. Callers
/// that take `&dyn MatrixStore` can be backed by `Database` today and
/// an alternate backend tomorrow.
impl MatrixStore for Database {
    fn get_nid(&self, s: &str) -> StoreResult<Option<u64>> {
        Database::get_nid(self, s)
    }
    fn resolve_nid(&self, nid: u64) -> StoreResult<Option<String>> {
        Database::resolve_nid(self, nid)
    }
    fn get_user(&self, user_nid: u64) -> StoreResult<Option<Value>> {
        Database::get_user(self, user_nid)
    }
    fn user_is_deactivated(&self, user_nid: u64) -> StoreResult<bool> {
        Database::user_is_deactivated(self, user_nid)
    }
    fn get_membership(&self, room_nid: u64, user_nid: u64) -> StoreResult<Option<u8>> {
        Database::get_membership(self, room_nid, user_nid)
    }
    fn get_room_members(&self, room_nid: u64) -> StoreResult<Vec<u64>> {
        Database::get_room_members(self, room_nid)
    }
    fn get_user_joined_rooms(&self, user_nid: u64) -> StoreResult<Vec<u64>> {
        Database::get_user_joined_rooms(self, user_nid)
    }
    fn get_state_event_nid(
        &self,
        room_nid: u64,
        type_nid: u64,
        state_key_nid: u64,
    ) -> StoreResult<Option<u64>> {
        Database::get_state_event_nid(self, room_nid, type_nid, state_key_nid)
    }
    fn get_all_state_event_nids(&self, room_nid: u64) -> StoreResult<Vec<u64>> {
        Database::get_all_state_event_nids(self, room_nid)
    }
    fn get_event(&self, event_nid: u64) -> StoreResult<Option<(EventHeader, Vec<u8>)>> {
        Database::get_event(self, event_nid)
    }
    fn get_event_nid_by_id(&self, event_id: &str) -> StoreResult<Option<u64>> {
        Database::get_event_nid_by_id(self, event_id)
    }
    fn get_event_id_by_nid(&self, event_nid: u64) -> StoreResult<Option<String>> {
        Database::get_event_id_by_nid(self, event_nid)
    }
    fn get_extremities(&self, room_nid: u64) -> StoreResult<Vec<u64>> {
        Database::get_extremities(self, room_nid)
    }
    fn get_redacted_by(&self, target_event_nid: u64) -> StoreResult<Option<u64>> {
        Database::get_redacted_by(self, target_event_nid)
    }
}

/// Convenience: `Arc<Database>` is the most common handle shape in the
/// codebase, so shipping an impl for it means call sites can treat
/// `store: Arc<Database>` as `store: Arc<dyn MatrixStore>` by
/// substitution without a cast.
impl<T: MatrixStore + ?Sized> MatrixStore for Arc<T> {
    fn get_nid(&self, s: &str) -> StoreResult<Option<u64>> {
        (**self).get_nid(s)
    }
    fn resolve_nid(&self, nid: u64) -> StoreResult<Option<String>> {
        (**self).resolve_nid(nid)
    }
    fn get_user(&self, user_nid: u64) -> StoreResult<Option<Value>> {
        (**self).get_user(user_nid)
    }
    fn user_is_deactivated(&self, user_nid: u64) -> StoreResult<bool> {
        (**self).user_is_deactivated(user_nid)
    }
    fn get_membership(&self, room_nid: u64, user_nid: u64) -> StoreResult<Option<u8>> {
        (**self).get_membership(room_nid, user_nid)
    }
    fn get_room_members(&self, room_nid: u64) -> StoreResult<Vec<u64>> {
        (**self).get_room_members(room_nid)
    }
    fn get_user_joined_rooms(&self, user_nid: u64) -> StoreResult<Vec<u64>> {
        (**self).get_user_joined_rooms(user_nid)
    }
    fn get_state_event_nid(
        &self,
        room_nid: u64,
        type_nid: u64,
        state_key_nid: u64,
    ) -> StoreResult<Option<u64>> {
        (**self).get_state_event_nid(room_nid, type_nid, state_key_nid)
    }
    fn get_all_state_event_nids(&self, room_nid: u64) -> StoreResult<Vec<u64>> {
        (**self).get_all_state_event_nids(room_nid)
    }
    fn get_event(&self, event_nid: u64) -> StoreResult<Option<(EventHeader, Vec<u8>)>> {
        (**self).get_event(event_nid)
    }
    fn get_event_nid_by_id(&self, event_id: &str) -> StoreResult<Option<u64>> {
        (**self).get_event_nid_by_id(event_id)
    }
    fn get_event_id_by_nid(&self, event_nid: u64) -> StoreResult<Option<String>> {
        (**self).get_event_id_by_nid(event_nid)
    }
    fn get_extremities(&self, room_nid: u64) -> StoreResult<Vec<u64>> {
        (**self).get_extremities(room_nid)
    }
    fn get_redacted_by(&self, target_event_nid: u64) -> StoreResult<Option<u64>> {
        (**self).get_redacted_by(target_event_nid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn blanket_impl_compiles_and_dispatches() {
        let tmp = TempDir::new().unwrap();
        let db = Database::open(tmp.path()).unwrap();

        // Take &dyn MatrixStore — prove object-safety and that
        // Database can be coerced.
        let store: &dyn MatrixStore = &db;
        assert!(store.get_nid("nonexistent").unwrap().is_none());

        // Same for Arc<Database> via the Arc blanket.
        let arc_db = Arc::new(db);
        let store: Arc<dyn MatrixStore> = arc_db.clone();
        assert!(store.get_nid("nonexistent").unwrap().is_none());
    }
}
