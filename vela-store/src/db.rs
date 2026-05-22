use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use rocksdb::{ColumnFamilyDescriptor, DB, Direction, IteratorMode, Options, WriteBatch};
use serde_json::Value;

use crate::cf::COLUMN_FAMILIES;
use crate::keys;
use crate::nid;

/// Persisted monotonic u64 allocator. `next()` is an atomic
/// fetch_add until the in-memory block is exhausted; then it claims
/// a new block by persisting a fresh high water mark to
/// `meta[meta_key]`. On reopen, `next` resumes at the persisted high
/// water mark — strictly above every NID handed out previously.
/// Crash-loss is bounded by `block_size` (an unused tail of one
/// in-flight block).
pub struct PersistedCounter {
    meta_key: &'static str,
    block_size: u64,
    next: AtomicU64,
    /// Exclusive upper bound of the currently-claimed range.
    high_water: AtomicU64,
    claim_lock: Mutex<()>,
}

impl PersistedCounter {
    /// Open the counter against meta CF, seeding `initial_value` on
    /// first boot. Pick `initial_value` strictly above any NID an
    /// older binary might have allocated — `u64::MAX / 2` for the
    /// migration from the original shared-counter scheme.
    pub fn open(
        db: &DB,
        meta_key: &'static str,
        block_size: u64,
        initial_value: u64,
    ) -> Result<Self, rocksdb::Error> {
        let cf = db.cf_handle("meta").expect("meta CF must exist");
        let start = match db.get_cf(&cf, meta_key.as_bytes())? {
            Some(bytes) if bytes.len() == 8 => keys::decode_u64(&bytes),
            _ => {
                // First boot — seed the meta key so subsequent opens
                // skip this branch.
                db.put_cf(&cf, meta_key.as_bytes(), keys::encode_u64(initial_value))?;
                initial_value
            }
        };
        Ok(Self {
            meta_key,
            block_size,
            next: AtomicU64::new(start),
            high_water: AtomicU64::new(start),
            claim_lock: Mutex::new(()),
        })
    }

    /// Counter for read-only secondary DBs — never claims a block
    /// (high water is `u64::MAX`), so the disk-write path is
    /// unreachable from a process that can't write anyway.
    pub fn ephemeral(initial_value: u64) -> Self {
        Self {
            meta_key: "<ephemeral>",
            block_size: u64::MAX,
            next: AtomicU64::new(initial_value),
            high_water: AtomicU64::new(u64::MAX),
            claim_lock: Mutex::new(()),
        }
    }

    pub fn next(&self, db: &DB) -> Result<u64, rocksdb::Error> {
        let v = self.next.fetch_add(1, Ordering::Relaxed);
        if v < self.high_water.load(Ordering::Acquire) {
            return Ok(v);
        }
        let _g = self.claim_lock.lock().unwrap();
        if v < self.high_water.load(Ordering::Acquire) {
            return Ok(v);
        }
        // Persist the new high water before updating the in-memory
        // ceiling: a crash in between can only over-reserve (waste
        // IDs), never under-reserve (collide on a future reopen).
        let new_high = v.saturating_add(self.block_size + 1);
        let cf = db.cf_handle("meta").expect("meta CF must exist");
        db.put_cf(&cf, self.meta_key.as_bytes(), keys::encode_u64(new_high))?;
        self.high_water.store(new_high, Ordering::Release);
        Ok(v)
    }
}

/// Meta-CF keys for the HiLo NID counters. Access only via
/// `PersistedCounter`.
mod b_meta {
    pub const EVENT_NID: &str = "hilo:next_event_nid";
    pub const STRING_NID: &str = "hilo:next_string_nid";
    pub const SNAPSHOT_NID: &str = "hilo:next_snapshot_nid";
}

/// On-disk schema version. Bumped whenever a change to a CF layout
/// (key format, value encoding, new required CF, removed CF) makes
/// older data unreadable. Vela refuses to open a DB whose stamped
/// version differs from the binary's expected version — the implicit
/// contract is that any breaking schema change ships alongside a
/// migrator that brings the on-disk data up to the new version.
pub const SCHEMA_VERSION: &str = "1";
const SCHEMA_VERSION_KEY: &str = "schema_version";

/// How `persist_event_kind` should treat an event with respect to the
/// timeline, current state, and forward extremities. Use this for new
/// callers that need the in-between behaviours the bool form of
/// `persist_event` can't express:
/// - `BackfillTimeline`: gap-fill events that need a `stream_pos` so
///   `/messages` stream pagination finds them, but mustn't replace the
///   live forward extremity (they're historically older than it).
/// - `StateBundleOnly`: `send_join` state events that define current
///   state for the joining server but predate the join — they update
///   `room_state` so /sync surfaces them via the state.events channel,
///   without faking a recent timeline entry.
///
/// Existing callers using `persist_event(.., suppress)` keep working:
/// `suppress=false` → `Live`, `suppress=true` → `Outlier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum PersistKind {
    /// Live event from a local user or fresh federation transaction.
    /// Timeline yes, state yes (when the event has a state_key),
    /// extremity yes.
    Live,
    /// Backfilled gap-fill: /backfill response, /get_missing_events,
    /// /timestamp_to_event remote answer. Timeline yes, state no,
    /// extremity no — the event predates the room's actual forward
    /// extremity.
    BackfillTimeline,
    /// Outlier — auth-chain context, /event PDU fetches, soft-failed
    /// events. events CF only; absent from timeline, current state,
    /// and extremity set. paginate_dag still walks through outliers
    /// via prev_events.
    Outlier,
    /// State events from a `send_join` state bundle. State yes (when
    /// the event has a state_key), timeline no, extremity no. Only
    /// the join event itself becomes the post-join extremity, persisted
    /// separately as `Live` by the caller.
    StateBundleOnly,
}

impl PersistKind {
    pub(crate) fn writes_timeline(self) -> bool {
        matches!(self, PersistKind::Live | PersistKind::BackfillTimeline)
    }

    pub(crate) fn writes_room_state(self) -> bool {
        matches!(self, PersistKind::Live | PersistKind::StateBundleOnly)
    }

    pub(crate) fn updates_extremities(self) -> bool {
        matches!(self, PersistKind::Live)
    }
}

pub struct Database {
    pub(crate) db: DB,
    pub(crate) event_nid_counter: PersistedCounter,
    pub(crate) string_nid_counter: PersistedCounter,
    pub(crate) stream_counter: AtomicU64,
    pub(crate) snapshot_nid_counter: PersistedCounter,
    /// Monotonic position into `receipts_stream`, advanced once per
    /// locally-originated receipt write. Recovered from the on-disk CF
    /// at open. Independent from `stream_counter` so receipt EDU
    /// fan-out doesn't interleave with PDU stream positions.
    pub(crate) receipts_stream_counter: AtomicU64,
    /// Monotonic position into `presence_stream`, advanced once per
    /// locally-originated presence change. Same shape and rationale
    /// as `receipts_stream_counter`.
    pub(crate) presence_stream_counter: AtomicU64,
    /// Monotonic position into `to_device_outbound`, advanced once per
    /// queued `m.direct_to_device` EDU. Each entry already contains
    /// the destination, so unlike receipts/presence we don't need a
    /// per-destination cursor — federation_sender's existing PDU-style
    /// scan-from-cursor model fits naturally.
    pub(crate) to_device_outbound_counter: AtomicU64,
}

impl Database {
    /// Open the database as a read-only secondary against a running
    /// primary. Used by out-of-process inspection tools (`vela-admin`)
    /// so they can stat / list / dump without bouncing the server.
    ///
    /// `secondary_dir` is a scratch path RocksDB uses to materialise
    /// catch-up SST views; it must be on the same filesystem (or at
    /// least support hardlinks to the primary's SSTs) and be unique
    /// per concurrent caller. Returns a Database whose write methods
    /// will fail at the RocksDB layer — callers are expected to only
    /// run read paths against it. We deliberately don't statically
    /// type the read-only-ness; the noise of a `ReadOnlyDatabase`
    /// wrapper would dwarf the actual surface, and the only caller
    /// (`vela-admin`) is small enough to audit.
    pub fn open_secondary(primary: &Path, secondary_dir: &Path) -> Result<Self, rocksdb::Error> {
        let mut db_opts = Options::default();
        db_opts.set_max_background_jobs(4);
        // Secondary mode refuses to create missing CFs (it can't
        // write anything). Snapshot whatever CFs the primary
        // currently has on disk so we don't fail just because the
        // binary's COLUMN_FAMILIES list moved forward of the
        // running server's.
        let existing = DB::list_cf(&db_opts, primary)
            .unwrap_or_else(|_| COLUMN_FAMILIES.iter().map(|s| s.to_string()).collect());
        let cfs: Vec<ColumnFamilyDescriptor> = existing
            .iter()
            .map(|name| {
                let mut cf_opts = Options::default();
                configure_cf(&mut cf_opts, name);
                ColumnFamilyDescriptor::new(name, cf_opts)
            })
            .collect();
        let db = DB::open_cf_descriptors_as_secondary(&db_opts, primary, secondary_dir, cfs)?;
        Ok(Self {
            db,
            // Secondary DBs never allocate ids / stream positions;
            // pick dummy ephemeral counters so any accidental
            // allocator call is at least visible in logs. The
            // allocator paths would fail at the RocksDB layer
            // anyway (writes refused on the secondary).
            event_nid_counter: PersistedCounter::ephemeral(1),
            string_nid_counter: PersistedCounter::ephemeral(1),
            stream_counter: AtomicU64::new(1),
            receipts_stream_counter: AtomicU64::new(1),
            presence_stream_counter: AtomicU64::new(1),
            snapshot_nid_counter: PersistedCounter::ephemeral(1),
            to_device_outbound_counter: AtomicU64::new(1),
        })
    }

    pub fn open(path: &Path) -> Result<Self, rocksdb::Error> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_max_background_jobs(4);
        db_opts.increase_parallelism(num_cpus() as i32);

        let cfs: Vec<ColumnFamilyDescriptor> = COLUMN_FAMILIES
            .iter()
            .map(|name| {
                let mut cf_opts = Options::default();
                configure_cf(&mut cf_opts, name);
                ColumnFamilyDescriptor::new(*name, cf_opts)
            })
            .collect();

        let db = DB::open_cf_descriptors(&db_opts, path, cfs)?;

        // Schema-version stamp. Forward-compatible: a clean DB has no
        // version key, so we stamp it on first open. An existing DB
        // with an older / mismatched version is refused — the stamp is
        // the contract that any breaking schema change ships alongside
        // a migrator.
        {
            let cf_meta = db.cf_handle("meta").expect("meta CF created");
            match db.get_cf(&cf_meta, SCHEMA_VERSION_KEY.as_bytes())? {
                Some(bytes) => {
                    let on_disk = String::from_utf8_lossy(&bytes).into_owned();
                    if on_disk != SCHEMA_VERSION {
                        // Refuse to operate. Operators see this on
                        // startup, not in a request path, so a panic is
                        // the right signal — the binary won't touch
                        // unsafe data.
                        panic!(
                            "Vela DB schema version mismatch: on-disk={}, binary expects={}. \
                             Migration not yet implemented.",
                            on_disk, SCHEMA_VERSION
                        );
                    }
                }
                None => {
                    db.put_cf(
                        &cf_meta,
                        SCHEMA_VERSION_KEY.as_bytes(),
                        SCHEMA_VERSION.as_bytes(),
                    )?;
                }
            }
        }

        // One-time repair for `room_state` entries left dangling by
        // the recover_max_nid bug fixed in this release. Cheap on a
        // clean DB (one iterator pass, no writes). Logs at warn level
        // when it actually fixes anything so operators see what the
        // upgrade did.
        repair_room_state_orphans(&db)?;

        // Populate `presence_activity_index` for any existing
        // `user_presence` records. v0.1.1 DBs have presence records
        // but no index; the sweeper relies on the index to do its
        // prefix-bounded walk. Idempotent — re-running is a series
        // of put_cf no-ops since every index key is already present.
        {
            let presence_cf = db.cf_handle("user_presence").unwrap();
            let index_cf = db.cf_handle("presence_activity_index").unwrap();
            let mut batch = WriteBatch::default();
            let mut count = 0u64;
            for entry in db.iterator_cf(&presence_cf, IteratorMode::Start) {
                let (key, val) = entry?;
                if key.len() != 8 {
                    continue;
                }
                let user_nid = keys::decode_u64(&key);
                let rec: Value = serde_json::from_slice(&val).unwrap_or(Value::Null);
                if let Some(ms) = rec.get("last_active_ms").and_then(|x| x.as_u64()) {
                    batch.put_cf(&index_cf, presence_activity_key(ms, user_nid), []);
                    count += 1;
                }
            }
            if count > 0 {
                db.write(batch)?;
                tracing::debug!(count, "presence_activity_index populated at open");
            }
        }

        // Seed NID counters at u64::MAX/2 on first boot: above any
        // NID that an older binary might have allocated below that
        // threshold, so no migration scan is needed.
        let event_nid_counter = PersistedCounter::open(&db, b_meta::EVENT_NID, 1000, u64::MAX / 2)?;
        let string_nid_counter =
            PersistedCounter::open(&db, b_meta::STRING_NID, 100, u64::MAX / 2)?;
        let snapshot_nid_counter =
            PersistedCounter::open(&db, b_meta::SNAPSHOT_NID, 100, u64::MAX / 2)?;

        let stream_counter = recover_max_stream(&db);
        // Half-max sanity tripwire. At our load-test ceiling (~50k
        // bumps/sec sustained) this triggers in ~5 million years, so
        // hitting it almost certainly means recovery is wrong, not
        // that we've actually consumed half the u64 space. Logged
        // loudly so an operator notices before the wrap.
        if stream_counter > u64::MAX / 2 {
            tracing::error!(
                stream_counter,
                "stream_counter past u64::MAX/2 on recovery — \
                 investigate before further writes"
            );
        }
        let receipts_stream_counter = recover_max_receipts_stream(&db).unwrap_or(1);
        let presence_stream_counter = recover_max_presence_stream(&db).unwrap_or(1);
        let to_device_outbound_counter = recover_max_to_device_outbound(&db).unwrap_or(1);

        Ok(Self {
            db,
            event_nid_counter,
            string_nid_counter,
            stream_counter: AtomicU64::new(stream_counter),
            snapshot_nid_counter,
            receipts_stream_counter: AtomicU64::new(receipts_stream_counter),
            presence_stream_counter: AtomicU64::new(presence_stream_counter),
            to_device_outbound_counter: AtomicU64::new(to_device_outbound_counter),
        })
    }

    // --- Counter operations ---

    /// Allocate the next event NID. Atomic fast path; occasionally
    /// persists a new range to the `meta` CF when the in-memory
    /// block is exhausted (see `PersistedCounter`).
    pub fn next_nid(&self) -> Result<u64, rocksdb::Error> {
        self.event_nid_counter.next(&self.db)
    }

    /// Allocate a fresh stream position. The returned `StreamPosition`
    /// is monotonically greater than any previously allocated position
    /// across restarts (durability provided by RocksDB's sequence
    /// number; see `recover_max_stream`).
    pub fn next_stream_position(&self) -> StreamPosition {
        StreamPosition(self.stream_counter.fetch_add(1, Ordering::Relaxed))
    }

    pub fn db_ref(&self) -> &DB {
        &self.db
    }

    /// Create a point-in-time checkpoint of the database at `out_path`.
    ///
    /// RocksDB's native checkpoint API: creates a new directory
    /// containing a consistent snapshot of every live SST (via hard
    /// links when on the same filesystem, so it's near-free in both
    /// time and disk). The snapshot is a complete, self-contained
    /// RocksDB you can `cp -a` off-box or open with the `vela` binary
    /// pointed at it.
    ///
    /// `out_path` must not already exist — RocksDB refuses to overwrite.
    /// Caller chooses a timestamped path per backup run.
    pub fn checkpoint(&self, out_path: &Path) -> Result<(), rocksdb::Error> {
        let checkpoint = rocksdb::checkpoint::Checkpoint::new(&self.db)?;
        checkpoint.create_checkpoint(out_path)
    }

    pub fn next_snapshot_nid(&self) -> Result<u64, rocksdb::Error> {
        self.snapshot_nid_counter.next(&self.db)
    }

    /// Returns the last allocated stream position (the position of the most recent event).
    pub fn current_stream_position(&self) -> u64 {
        self.stream_counter
            .load(Ordering::Relaxed)
            .saturating_sub(1)
    }

    // --- NID operations ---

    pub fn get_or_create_nid(&self, string: &str) -> Result<u64, rocksdb::Error> {
        nid::get_or_create_nid(&self.db, &self.string_nid_counter, string)
    }

    pub fn get_nid(&self, string: &str) -> Result<Option<u64>, rocksdb::Error> {
        nid::get_nid(&self.db, string)
    }

    pub fn resolve_nid(&self, nid: u64) -> Result<Option<String>, rocksdb::Error> {
        nid::resolve_nid(&self.db, nid)
    }

    // --- User operations ---

    pub fn create_user(&self, user_id: &str, password_hash: &str) -> Result<u64, rocksdb::Error> {
        let user_nid = self.get_or_create_nid(user_id)?;
        let cf = self.db.cf_handle("users").unwrap();
        let record = serde_json::json!({
            "user_id": user_id,
            "password_hash": password_hash,
        });
        self.db.put_cf(
            &cf,
            keys::encode_u64(user_nid),
            record.to_string().as_bytes(),
        )?;
        Ok(user_nid)
    }

    pub fn get_user(&self, user_nid: u64) -> Result<Option<Value>, rocksdb::Error> {
        let cf = self.db.cf_handle("users").unwrap();
        match self.db.get_cf(&cf, keys::encode_u64(user_nid))? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).unwrap_or(Value::Null))),
            None => Ok(None),
        }
    }

    pub fn user_exists(&self, user_id: &str) -> Result<bool, rocksdb::Error> {
        Ok(self.get_nid(user_id)?.is_some())
    }

    /// Return every user_id stored in the `users` CF. Used by
    /// `vela-admin users` to enumerate accounts; iterates the full
    /// CF, so cost is proportional to user count.
    pub fn list_local_user_ids(&self) -> Result<Vec<String>, rocksdb::Error> {
        let cf = self.db.cf_handle("users").unwrap();
        let mut out = Vec::new();
        let iter = self.db.iterator_cf(&cf, IteratorMode::Start);
        for item in iter {
            let (_, val) = item?;
            if let Ok(json) = serde_json::from_slice::<Value>(&val)
                && let Some(uid) = json.get("user_id").and_then(|v| v.as_str())
            {
                out.push(uid.to_string());
            }
        }
        Ok(out)
    }

    /// Replace the stored password hash for an existing user. No-op if the
    /// user record is missing (returns Ok without creating one).
    pub fn update_user_password(
        &self,
        user_nid: u64,
        password_hash: &str,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("users").unwrap();
        let key = keys::encode_u64(user_nid);
        let mut record: Value = match self.db.get_cf(&cf, key)? {
            Some(bytes) => serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            None => return Ok(()),
        };
        if let Some(obj) = record.as_object_mut() {
            obj.insert(
                "password_hash".to_string(),
                Value::String(password_hash.to_string()),
            );
            self.db.put_cf(&cf, key, record.to_string().as_bytes())?;
        }
        Ok(())
    }

    /// Mark a user as deactivated. Clears the password hash so no further
    /// login can succeed even if tokens somehow survive.
    pub fn deactivate_user(&self, user_nid: u64) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("users").unwrap();
        let key = keys::encode_u64(user_nid);
        let mut record: Value = match self.db.get_cf(&cf, key)? {
            Some(bytes) => serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            None => return Ok(()),
        };
        if let Some(obj) = record.as_object_mut() {
            obj.insert("deactivated".to_string(), Value::Bool(true));
            obj.insert("password_hash".to_string(), Value::String(String::new()));
            self.db.put_cf(&cf, key, record.to_string().as_bytes())?;
        }
        Ok(())
    }

    pub fn user_is_deactivated(&self, user_nid: u64) -> Result<bool, rocksdb::Error> {
        Ok(self
            .get_user(user_nid)?
            .and_then(|r| r.get("deactivated").and_then(|v| v.as_bool()))
            .unwrap_or(false))
    }

    /// Reverse of `deactivate_user`: clear the `deactivated` flag so
    /// the account can log in again. Does NOT restore the password
    /// hash — `deactivate_user` blanks it, and the operator must run
    /// `update_user_password` (typically via `!reset-password`) to
    /// give the user working credentials. No-op when the user record
    /// is missing or the flag was never set.
    pub fn reactivate_user(&self, user_nid: u64) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("users").unwrap();
        let key = keys::encode_u64(user_nid);
        let mut record: Value = match self.db.get_cf(&cf, key)? {
            Some(bytes) => serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            None => return Ok(()),
        };
        if let Some(obj) = record.as_object_mut() {
            obj.insert("deactivated".to_string(), Value::Bool(false));
            self.db.put_cf(&cf, key, record.to_string().as_bytes())?;
        }
        Ok(())
    }

    // --- Token operations ---

    pub fn create_token(&self, user_nid: u64, device_id: &str) -> Result<String, rocksdb::Error> {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        // Generate 32 random bytes, base64url encode
        let token_bytes: [u8; 32] = rand::random();
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);

        // Store SHA-256(token) → {user_nid, device_id}
        let token_hash = Sha256::digest(token.as_bytes());
        let cf = self.db.cf_handle("tokens").unwrap();
        let record = serde_json::json!({
            "user_nid": user_nid,
            "device_id": device_id,
        });
        self.db
            .put_cf(&cf, token_hash.as_slice(), record.to_string().as_bytes())?;
        Ok(token)
    }

    /// Mint a refreshable access token paired with a refresh token. The
    /// access token expires after `expires_in_ms`; the refresh token can
    /// rotate it via [`Database::refresh_access_token`].
    pub fn create_token_pair(
        &self,
        user_nid: u64,
        device_id: &str,
        expires_in_ms: u64,
    ) -> Result<(String, String), rocksdb::Error> {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let access_bytes: [u8; 32] = rand::random();
        let refresh_bytes: [u8; 32] = rand::random();
        let access_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(access_bytes);
        let refresh_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(refresh_bytes);

        let now_ms = now_ms();
        let expires_at_ms = now_ms.saturating_add(expires_in_ms);
        let access_hash = Sha256::digest(access_token.as_bytes());
        let refresh_hash = Sha256::digest(refresh_token.as_bytes());

        let access_cf = self.db.cf_handle("tokens").unwrap();
        let refresh_cf = self.db.cf_handle("refresh_tokens").unwrap();

        let access_record = serde_json::json!({
            "user_nid": user_nid,
            "device_id": device_id,
            "expires_at_ms": expires_at_ms,
        });
        let refresh_record = serde_json::json!({
            "user_nid": user_nid,
            "device_id": device_id,
            "access_hash": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(access_hash),
        });

        let mut batch = WriteBatch::default();
        batch.put_cf(
            &access_cf,
            access_hash.as_slice(),
            access_record.to_string().as_bytes(),
        );
        batch.put_cf(
            &refresh_cf,
            refresh_hash.as_slice(),
            refresh_record.to_string().as_bytes(),
        );
        self.db.write(batch)?;
        Ok((access_token, refresh_token))
    }

    /// Consume a refresh token, invalidating the previously paired access
    /// token, and mint a new (access, refresh) pair for the same
    /// (user, device). Returns `None` if the refresh token is unknown
    /// (already consumed, never issued, or wrong token).
    pub fn refresh_access_token(
        &self,
        refresh_token: &str,
        expires_in_ms: u64,
    ) -> Result<Option<(String, String, u64, String)>, rocksdb::Error> {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let old_refresh_hash = Sha256::digest(refresh_token.as_bytes());
        let refresh_cf = self.db.cf_handle("refresh_tokens").unwrap();
        let old_refresh_record = match self.db.get_cf(&refresh_cf, old_refresh_hash.as_slice())? {
            Some(b) => b,
            None => return Ok(None),
        };
        let old_refresh: Value = match serde_json::from_slice(&old_refresh_record) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let user_nid = match old_refresh["user_nid"].as_u64() {
            Some(n) => n,
            None => return Ok(None),
        };
        let device_id = match old_refresh["device_id"].as_str() {
            Some(d) => d.to_string(),
            None => return Ok(None),
        };

        let new_access_bytes: [u8; 32] = rand::random();
        let new_refresh_bytes: [u8; 32] = rand::random();
        let new_access = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(new_access_bytes);
        let new_refresh =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(new_refresh_bytes);

        let now_ms = now_ms();
        let expires_at_ms = now_ms.saturating_add(expires_in_ms);
        let new_access_hash = Sha256::digest(new_access.as_bytes());
        let new_refresh_hash = Sha256::digest(new_refresh.as_bytes());

        let access_cf = self.db.cf_handle("tokens").unwrap();
        let new_access_record = serde_json::json!({
            "user_nid": user_nid,
            "device_id": device_id,
            "expires_at_ms": expires_at_ms,
        });
        let new_refresh_record = serde_json::json!({
            "user_nid": user_nid,
            "device_id": device_id,
            "access_hash": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(new_access_hash),
        });

        let mut batch = WriteBatch::default();
        // Invalidate the previous access token if we still have its hash.
        if let Some(prev_access_b64) = old_refresh["access_hash"].as_str()
            && let Ok(prev_access_bytes) =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(prev_access_b64)
        {
            batch.delete_cf(&access_cf, &prev_access_bytes);
        }
        // Burn the consumed refresh token.
        batch.delete_cf(&refresh_cf, old_refresh_hash.as_slice());
        // Issue the new pair.
        batch.put_cf(
            &access_cf,
            new_access_hash.as_slice(),
            new_access_record.to_string().as_bytes(),
        );
        batch.put_cf(
            &refresh_cf,
            new_refresh_hash.as_slice(),
            new_refresh_record.to_string().as_bytes(),
        );
        self.db.write(batch)?;

        Ok(Some((new_access, new_refresh, user_nid, device_id)))
    }

    /// Validate an access token. Returns (user_nid, device_id) if valid
    /// and (if the token is refreshable) not yet expired.
    pub fn validate_token(&self, token: &str) -> Result<Option<(u64, String)>, rocksdb::Error> {
        use sha2::{Digest, Sha256};

        let token_hash = Sha256::digest(token.as_bytes());
        let cf = self.db.cf_handle("tokens").unwrap();
        match self.db.get_cf(&cf, token_hash.as_slice())? {
            Some(bytes) => {
                let record: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                if let Some(exp) = record["expires_at_ms"].as_u64()
                    && now_ms() >= exp
                {
                    return Ok(None);
                }
                match (record["user_nid"].as_u64(), record["device_id"].as_str()) {
                    (Some(user_nid), Some(device_id)) => {
                        Ok(Some((user_nid, device_id.to_string())))
                    }
                    _ => Ok(None), // corrupt token record
                }
            }
            None => Ok(None),
        }
    }

    // --- Device operations ---

    /// Delete every token belonging to `user_nid`, optionally keeping tokens
    /// whose device matches `keep_device`. Token records are full-scanned —
    /// acceptable at current scale; if we grow, add a user→token index.
    pub fn delete_user_tokens(
        &self,
        user_nid: u64,
        keep_device: Option<&str>,
    ) -> Result<usize, rocksdb::Error> {
        let access_cf = self.db.cf_handle("tokens").unwrap();
        let refresh_cf = self.db.cf_handle("refresh_tokens").unwrap();
        let mut batch = WriteBatch::default();
        let mut removed = 0usize;
        for (cf, count) in [(&access_cf, true), (&refresh_cf, false)] {
            let iter = self.db.iterator_cf(cf, IteratorMode::Start);
            for item in iter {
                let (key, val) = item?;
                let record: Value = match serde_json::from_slice(&val) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if record["user_nid"].as_u64() != Some(user_nid) {
                    continue;
                }
                if let Some(keep) = keep_device
                    && record["device_id"].as_str() == Some(keep)
                {
                    continue;
                }
                batch.delete_cf(cf, &key);
                if count {
                    removed += 1;
                }
            }
        }
        self.db.write(batch)?;
        Ok(removed)
    }

    pub fn create_device(&self, user_nid: u64, device_id: &str) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("devices").unwrap();
        let key = keys::encode_u64_bytes(user_nid, device_id.as_bytes());
        let record = serde_json::json!({"device_id": device_id});
        self.db.put_cf(&cf, &key, record.to_string().as_bytes())
    }

    pub fn get_device(
        &self,
        user_nid: u64,
        device_id: &str,
    ) -> Result<Option<Value>, rocksdb::Error> {
        let cf = self.db.cf_handle("devices").unwrap();
        let key = keys::encode_u64_bytes(user_nid, device_id.as_bytes());
        match self.db.get_cf(&cf, &key)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
            None => Ok(None),
        }
    }

    /// Update fields on a device record (currently `display_name`).
    /// Creates the record if missing.
    pub fn update_device_display_name(
        &self,
        user_nid: u64,
        device_id: &str,
        display_name: &str,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("devices").unwrap();
        let key = keys::encode_u64_bytes(user_nid, device_id.as_bytes());
        let mut rec = match self.db.get_cf(&cf, &key)? {
            Some(b) => serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null),
            None => serde_json::json!({"device_id": device_id}),
        };
        if let Some(obj) = rec.as_object_mut() {
            obj.insert(
                "display_name".to_string(),
                Value::String(display_name.to_string()),
            );
        }
        self.db.put_cf(&cf, &key, rec.to_string().as_bytes())
    }

    pub fn delete_device(&self, user_nid: u64, device_id: &str) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("devices").unwrap();
        let key = keys::encode_u64_bytes(user_nid, device_id.as_bytes());
        self.db.delete_cf(&cf, &key)
    }

    /// Delete every token issued for `(user_nid, device_id)`. Symmetric
    /// with `delete_user_tokens(user_nid, keep_device)` but inverted —
    /// here we drop just the named device's tokens instead.
    pub fn delete_device_tokens(
        &self,
        user_nid: u64,
        device_id: &str,
    ) -> Result<usize, rocksdb::Error> {
        let access_cf = self.db.cf_handle("tokens").unwrap();
        let refresh_cf = self.db.cf_handle("refresh_tokens").unwrap();
        let mut batch = WriteBatch::default();
        let mut removed = 0usize;
        for (cf, count) in [(&access_cf, true), (&refresh_cf, false)] {
            let iter = self.db.iterator_cf(cf, IteratorMode::Start);
            for item in iter {
                let (key, val) = item?;
                let record: Value = match serde_json::from_slice(&val) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if record["user_nid"].as_u64() != Some(user_nid) {
                    continue;
                }
                if record["device_id"].as_str() != Some(device_id) {
                    continue;
                }
                batch.delete_cf(cf, &key);
                if count {
                    removed += 1;
                }
            }
        }
        self.db.write(batch)?;
        Ok(removed)
    }

    pub fn list_devices(&self, user_nid: u64) -> Result<Vec<Value>, rocksdb::Error> {
        let cf = self.db.cf_handle("devices").unwrap();
        let prefix = keys::encode_u64(user_nid);
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        let mut out = Vec::new();
        for item in iter {
            let (key, val) = item?;
            if key.len() < 8 || key[..8] != prefix[..] {
                break;
            }
            if let Ok(v) = serde_json::from_slice::<Value>(&val) {
                out.push(v);
            }
        }
        Ok(out)
    }

    // --- Room operations ---

    pub fn create_room_meta(
        &self,
        room_nid: u64,
        room_id: &str,
        version: &str,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("room_meta").unwrap();
        let record = serde_json::json!({
            "room_id": room_id,
            "version": version,
        });
        self.db.put_cf(
            &cf,
            keys::encode_u64(room_nid),
            record.to_string().as_bytes(),
        )
    }

    /// Read the persisted room version string. Returns `None` if the
    /// room is unknown or its meta record is malformed. Callers parse
    /// this through `RoomVersion::parse` and fall back to v12 when the
    /// value is absent (pre-v6 rooms aren't persisted by vela in the
    /// first place; legacy meta records from very early development
    /// occasionally lacked the field).
    pub fn get_room_version(&self, room_nid: u64) -> Result<Option<String>, rocksdb::Error> {
        let cf = self.db.cf_handle("room_meta").unwrap();
        let bytes = match self.db.get_cf(&cf, keys::encode_u64(room_nid))? {
            Some(b) => b,
            None => return Ok(None),
        };
        let record: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        Ok(record
            .get("version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()))
    }

    /// MSC3706: flag a room as partial-state and stash the server hints
    /// the background filler will probe for `/state`. Merges with any
    /// existing meta record (room_id + version stay intact). Called
    /// from the outbound send_join path when the remote responded with
    /// `partial_state: true`.
    pub fn set_partial_state_join(
        &self,
        room_nid: u64,
        servers_in_room: &[String],
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("room_meta").unwrap();
        let key = keys::encode_u64(room_nid);
        let mut record = match self.db.get_cf(&cf, key)? {
            Some(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
                .unwrap_or_else(|_| serde_json::json!({})),
            None => serde_json::json!({}),
        };
        if let Some(obj) = record.as_object_mut() {
            obj.insert("partial_state".into(), serde_json::json!(true));
            obj.insert("servers_in_room".into(), serde_json::json!(servers_in_room));
        }
        self.db.put_cf(&cf, key, record.to_string().as_bytes())
    }

    /// MSC3706: lift the partial-state flag once the filler has merged
    /// in the rest of the room's state. Idempotent — clearing an
    /// already-cleared room is fine.
    pub fn clear_partial_state(&self, room_nid: u64) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("room_meta").unwrap();
        let key = keys::encode_u64(room_nid);
        let Some(bytes) = self.db.get_cf(&cf, key)? else {
            return Ok(());
        };
        let mut record: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        if let Some(obj) = record.as_object_mut() {
            obj.remove("partial_state");
            obj.remove("servers_in_room");
        }
        self.db.put_cf(&cf, key, record.to_string().as_bytes())
    }

    /// MSC3706: `(partial_state, servers_in_room)`. `partial_state=false`
    /// when the room is fully-stated (the common case); the servers
    /// list is empty in that case. Rooms predating MSC3706 always
    /// decode as full-state.
    pub fn get_partial_state_info(
        &self,
        room_nid: u64,
    ) -> Result<(bool, Vec<String>), rocksdb::Error> {
        let cf = self.db.cf_handle("room_meta").unwrap();
        let Some(bytes) = self.db.get_cf(&cf, keys::encode_u64(room_nid))? else {
            return Ok((false, Vec::new()));
        };
        let record: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return Ok((false, Vec::new())),
        };
        let partial = record
            .get("partial_state")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let servers = record
            .get("servers_in_room")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok((partial, servers))
    }

    /// List every room currently flagged as partial-state. Returns
    /// `(room_nid, room_id, servers_in_room)` triples. Called by the
    /// background filler on boot to bootstrap its work queue.
    pub fn list_partial_state_rooms(
        &self,
    ) -> Result<Vec<(u64, String, Vec<String>)>, rocksdb::Error> {
        let cf = self.db.cf_handle("room_meta").unwrap();
        let mut out = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (k, v) = item?;
            if k.len() != 8 {
                continue;
            }
            let nid = keys::decode_u64(&k);
            let Ok(record) = serde_json::from_slice::<serde_json::Value>(&v) else {
                continue;
            };
            if !record
                .get("partial_state")
                .and_then(|x| x.as_bool())
                .unwrap_or(false)
            {
                continue;
            }
            let room_id = record
                .get("room_id")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            let servers = record
                .get("servers_in_room")
                .and_then(|x| x.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            out.push((nid, room_id, servers));
        }
        Ok(out)
    }

    /// `get_room_version` decoded straight to the typed enum. Falls back
    /// to v12 when the meta record is missing, malformed, or carries an
    /// unsupported version string — that's safe for vela because v12 is
    /// the only version we EMIT today and any room we already persisted
    /// went through `create_room_meta` with a known-supported value.
    /// Federated joins hitting this fallback path will fail
    /// downstream auth-rule checks if the wire-format event shape
    /// disagrees, which is the right outcome.
    pub fn get_room_version_typed(
        &self,
        room_nid: u64,
    ) -> Result<vela_core::events::room_version::RoomVersion, rocksdb::Error> {
        let raw = self.get_room_version(room_nid)?;
        Ok(raw
            .as_deref()
            .and_then(vela_core::events::room_version::RoomVersion::parse)
            .unwrap_or(vela_core::events::room_version::RoomVersion::V12))
    }

    // --- User filters (sync) ---

    /// Store a sync filter definition for a user. Returns the assigned
    /// `filter_id` (base64-url-no-pad of a monotonic counter so the value
    /// can never start with `{` per spec).
    pub fn store_filter(
        &self,
        user_nid: u64,
        definition: &Value,
    ) -> Result<String, rocksdb::Error> {
        use base64::Engine;
        let cf = self.db.cf_handle("user_filters").unwrap();
        // Fresh per-user counter via prefix-scan max + 1. Filters are
        // append-only and small in volume, so the scan is fine.
        let prefix = keys::encode_u64(user_nid);
        let mut next_id: u64 = 1;
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        for item in iter {
            let (key, _) = item?;
            if key.len() < 16 || key[..8] != prefix[..] {
                break;
            }
            let id = keys::decode_u64(&key[8..16]);
            if id >= next_id {
                next_id = id + 1;
            }
        }
        let id_bytes = keys::encode_u64(next_id);
        let mut full_key = Vec::with_capacity(16);
        full_key.extend_from_slice(&prefix);
        full_key.extend_from_slice(&id_bytes);
        self.db
            .put_cf(&cf, &full_key, definition.to_string().as_bytes())?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id_bytes))
    }

    // --- User presence ---
    //
    // Presence is a single record per user: `{presence, status_msg,
    // last_active_ms}`. Writes happen from /presence/{userId}/status PUTs
    // and from each /sync tick for the calling user (to keep
    // last_active fresh). Reads: /sync bundles presence for rooms-mate
    // users, /presence/{userId}/status point reads.

    pub fn set_presence(&self, user_nid: u64, record: &Value) -> Result<(), rocksdb::Error> {
        let presence_cf = self.db.cf_handle("user_presence").unwrap();
        let index_cf = self.db.cf_handle("presence_activity_index").unwrap();

        let old_activity_ms = self
            .db
            .get_cf(&presence_cf, keys::encode_u64(user_nid))?
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|v| v.get("last_active_ms").and_then(|x| x.as_u64()));
        let new_activity_ms = record.get("last_active_ms").and_then(|x| x.as_u64());

        let mut batch = WriteBatch::default();
        batch.put_cf(
            &presence_cf,
            keys::encode_u64(user_nid),
            record.to_string().as_bytes(),
        );
        if let Some(old) = old_activity_ms
            && Some(old) != new_activity_ms
        {
            batch.delete_cf(&index_cf, presence_activity_key(old, user_nid));
        }
        if let Some(new) = new_activity_ms {
            batch.put_cf(&index_cf, presence_activity_key(new, user_nid), []);
        }
        self.db.write(batch)
    }

    /// Locally-originated presence write. Atomically updates
    /// `user_presence` + the activity index + appends to
    /// `presence_stream` (so the federation sender fans it out to
    /// peers that share rooms with this user). Returns the assigned
    /// stream position.
    ///
    /// Inbound EDUs from federation MUST NOT call this — peers fan
    /// out their own users' presence. Use `set_presence` for inbound
    /// dispatch.
    pub fn set_local_presence(&self, user_nid: u64, record: &Value) -> Result<u64, rocksdb::Error> {
        let presence_cf = self.db.cf_handle("user_presence").unwrap();
        let stream_cf = self.db.cf_handle("presence_stream").unwrap();
        let index_cf = self.db.cf_handle("presence_activity_index").unwrap();

        let pos = self.presence_stream_counter.fetch_add(1, Ordering::Relaxed);

        let old_activity_ms = self
            .db
            .get_cf(&presence_cf, keys::encode_u64(user_nid))?
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|v| v.get("last_active_ms").and_then(|x| x.as_u64()));
        let new_activity_ms = record.get("last_active_ms").and_then(|x| x.as_u64());

        // The stream entry is just the user_nid — readers re-fetch the
        // current `user_presence` record at scan time, so multiple
        // updates to the same user collapse naturally to "latest at
        // scan time" without unbounded growth in the stream payload.
        let mut batch = WriteBatch::default();
        batch.put_cf(
            &presence_cf,
            keys::encode_u64(user_nid),
            record.to_string().as_bytes(),
        );
        batch.put_cf(
            &stream_cf,
            keys::encode_u64(pos),
            keys::encode_u64(user_nid),
        );
        if let Some(old) = old_activity_ms
            && Some(old) != new_activity_ms
        {
            batch.delete_cf(&index_cf, presence_activity_key(old, user_nid));
        }
        if let Some(new) = new_activity_ms {
            batch.put_cf(&index_cf, presence_activity_key(new, user_nid), []);
        }
        self.db.write(batch)?;
        Ok(pos)
    }

    /// Walk the `presence_activity_index` and return user NIDs whose
    /// `last_active_ms` is strictly older than `cutoff_ms`. This is
    /// the candidate set for sweeper transitions — exhaustively
    /// scanning `user_presence` instead would be O(local users) per
    /// tick even when only a handful of users are actually due for a
    /// state change.
    pub fn presence_activity_due(&self, cutoff_ms: u64) -> Result<Vec<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("presence_activity_index").unwrap();
        let mut out = Vec::new();
        for entry in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (key, _) = entry?;
            if key.len() != 16 {
                continue;
            }
            let activity_ms = keys::decode_u64(&key[0..8]);
            if activity_ms >= cutoff_ms {
                // Index is sorted by activity_ms — first non-eligible
                // entry means every later entry is also non-eligible.
                break;
            }
            let user_nid = keys::decode_u64(&key[8..16]);
            out.push(user_nid);
        }
        Ok(out)
    }

    /// Append a per-destination `m.direct_to_device` EDU content to
    /// the outbound queue. Returns the assigned stream position.
    /// `content_json` is the spec's `content` block — caller wraps it
    /// with `edu_type` at send time.
    ///
    /// Unlike the receipts/presence streams (which derive payloads
    /// from durable local state at scan time), to-device EDUs are
    /// transient by nature — the message_id is unique per call and
    /// the payload is the user's encrypted content. We persist the
    /// EDU verbatim so the federation sender can replay it after
    /// peer outage or local restart.
    pub fn enqueue_to_device_outbound(
        &self,
        destination: &str,
        content_json: &Value,
    ) -> Result<u64, rocksdb::Error> {
        let cf = self.db.cf_handle("to_device_outbound").unwrap();
        let pos = self
            .to_device_outbound_counter
            .fetch_add(1, Ordering::Relaxed);
        let key = to_device_outbound_key(destination, pos);
        self.db
            .put_cf(&cf, &key, content_json.to_string().as_bytes())?;
        Ok(pos)
    }

    /// Scan the per-destination to-device queue strictly after
    /// `cursor` for `destination`, returning up to `limit` entries.
    /// Returned tuples are `(stream_pos, content_json)`. Also opportunistically
    /// prunes entries with pos <= cursor (already delivered) — keeps
    /// the queue bounded without a separate compaction task.
    pub fn scan_to_device_outbound(
        &self,
        destination: &str,
        cursor: u64,
        limit: usize,
    ) -> Result<(Vec<(u64, Value)>, u64), rocksdb::Error> {
        let cf = self.db.cf_handle("to_device_outbound").unwrap();
        let prefix = to_device_outbound_prefix(destination);

        // Prune below cursor. cursor==0 means "nothing delivered yet."
        if cursor > 0 {
            let mut to_delete: Vec<Vec<u8>> = Vec::new();
            let iter = self.db.prefix_iterator_cf(&cf, &prefix);
            for item in iter {
                let (key, _) = item?;
                if !key.starts_with(&prefix) {
                    break;
                }
                if key.len() < prefix.len() + 8 {
                    continue;
                }
                let pos_bytes = &key[prefix.len()..prefix.len() + 8];
                let mut buf = [0u8; 8];
                buf.copy_from_slice(pos_bytes);
                let pos = u64::from_be_bytes(buf);
                if pos <= cursor {
                    to_delete.push(key.to_vec());
                } else {
                    // Iterator is in ascending order — once we pass
                    // cursor, no more candidates for deletion.
                    break;
                }
            }
            if !to_delete.is_empty() {
                let mut batch = WriteBatch::default();
                for k in &to_delete {
                    batch.delete_cf(&cf, k);
                }
                self.db.write(batch)?;
            }
        }

        // Forward scan from cursor+1.
        let mut new_cursor = cursor;
        let mut out = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf, &prefix);
        for item in iter {
            let (key, val) = item?;
            if !key.starts_with(&prefix) {
                break;
            }
            if key.len() < prefix.len() + 8 {
                continue;
            }
            let pos_bytes = &key[prefix.len()..prefix.len() + 8];
            let mut buf = [0u8; 8];
            buf.copy_from_slice(pos_bytes);
            let pos = u64::from_be_bytes(buf);
            if pos <= cursor {
                continue;
            }
            let content: Value = match serde_json::from_slice(&val) {
                Ok(v) => v,
                Err(_) => continue,
            };
            out.push((pos, content));
            new_cursor = pos;
            if out.len() >= limit {
                break;
            }
        }
        Ok((out, new_cursor))
    }

    /// Bump and return the next `m.device_list_update` `stream_id`
    /// for `user_nid`. Per spec each user has its own monotonic
    /// stream — values aren't comparable across users. Persisted in
    /// the meta CF so it survives restart.
    ///
    /// Not atomic against concurrent writes for the same user; in
    /// practice device-list events for one user serialise through the
    /// caller's session, and the resulting duplicate ID would only
    /// cause receivers to refetch keys (the conservative response to
    /// any gap).
    /// Read the current device-list stream id for `user_nid` without
    /// bumping it. Used by handlers that need to report the current
    /// generation (e.g. federation `/user/devices/{userId}`).
    /// Returns 0 if the user has never had a device-list emit.
    pub fn current_user_device_list_stream(&self, user_nid: u64) -> Result<u64, rocksdb::Error> {
        let cf = self.db.cf_handle("meta").unwrap();
        let key = format!("device_list_stream:{user_nid}");
        Ok(self
            .db
            .get_cf(&cf, key.as_bytes())?
            .and_then(|b| {
                if b.len() == 8 {
                    Some(keys::decode_u64(&b))
                } else {
                    None
                }
            })
            .unwrap_or(0))
    }

    pub fn bump_user_device_list_stream(&self, user_nid: u64) -> Result<u64, rocksdb::Error> {
        let cf = self.db.cf_handle("meta").unwrap();
        let key = format!("device_list_stream:{user_nid}");
        let prev = self
            .db
            .get_cf(&cf, key.as_bytes())?
            .and_then(|b| {
                if b.len() == 8 {
                    Some(keys::decode_u64(&b))
                } else {
                    None
                }
            })
            .unwrap_or(0);
        let next = prev + 1;
        self.db
            .put_cf(&cf, key.as_bytes(), keys::encode_u64(next))?;
        Ok(next)
    }

    /// Append an `m.device_list_update` EDU content for delivery to
    /// `destination`. Mirrors `enqueue_to_device_outbound`'s shape.
    pub fn enqueue_device_list_outbound(
        &self,
        destination: &str,
        content_json: &Value,
    ) -> Result<u64, rocksdb::Error> {
        let cf = self.db.cf_handle("device_list_outbound").unwrap();
        let pos = self
            .to_device_outbound_counter
            .fetch_add(1, Ordering::Relaxed);
        let key = to_device_outbound_key(destination, pos);
        self.db
            .put_cf(&cf, &key, content_json.to_string().as_bytes())?;
        Ok(pos)
    }

    /// Scan device-list outbound queue strictly after `cursor`.
    /// Mirrors `scan_to_device_outbound` (same key shape, separate CF).
    pub fn scan_device_list_outbound(
        &self,
        destination: &str,
        cursor: u64,
        limit: usize,
    ) -> Result<(Vec<(u64, Value)>, u64), rocksdb::Error> {
        let cf = self.db.cf_handle("device_list_outbound").unwrap();
        let prefix = to_device_outbound_prefix(destination);

        if cursor > 0 {
            let mut to_delete: Vec<Vec<u8>> = Vec::new();
            let iter = self.db.prefix_iterator_cf(&cf, &prefix);
            for item in iter {
                let (key, _) = item?;
                if !key.starts_with(&prefix) {
                    break;
                }
                if key.len() < prefix.len() + 8 {
                    continue;
                }
                let pos_bytes = &key[prefix.len()..prefix.len() + 8];
                let mut buf = [0u8; 8];
                buf.copy_from_slice(pos_bytes);
                let pos = u64::from_be_bytes(buf);
                if pos <= cursor {
                    to_delete.push(key.to_vec());
                } else {
                    break;
                }
            }
            if !to_delete.is_empty() {
                let mut batch = WriteBatch::default();
                for k in &to_delete {
                    batch.delete_cf(&cf, k);
                }
                self.db.write(batch)?;
            }
        }

        let mut new_cursor = cursor;
        let mut out = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf, &prefix);
        for item in iter {
            let (key, val) = item?;
            if !key.starts_with(&prefix) {
                break;
            }
            if key.len() < prefix.len() + 8 {
                continue;
            }
            let pos_bytes = &key[prefix.len()..prefix.len() + 8];
            let mut buf = [0u8; 8];
            buf.copy_from_slice(pos_bytes);
            let pos = u64::from_be_bytes(buf);
            if pos <= cursor {
                continue;
            }
            let content: Value = match serde_json::from_slice(&val) {
                Ok(v) => v,
                Err(_) => continue,
            };
            out.push((pos, content));
            new_cursor = pos;
            if out.len() >= limit {
                break;
            }
        }
        Ok((out, new_cursor))
    }

    /// Append an `m.signing_key_update` EDU content for delivery to
    /// `destination`. Mirrors `enqueue_device_list_outbound` —
    /// same per-destination cursor counter, separate CF.
    pub fn enqueue_signing_key_update_outbound(
        &self,
        destination: &str,
        content_json: &Value,
    ) -> Result<u64, rocksdb::Error> {
        let cf = self.db.cf_handle("signing_key_update_outbound").unwrap();
        let pos = self
            .to_device_outbound_counter
            .fetch_add(1, Ordering::Relaxed);
        let key = to_device_outbound_key(destination, pos);
        self.db
            .put_cf(&cf, &key, content_json.to_string().as_bytes())?;
        Ok(pos)
    }

    /// Drain the signing-key-update outbound queue strictly after
    /// `cursor`. Mirrors `scan_device_list_outbound`'s shape.
    pub fn scan_signing_key_update_outbound(
        &self,
        destination: &str,
        cursor: u64,
        limit: usize,
    ) -> Result<(Vec<(u64, Value)>, u64), rocksdb::Error> {
        let cf = self.db.cf_handle("signing_key_update_outbound").unwrap();
        let prefix = to_device_outbound_prefix(destination);

        if cursor > 0 {
            let mut to_delete: Vec<Vec<u8>> = Vec::new();
            let iter = self.db.prefix_iterator_cf(&cf, &prefix);
            for item in iter {
                let (key, _) = item?;
                if !key.starts_with(&prefix) {
                    break;
                }
                if key.len() < prefix.len() + 8 {
                    continue;
                }
                let pos_bytes = &key[prefix.len()..prefix.len() + 8];
                let mut buf = [0u8; 8];
                buf.copy_from_slice(pos_bytes);
                let pos = u64::from_be_bytes(buf);
                if pos <= cursor {
                    to_delete.push(key.to_vec());
                } else {
                    break;
                }
            }
            if !to_delete.is_empty() {
                let mut batch = WriteBatch::default();
                for k in &to_delete {
                    batch.delete_cf(&cf, k);
                }
                self.db.write(batch)?;
            }
        }

        let mut new_cursor = cursor;
        let mut out = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf, &prefix);
        for item in iter {
            let (key, val) = item?;
            if !key.starts_with(&prefix) {
                break;
            }
            if key.len() < prefix.len() + 8 {
                continue;
            }
            let pos_bytes = &key[prefix.len()..prefix.len() + 8];
            let mut buf = [0u8; 8];
            buf.copy_from_slice(pos_bytes);
            let pos = u64::from_be_bytes(buf);
            if pos <= cursor {
                continue;
            }
            let content: Value = match serde_json::from_slice(&val) {
                Ok(v) => v,
                Err(_) => continue,
            };
            out.push((pos, content));
            new_cursor = pos;
            if out.len() >= limit {
                break;
            }
        }
        Ok((out, new_cursor))
    }

    /// Set whether `room_nid` is published in the public-rooms
    /// directory. Independent of join rules — a public-join room can
    /// be private-in-directory and vice versa, per the c2s spec on
    /// `/directory/list/room/{roomId}`.
    pub fn set_room_directory_visibility(
        &self,
        room_nid: u64,
        public: bool,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("room_directory").unwrap();
        let key = keys::encode_u64(room_nid);
        if public {
            self.db.put_cf(&cf, key, [1u8])
        } else {
            self.db.delete_cf(&cf, key)
        }
    }

    /// Read directory visibility. `None` means "never set" — caller
    /// can decide a default (e.g. fall back to join_rules == "public"
    /// for legacy rooms created before this CF existed).
    pub fn get_room_directory_visibility(
        &self,
        room_nid: u64,
    ) -> Result<Option<bool>, rocksdb::Error> {
        let cf = self.db.cf_handle("room_directory").unwrap();
        match self.db.get_cf(&cf, keys::encode_u64(room_nid))? {
            Some(b) if !b.is_empty() => Ok(Some(b[0] == 1)),
            None => Ok(None),
            _ => Ok(None),
        }
    }

    /// Inbound `m.direct_to_device` EDUs carry a unique `message_id`
    /// per spec. Receivers MUST dedupe — the sender may retry the
    /// same message_id after a transient failure. Returns true if
    /// this message_id has been seen before for `(origin, message_id)`.
    pub fn check_and_record_to_device_message_id(
        &self,
        origin: &str,
        message_id: &str,
    ) -> Result<bool, rocksdb::Error> {
        let cf = self.db.cf_handle("to_device_seen_message_ids").unwrap();
        let mut key = Vec::with_capacity(origin.len() + 1 + message_id.len());
        key.extend_from_slice(origin.as_bytes());
        key.push(0xff);
        key.extend_from_slice(message_id.as_bytes());
        if self.db.get_cf(&cf, &key)?.is_some() {
            return Ok(true);
        }
        self.db.put_cf(&cf, &key, [1u8])?;
        Ok(false)
    }

    /// Scan `presence_stream` strictly after `cursor`, returning up to
    /// `limit` entries. Each entry yields the changed `user_nid` (the
    /// caller re-reads `user_presence` for the current state).
    pub fn scan_presence_stream(
        &self,
        cursor: u64,
        limit: usize,
    ) -> Result<(Vec<(u64, u64)>, u64), rocksdb::Error> {
        let cf = self.db.cf_handle("presence_stream").unwrap();
        let start = keys::encode_u64(cursor.saturating_add(1));
        let iter = self
            .db
            .iterator_cf(&cf, IteratorMode::From(&start, Direction::Forward));

        let mut out: Vec<(u64, u64)> = Vec::with_capacity(limit.min(64));
        let mut new_cursor = cursor;
        for item in iter {
            let (key, val) = item?;
            if key.len() != 8 || val.len() != 8 {
                continue;
            }
            let pos = keys::decode_u64(&key);
            let user_nid = keys::decode_u64(&val);
            out.push((pos, user_nid));
            new_cursor = pos;
            if out.len() >= limit {
                break;
            }
        }
        Ok((out, new_cursor))
    }

    pub fn get_presence(&self, user_nid: u64) -> Result<Option<Value>, rocksdb::Error> {
        let cf = self.db.cf_handle("user_presence").unwrap();
        match self.db.get_cf(&cf, keys::encode_u64(user_nid))? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).unwrap_or(Value::Null))),
            None => Ok(None),
        }
    }

    /// Touch `last_active_ms` without changing the state/message. Called
    /// on each `/sync` tick for the syncing user so online-ness decays
    /// accurately even when they never call `/presence/.../status`.
    /// Maintains the activity index atomically.
    pub fn touch_presence(&self, user_nid: u64, now_ms: u64) -> Result<(), rocksdb::Error> {
        let presence_cf = self.db.cf_handle("user_presence").unwrap();
        let index_cf = self.db.cf_handle("presence_activity_index").unwrap();
        let key = keys::encode_u64(user_nid);

        let (mut rec, old_activity_ms) = match self.db.get_cf(&presence_cf, key)? {
            Some(b) => {
                let v: Value = serde_json::from_slice(&b).unwrap_or(Value::Null);
                let old = v.get("last_active_ms").and_then(|x| x.as_u64());
                (v, old)
            }
            None => (serde_json::json!({"presence": "online"}), None),
        };
        if let Some(obj) = rec.as_object_mut() {
            obj.insert("last_active_ms".into(), Value::from(now_ms));
        }

        let mut batch = WriteBatch::default();
        batch.put_cf(&presence_cf, key, rec.to_string().as_bytes());
        if let Some(old) = old_activity_ms
            && old != now_ms
        {
            batch.delete_cf(&index_cf, presence_activity_key(old, user_nid));
        }
        batch.put_cf(&index_cf, presence_activity_key(now_ms, user_nid), []);
        self.db.write(batch)
    }

    // --- User pushers ---

    /// Insert or replace a pusher record. The spec key is `(app_id, pushkey)`;
    /// we also partition by `user_nid` so records don't collide across users.
    pub fn set_pusher(
        &self,
        user_nid: u64,
        app_id: &str,
        pushkey: &str,
        record: &Value,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("user_pushers").unwrap();
        let mut key = Vec::with_capacity(8 + app_id.len() + 1 + pushkey.len());
        key.extend_from_slice(&keys::encode_u64(user_nid));
        key.extend_from_slice(app_id.as_bytes());
        key.push(0);
        key.extend_from_slice(pushkey.as_bytes());
        self.db.put_cf(&cf, &key, record.to_string().as_bytes())
    }

    pub fn delete_pusher(
        &self,
        user_nid: u64,
        app_id: &str,
        pushkey: &str,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("user_pushers").unwrap();
        let mut key = Vec::with_capacity(8 + app_id.len() + 1 + pushkey.len());
        key.extend_from_slice(&keys::encode_u64(user_nid));
        key.extend_from_slice(app_id.as_bytes());
        key.push(0);
        key.extend_from_slice(pushkey.as_bytes());
        self.db.delete_cf(&cf, &key)
    }

    pub fn list_pushers(&self, user_nid: u64) -> Result<Vec<Value>, rocksdb::Error> {
        let cf = self.db.cf_handle("user_pushers").unwrap();
        let prefix = keys::encode_u64(user_nid);
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        let mut out = Vec::new();
        for item in iter {
            let (key, val) = item?;
            if key.len() < 8 || key[..8] != prefix[..] {
                break;
            }
            if let Ok(v) = serde_json::from_slice::<Value>(&val) {
                out.push(v);
            }
        }
        Ok(out)
    }

    /// Delete every pusher belonging to `user_nid` whose stored
    /// `device_id` does not match `keep_device`. Used by
    /// `/account/password` with `logout_devices=true`: the spec
    /// requires that pushers for devices being logged out are
    /// removed alongside their access tokens.
    pub fn delete_user_pushers_except(
        &self,
        user_nid: u64,
        keep_device: &str,
    ) -> Result<usize, rocksdb::Error> {
        let cf = self.db.cf_handle("user_pushers").unwrap();
        let prefix = keys::encode_u64(user_nid);
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        let mut batch = WriteBatch::default();
        let mut removed = 0usize;
        for item in iter {
            let (key, val) = item?;
            if key.len() < 8 || key[..8] != prefix[..] {
                break;
            }
            let device_id = serde_json::from_slice::<Value>(&val)
                .ok()
                .and_then(|v| {
                    v.get("device_id")
                        .and_then(|d| d.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_default();
            if device_id == keep_device {
                continue;
            }
            batch.delete_cf(&cf, &key);
            removed += 1;
        }
        if removed > 0 {
            self.db.write(batch)?;
        }
        Ok(removed)
    }

    /// Delete every pusher belonging to `user_nid`. Used on account
    /// deactivation so the user stops receiving push notifications.
    /// Returns the number of pushers removed.
    pub fn delete_user_pushers(&self, user_nid: u64) -> Result<usize, rocksdb::Error> {
        let cf = self.db.cf_handle("user_pushers").unwrap();
        let prefix = keys::encode_u64(user_nid);
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        let mut batch = WriteBatch::default();
        let mut removed = 0usize;
        for item in iter {
            let (key, _val) = item?;
            if key.len() < 8 || key[..8] != prefix[..] {
                break;
            }
            batch.delete_cf(&cf, &key);
            removed += 1;
        }
        if removed > 0 {
            self.db.write(batch)?;
        }
        Ok(removed)
    }

    // --- Application Service storage ---

    /// Persist (or overwrite) an Application Service record. `value`
    /// is the JSON-serialised AppService record from vela-api.
    pub fn put_appservice(&self, appservice_nid: u64, value: &Value) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("appservices").unwrap();
        self.db.put_cf(
            &cf,
            keys::encode_u64(appservice_nid),
            value.to_string().as_bytes(),
        )
    }

    /// Iterate every registered AS. Used at boot to rebuild the
    /// in-memory registry.
    pub fn iter_appservices(&self) -> Result<Vec<(u64, Value)>, rocksdb::Error> {
        let cf = self.db.cf_handle("appservices").unwrap();
        let mut out = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (k, v) = item?;
            if k.len() != 8 {
                continue;
            }
            let nid = keys::decode_u64(&k);
            if let Ok(val) = serde_json::from_slice::<Value>(&v) {
                out.push((nid, val));
            }
        }
        Ok(out)
    }

    pub fn delete_appservice(&self, appservice_nid: u64) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("appservices").unwrap();
        self.db.delete_cf(&cf, keys::encode_u64(appservice_nid))
    }

    /// Push one pending transaction onto an AS's outbox.
    pub fn push_appservice_outbox(
        &self,
        appservice_nid: u64,
        txn_seq: u64,
        value: &Value,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("appservice_outbox").unwrap();
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&appservice_nid.to_be_bytes());
        key[8..].copy_from_slice(&txn_seq.to_be_bytes());
        self.db.put_cf(&cf, key, value.to_string().as_bytes())
    }

    /// Peek the oldest pending transaction for one AS. Returns
    /// `(txn_seq, value)` so the caller can delete after delivery.
    pub fn peek_appservice_outbox(
        &self,
        appservice_nid: u64,
    ) -> Result<Option<(u64, Value)>, rocksdb::Error> {
        let cf = self.db.cf_handle("appservice_outbox").unwrap();
        let prefix = keys::encode_u64(appservice_nid);
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        for item in iter {
            let (k, v) = item?;
            if k.len() != 16 || k[..8] != prefix[..] {
                break;
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&k[8..16]);
            let txn_seq = u64::from_be_bytes(buf);
            if let Ok(val) = serde_json::from_slice::<Value>(&v) {
                return Ok(Some((txn_seq, val)));
            }
        }
        Ok(None)
    }

    /// Remove a transaction after successful delivery. Idempotent.
    pub fn pop_appservice_outbox(
        &self,
        appservice_nid: u64,
        txn_seq: u64,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("appservice_outbox").unwrap();
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&appservice_nid.to_be_bytes());
        key[8..].copy_from_slice(&txn_seq.to_be_bytes());
        self.db.delete_cf(&cf, key)
    }

    /// Highest existing `txn_seq` for one AS. Boot uses this to
    /// prime the in-memory sequence counter without reusing ids.
    pub fn max_appservice_outbox_seq(
        &self,
        appservice_nid: u64,
    ) -> Result<Option<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("appservice_outbox").unwrap();
        let prefix = keys::encode_u64(appservice_nid);
        let mut max = None;
        for item in self.db.prefix_iterator_cf(&cf, prefix) {
            let (k, _) = item?;
            if k.len() != 16 || k[..8] != prefix[..] {
                break;
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&k[8..16]);
            max = Some(u64::from_be_bytes(buf));
        }
        Ok(max)
    }

    /// Append an abuse report into `event_reports`. Key is
    /// `[ts_ns_be][reporter_nid_be]`. Nanosecond resolution avoids
    /// same-millisecond collisions when one user submits multiple
    /// reports in rapid succession; reverse iteration still yields
    /// newest-first (what the admin bot wants).
    pub fn insert_event_report(
        &self,
        ts_ns: u64,
        reporter_nid: u64,
        value: &Value,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("event_reports").unwrap();
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&ts_ns.to_be_bytes());
        key[8..].copy_from_slice(&reporter_nid.to_be_bytes());
        self.db.put_cf(&cf, key, value.to_string().as_bytes())
    }

    /// Return the `limit` most-recent reports, newest first.
    pub fn list_recent_reports(&self, limit: usize) -> Result<Vec<Value>, rocksdb::Error> {
        let cf = self.db.cf_handle("event_reports").unwrap();
        let iter = self.db.iterator_cf(&cf, IteratorMode::End);
        let mut out = Vec::with_capacity(limit);
        for item in iter {
            let (_k, v) = item?;
            if let Ok(json) = serde_json::from_slice::<Value>(&v) {
                out.push(json);
            }
            if out.len() == limit {
                break;
            }
        }
        Ok(out)
    }

    pub fn get_filter(
        &self,
        user_nid: u64,
        filter_id: &str,
    ) -> Result<Option<Value>, rocksdb::Error> {
        use base64::Engine;
        let cf = self.db.cf_handle("user_filters").unwrap();
        let id_bytes =
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(filter_id.as_bytes()) {
                Ok(b) if b.len() == 8 => b,
                _ => return Ok(None),
            };
        let mut full_key = Vec::with_capacity(16);
        full_key.extend_from_slice(&keys::encode_u64(user_nid));
        full_key.extend_from_slice(&id_bytes);
        match self.db.get_cf(&cf, &full_key)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
            None => Ok(None),
        }
    }

    /// Enumerate every room_id known to the server (as recorded by
    /// `create_room_meta`). Used by `/publicRooms` to build the directory.
    pub fn list_room_ids(&self) -> Result<Vec<String>, rocksdb::Error> {
        let cf = self.db.cf_handle("room_meta").unwrap();
        let iter = self.db.iterator_cf(&cf, IteratorMode::Start);
        let mut out = Vec::new();
        for item in iter {
            let (_k, v) = item?;
            let Ok(rec) = serde_json::from_slice::<Value>(&v) else {
                continue;
            };
            if let Some(s) = rec.get("room_id").and_then(|v| v.as_str()) {
                out.push(s.to_string());
            }
        }
        Ok(out)
    }

    // --- Event persistence ---

    /// Persist an event with its binary header and canonical JSON.
    /// Also updates all relevant indexes atomically via WriteBatch.
    /// Persist an event to the database.
    ///
    /// `suppress_current_state`: when true, this event does NOT affect the
    /// server's "current state" view:
    /// - It is NOT added to `room_extremities`.
    /// - It does NOT update `room_state` (even if it's a state event).
    ///
    /// Two cases set this to true:
    /// 1. Soft-failed events per spec §Soft failure — stored, in state_res, but
    ///    not current-state, not a forward extremity. The caller additionally
    ///    records the soft-fail marker via [`Database::mark_soft_failed`].
    /// 2. Historical events pulled by federation gap-filling — they pre-date
    ///    current state and shouldn't rewrite it, nor should they become our
    ///    new forward extremity.
    ///
    /// For state-at-event lookups, `event_state` is always written: every event
    /// inherits a snapshot_nid from its first prev_event that has one. Accepted
    /// state events overwrite this via a subsequent `persist_state_snapshot`
    /// call.
    pub fn persist_event(
        &self,
        event_nid: u64,
        event_id: &str,
        room_nid: u64,
        type_nid: u64,
        sender_nid: u64,
        state_key_nid: u64, // 0 if not state event
        origin_server_ts: u64,
        depth: u64,
        event_json: &[u8],
        prev_event_nids: &[u64],
        auth_event_nids: &[u64],
        is_state: bool,
        suppress_current_state: bool,
    ) -> Result<u64, rocksdb::Error> {
        let kind = if suppress_current_state {
            PersistKind::Outlier
        } else {
            PersistKind::Live
        };
        self.persist_event_kind(
            event_nid,
            event_id,
            room_nid,
            type_nid,
            sender_nid,
            state_key_nid,
            origin_server_ts,
            depth,
            event_json,
            prev_event_nids,
            auth_event_nids,
            is_state,
            kind,
        )
    }

    /// `persist_event` extended with explicit `PersistKind`. Use this
    /// for callers that need `BackfillTimeline` or `StateBundleOnly`
    /// — bool form maps `false → Live` and `true → Outlier`, which
    /// covers the live and outlier paths but not backfill or
    /// send_join state bootstrap.
    #[allow(clippy::too_many_arguments)]
    pub fn persist_event_kind(
        &self,
        event_nid: u64,
        event_id: &str,
        room_nid: u64,
        type_nid: u64,
        sender_nid: u64,
        state_key_nid: u64,
        origin_server_ts: u64,
        depth: u64,
        event_json: &[u8],
        prev_event_nids: &[u64],
        auth_event_nids: &[u64],
        is_state: bool,
        kind: PersistKind,
    ) -> Result<u64, rocksdb::Error> {
        // Only allocate a timeline stream position for events that should
        // appear in the forward timeline. Historical / soft-failed events
        // must not consume a position (they'd sort after all current events,
        // scrambling backwards pagination).
        let stream_pos: u64 = if kind.writes_timeline() {
            self.next_stream_position().as_u64()
        } else {
            0
        };

        // Build binary header + JSON value
        let mut value = Vec::with_capacity(40 + event_json.len());
        value.extend_from_slice(&keys::encode_u64(type_nid));
        value.extend_from_slice(&keys::encode_u64(sender_nid));
        value.extend_from_slice(&keys::encode_u64(state_key_nid));
        value.extend_from_slice(&keys::encode_u64(origin_server_ts));
        value.extend_from_slice(&keys::encode_u64(depth));
        value.extend_from_slice(event_json);

        // Determine parent snapshot_nid from prev_events (looked up OUTSIDE the
        // batch — it's a read). Needed for event_state inheritance so that
        // non-state events are snapshot-addressable.
        let parent_snapshot_nid = {
            let cf_event_state = self.db.cf_handle("event_state").unwrap();
            let mut found: Option<u64> = None;
            for &prev_nid in prev_event_nids {
                if let Some(b) = self
                    .db
                    .get_cf(&cf_event_state, keys::encode_u64(prev_nid))?
                {
                    found = Some(keys::decode_u64(&b));
                    break;
                }
            }
            found
        };

        let mut batch = WriteBatch::default();

        // events CF
        let cf_events = self.db.cf_handle("events").unwrap();
        batch.put_cf(&cf_events, keys::encode_u64(event_nid), &value);

        // event_ids CF (event_id string → event_nid)
        let cf_eids = self.db.cf_handle("event_ids").unwrap();
        batch.put_cf(&cf_eids, event_id.as_bytes(), keys::encode_u64(event_nid));

        // event_id_reverse CF (event_nid → event_id string)
        let cf_eid_rev = self.db.cf_handle("event_id_reverse").unwrap();
        batch.put_cf(
            &cf_eid_rev,
            keys::encode_u64(event_nid),
            event_id.as_bytes(),
        );

        // room_timeline CF: events that should appear in the stream-pos
        // timeline. Outliers and StateBundleOnly are queryable by
        // event_id but not by stream_pos.
        if kind.writes_timeline() {
            let cf_timeline = self.db.cf_handle("room_timeline").unwrap();
            batch.put_cf(
                &cf_timeline,
                keys::encode_u64_pair(room_nid, stream_pos),
                keys::encode_u64(event_nid),
            );
        }

        // event_depth CF
        let cf_depth = self.db.cf_handle("event_depth").unwrap();
        batch.put_cf(
            &cf_depth,
            keys::encode_u64(event_nid),
            keys::encode_u64(depth),
        );

        // event_edges CF (prev_events as packed NIDs)
        let cf_edges = self.db.cf_handle("event_edges").unwrap();
        batch.put_cf(
            &cf_edges,
            keys::encode_u64(event_nid),
            keys::encode_u64_array(prev_event_nids),
        );

        // event_auth_edges CF
        let cf_auth = self.db.cf_handle("event_auth_edges").unwrap();
        batch.put_cf(
            &cf_auth,
            keys::encode_u64(event_nid),
            keys::encode_u64_array(auth_event_nids),
        );

        // event_state CF: inherit from parent. For accepted state events, the
        // caller's subsequent persist_state_snapshot overwrites this with the
        // new post-event snapshot. For soft-failed state events and for any
        // message event, this inherited value is the final one.
        if let Some(snap) = parent_snapshot_nid {
            let cf_event_state = self.db.cf_handle("event_state").unwrap();
            batch.put_cf(
                &cf_event_state,
                keys::encode_u64(event_nid),
                keys::encode_u64(snap),
            );
        }

        // room_state CF: only state events that should affect current state.
        // Backfilled state events are historical — they shouldn't rewrite
        // current state. Outliers don't appear in current state either.
        //
        // Federation state-res tiebreak at write time: when an EXISTING
        // state event for this (type, state_key) is newer by depth /
        // origin_server_ts / event_id (the spec's reverse-topological
        // ordering), keep it. Without this, federated transactions that
        // arrive out of order can clobber a newer state event with an
        // older one — TestUnbanViaInvite hits exactly this when the
        // ban→unban→invite sequence reaches us in (ban, invite, leave)
        // arrival order: the older `leave` overwrites the newer
        // `invite` and the test never sees the room transition into
        // rooms.invite.
        if is_state && kind.writes_room_state() {
            let cf_state = self.db.cf_handle("room_state").unwrap();
            let key = keys::encode_u64_triple(room_nid, type_nid, state_key_nid);
            let mut overwrite = true;
            if let Ok(Some(existing_bytes)) = self.db.get_cf(&cf_state, key) {
                let existing_nid = keys::decode_u64(&existing_bytes);
                if existing_nid != event_nid
                    && let Ok(Some((existing, _))) = self.get_event(existing_nid)
                {
                    let existing_id = self.get_event_id_by_nid(existing_nid).ok().flatten();
                    let new_wins = match (depth.cmp(&existing.depth), existing_id.as_deref()) {
                        (std::cmp::Ordering::Greater, _) => true,
                        (std::cmp::Ordering::Less, _) => false,
                        (std::cmp::Ordering::Equal, _) => {
                            match origin_server_ts.cmp(&existing.origin_server_ts) {
                                std::cmp::Ordering::Greater => true,
                                std::cmp::Ordering::Less => false,
                                std::cmp::Ordering::Equal => match existing_id {
                                    Some(eid) => event_id > eid.as_str(),
                                    None => true,
                                },
                            }
                        }
                    };
                    overwrite = new_wins;
                }
            }
            if overwrite {
                batch.put_cf(&cf_state, key, keys::encode_u64(event_nid));
            }
        }

        // room_extremities CF: only events that should become forward
        // extremities. Backfilled and outlier events MUST NOT replace
        // the live extremity set. Live events overwrite to `[event_nid]`
        // — same as pre-refactor. Read-modify-write to preserve fork
        // extremities is the spec-correct shape, but federated events
        // whose prev_events don't match our current extremities cause
        // the set to grow indefinitely (the federated event isn't
        // referenced as prev by any subsequent local event), and
        // downstream flows that pick a single "latest" extremity break
        // in subtle ways. Tracked as future work; the overwrite at
        // least keeps the room's forward DAG navigable.
        if kind.updates_extremities() {
            let cf_extremities = self.db.cf_handle("room_extremities").unwrap();
            batch.put_cf(
                &cf_extremities,
                keys::encode_u64(room_nid),
                keys::encode_u64_array(&[event_nid]),
            );
        }

        self.db.write(batch)?;
        Ok(stream_pos)
    }

    /// Load the state snapshot associated with a given event — i.e. the list
    /// of state event NIDs representing the room state AFTER that event was
    /// applied. Returns None if the event has no recorded snapshot.
    pub fn get_state_at_event(&self, event_nid: u64) -> Result<Option<Vec<u64>>, rocksdb::Error> {
        let cf_event_state = self.db.cf_handle("event_state").unwrap();
        let snapshot_nid = match self
            .db
            .get_cf(&cf_event_state, keys::encode_u64(event_nid))?
        {
            Some(b) => keys::decode_u64(&b),
            None => return Ok(None),
        };
        let cf_snapshots = self.db.cf_handle("state_snapshots").unwrap();
        match self
            .db
            .get_cf(&cf_snapshots, keys::encode_u64(snapshot_nid))?
        {
            Some(b) => Ok(Some(keys::decode_u64_array(&b))),
            None => Ok(None),
        }
    }

    /// Persist a state snapshot (flat list of state event NIDs).
    /// Promote a state event into a fresh per-event state snapshot.
    ///
    /// Centralises the replicated "read current state → remove any
    /// (type, state_key) match → append new event → persist_state_snapshot"
    /// pattern that every accepted-state-event path runs after
    /// `persist_event`. Keeping the three-step sequence here means
    /// callers can't drop the retain-filter (which silently breaks
    /// state-at-event lookups) or forget the snapshot entirely (which
    /// manifests as "sender is not joined" the next time a remote
    /// server sends a message — exactly the federation bug chain).
    ///
    /// The caller must still decide **whether** to promote (spec: only
    /// accepted, non-soft-failed state events); this helper only runs
    /// the mechanical parts consistently once that decision is made.
    pub fn promote_state_event(
        &self,
        room_nid: u64,
        event_nid: u64,
        type_nid: u64,
        state_key_nid: u64,
    ) -> Result<(), rocksdb::Error> {
        // Build the new snapshot from current room_state. persist_event has
        // already overwritten room_state[(type, state_key)] with event_nid,
        // so retain-filter the matching entry and re-append (no-op for the
        // entry, but keeps any other state events for this (type, sk) out
        // of duplicates if the indexing ever changes).
        let mut all_state_nids = self.get_all_state_event_nids(room_nid)?;
        all_state_nids.retain(|existing| match self.get_event(*existing) {
            Ok(Some((h, _))) => !(h.type_nid == type_nid && h.state_key_nid == state_key_nid),
            _ => true,
        });
        all_state_nids.push(event_nid);
        self.persist_state_snapshot(room_nid, event_nid, &all_state_nids)?;

        // Find the predecessor (the state event this one replaces) by
        // scanning the parent snapshot — i.e. the state BEFORE event_nid
        // was applied. We can't use current room_state for this because
        // persist_event already overwrote the (type, state_key) slot with
        // event_nid; reading there would yield a self-reference and stamp
        // `unsigned.replaces_state` with the event's own id (regression
        // observed in TestUnbanViaInvite where a fresh ban/leave reported
        // its own id as the prior membership event).
        //
        // event_state[event_nid] currently holds the parent snapshot id
        // (set by persist_event); persist_state_snapshot above just
        // overwrote it, so re-fetch from the new snapshot would be wrong.
        // We therefore look at the prev_events directly.
        let prev_event_nids = self.get_prev_events(event_nid)?;
        let mut replaced: Option<u64> = None;
        for prev_nid in &prev_event_nids {
            if let Some(parent_snapshot) = self.get_state_at_event(*prev_nid)? {
                for candidate in parent_snapshot {
                    if candidate == event_nid {
                        continue;
                    }
                    if let Ok(Some((h, _))) = self.get_event(candidate)
                        && h.type_nid == type_nid
                        && h.state_key_nid == state_key_nid
                    {
                        replaced = Some(candidate);
                        break;
                    }
                }
                if replaced.is_some() {
                    break;
                }
            }
        }
        if let Some(prev_nid) = replaced {
            let cf = self.db.cf_handle("state_replaces").unwrap();
            self.db
                .put_cf(&cf, keys::encode_u64(event_nid), keys::encode_u64(prev_nid))?;
        }
        Ok(())
    }

    /// Returns the event_nid that this state event replaced (i.e. the
    /// previous state event with the same (type, state_key)), or None
    /// if this is the first state event of its kind. Populated by
    /// `promote_state_event`.
    pub fn get_replaced_state_nid(&self, event_nid: u64) -> Result<Option<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("state_replaces").unwrap();
        match self.db.get_cf(&cf, keys::encode_u64(event_nid))? {
            Some(b) => Ok(Some(keys::decode_u64(&b))),
            None => Ok(None),
        }
    }

    /// Record that `event_nid` replaced `prev_nid` in current state.
    /// Used by federated-join paths which build snapshots manually
    /// instead of calling `promote_state_event`.
    pub fn record_state_replaces(
        &self,
        event_nid: u64,
        prev_nid: u64,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("state_replaces").unwrap();
        self.db
            .put_cf(&cf, keys::encode_u64(event_nid), keys::encode_u64(prev_nid))
    }

    /// Force `room_state[room_nid][type_nid][state_key_nid] = event_nid`.
    /// Used during federated-join bootstrap: events shared between the
    /// auth_chain and the state bundle get persisted on the auth_chain
    /// pass with `suppress_current_state=true` (which skips the room_state
    /// update); the dedup early-return then prevents the state pass from
    /// promoting them. This method closes that gap by stamping current
    /// state explicitly once bootstrap knows the full state set.
    pub fn set_room_state_entry(
        &self,
        room_nid: u64,
        type_nid: u64,
        state_key_nid: u64,
        event_nid: u64,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("room_state").unwrap();
        self.db.put_cf(
            &cf,
            keys::encode_u64_triple(room_nid, type_nid, state_key_nid),
            keys::encode_u64(event_nid),
        )
    }

    pub fn persist_state_snapshot(
        &self,
        room_nid: u64,
        event_nid: u64,
        state_event_nids: &[u64],
    ) -> Result<u64, rocksdb::Error> {
        let snapshot_nid = self.next_snapshot_nid()?;

        let mut batch = WriteBatch::default();

        let cf_snapshots = self.db.cf_handle("state_snapshots").unwrap();
        batch.put_cf(
            &cf_snapshots,
            keys::encode_u64(snapshot_nid),
            keys::encode_u64_array(state_event_nids),
        );

        let cf_event_state = self.db.cf_handle("event_state").unwrap();
        batch.put_cf(
            &cf_event_state,
            keys::encode_u64(event_nid),
            keys::encode_u64(snapshot_nid),
        );

        self.db.write(batch)?;
        let _ = room_nid; // will be used for optimizations later
        Ok(snapshot_nid)
    }

    /// Update the room bump timestamp.
    pub fn update_room_bump(
        &self,
        room_nid: u64,
        timestamp: u64,
        event_nid: u64,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("room_bump").unwrap();
        self.db.put_cf(
            &cf,
            keys::encode_u64(room_nid),
            keys::encode_u64_pair(timestamp, event_nid),
        )
    }

    /// Get the room bump timestamp (for sorting by recency).
    pub fn get_room_bump(&self, room_nid: u64) -> Result<Option<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("room_bump").unwrap();
        match self.db.get_cf(&cf, keys::encode_u64(room_nid))? {
            Some(bytes) if bytes.len() >= 16 => {
                let (ts, _event_nid) = keys::decode_u64_pair(&bytes);
                Ok(Some(ts))
            }
            _ => Ok(None),
        }
    }

    // --- Membership operations ---

    pub fn set_membership(
        &self,
        room_nid: u64,
        user_nid: u64,
        membership: u8,
    ) -> Result<(), rocksdb::Error> {
        let mut batch = WriteBatch::default();

        let cf_mem = self.db.cf_handle("memberships").unwrap();
        batch.put_cf(
            &cf_mem,
            keys::encode_u64_pair(room_nid, user_nid),
            [membership],
        );

        let cf_ur = self.db.cf_handle("user_rooms").unwrap();
        batch.put_cf(
            &cf_ur,
            keys::encode_u64_pair(user_nid, room_nid),
            [membership],
        );

        // Record the stream position of this transition so sync can filter
        // invite/leave rooms by the `since` token. We burn a fresh position
        // even when the event persist path allocates its own — the two
        // counters move in lockstep through the same global allocator, and
        // a one-off extra tick per membership change is negligible.
        let cf_pos = self.db.cf_handle("user_membership_pos").unwrap();
        let stream_pos = self.next_stream_position();
        batch.put_cf(
            &cf_pos,
            keys::encode_u64_pair(user_nid, room_nid),
            stream_pos.to_be_bytes(),
        );

        self.db.write(batch)
    }

    /// Drop the per-user record of this room: removes from `memberships`,
    /// `user_rooms`, and `user_membership_pos`. The room itself and other
    /// users' state are untouched.
    pub fn forget_room(&self, user_nid: u64, room_nid: u64) -> Result<(), rocksdb::Error> {
        let mut batch = WriteBatch::default();
        let cf_mem = self.db.cf_handle("memberships").unwrap();
        batch.delete_cf(&cf_mem, keys::encode_u64_pair(room_nid, user_nid));
        let cf_ur = self.db.cf_handle("user_rooms").unwrap();
        batch.delete_cf(&cf_ur, keys::encode_u64_pair(user_nid, room_nid));
        let cf_pos = self.db.cf_handle("user_membership_pos").unwrap();
        batch.delete_cf(&cf_pos, keys::encode_u64_pair(user_nid, room_nid));
        self.db.write(batch)
    }

    /// Stream position of the most recent membership transition for
    /// `(user_nid, room_nid)`, or `None` if no transition was recorded
    /// (e.g. rooms that pre-date this index).
    pub fn get_user_room_membership_pos(
        &self,
        user_nid: u64,
        room_nid: u64,
    ) -> Result<Option<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("user_membership_pos").unwrap();
        match self
            .db
            .get_cf(&cf, keys::encode_u64_pair(user_nid, room_nid))?
        {
            Some(bytes) => Ok(Some(keys::decode_u64(&bytes))),
            None => Ok(None),
        }
    }

    pub fn get_membership(
        &self,
        room_nid: u64,
        user_nid: u64,
    ) -> Result<Option<u8>, rocksdb::Error> {
        let cf = self.db.cf_handle("memberships").unwrap();
        match self
            .db
            .get_cf(&cf, keys::encode_u64_pair(room_nid, user_nid))?
        {
            Some(bytes) => Ok(Some(bytes[0])),
            None => Ok(None),
        }
    }

    /// Get all rooms a user has joined (membership = 1).
    pub fn get_user_joined_rooms(&self, user_nid: u64) -> Result<Vec<u64>, rocksdb::Error> {
        self.get_user_rooms_by_membership(user_nid, 1)
    }

    /// Get all rooms a user has been invited to (membership = 2).
    pub fn get_user_invited_rooms(&self, user_nid: u64) -> Result<Vec<u64>, rocksdb::Error> {
        self.get_user_rooms_by_membership(user_nid, 2)
    }

    /// Get all rooms a user has knocked on (membership = 4).
    pub fn get_user_knocked_rooms(&self, user_nid: u64) -> Result<Vec<u64>, rocksdb::Error> {
        self.get_user_rooms_by_membership(user_nid, 4)
    }

    /// Get all rooms a user has left or been banned from (membership = 0 or 3).
    pub fn get_user_left_rooms(&self, user_nid: u64) -> Result<Vec<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("user_rooms").unwrap();
        let prefix = keys::encode_u64(user_nid);
        let mut rooms = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        for item in iter {
            let (key, val) = item?;
            if key.len() < 16 || key[..8] != prefix[..] {
                break;
            }
            if val[0] == 0 || val[0] == 3 {
                rooms.push(keys::decode_u64(&key[8..16]));
            }
        }
        Ok(rooms)
    }

    fn get_user_rooms_by_membership(
        &self,
        user_nid: u64,
        target: u8,
    ) -> Result<Vec<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("user_rooms").unwrap();
        let prefix = keys::encode_u64(user_nid);
        let mut rooms = Vec::new();

        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        for item in iter {
            let (key, val) = item?;
            if key.len() < 16 || key[..8] != prefix[..] {
                break;
            }
            if val[0] == target {
                rooms.push(keys::decode_u64(&key[8..16]));
            }
        }
        Ok(rooms)
    }

    // --- Room aliases ---

    /// Stores `alias → room_id` with no creator tracked. Kept for callers
    /// that don't have a user identity at hand (federation lookups,
    /// migration tooling); UI flows go through `set_room_alias_with_creator`
    /// so DELETE can authorise the requester.
    pub fn set_room_alias(&self, alias: &str, room_id: &str) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("room_aliases").unwrap();
        self.db.put_cf(&cf, alias.as_bytes(), room_id.as_bytes())
    }

    /// Stores `alias → {room_id, creator, created_at}` so DELETE can verify
    /// the requester. JSON-encoded so future fields can be added without a
    /// schema migration — readers tolerate unknown keys and missing values
    /// (see `get_room_alias_record`).
    pub fn set_room_alias_with_creator(
        &self,
        alias: &str,
        room_id: &str,
        creator: &str,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("room_aliases").unwrap();
        let payload = serde_json::json!({
            "room_id": room_id,
            "creator": creator,
            "created_at": now_ms(),
        })
        .to_string();
        self.db.put_cf(&cf, alias.as_bytes(), payload.as_bytes())
    }

    pub fn get_room_alias(&self, alias: &str) -> Result<Option<String>, rocksdb::Error> {
        Ok(self.get_room_alias_record(alias)?.map(|(rid, _)| rid))
    }

    /// Returns `(room_id, creator_user_id)` if the alias exists. Falls back
    /// to `(room_id, None)` for legacy raw-bytes entries written before
    /// creator tracking landed — those aliases are deletable only by users
    /// with sufficient power level. We don't auto-migrate legacy rows: the
    /// next PUT against the alias (which only succeeds after a DELETE)
    /// transitions to the JSON shape, so the data heals lazily.
    pub fn get_room_alias_record(
        &self,
        alias: &str,
    ) -> Result<Option<(String, Option<String>)>, rocksdb::Error> {
        let cf = self.db.cf_handle("room_aliases").unwrap();
        let Some(bytes) = self.db.get_cf(&cf, alias.as_bytes())? else {
            return Ok(None);
        };
        // Try JSON shape first; fall back to raw room_id bytes.
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && let Some(obj) = v.as_object()
            && let Some(rid) = obj.get("room_id").and_then(|v| v.as_str())
        {
            let creator = obj
                .get("creator")
                .and_then(|v| v.as_str())
                .map(String::from);
            return Ok(Some((rid.to_string(), creator)));
        }
        Ok(Some((String::from_utf8_lossy(&bytes).to_string(), None)))
    }

    pub fn delete_room_alias(&self, alias: &str) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("room_aliases").unwrap();
        self.db.delete_cf(&cf, alias.as_bytes())
    }

    /// Reverse-lookup all aliases that map to `room_id`. The aliases CF is
    /// keyed by alias-string; without a secondary index we full-scan. Acceptable
    /// at current scale; revisit when alias volume grows.
    pub fn list_aliases_for_room(&self, room_id: &str) -> Result<Vec<String>, rocksdb::Error> {
        let cf = self.db.cf_handle("room_aliases").unwrap();
        let iter = self.db.iterator_cf(&cf, IteratorMode::Start);
        let mut out = Vec::new();
        for item in iter {
            let (k, v) = item?;
            // Accept both the legacy raw-bytes shape and the new JSON
            // record. Mixing both during rolling upgrades is fine.
            let stored_room_id = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&v) {
                json.get("room_id")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| String::from_utf8_lossy(&v).to_string())
            } else {
                String::from_utf8_lossy(&v).to_string()
            };
            if stored_room_id == room_id {
                out.push(String::from_utf8_lossy(&k).to_string());
            }
        }
        Ok(out)
    }

    /// Get all joined member NIDs for a room.
    pub fn get_room_members(&self, room_nid: u64) -> Result<Vec<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("memberships").unwrap();
        let prefix = keys::encode_u64(room_nid);
        let mut members = Vec::new();

        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        for item in iter {
            let (key, val) = item?;
            if key.len() < 16 || key[..8] != prefix[..] {
                break;
            }
            if val[0] == 1 {
                members.push(keys::decode_u64(&key[8..16]));
            }
        }
        Ok(members)
    }

    /// Like `get_room_members` but filters by an arbitrary membership
    /// byte (1=join, 2=invite, 3=ban, 4=knock, 0=leave). Used by the
    /// admin module to enumerate invited members without conflating
    /// with joined ones.
    pub fn get_room_members_by_membership(
        &self,
        room_nid: u64,
        membership: u8,
    ) -> Result<Vec<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("memberships").unwrap();
        let prefix = keys::encode_u64(room_nid);
        let mut members = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        for item in iter {
            let (key, val) = item?;
            if key.len() < 16 || key[..8] != prefix[..] {
                break;
            }
            if !val.is_empty() && val[0] == membership {
                members.push(keys::decode_u64(&key[8..16]));
            }
        }
        Ok(members)
    }

    /// List every persisted room_id (full enumeration via `room_meta`).
    /// Used by the admin `!server` command for a local-room count.
    pub fn list_room_meta_room_ids(&self) -> Result<Vec<String>, rocksdb::Error> {
        let cf = self.db.cf_handle("room_meta").unwrap();
        let mut out = Vec::new();
        let iter = self.db.iterator_cf(&cf, IteratorMode::Start);
        for item in iter {
            let (_, val) = item?;
            if let Ok(json) = serde_json::from_slice::<Value>(&val)
                && let Some(rid) = json.get("room_id").and_then(|v| v.as_str())
            {
                out.push(rid.to_string());
            }
        }
        Ok(out)
    }

    /// Count members with the given membership byte (1=join, 2=invite,
    /// 3=knock, 4=ban, 0=leave). Faster than materialising the full
    /// list when the caller only needs a count (e.g. /sync's room
    /// `summary` block).
    pub fn count_room_members_by_membership(
        &self,
        room_nid: u64,
        membership: u8,
    ) -> Result<u64, rocksdb::Error> {
        let cf = self.db.cf_handle("memberships").unwrap();
        let prefix = keys::encode_u64(room_nid);
        let mut count: u64 = 0;
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        for item in iter {
            let (key, val) = item?;
            if key.len() < 16 || key[..8] != prefix[..] {
                break;
            }
            if !val.is_empty() && val[0] == membership {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Record that a user's device keys changed, visible to a set of members.
    /// Used when membership changes in encrypted rooms.
    pub fn notify_device_key_change(
        &self,
        changed_user_nid: u64,
        observer_nids: &[u64],
        stream_pos: u64,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("device_key_changes").unwrap();
        let mut batch = WriteBatch::default();
        for &observer_nid in observer_nids {
            let key = keys::encode_u64_pair(observer_nid, stream_pos);
            let val = keys::encode_u64(changed_user_nid);
            batch.put_cf(&cf, key, val);
        }
        self.db.write(batch)
    }

    // --- Room state queries ---

    /// Get current state event NID for a (room, type, state_key) tuple.
    pub fn get_state_event_nid(
        &self,
        room_nid: u64,
        type_nid: u64,
        state_key_nid: u64,
    ) -> Result<Option<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("room_state").unwrap();
        match self.db.get_cf(
            &cf,
            keys::encode_u64_triple(room_nid, type_nid, state_key_nid),
        )? {
            Some(bytes) => Ok(Some(keys::decode_u64(&bytes))),
            None => Ok(None),
        }
    }

    /// Get all current state event NIDs for a room.
    pub fn get_all_state_event_nids(&self, room_nid: u64) -> Result<Vec<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("room_state").unwrap();
        let prefix = keys::encode_u64(room_nid);
        let mut nids = Vec::new();

        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        for item in iter {
            let (key, val) = item?;
            if key.len() < 24 || key[..8] != prefix[..] {
                break;
            }
            nids.push(keys::decode_u64(&val));
        }
        Ok(nids)
    }

    // --- Event retrieval ---

    /// Get event by NID. Returns (header_fields, json_bytes).
    pub fn get_event(
        &self,
        event_nid: u64,
    ) -> Result<Option<(EventHeader, Vec<u8>)>, rocksdb::Error> {
        let cf = self.db.cf_handle("events").unwrap();
        match self.db.get_cf(&cf, keys::encode_u64(event_nid))? {
            Some(bytes) if bytes.len() > 40 => {
                let header = EventHeader {
                    type_nid: keys::decode_u64(&bytes[0..8]),
                    sender_nid: keys::decode_u64(&bytes[8..16]),
                    state_key_nid: keys::decode_u64(&bytes[16..24]),
                    origin_server_ts: keys::decode_u64(&bytes[24..32]),
                    depth: keys::decode_u64(&bytes[32..40]),
                };
                let json = bytes[40..].to_vec();
                Ok(Some((header, json)))
            }
            _ => Ok(None),
        }
    }

    /// Look up event_nid by event_id string.
    pub fn get_event_nid_by_id(&self, event_id: &str) -> Result<Option<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("event_ids").unwrap();
        match self.db.get_cf(&cf, event_id.as_bytes())? {
            Some(bytes) => Ok(Some(keys::decode_u64(&bytes))),
            None => Ok(None),
        }
    }

    /// Look up event_id string by event_nid (reverse lookup, no recomputation).
    pub fn get_event_id_by_nid(&self, event_nid: u64) -> Result<Option<String>, rocksdb::Error> {
        let cf = self.db.cf_handle("event_id_reverse").unwrap();
        match self.db.get_cf(&cf, keys::encode_u64(event_nid))? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).to_string())),
            None => Ok(None),
        }
    }

    /// Get forward extremities for a room.
    pub fn get_extremities(&self, room_nid: u64) -> Result<Vec<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("room_extremities").unwrap();
        match self.db.get_cf(&cf, keys::encode_u64(room_nid))? {
            Some(bytes) => Ok(keys::decode_u64_array(&bytes)),
            None => Ok(vec![]),
        }
    }

    /// Get event depth by NID.
    pub fn get_event_depth(&self, event_nid: u64) -> Result<Option<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("event_depth").unwrap();
        match self.db.get_cf(&cf, keys::encode_u64(event_nid))? {
            Some(bytes) => Ok(Some(keys::decode_u64(&bytes))),
            None => Ok(None),
        }
    }

    // --- Redactions ---

    /// Record that `target_event_nid` has been redacted by `redactor_event_nid`.
    /// Later writes overwrite earlier ones; callers are expected to apply their
    /// own ordering rules (we keep the first accepted redaction).
    pub fn mark_redacted_by(
        &self,
        target_event_nid: u64,
        redactor_event_nid: u64,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("event_redactions").unwrap();
        self.db.put_cf(
            &cf,
            keys::encode_u64(target_event_nid),
            keys::encode_u64(redactor_event_nid),
        )
    }

    /// Returns the redactor event NID if `target_event_nid` has been redacted.
    pub fn get_redacted_by(&self, target_event_nid: u64) -> Result<Option<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("event_redactions").unwrap();
        match self.db.get_cf(&cf, keys::encode_u64(target_event_nid))? {
            Some(bytes) => Ok(Some(keys::decode_u64(&bytes))),
            None => Ok(None),
        }
    }

    // --- Event relations (m.relates_to) ---

    /// Record that `child_event_nid` relates to `parent_event_nid` via
    /// `rel_type_nid`. The stream position of the child is keyed in so the
    /// `/relations` endpoint can iterate most-recent-first via a reverse
    /// prefix scan.
    ///
    /// Also maintains:
    ///   - `relation_counts[(parent, rel_type)]` for O(1) count reads
    ///   - `thread_index[(room, !latest_sp, root)]` + `thread_root_latest[(room, root)]`
    ///     when `rel_type` is m.thread (so /threads is an ordered scan)
    ///   - `thread_participants[(root, sender)]` when `rel_type` is m.thread
    ///     (so `current_user_participated` is an O(1) point lookup)
    pub fn record_relation(
        &self,
        parent_event_nid: u64,
        child_stream_pos: u64,
        child_event_nid: u64,
        rel_type_nid: u64,
        child_type_nid: u64,
        room_nid: u64,
        child_sender_nid: u64,
        is_m_thread: bool,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("event_relations").unwrap();
        let mut value = [0u8; 24];
        value[0..8].copy_from_slice(&keys::encode_u64(child_event_nid));
        value[8..16].copy_from_slice(&keys::encode_u64(rel_type_nid));
        value[16..24].copy_from_slice(&keys::encode_u64(child_type_nid));
        self.db.put_cf(
            &cf,
            keys::encode_u64_pair(parent_event_nid, child_stream_pos),
            value,
        )?;
        self.bump_relation_count(parent_event_nid, rel_type_nid, 1)?;
        if is_m_thread {
            self.update_thread_index(room_nid, parent_event_nid, child_stream_pos)?;
            let pcf = self.db.cf_handle("thread_participants").unwrap();
            self.db.put_cf(
                &pcf,
                keys::encode_u64_pair(parent_event_nid, child_sender_nid),
                [] as [u8; 0],
            )?;
        }
        Ok(())
    }

    /// O(1) lookup: has `user_nid` posted any m.thread reply to the
    /// given thread root? The `thread_participants` CF is
    /// monotonic — entries are not removed on reply redaction, since
    /// a redacted reply still counts as participation per spec.
    pub fn user_participated_in_thread(
        &self,
        root_nid: u64,
        user_nid: u64,
    ) -> Result<bool, rocksdb::Error> {
        let cf = self.db.cf_handle("thread_participants").unwrap();
        Ok(self
            .db
            .get_cf(&cf, keys::encode_u64_pair(root_nid, user_nid))?
            .is_some())
    }

    /// Increment (`delta > 0`) or decrement (`delta < 0`) the
    /// (parent, rel_type) counter. Saturates at 0 — a counter that
    /// would go negative stays at 0 (paranoia against duplicate
    /// redactions or backfill recording the same event twice).
    fn bump_relation_count(
        &self,
        parent_event_nid: u64,
        rel_type_nid: u64,
        delta: i64,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("relation_counts").unwrap();
        let key = keys::encode_u64_pair(parent_event_nid, rel_type_nid);
        let current = self
            .db
            .get_cf(&cf, key)?
            .map(|b| keys::decode_u64(&b))
            .unwrap_or(0);
        let next = if delta >= 0 {
            current.saturating_add(delta as u64)
        } else {
            current.saturating_sub((-delta) as u64)
        };
        self.db.put_cf(&cf, key, keys::encode_u64(next))
    }

    /// O(1) read of the (parent, rel_type) counter. Returns 0 when
    /// no children have been recorded for this pair.
    pub fn count_relation_for_type(
        &self,
        parent_event_nid: u64,
        rel_type_nid: u64,
    ) -> Result<u64, rocksdb::Error> {
        let cf = self.db.cf_handle("relation_counts").unwrap();
        let key = keys::encode_u64_pair(parent_event_nid, rel_type_nid);
        Ok(self
            .db
            .get_cf(&cf, key)?
            .map(|b| keys::decode_u64(&b))
            .unwrap_or(0))
    }

    /// Decrement the (parent, rel_type) counter — called when a
    /// relation event is redacted. The thread_index is left in
    /// place; it self-corrects on the next thread reply and a
    /// slightly-stale `latest_event` is bounded in impact.
    pub fn relation_redacted(
        &self,
        parent_event_nid: u64,
        rel_type_nid: u64,
    ) -> Result<(), rocksdb::Error> {
        self.bump_relation_count(parent_event_nid, rel_type_nid, -1)
    }

    /// Thread index key layout. The middle word is `!latest_sp`
    /// (`u64::MAX - latest_sp`) so forward iteration walks
    /// newest-first.
    fn encode_thread_index_key(room_nid: u64, latest_sp: u64, root_nid: u64) -> [u8; 24] {
        keys::encode_u64_triple(room_nid, u64::MAX - latest_sp, root_nid)
    }

    /// Update the thread_index after a new m.thread child lands.
    /// Deletes the prior (room, !latest_sp, root) key when one
    /// exists so the index stays a tight set of "latest activity
    /// per root".
    fn update_thread_index(
        &self,
        room_nid: u64,
        root_nid: u64,
        new_latest_sp: u64,
    ) -> Result<(), rocksdb::Error> {
        let idx_cf = self.db.cf_handle("thread_index").unwrap();
        let latest_cf = self.db.cf_handle("thread_root_latest").unwrap();
        let latest_key = keys::encode_u64_pair(room_nid, root_nid);
        if let Some(prev_bytes) = self.db.get_cf(&latest_cf, latest_key)? {
            let prev_sp = keys::decode_u64(&prev_bytes);
            if prev_sp >= new_latest_sp {
                // A newer m.thread child already landed (federation
                // out-of-order delivery, say). Leave the index alone.
                return Ok(());
            }
            self.db.delete_cf(
                &idx_cf,
                Self::encode_thread_index_key(room_nid, prev_sp, root_nid),
            )?;
        }
        self.db.put_cf(
            &idx_cf,
            Self::encode_thread_index_key(room_nid, new_latest_sp, root_nid),
            [] as [u8; 0],
        )?;
        self.db
            .put_cf(&latest_cf, latest_key, keys::encode_u64(new_latest_sp))
    }

    /// Iterate thread roots in `room_nid` ordered by latest m.thread
    /// activity (newest first). `before_latest_sp` is exclusive on
    /// the latest_sp axis. Returns `(latest_child_sp, root_event_nid)`
    /// tuples.
    pub fn list_thread_roots(
        &self,
        room_nid: u64,
        before_latest_sp: u64,
        limit: usize,
    ) -> Result<Vec<(u64, u64)>, rocksdb::Error> {
        let cf = self.db.cf_handle("thread_index").unwrap();
        let start_key = Self::encode_thread_index_key(room_nid, before_latest_sp, u64::MAX);
        let iter = self.db.iterator_cf(
            &cf,
            IteratorMode::From(&start_key, rocksdb::Direction::Forward),
        );
        let prefix = keys::encode_u64(room_nid);
        let mut out = Vec::new();
        for item in iter {
            let (key, _val) = item?;
            if key.len() < 24 || key[..8] != prefix[..] {
                break;
            }
            // Stored as (room, !latest_sp_desc, root). Decode by
            // inverting the middle word.
            let inv_sp = keys::decode_u64(&key[8..16]);
            let latest_sp = u64::MAX - inv_sp;
            let root_nid = keys::decode_u64(&key[16..24]);
            if latest_sp >= before_latest_sp {
                continue;
            }
            out.push((latest_sp, root_nid));
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// Count children of `parent_event_nid` matching `rel_type_nid`.
    /// Walks the index without loading values — cheaper than
    /// `list_relations` for "is the count >0?" / aggregation use.
    /// Returns `(count, any_user_participated)` where the second
    /// element is true if any child's sender_nid equals `user_nid`
    /// (when supplied). Pass `user_nid=None` to skip the check.
    pub fn count_relations_with_user_check(
        &self,
        parent_event_nid: u64,
        rel_type_nid: u64,
        user_nid: Option<u64>,
    ) -> Result<(u64, bool), rocksdb::Error> {
        let cf = self.db.cf_handle("event_relations").unwrap();
        let prefix = keys::encode_u64(parent_event_nid);
        let start_key = keys::encode_u64_pair(parent_event_nid, u64::MAX);
        let iter = self.db.iterator_cf(
            &cf,
            IteratorMode::From(&start_key, rocksdb::Direction::Reverse),
        );
        let mut count = 0u64;
        let mut participated = false;
        for item in iter {
            let (key, val) = item?;
            if key.len() < 16 || key[..8] != prefix[..] {
                break;
            }
            if val.len() < 24 {
                continue;
            }
            let rt = keys::decode_u64(&val[8..16]);
            if rt != rel_type_nid {
                continue;
            }
            count += 1;
            if let Some(want) = user_nid
                && !participated
            {
                let child_nid = keys::decode_u64(&val[0..8]);
                if let Ok(Some((h, _))) = self.get_event(child_nid)
                    && h.sender_nid == want
                {
                    participated = true;
                }
            }
        }
        Ok((count, participated))
    }

    /// Iterate child events of `parent_event_nid`. Returns
    /// `(child_stream_pos, child_event_nid, rel_type_nid, child_type_nid)`
    /// tuples filtered by `rel_type_nid` / `child_type_nid` if supplied.
    /// `before_stream_pos` is exclusive; `dir_backwards` controls order
    /// (true = newest first per spec default).
    pub fn list_relations(
        &self,
        parent_event_nid: u64,
        rel_type_nid: Option<u64>,
        child_type_nid: Option<u64>,
        before_stream_pos: u64,
        dir_backwards: bool,
        limit: usize,
    ) -> Result<Vec<(u64, u64, u64, u64)>, rocksdb::Error> {
        let cf = self.db.cf_handle("event_relations").unwrap();
        let prefix = keys::encode_u64(parent_event_nid);

        // Seek to (parent, before_stream_pos) then walk in chosen direction.
        let start_key = keys::encode_u64_pair(parent_event_nid, before_stream_pos);
        let direction = if dir_backwards {
            rocksdb::Direction::Reverse
        } else {
            rocksdb::Direction::Forward
        };

        let iter = self
            .db
            .iterator_cf(&cf, IteratorMode::From(&start_key, direction));

        let mut out = Vec::new();
        for item in iter {
            let (key, val) = item?;
            if key.len() < 16 || key[..8] != prefix[..] {
                break;
            }
            let (_pn, sp) = keys::decode_u64_pair(&key);
            // For reverse-from-MAX, the seek lands at the first key <= start.
            // For forward, the seek lands at the first key >= start.
            // Skip the boundary itself so callers can pass an exclusive bound.
            if dir_backwards && sp >= before_stream_pos {
                continue;
            }
            if !dir_backwards && sp <= before_stream_pos {
                continue;
            }
            if val.len() < 24 {
                continue;
            }
            let child_nid = keys::decode_u64(&val[0..8]);
            let rt = keys::decode_u64(&val[8..16]);
            let ct = keys::decode_u64(&val[16..24]);
            if let Some(want) = rel_type_nid
                && rt != want
            {
                continue;
            }
            if let Some(want) = child_type_nid
                && ct != want
            {
                continue;
            }
            out.push((sp, child_nid, rt, ct));
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    // --- Timeline queries ---

    /// Get events from room timeline in a range of stream positions.
    /// Returns Vec<(stream_pos, event_nid)>.
    pub fn get_timeline_range(
        &self,
        room_nid: u64,
        from: u64,
        to: u64,
        limit: usize,
    ) -> Result<Vec<(u64, u64)>, rocksdb::Error> {
        let cf = self.db.cf_handle("room_timeline").unwrap();
        let start_key = keys::encode_u64_pair(room_nid, from);
        let mut results = Vec::new();

        let iter = self.db.iterator_cf(
            &cf,
            IteratorMode::From(&start_key, rocksdb::Direction::Forward),
        );
        for item in iter {
            let (key, val) = item?;
            if key.len() < 16 {
                break;
            }
            let (rn, sp) = keys::decode_u64_pair(&key);
            if rn != room_nid || sp >= to {
                break;
            }
            results.push((sp, keys::decode_u64(&val)));
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }

    /// Get events from room timeline going backwards from a position.
    /// If `before` is u64::MAX, starts from the latest event.
    /// Returns Vec<(stream_pos, event_nid)> in chronological order.
    pub fn get_timeline_latest(
        &self,
        room_nid: u64,
        limit: usize,
    ) -> Result<Vec<(u64, u64)>, rocksdb::Error> {
        self.get_timeline_before(room_nid, u64::MAX, limit)
    }

    pub fn get_timeline_before(
        &self,
        room_nid: u64,
        before: u64,
        limit: usize,
    ) -> Result<Vec<(u64, u64)>, rocksdb::Error> {
        let cf = self.db.cf_handle("room_timeline").unwrap();
        // Use saturating_sub to make `before` exclusive — the client already has
        // the event at `before`, so start scanning from one position earlier.
        let seek_pos = if before == u64::MAX {
            before
        } else {
            before.saturating_sub(1)
        };
        let end_key = keys::encode_u64_pair(room_nid, seek_pos);
        let mut results = Vec::new();

        let iter = self.db.iterator_cf(
            &cf,
            IteratorMode::From(&end_key, rocksdb::Direction::Reverse),
        );
        for item in iter {
            let (key, val) = item?;
            if key.len() < 16 {
                break;
            }
            let (rn, sp) = keys::decode_u64_pair(&key);
            if rn != room_nid {
                break;
            }
            results.push((sp, keys::decode_u64(&val)));
            if results.len() >= limit {
                break;
            }
        }
        results.reverse(); // Chronological order
        Ok(results)
    }

    // --- Sync position ---

    pub fn get_sync_position(
        &self,
        user_nid: u64,
        device_id: &str,
    ) -> Result<Option<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("sync_tokens").unwrap();
        let key = keys::encode_u64_bytes(user_nid, device_id.as_bytes());
        match self.db.get_cf(&cf, &key)? {
            Some(bytes) => Ok(Some(keys::decode_u64(&bytes))),
            None => Ok(None),
        }
    }

    pub fn set_sync_position(
        &self,
        user_nid: u64,
        device_id: &str,
        position: u64,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("sync_tokens").unwrap();
        let key = keys::encode_u64_bytes(user_nid, device_id.as_bytes());
        self.db.put_cf(&cf, &key, keys::encode_u64(position))
    }

    // --- Transaction idempotency ---

    /// Look up a previously-recorded transaction event_id. `scope` is
    /// the request-path discriminator — for `PUT /rooms/{room}/send/
    /// {event_type}/{txn}` we use `"send/{room}/{event_type}"`. The
    /// scope must combine with `(user_nid, device_id, txn_id)` to
    /// match what `set_transaction` recorded; otherwise the lookup
    /// misses and a fresh event is minted, which is the spec-correct
    /// behaviour for "same txn_id, different room/endpoint."
    pub fn get_transaction(
        &self,
        user_nid: u64,
        device_id: &str,
        scope: &str,
        txn_id: &str,
    ) -> Result<Option<String>, rocksdb::Error> {
        let cf = self.db.cf_handle("transactions").unwrap();
        let key = transaction_key(user_nid, device_id, scope, txn_id);
        match self.db.get_cf(&cf, &key)? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).to_string())),
            None => Ok(None),
        }
    }

    pub fn set_transaction(
        &self,
        user_nid: u64,
        device_id: &str,
        scope: &str,
        txn_id: &str,
        event_id: &str,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("transactions").unwrap();
        let key = transaction_key(user_nid, device_id, scope, txn_id);
        self.db.put_cf(&cf, &key, event_id.as_bytes())
    }

    // --- Profile operations ---

    /// Walk the `users` CF and return every `(user_nid, record)` pair.
    /// Used by user-directory search — caller does the substring filter +
    /// deactivation screen in memory since the full user set is typically
    /// small. Don't call this on a hot path.
    pub fn scan_all_users(&self) -> Result<Vec<(u64, Value)>, rocksdb::Error> {
        let cf = self.db.cf_handle("users").unwrap();
        let mut out = Vec::new();
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (k, v) = item?;
            if k.len() != 8 {
                continue;
            }
            let mut nid_bytes = [0u8; 8];
            nid_bytes.copy_from_slice(&k);
            let nid = u64::from_be_bytes(nid_bytes);
            if let Ok(record) = serde_json::from_slice::<Value>(&v) {
                out.push((nid, record));
            }
        }
        Ok(out)
    }

    pub fn update_user_profile(
        &self,
        user_nid: u64,
        displayname: Option<&str>,
        avatar_url: Option<&str>,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("users").unwrap();
        let mut record = match self.db.get_cf(&cf, keys::encode_u64(user_nid))? {
            Some(bytes) => serde_json::from_slice::<Value>(&bytes).unwrap_or(serde_json::json!({})),
            None => return Ok(()),
        };
        let obj = record.as_object_mut().unwrap();
        if let Some(name) = displayname {
            obj.insert("displayname".into(), Value::String(name.to_string()));
        }
        if let Some(avatar) = avatar_url {
            obj.insert("avatar_url".into(), Value::String(avatar.to_string()));
        }
        self.db.put_cf(
            &cf,
            keys::encode_u64(user_nid),
            record.to_string().as_bytes(),
        )
    }

    // --- Account data operations ---

    pub fn get_account_data(
        &self,
        user_nid: u64,
        data_type: &str,
    ) -> Result<Option<Value>, rocksdb::Error> {
        let cf = self.db.cf_handle("account_data").unwrap();
        let key = keys::encode_u64_bytes(user_nid, data_type.as_bytes());
        match self.db.get_cf(&cf, &key)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).unwrap_or(Value::Null))),
            None => Ok(None),
        }
    }

    pub fn set_account_data(
        &self,
        user_nid: u64,
        data_type: &str,
        value: &Value,
    ) -> Result<(), rocksdb::Error> {
        let mut batch = WriteBatch::default();
        let cf = self.db.cf_handle("account_data").unwrap();
        let key = keys::encode_u64_bytes(user_nid, data_type.as_bytes());
        batch.put_cf(&cf, &key, value.to_string().as_bytes());

        // Record the stream position of this write so /sync can stream
        // account_data changes on incremental polls. Without this,
        // clients (e.g. Element's cross-signing setup) that expect to
        // see their own writes reflected in the next sync hang.
        let cf_pos = self.db.cf_handle("account_data_pos").unwrap();
        let stream_pos = self.next_stream_position();
        batch.put_cf(&cf_pos, &key, stream_pos.to_be_bytes());

        self.db.write(batch)
    }

    // --- Key backup CF (per-row sessions, per-user versions metadata) -----
    //
    // The handlers in vela-api/src/key_backup.rs live on top of these
    // primitives. Per-session writes are atomic point updates, so two
    // concurrent PUTs targeting different session_ids never race; the
    // earlier account_data-blob design suffered a lost-write race
    // during Element's parallel session upload.

    /// Read the version-metadata JSON blob for `user_nid`. Returns
    /// `None` when this user has never created a backup version.
    pub fn key_backup_versions_get(&self, user_nid: u64) -> Result<Option<Value>, rocksdb::Error> {
        let cf = self.db.cf_handle("key_backup").unwrap();
        let key = key_backup_versions_key(user_nid);
        match self.db.get_cf(&cf, &key)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
            None => Ok(None),
        }
    }

    /// Overwrite the version-metadata JSON blob for `user_nid`.
    /// Versions are small (max ~handful per user); a blob write is
    /// fine here. Per-session data is handled separately by
    /// `key_backup_session_put`.
    pub fn key_backup_versions_set(
        &self,
        user_nid: u64,
        value: &Value,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("key_backup").unwrap();
        let key = key_backup_versions_key(user_nid);
        self.db.put_cf(&cf, &key, value.to_string().as_bytes())
    }

    /// Store one session blob. Returns true iff the row was written
    /// (either new or replaced an existing one); false iff the existing
    /// row was preferred per the spec's replacement rule and the new
    /// data was discarded. Caller is expected to have evaluated the
    /// replacement rule via `key_backup::should_replace` and only call
    /// here when the new row should win.
    pub fn key_backup_session_put(
        &self,
        user_nid: u64,
        version: &str,
        room_id: &str,
        session_id: &str,
        value: &Value,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("key_backup").unwrap();
        let key = key_backup_session_key(user_nid, version, room_id, session_id);
        self.db.put_cf(&cf, &key, value.to_string().as_bytes())
    }

    /// Look up one session blob. Returns `None` for unknown session_id.
    pub fn key_backup_session_get(
        &self,
        user_nid: u64,
        version: &str,
        room_id: &str,
        session_id: &str,
    ) -> Result<Option<Value>, rocksdb::Error> {
        let cf = self.db.cf_handle("key_backup").unwrap();
        let key = key_backup_session_key(user_nid, version, room_id, session_id);
        match self.db.get_cf(&cf, &key)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
            None => Ok(None),
        }
    }

    /// Delete one session. Returns true iff something was actually
    /// removed (used by the count maintenance).
    pub fn key_backup_session_delete(
        &self,
        user_nid: u64,
        version: &str,
        room_id: &str,
        session_id: &str,
    ) -> Result<bool, rocksdb::Error> {
        let cf = self.db.cf_handle("key_backup").unwrap();
        let key = key_backup_session_key(user_nid, version, room_id, session_id);
        let existed = self.db.get_cf(&cf, &key)?.is_some();
        if existed {
            self.db.delete_cf(&cf, &key)?;
        }
        Ok(existed)
    }

    /// Iterate every session within (user, version, room). Used by
    /// `GET /room_keys/keys/{roomId}` to construct the per-room
    /// session map. Order is RocksDB iteration order — caller treats
    /// the result as an unordered collection.
    pub fn key_backup_iter_room(
        &self,
        user_nid: u64,
        version: &str,
        room_id: &str,
    ) -> Result<Vec<(String, Value)>, rocksdb::Error> {
        let cf = self.db.cf_handle("key_backup").unwrap();
        let prefix = key_backup_room_prefix(user_nid, version, room_id);
        let iter = self.db.prefix_iterator_cf(&cf, &prefix);
        let mut out = Vec::new();
        for item in iter {
            let (key, val) = item?;
            if !key.starts_with(&prefix) {
                break;
            }
            if let Some((sid, value)) = key_backup_parse_session_row(&prefix, &key, &val) {
                out.push((sid, value));
            }
        }
        Ok(out)
    }

    /// Iterate every session within (user, version) across all rooms.
    /// Used by `GET /room_keys/keys` to construct the full backup map.
    pub fn key_backup_iter_version(
        &self,
        user_nid: u64,
        version: &str,
    ) -> Result<Vec<(String, String, Value)>, rocksdb::Error> {
        let cf = self.db.cf_handle("key_backup").unwrap();
        let prefix = key_backup_version_prefix(user_nid, version);
        let iter = self.db.prefix_iterator_cf(&cf, &prefix);
        let mut out = Vec::new();
        for item in iter {
            let (key, val) = item?;
            if !key.starts_with(&prefix) {
                break;
            }
            if let Some((room_id, session_id, value)) =
                key_backup_parse_version_row(&prefix, &key, &val)
            {
                out.push((room_id, session_id, value));
            }
        }
        Ok(out)
    }

    /// Delete all sessions in `(user, version, room_id)`. Returns
    /// the number of sessions actually removed for count-maintenance.
    pub fn key_backup_delete_room(
        &self,
        user_nid: u64,
        version: &str,
        room_id: &str,
    ) -> Result<u64, rocksdb::Error> {
        let cf = self.db.cf_handle("key_backup").unwrap();
        let prefix = key_backup_room_prefix(user_nid, version, room_id);
        let mut to_delete = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf, &prefix);
        for item in iter {
            let (key, _) = item?;
            if !key.starts_with(&prefix) {
                break;
            }
            to_delete.push(key.to_vec());
        }
        let count = to_delete.len() as u64;
        let mut batch = WriteBatch::default();
        for k in &to_delete {
            batch.delete_cf(&cf, k);
        }
        self.db.write(batch)?;
        Ok(count)
    }

    /// Delete every session in `(user, version)`. Returns the number
    /// of sessions actually removed.
    pub fn key_backup_delete_version(
        &self,
        user_nid: u64,
        version: &str,
    ) -> Result<u64, rocksdb::Error> {
        let cf = self.db.cf_handle("key_backup").unwrap();
        let prefix = key_backup_version_prefix(user_nid, version);
        let mut to_delete = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf, &prefix);
        for item in iter {
            let (key, _) = item?;
            if !key.starts_with(&prefix) {
                break;
            }
            to_delete.push(key.to_vec());
        }
        let count = to_delete.len() as u64;
        let mut batch = WriteBatch::default();
        for k in &to_delete {
            batch.delete_cf(&cf, k);
        }
        // Also clear the stats row for this version.
        batch.delete_cf(&cf, key_backup_stats_key(user_nid, version));
        self.db.write(batch)?;
        Ok(count)
    }

    /// Read packed `(count, etag)` for a backup version. Defaults to
    /// `(0, 0)` when no stats have been written.
    pub fn key_backup_stats_get(
        &self,
        user_nid: u64,
        version: &str,
    ) -> Result<(u64, u64), rocksdb::Error> {
        let cf = self.db.cf_handle("key_backup").unwrap();
        let key = key_backup_stats_key(user_nid, version);
        match self.db.get_cf(&cf, &key)? {
            Some(bytes) if bytes.len() == 16 => {
                let mut count_buf = [0u8; 8];
                let mut etag_buf = [0u8; 8];
                count_buf.copy_from_slice(&bytes[..8]);
                etag_buf.copy_from_slice(&bytes[8..]);
                Ok((u64::from_be_bytes(count_buf), u64::from_be_bytes(etag_buf)))
            }
            _ => Ok((0, 0)),
        }
    }

    /// Write packed `(count, etag)` for a backup version.
    pub fn key_backup_stats_set(
        &self,
        user_nid: u64,
        version: &str,
        count: u64,
        etag: u64,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("key_backup").unwrap();
        let key = key_backup_stats_key(user_nid, version);
        let mut val = [0u8; 16];
        val[..8].copy_from_slice(&count.to_be_bytes());
        val[8..].copy_from_slice(&etag.to_be_bytes());
        self.db.put_cf(&cf, &key, val)
    }

    /// MSC4306 thread subscription state for one user/room/thread.
    /// `state`: 0 = unsubscribed (sentinel kept for conflict detection),
    /// 1 = manual subscription, 2 = automatic subscription.
    /// `pos`: stream position at last write — automatic-subscribe
    /// attempts whose cause event predates the last unsubscribe at
    /// this position must be refused.
    pub fn get_thread_subscription(
        &self,
        user_nid: u64,
        room_nid: u64,
        thread_root: &str,
    ) -> Result<Option<(u8, u64)>, rocksdb::Error> {
        let cf = self.db.cf_handle("thread_subscriptions").unwrap();
        let key = keys::encode_u64_pair_bytes(user_nid, room_nid, thread_root.as_bytes());
        match self.db.get_cf(&cf, &key)? {
            Some(bytes) if bytes.len() == 9 => {
                let state = bytes[0];
                let pos = u64::from_be_bytes(bytes[1..9].try_into().unwrap());
                Ok(Some((state, pos)))
            }
            _ => Ok(None),
        }
    }

    /// Iterate every thread subscription belonging to `user_nid`.
    /// Yields `(room_nid, thread_root_event_id, state, pos)`. Used by
    /// the MSC4308 sliding-sync extension to surface the user's
    /// per-thread state in the response.
    pub fn iter_thread_subscriptions(
        &self,
        user_nid: u64,
    ) -> Result<Vec<(u64, String, u8, u64)>, rocksdb::Error> {
        let cf = self.db.cf_handle("thread_subscriptions").unwrap();
        let prefix = user_nid.to_be_bytes();
        let mut out: Vec<(u64, String, u8, u64)> = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        for item in iter {
            let (key, val) = item?;
            if key.len() < 16 || key[..8] != prefix[..] {
                break;
            }
            if val.len() != 9 {
                continue;
            }
            let room_nid = u64::from_be_bytes(key[8..16].try_into().unwrap());
            let thread_root = match std::str::from_utf8(&key[16..]) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };
            let state = val[0];
            let pos = u64::from_be_bytes(val[1..9].try_into().unwrap());
            out.push((room_nid, thread_root, state, pos));
        }
        Ok(out)
    }

    /// Persist a thread subscription state change and return the
    /// stream position recorded for it. Callers pass `state` as
    /// 0 (unsubscribed), 1 (manual), or 2 (automatic).
    pub fn set_thread_subscription(
        &self,
        user_nid: u64,
        room_nid: u64,
        thread_root: &str,
        state: u8,
    ) -> Result<u64, rocksdb::Error> {
        let cf = self.db.cf_handle("thread_subscriptions").unwrap();
        let key = keys::encode_u64_pair_bytes(user_nid, room_nid, thread_root.as_bytes());
        let pos = self.next_stream_position().as_u64();
        let mut value = [0u8; 9];
        value[0] = state;
        value[1..9].copy_from_slice(&pos.to_be_bytes());
        self.db.put_cf(&cf, &key, value)?;
        Ok(pos)
    }

    /// Return `(data_type, value)` for account_data entries whose most
    /// recent update is strictly after `since_pos`. Used by incremental
    /// /sync to stream changes since the client's last token.
    pub fn get_account_data_since(
        &self,
        user_nid: u64,
        since_pos: u64,
    ) -> Result<Vec<(String, Value)>, rocksdb::Error> {
        let cf_pos = self.db.cf_handle("account_data_pos").unwrap();
        let cf_data = self.db.cf_handle("account_data").unwrap();
        let prefix = keys::encode_u64(user_nid);
        let mut out = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf_pos, prefix);
        for item in iter {
            let (key, val) = item?;
            if key.len() <= 8 || key[..8] != prefix[..] {
                break;
            }
            if val.len() != 8 {
                continue;
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&val);
            let pos = u64::from_be_bytes(buf);
            if pos <= since_pos {
                continue;
            }
            let data_type = String::from_utf8_lossy(&key[8..]).to_string();
            let value_bytes = match self.db.get_cf(&cf_data, &key)? {
                Some(b) => b,
                None => continue,
            };
            let value: Value = serde_json::from_slice(&value_bytes).unwrap_or(Value::Null);
            out.push((data_type, value));
        }
        Ok(out)
    }

    pub fn get_all_account_data(
        &self,
        user_nid: u64,
    ) -> Result<Vec<(String, Value)>, rocksdb::Error> {
        let cf = self.db.cf_handle("account_data").unwrap();
        let prefix = keys::encode_u64(user_nid);
        let mut results = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        for item in iter {
            let (key, val) = item?;
            if key.len() <= 8 || key[..8] != prefix[..] {
                break;
            }
            let data_type = String::from_utf8_lossy(&key[8..]).to_string();
            let value: Value = serde_json::from_slice(&val).unwrap_or(Value::Null);
            results.push((data_type, value));
        }
        Ok(results)
    }

    pub fn get_room_account_data(
        &self,
        user_nid: u64,
        room_nid: u64,
        data_type: &str,
    ) -> Result<Option<Value>, rocksdb::Error> {
        let cf = self.db.cf_handle("room_account_data").unwrap();
        let mut key = Vec::with_capacity(16 + data_type.len());
        key.extend_from_slice(&keys::encode_u64(user_nid));
        key.extend_from_slice(&keys::encode_u64(room_nid));
        key.extend_from_slice(data_type.as_bytes());
        match self.db.get_cf(&cf, &key)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).unwrap_or(Value::Null))),
            None => Ok(None),
        }
    }

    /// All room-scoped account data entries `(data_type, content)` for the
    /// given `(user_nid, room_nid)`. Used by sync to populate
    /// `rooms.join.{room_id}.account_data.events`.
    pub fn get_all_room_account_data(
        &self,
        user_nid: u64,
        room_nid: u64,
    ) -> Result<Vec<(String, Value)>, rocksdb::Error> {
        let cf = self.db.cf_handle("room_account_data").unwrap();
        let mut prefix = Vec::with_capacity(16);
        prefix.extend_from_slice(&keys::encode_u64(user_nid));
        prefix.extend_from_slice(&keys::encode_u64(room_nid));

        let iter = self.db.prefix_iterator_cf(&cf, &prefix);
        let mut out = Vec::new();
        for item in iter {
            let (key, val) = item?;
            if key.len() < 16 || key[..16] != prefix[..] {
                break;
            }
            let dtype = String::from_utf8_lossy(&key[16..]).to_string();
            let v: Value = serde_json::from_slice(&val).unwrap_or(Value::Null);
            out.push((dtype, v));
        }
        Ok(out)
    }

    pub fn set_room_account_data(
        &self,
        user_nid: u64,
        room_nid: u64,
        data_type: &str,
        value: &Value,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("room_account_data").unwrap();
        let mut key = Vec::with_capacity(16 + data_type.len());
        key.extend_from_slice(&keys::encode_u64(user_nid));
        key.extend_from_slice(&keys::encode_u64(room_nid));
        key.extend_from_slice(data_type.as_bytes());
        let pos = self.next_stream_position().as_u64();
        let mut batch = WriteBatch::default();
        batch.put_cf(&cf, &key, value.to_string().as_bytes());
        self.batch_put_stream_pos(
            &mut batch,
            &room_account_data_pos_key(user_nid, room_nid),
            pos,
        );
        self.db.write(batch)
    }

    // --- Media metadata ---

    pub fn set_media_metadata(
        &self,
        media_id: &str,
        metadata: &Value,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("media_metadata").unwrap();
        self.db
            .put_cf(&cf, media_id.as_bytes(), metadata.to_string().as_bytes())
    }

    pub fn get_media_metadata(&self, media_id: &str) -> Result<Option<Value>, rocksdb::Error> {
        let cf = self.db.cf_handle("media_metadata").unwrap();
        match self.db.get_cf(&cf, media_id.as_bytes())? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).unwrap_or(Value::Null))),
            None => Ok(None),
        }
    }

    /// Iterate every media metadata row. Used by the retention sweeper;
    /// caller is expected to bound the work itself (we don't paginate
    /// here because typical media volumes are well under a million
    /// rows even at matrix.org-scale, and the sweeper runs daily).
    pub fn list_media_metadata(&self) -> Result<Vec<(String, Value)>, rocksdb::Error> {
        let cf = self.db.cf_handle("media_metadata").unwrap();
        let iter = self.db.iterator_cf(&cf, IteratorMode::Start);
        let mut out = Vec::new();
        for item in iter {
            let (k, v) = item?;
            let media_id = String::from_utf8_lossy(&k).to_string();
            let metadata: Value = serde_json::from_slice(&v).unwrap_or(Value::Null);
            out.push((media_id, metadata));
        }
        Ok(out)
    }

    pub fn delete_media_metadata(&self, media_id: &str) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("media_metadata").unwrap();
        self.db.delete_cf(&cf, media_id.as_bytes())
    }

    // --- Receipts ---

    pub fn set_receipt(
        &self,
        room_nid: u64,
        receipt_type: &str,
        user_nid: u64,
        event_id: &str,
        timestamp: u64,
        thread_id: Option<&str>,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("receipts").unwrap();
        let key = receipt_key(room_nid, receipt_type, user_nid, thread_id);
        let val = serde_json::json!({"event_id": event_id, "ts": timestamp});
        let pos = self.next_stream_position().as_u64();
        let mut batch = WriteBatch::default();
        batch.put_cf(&cf, &key, val.to_string().as_bytes());
        self.batch_put_stream_pos(&mut batch, &receipts_room_pos_key(room_nid), pos);
        self.db.write(batch)
    }

    /// Highest stream position at which any receipt has been written
    /// for `room_nid`. `/sync` uses this to skip emitting the receipt
    /// snapshot on incremental syncs whose `since` cursor already
    /// covers every receipt update — turning what was a 0ms response
    /// into a real long-poll wait.
    pub fn get_room_receipts_max_pos(&self, room_nid: u64) -> Result<Option<u64>, rocksdb::Error> {
        self.get_stream_pos(&receipts_room_pos_key(room_nid))
    }

    /// Highest stream position at which any room-scoped account_data
    /// has been written for `(user_nid, room_nid)`. Same role as
    /// `get_room_receipts_max_pos` but for `m.fully_read` and room tags.
    pub fn get_room_account_data_max_pos(
        &self,
        user_nid: u64,
        room_nid: u64,
    ) -> Result<Option<u64>, rocksdb::Error> {
        self.get_stream_pos(&room_account_data_pos_key(user_nid, room_nid))
    }

    /// Write a u64 stream position into the generic `stream_positions`
    /// CF, scoped by the caller-supplied prefixed key. Helper so the
    /// receipt and room-account-data paths share the same encoding
    /// machinery without duplicating put-CF boilerplate.
    fn batch_put_stream_pos(&self, batch: &mut WriteBatch, key: &[u8], pos: u64) {
        let cf = self.db.cf_handle("stream_positions").unwrap();
        batch.put_cf(&cf, key, pos.to_be_bytes());
    }

    /// Read a u64 stream position from the generic `stream_positions`
    /// CF. Returns `None` when the key is absent (no write has ever
    /// happened for this scope) or when the stored value is malformed.
    fn get_stream_pos(&self, key: &[u8]) -> Result<Option<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("stream_positions").unwrap();
        let Some(bytes) = self.db.get_cf(&cf, key)? else {
            return Ok(None);
        };
        if bytes.len() != 8 {
            return Ok(None);
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes);
        Ok(Some(u64::from_be_bytes(buf)))
    }

    /// Locally-originated receipt write. Atomically updates the
    /// `receipts` CF (so our users see it via `/sync`) AND appends to
    /// `receipts_stream` (so the federation sender fans it out to
    /// remote peers in the rooms involved). Returns the assigned
    /// stream position, mostly for tests.
    ///
    /// Inbound EDUs from federation MUST NOT call this — peers are
    /// responsible for fanning out their own users' receipts. Use
    /// `set_receipt` for inbound dispatch (no stream append).
    pub fn set_local_receipt(
        &self,
        room_nid: u64,
        receipt_type: &str,
        user_nid: u64,
        event_id: &str,
        timestamp: u64,
        thread_id: Option<&str>,
    ) -> Result<u64, rocksdb::Error> {
        let receipts_cf = self.db.cf_handle("receipts").unwrap();
        let stream_cf = self.db.cf_handle("receipts_stream").unwrap();

        let pos = self.receipts_stream_counter.fetch_add(1, Ordering::Relaxed);

        let receipts_key = receipt_key(room_nid, receipt_type, user_nid, thread_id);
        let receipts_val = serde_json::json!({"event_id": event_id, "ts": timestamp}).to_string();

        let stream_key = keys::encode_u64(pos);
        let stream_val = serde_json::json!({
            "room": room_nid,
            "type": receipt_type,
            "user": user_nid,
            "event_id": event_id,
            "ts": timestamp,
            "thread_id": thread_id,
        })
        .to_string();

        // Also record the room-level max receipt stream position so
        // /sync can skip emitting the receipt snapshot on incremental
        // syncs whose `since` already covers it. We use the global
        // stream counter (not the federation receipts_stream counter)
        // because `since` cursors are global-stream-pos values.
        let global_pos = self.next_stream_position().as_u64();

        let mut batch = WriteBatch::default();
        batch.put_cf(&receipts_cf, &receipts_key, receipts_val.as_bytes());
        batch.put_cf(&stream_cf, stream_key, stream_val.as_bytes());
        self.batch_put_stream_pos(&mut batch, &receipts_room_pos_key(room_nid), global_pos);
        self.db.write(batch)?;
        Ok(pos)
    }

    /// Lookup the event_id of the most recent receipt of `receipt_type`
    /// (e.g. "m.read") that `user_nid` posted in `room_nid`, or `None`
    /// if no such receipt exists. Used by /sync to compute
    /// `unread_notifications` against the user's last-seen position.
    /// Looks at the unthreaded receipt only; threaded counts use
    /// `get_user_thread_receipt_event_id`.
    pub fn get_user_receipt_event_id(
        &self,
        room_nid: u64,
        receipt_type: &str,
        user_nid: u64,
    ) -> Result<Option<String>, rocksdb::Error> {
        self.get_user_thread_receipt_event_id(room_nid, receipt_type, user_nid, None)
    }

    /// Same shape as `get_user_receipt_event_id` but scoped to a specific
    /// thread_id (or unthreaded when `thread_id == None`). Used by /sync's
    /// notification accounting to honour threaded "main" receipts.
    pub fn get_user_thread_receipt_event_id(
        &self,
        room_nid: u64,
        receipt_type: &str,
        user_nid: u64,
        thread_id: Option<&str>,
    ) -> Result<Option<String>, rocksdb::Error> {
        let cf = self.db.cf_handle("receipts").unwrap();
        let key = receipt_key(room_nid, receipt_type, user_nid, thread_id);
        match self.db.get_cf(&cf, &key)? {
            Some(bytes) => {
                let v: Value = match serde_json::from_slice(&bytes) {
                    Ok(v) => v,
                    Err(_) => return Ok(None),
                };
                Ok(v.get("event_id")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()))
            }
            None => Ok(None),
        }
    }

    /// Scan `receipts_stream` strictly after `cursor`, returning up to
    /// `limit` entries plus the new cursor (= position of the last
    /// entry returned, or `cursor` if none). Each entry is the raw
    /// JSON object stored at write time:
    /// `{room, type, user, event_id, ts}`.
    pub fn scan_receipts_stream(
        &self,
        cursor: u64,
        limit: usize,
    ) -> Result<(Vec<(u64, Value)>, u64), rocksdb::Error> {
        let cf = self.db.cf_handle("receipts_stream").unwrap();
        // Strictly-after semantics: start at cursor + 1.
        let start = keys::encode_u64(cursor.saturating_add(1));
        let iter = self
            .db
            .iterator_cf(&cf, IteratorMode::From(&start, Direction::Forward));

        let mut out = Vec::with_capacity(limit.min(64));
        let mut new_cursor = cursor;
        for item in iter {
            let (key, val) = item?;
            if key.len() != 8 {
                continue;
            }
            let pos = keys::decode_u64(&key);
            let entry: Value = match serde_json::from_slice(&val) {
                Ok(v) => v,
                Err(_) => continue,
            };
            out.push((pos, entry));
            new_cursor = pos;
            if out.len() >= limit {
                break;
            }
        }
        Ok((out, new_cursor))
    }

    /// Returned tuples: `(receipt_type, user_nid, thread_id, value)`.
    /// `thread_id` is `None` for unthreaded receipts; otherwise carries the
    /// `"main"` sentinel or a thread-root event id (CS-API §receipts).
    pub fn get_room_receipts(
        &self,
        room_nid: u64,
    ) -> Result<Vec<(String, u64, Option<String>, Value)>, rocksdb::Error> {
        let cf = self.db.cf_handle("receipts").unwrap();
        let prefix = keys::encode_u64(room_nid);
        let mut results = Vec::new();

        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        for item in iter {
            let (key, val) = item?;
            if key.len() <= 8 || key[..8] != prefix[..] {
                break;
            }
            let receipt: Value = serde_json::from_slice(&val).unwrap_or(Value::Null);
            // Layout after room prefix: `<type> 0x00 <user_nid:8> 0x00 <thread_id?>`.
            let rest = &key[8..];
            let Some(type_end) = rest.iter().position(|&b| b == 0) else {
                continue;
            };
            let receipt_type = String::from_utf8_lossy(&rest[..type_end]).to_string();
            let after_type = &rest[type_end + 1..];
            if after_type.len() < 8 {
                continue;
            }
            let user_nid = keys::decode_u64(&after_type[..8]);
            let after_user = &after_type[8..];
            // Pre-thread-id keys may not have the trailing 0x00 separator; treat
            // such keys as unthreaded receipts to stay tolerant of older data.
            let thread_id: Option<String> = if after_user.is_empty() {
                None
            } else if after_user[0] == 0 {
                let tid_bytes = &after_user[1..];
                if tid_bytes.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(tid_bytes).to_string())
                }
            } else {
                None
            };
            results.push((receipt_type, user_nid, thread_id, receipt));
        }
        Ok(results)
    }

    // --- E2EE: Device keys ---

    pub fn set_device_keys(
        &self,
        user_nid: u64,
        device_id: &str,
        keys_json: &Value,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("device_keys").unwrap();
        let key = keys::encode_u64_bytes(user_nid, device_id.as_bytes());
        self.db.put_cf(&cf, &key, keys_json.to_string().as_bytes())
    }

    pub fn get_device_keys(
        &self,
        user_nid: u64,
        device_id: &str,
    ) -> Result<Option<Value>, rocksdb::Error> {
        let cf = self.db.cf_handle("device_keys").unwrap();
        let key = keys::encode_u64_bytes(user_nid, device_id.as_bytes());
        match self.db.get_cf(&cf, &key)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).unwrap_or(Value::Null))),
            None => Ok(None),
        }
    }

    pub fn get_all_device_keys(
        &self,
        user_nid: u64,
    ) -> Result<Vec<(String, Value)>, rocksdb::Error> {
        let cf = self.db.cf_handle("device_keys").unwrap();
        let prefix = keys::encode_u64(user_nid);
        let mut results = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        for item in iter {
            let (key, val) = item?;
            if key.len() <= 8 || key[..8] != prefix[..] {
                break;
            }
            let device_id = String::from_utf8_lossy(&key[8..]).to_string();
            let keys: Value = serde_json::from_slice(&val).unwrap_or(Value::Null);
            results.push((device_id, keys));
        }
        Ok(results)
    }

    /// Drop every E2EE artefact for `user_nid`: device keys, one-time keys,
    /// and cross-signing keys. Used on account deactivation. Returns
    /// `(device_keys_removed, otks_removed, cross_signing_removed)`.
    ///
    /// All three CFs are u64-prefixed by user_nid so a single prefix scan
    /// per CF suffices.
    pub fn delete_user_e2ee_keys(
        &self,
        user_nid: u64,
    ) -> Result<(usize, usize, usize), rocksdb::Error> {
        let prefix = keys::encode_u64(user_nid);
        let mut batch = WriteBatch::default();
        let mut device_removed = 0usize;
        let mut otk_removed = 0usize;
        let mut cross_removed = 0usize;

        let device_cf = self.db.cf_handle("device_keys").unwrap();
        for item in self.db.prefix_iterator_cf(&device_cf, prefix) {
            let (key, _) = item?;
            if key.len() < 8 || key[..8] != prefix[..] {
                break;
            }
            batch.delete_cf(&device_cf, &key);
            device_removed += 1;
        }

        let otk_cf = self.db.cf_handle("one_time_keys").unwrap();
        for item in self.db.prefix_iterator_cf(&otk_cf, prefix) {
            let (key, _) = item?;
            if key.len() < 8 || key[..8] != prefix[..] {
                break;
            }
            batch.delete_cf(&otk_cf, &key);
            otk_removed += 1;
        }

        let cross_cf = self.db.cf_handle("cross_signing_keys").unwrap();
        for item in self.db.prefix_iterator_cf(&cross_cf, prefix) {
            let (key, _) = item?;
            if key.len() < 8 || key[..8] != prefix[..] {
                break;
            }
            batch.delete_cf(&cross_cf, &key);
            cross_removed += 1;
        }

        if device_removed + otk_removed + cross_removed > 0 {
            self.db.write(batch)?;
        }
        Ok((device_removed, otk_removed, cross_removed))
    }

    // --- E2EE: One-time keys ---

    pub fn add_one_time_keys(
        &self,
        user_nid: u64,
        device_id: &str,
        otks: &serde_json::Map<String, Value>,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("one_time_keys").unwrap();
        let mut batch = WriteBatch::default();
        for (key_id, key_data) in otks {
            let db_key =
                keys::encode_u64_bytes_bytes(user_nid, device_id.as_bytes(), key_id.as_bytes());
            batch.put_cf(&cf, &db_key, key_data.to_string().as_bytes());
        }
        self.db.write(batch)
    }

    pub fn count_one_time_keys(
        &self,
        user_nid: u64,
        device_id: &str,
    ) -> Result<std::collections::HashMap<String, u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("one_time_keys").unwrap();
        // Build the prefix that matches encode_u64_bytes_bytes: (user_nid || len:u16 || device_id)
        let device_bytes = device_id.as_bytes();
        let len = device_bytes.len() as u16;
        let mut prefix = Vec::with_capacity(8 + 2 + device_bytes.len());
        prefix.extend_from_slice(&keys::encode_u64(user_nid));
        prefix.extend_from_slice(&len.to_be_bytes());
        prefix.extend_from_slice(device_bytes);

        let mut counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

        let iter = self.db.prefix_iterator_cf(&cf, &prefix);
        for item in iter {
            let (key, _) = item?;
            if key.len() <= prefix.len() || key[..prefix.len()] != prefix[..] {
                break;
            }
            let key_id = String::from_utf8_lossy(&key[prefix.len()..]);
            let algo = key_id.split(':').next().unwrap_or("unknown");
            *counts.entry(algo.to_string()).or_insert(0) += 1;
        }
        Ok(counts)
    }

    pub fn claim_one_time_key(
        &self,
        user_nid: u64,
        device_id: &str,
        algorithm: &str,
    ) -> Result<Option<(String, Value)>, rocksdb::Error> {
        let cf = self.db.cf_handle("one_time_keys").unwrap();
        let device_bytes = device_id.as_bytes();
        let len = device_bytes.len() as u16;
        let mut prefix = Vec::with_capacity(8 + 2 + device_bytes.len());
        prefix.extend_from_slice(&keys::encode_u64(user_nid));
        prefix.extend_from_slice(&len.to_be_bytes());
        prefix.extend_from_slice(device_bytes);

        // Synapse returns the lexicographically-largest key id (i.e.
        // `signed_curve25519:N` for the highest N the client uploaded
        // with single-digit suffixes). The test ordering relies on
        // this. We forward-scan all matches, take the max — N is
        // small (~50 OTKs per device) so the linear pass is cheap and
        // avoids the rocksdb reverse-prefix-iterator footgun.
        let iter = self.db.prefix_iterator_cf(&cf, &prefix);
        let mut best: Option<(Vec<u8>, String, Value)> = None;
        for item in iter {
            let (key, val) = item?;
            if key.len() <= prefix.len() || key[..prefix.len()] != prefix[..] {
                break;
            }
            let key_id = String::from_utf8_lossy(&key[prefix.len()..]).to_string();
            if !key_id.starts_with(algorithm) {
                continue;
            }
            let take = best
                .as_ref()
                .map(|(_, prev_id, _)| key_id > *prev_id)
                .unwrap_or(true);
            if take {
                let value: Value = serde_json::from_slice(&val).unwrap_or(Value::Null);
                best = Some((key.to_vec(), key_id, value));
            }
        }
        if let Some((key_bytes, key_id, value)) = best {
            self.db.delete_cf(&cf, &key_bytes)?;
            return Ok(Some((key_id, value)));
        }
        Ok(None)
    }

    // --- E2EE: To-device messages ---

    pub fn queue_to_device(
        &self,
        target_user_nid: u64,
        target_device_id: &str,
        event_type: &str,
        sender: &str,
        content: &Value,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("to_device_messages").unwrap();
        let msg_id = self.next_stream_position();
        let key = keys::encode_u64_bytes_bytes(
            target_user_nid,
            target_device_id.as_bytes(),
            &msg_id.to_be_bytes(),
        );
        let msg = serde_json::json!({
            "type": event_type,
            "sender": sender,
            "content": content,
        });
        self.db.put_cf(&cf, &key, msg.to_string().as_bytes())
    }

    pub fn get_to_device_messages(
        &self,
        user_nid: u64,
        device_id: &str,
    ) -> Result<Vec<(Vec<u8>, Value)>, rocksdb::Error> {
        let cf = self.db.cf_handle("to_device_messages").unwrap();
        // Must match encode_u64_bytes_bytes prefix: (user_nid || len:u16 || device_id)
        let device_bytes = device_id.as_bytes();
        let len = device_bytes.len() as u16;
        let mut prefix = Vec::with_capacity(8 + 2 + device_bytes.len());
        prefix.extend_from_slice(&keys::encode_u64(user_nid));
        prefix.extend_from_slice(&len.to_be_bytes());
        prefix.extend_from_slice(device_bytes);
        let mut messages = Vec::new();

        let iter = self.db.prefix_iterator_cf(&cf, &prefix);
        for item in iter {
            let (key, val) = item?;
            if key.len() <= prefix.len() || key[..prefix.len()] != prefix[..] {
                break;
            }
            let msg: Value = serde_json::from_slice(&val).unwrap_or(Value::Null);
            messages.push((key.to_vec(), msg));
        }
        Ok(messages)
    }

    pub fn delete_to_device_messages(
        &self,
        keys_to_delete: &[Vec<u8>],
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("to_device_messages").unwrap();
        let mut batch = WriteBatch::default();
        for key in keys_to_delete {
            batch.delete_cf(&cf, key);
        }
        self.db.write(batch)
    }

    // --- E2EE: Cross-signing keys ---

    pub fn set_cross_signing_keys(
        &self,
        user_nid: u64,
        key_type: &str,
        keys_json: &Value,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("cross_signing_keys").unwrap();
        let key = keys::encode_u64_bytes(user_nid, key_type.as_bytes());
        self.db.put_cf(&cf, &key, keys_json.to_string().as_bytes())
    }

    pub fn get_cross_signing_keys(
        &self,
        user_nid: u64,
    ) -> Result<std::collections::HashMap<String, Value>, rocksdb::Error> {
        let cf = self.db.cf_handle("cross_signing_keys").unwrap();
        let prefix = keys::encode_u64(user_nid);
        let mut result = std::collections::HashMap::new();

        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        for item in iter {
            let (key, val) = item?;
            if key.len() <= 8 || key[..8] != prefix[..] {
                break;
            }
            let key_type = String::from_utf8_lossy(&key[8..]).to_string();
            let keys: Value = serde_json::from_slice(&val).unwrap_or(Value::Null);
            result.insert(key_type, keys);
        }
        Ok(result)
    }

    // --- E2EE: Device key changes ---

    /// Record that `changed_user_nid`'s device / cross-signing keys have
    /// been updated. Writes one entry per observer (= joined room-mate)
    /// so `get_device_key_changes(observer, ..)` can surface the change.
    /// Always includes the user themself as an observer so their own
    /// client sees its own device list refresh (needed by Element's
    /// cross-signing setup to re-query after self-signing).
    pub fn record_device_key_change(&self, changed_user_nid: u64) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("device_key_changes").unwrap();
        let pos = self.next_stream_position();
        let val = keys::encode_u64(changed_user_nid);

        // Collect observers: always self, plus every joined room-mate.
        let mut observers = std::collections::HashSet::new();
        observers.insert(changed_user_nid);
        if let Ok(rooms) = self.get_user_joined_rooms(changed_user_nid) {
            for room_nid in rooms {
                if let Ok(members) = self.get_room_members(room_nid) {
                    for m in members {
                        observers.insert(m);
                    }
                }
            }
        }

        let mut batch = WriteBatch::default();
        for obs in observers {
            batch.put_cf(&cf, keys::encode_u64_pair(obs, pos.as_u64()), val);
        }
        self.db.write(batch)
    }

    pub fn get_device_key_changes(
        &self,
        user_nid: u64,
        from: u64,
        to: u64,
    ) -> Result<Vec<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("device_key_changes").unwrap();
        let start = keys::encode_u64_pair(user_nid, from);
        let mut changed_users = Vec::new();

        let iter = self
            .db
            .iterator_cf(&cf, IteratorMode::From(&start, rocksdb::Direction::Forward));
        for item in iter {
            let (key, val) = item?;
            if key.len() < 16 {
                break;
            }
            let (observer, pos) = keys::decode_u64_pair(&key);
            if observer != user_nid || pos >= to {
                break;
            }
            let changed_nid = keys::decode_u64(&val);
            if !changed_users.contains(&changed_nid) {
                changed_users.push(changed_nid);
            }
        }
        Ok(changed_users)
    }

    /// Mirror of `notify_device_key_change` for the "user no longer
    /// shares a room with X" direction. Each observer gets one entry
    /// per (departure, pos) so /sync can emit `device_lists.left`.
    pub fn record_peer_departure(
        &self,
        departed_nid: u64,
        observer_nids: &[u64],
        stream_pos: u64,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("device_list_left").unwrap();
        let val = keys::encode_u64(departed_nid);
        let mut batch = WriteBatch::default();
        for &obs in observer_nids {
            if obs == departed_nid {
                continue;
            }
            batch.put_cf(&cf, keys::encode_u64_pair(obs, stream_pos), val);
        }
        self.db.write(batch)
    }

    /// Forward-scan `device_list_left[observer]` between [from, to)
    /// and return the deduplicated departed user_nids.
    pub fn get_device_list_left(
        &self,
        user_nid: u64,
        from: u64,
        to: u64,
    ) -> Result<Vec<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("device_list_left").unwrap();
        let start = keys::encode_u64_pair(user_nid, from);
        let mut left_users = Vec::new();
        let iter = self
            .db
            .iterator_cf(&cf, IteratorMode::From(&start, rocksdb::Direction::Forward));
        for item in iter {
            let (key, val) = item?;
            if key.len() < 16 {
                break;
            }
            let (observer, pos) = keys::decode_u64_pair(&key);
            if observer != user_nid || pos >= to {
                break;
            }
            let departed_nid = keys::decode_u64(&val);
            if !left_users.contains(&departed_nid) {
                left_users.push(departed_nid);
            }
        }
        Ok(left_users)
    }

    /// Return the prev_events (as NIDs) recorded for an event.
    pub fn get_prev_events(&self, event_nid: u64) -> Result<Vec<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("event_edges").unwrap();
        match self.db.get_cf(&cf, keys::encode_u64(event_nid))? {
            Some(b) => Ok(keys::decode_u64_array(&b)),
            None => Ok(Vec::new()),
        }
    }

    /// Resolve prev_event NIDs by parsing the stored event JSON.
    /// `persist_event` only records prevs whose NIDs were resolvable at
    /// write time — for a federated join the prev_events are messages
    /// on the originating server we don't have NIDs for, so the cache
    /// is empty. The spec keeps prev_events as event_id strings in the
    /// event JSON, so reading there is authoritative whenever we need
    /// the original list (e.g. driving a /backfill request). Falls
    /// back to the cached array when JSON isn't usable.
    pub fn get_prev_events_from_json(&self, event_nid: u64) -> Result<Vec<u64>, rocksdb::Error> {
        let Some((_, json_bytes)) = self.get_event(event_nid)? else {
            return self.get_prev_events(event_nid);
        };
        let value: Value = match serde_json::from_slice(&json_bytes) {
            Ok(v) => v,
            Err(_) => return self.get_prev_events(event_nid),
        };
        let Some(arr) = value.get("prev_events").and_then(|v| v.as_array()) else {
            return self.get_prev_events(event_nid);
        };
        let mut resolved: Vec<u64> = Vec::with_capacity(arr.len());
        for v in arr {
            if let Some(eid) = v.as_str()
                && let Ok(Some(n)) = self.get_event_nid_by_id(eid)
            {
                resolved.push(n);
            }
        }
        if resolved.is_empty() {
            return self.get_prev_events(event_nid);
        }
        Ok(resolved)
    }

    /// Return the auth_events (as NIDs) recorded for an event.
    pub fn get_auth_events(&self, event_nid: u64) -> Result<Vec<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("event_auth_edges").unwrap();
        match self.db.get_cf(&cf, keys::encode_u64(event_nid))? {
            Some(b) => Ok(keys::decode_u64_array(&b)),
            None => Ok(Vec::new()),
        }
    }

    /// Walk backwards through the event DAG from `start_event_nid`, returning
    /// up to `limit` events in depth-descending order (chronologically
    /// backwards in the federated DAG sense).
    ///
    /// Walks `prev_events` recursively via a min-heap keyed by
    /// `(-depth, origin_server_ts, event_id_string)` — descending depth
    /// (deepest first), then earliest timestamp tiebreaker, then event_id.
    ///
    /// `start_event_nid` is NOT included in the result. Pagination semantics:
    /// caller passes the last event of the previous page, gets the next page.
    ///
    /// Heap is hard-capped at `10 * limit` entries to bound memory on
    /// pathological many-prev-event DAGs. Excess prev_events on a single
    /// node are silently truncated (limit-bounded pagination is acceptable).
    pub fn walk_dag_backwards(
        &self,
        start_event_nid: u64,
        limit: usize,
    ) -> Result<Vec<u64>, rocksdb::Error> {
        use std::cmp::Reverse;
        use std::collections::{BinaryHeap, HashSet};

        if limit == 0 {
            return Ok(Vec::new());
        }
        let heap_cap = limit.saturating_mul(10);

        // Heap entry: Reverse((-depth_inverted, origin_server_ts, event_id_str), event_nid).
        // We want max-depth-first; BinaryHeap is a max-heap; we pop "largest"
        // tuple. To get max-depth-first, encode depth directly (larger depth =
        // larger key). For ts and event_id we want SMALLER first (earlier ts,
        // lexicographically smaller id) — so wrap those in Reverse.
        type Key = (u64, Reverse<u64>, Reverse<String>);
        let mut heap: BinaryHeap<(Key, u64)> = BinaryHeap::new();
        let mut seen: HashSet<u64> = HashSet::new();

        // Seed: enqueue the start event's prev_events. Start event itself
        // is excluded.
        // Use JSON-derived prev_events: a freshly-joined peer's join
        // event has empty event_edges (the original prev event ids
        // weren't resolvable to NIDs at send_join time), but reading
        // the join's stored JSON gives us the authoritative list and
        // any NIDs that have since been backfilled in resolve here.
        let start_prev = self.get_prev_events_from_json(start_event_nid)?;
        for p in start_prev {
            if !seen.contains(&p)
                && let Some(key) = self.event_walk_key(p)?
                && heap.len() < heap_cap
            {
                heap.push((key, p));
            }
        }

        let mut out = Vec::with_capacity(limit);
        while let Some((_, nid)) = heap.pop() {
            if !seen.insert(nid) {
                continue;
            }
            out.push(nid);
            if out.len() >= limit {
                break;
            }
            let prevs = self.get_prev_events_from_json(nid)?;
            for p in prevs {
                if seen.contains(&p) {
                    continue;
                }
                if heap.len() >= heap_cap {
                    break;
                }
                if let Some(key) = self.event_walk_key(p)? {
                    heap.push((key, p));
                }
            }
        }
        Ok(out)
    }

    /// Build the heap-ordering key for an event. Returns None if the event
    /// is unknown (caller treats as missing → backfill candidate).
    fn event_walk_key(
        &self,
        nid: u64,
    ) -> Result<Option<(u64, std::cmp::Reverse<u64>, std::cmp::Reverse<String>)>, rocksdb::Error>
    {
        use std::cmp::Reverse;
        let Some((header, _)) = self.get_event(nid)? else {
            return Ok(None);
        };
        let event_id = self.get_event_id_by_nid(nid)?.unwrap_or_default();
        Ok(Some((
            header.depth,
            Reverse(header.origin_server_ts),
            Reverse(event_id),
        )))
    }

    /// Compute the full auth chain for an event: transitive closure of
    /// `auth_events` via BFS. Capped at `max_events` to guard against
    /// pathological or malicious graphs. The starting event itself is NOT
    /// included in the returned set.
    pub fn get_auth_chain(
        &self,
        event_nid: u64,
        max_events: usize,
    ) -> Result<Vec<u64>, rocksdb::Error> {
        use std::collections::{HashSet, VecDeque};

        let mut seen: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<u64> = VecDeque::new();
        let mut out: Vec<u64> = Vec::new();

        queue.push_back(event_nid);
        while let Some(n) = queue.pop_front() {
            let auths = self.get_auth_events(n)?;
            for a in auths {
                if a == event_nid {
                    continue;
                }
                if seen.insert(a) {
                    out.push(a);
                    if out.len() >= max_events {
                        return Ok(out);
                    }
                    queue.push_back(a);
                }
            }
        }
        Ok(out)
    }

    /// Resolve all remote server names (not our own) that have joined members
    /// in the given room. Used to compute the destination list for outbound
    /// federation traffic.
    pub fn get_remote_servers_in_room(
        &self,
        room_nid: u64,
        our_server_name: &str,
    ) -> Result<Vec<String>, rocksdb::Error> {
        use std::collections::HashSet;
        let members = self.get_room_members(room_nid)?;
        let mut servers: HashSet<String> = HashSet::new();
        for user_nid in members {
            let Some(user_id) = self.resolve_nid(user_nid)? else {
                continue;
            };
            if let Some((_, domain)) = user_id.split_once(':')
                && domain != our_server_name
                && !domain.is_empty()
            {
                servers.insert(domain.to_string());
            }
        }
        Ok(servers.into_iter().collect())
    }

    // --- Meta operations ---

    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        let cf = self.db.cf_handle("meta").unwrap();
        self.db.get_cf(&cf, key.as_bytes())
    }

    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("meta").unwrap();
        self.db.put_cf(&cf, key.as_bytes(), value)
    }

    // --- Admin bot / admin room (vela-specific) ---

    /// Persist the user_nid of the server-internal admin bot user.
    /// Looked up by the bootstrap path on every start to decide whether
    /// the admin user already exists, and by the command-receive hook
    /// to short-circuit on bot-authored messages (the bot never
    /// dispatches commands to itself).
    pub fn set_admin_bot_user_nid(&self, user_nid: u64) -> Result<(), rocksdb::Error> {
        self.set_meta("admin_bot_user_nid", &keys::encode_u64(user_nid))
    }

    pub fn get_admin_bot_user_nid(&self) -> Result<Option<u64>, rocksdb::Error> {
        Ok(self.get_meta("admin_bot_user_nid")?.and_then(|b| {
            if b.len() == 8 {
                Some(keys::decode_u64(&b))
            } else {
                None
            }
        }))
    }

    /// Persist the room_id string of the admin room. Stored as the
    /// string (not nid) so callers can format it back into responses
    /// without an extra lookup. The room itself is also resolvable via
    /// `get_nid(room_id)`; `is_admin` uses the nid path.
    pub fn set_admin_room_id(&self, room_id: &str) -> Result<(), rocksdb::Error> {
        self.set_meta("admin_room_id", room_id.as_bytes())
    }

    pub fn get_admin_room_id(&self) -> Result<Option<String>, rocksdb::Error> {
        Ok(self
            .get_meta("admin_room_id")?
            .and_then(|b| String::from_utf8(b).ok()))
    }

    /// Convenience: resolve the admin room's nid via the recorded
    /// string. Returns `None` when no admin room exists yet (fresh
    /// deploy that hasn't booted past the bootstrap step) or when the
    /// stored string fails to map back to a nid (corruption-only path).
    pub fn get_admin_room_nid(&self) -> Result<Option<u64>, rocksdb::Error> {
        let Some(room_id) = self.get_admin_room_id()? else {
            return Ok(None);
        };
        self.get_nid(&room_id)
    }

    // --- Registration tokens (vela-specific dynamic tokens) ---
    //
    // The static `[registration] token` from vela.toml is seeded into
    // this CF on first boot when no admin exists yet, so the same
    // lookup path covers bootstrap and post-bootstrap. After the admin
    // room is up, the admin bot mints / lists / revokes tokens via
    // `!token *` commands.

    /// Insert a registration token. `uses_allowed = 0` means unlimited;
    /// `expires_at_ms = 0` means never expires. `created_by = 0` is the
    /// sentinel for "seeded by the operator's vela.toml" (no admin
    /// existed yet at the time).
    pub fn create_registration_token(
        &self,
        token: &str,
        uses_allowed: u64,
        expires_at_ms: u64,
        created_by_user_nid: u64,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("registration_tokens").unwrap();
        let record = serde_json::json!({
            "uses_allowed": uses_allowed,
            "uses_used": 0u64,
            "expires_at_ms": expires_at_ms,
            "created_by": created_by_user_nid,
            "created_at_ms": now_ms(),
        });
        self.db
            .put_cf(&cf, token.as_bytes(), record.to_string().as_bytes())
    }

    /// Snapshot of a registration token, or `None` if unknown.
    pub fn get_registration_token(&self, token: &str) -> Result<Option<Value>, rocksdb::Error> {
        let cf = self.db.cf_handle("registration_tokens").unwrap();
        Ok(self
            .db
            .get_cf(&cf, token.as_bytes())?
            .and_then(|b| serde_json::from_slice(&b).ok()))
    }

    /// List every stored registration token (token string + record).
    /// Used by `!tokens`. Full-scan, fine at expected scale (handful of
    /// tokens per deployment).
    pub fn list_registration_tokens(&self) -> Result<Vec<(String, Value)>, rocksdb::Error> {
        let cf = self.db.cf_handle("registration_tokens").unwrap();
        let mut out = Vec::new();
        let iter = self.db.iterator_cf(&cf, IteratorMode::Start);
        for item in iter {
            let (key, val) = item?;
            let Ok(token) = String::from_utf8(key.to_vec()) else {
                continue;
            };
            let Ok(record) = serde_json::from_slice::<Value>(&val) else {
                continue;
            };
            out.push((token, record));
        }
        Ok(out)
    }

    /// Delete a registration token. Idempotent: deleting an absent
    /// token is `Ok(())`.
    pub fn delete_registration_token(&self, token: &str) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("registration_tokens").unwrap();
        self.db.delete_cf(&cf, token.as_bytes())
    }

    /// Read-only "is this token currently usable?" check. Same rules as
    /// `consume_registration_token` (existence + not-expired + not-exhausted)
    /// without the write. Used to fail registration early — before
    /// expensive validation (password hashing) — so a wrong token doesn't
    /// waste CPU. The actual consume happens later, atomically with user
    /// creation, so a failed registration doesn't burn the token.
    pub fn validate_registration_token(&self, token: &str) -> Result<bool, rocksdb::Error> {
        let cf = self.db.cf_handle("registration_tokens").unwrap();
        let Some(bytes) = self.db.get_cf(&cf, token.as_bytes())? else {
            return Ok(false);
        };
        let record: Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let uses_allowed = record["uses_allowed"].as_u64().unwrap_or(0);
        let uses_used = record["uses_used"].as_u64().unwrap_or(0);
        let expires_at_ms = record["expires_at_ms"].as_u64().unwrap_or(0);
        if expires_at_ms != 0 && now_ms() >= expires_at_ms {
            return Ok(false);
        }
        if uses_allowed != 0 && uses_used >= uses_allowed {
            return Ok(false);
        }
        Ok(true)
    }

    /// Validate + consume one use of a registration token, atomically.
    /// Returns `Ok(true)` if the token was accepted (and its `uses_used`
    /// incremented), `Ok(false)` if the token is unknown / expired /
    /// exhausted. Caller treats `false` as "registration rejected"
    /// without distinguishing the reason — same surface every other
    /// homeserver presents.
    pub fn consume_registration_token(&self, token: &str) -> Result<bool, rocksdb::Error> {
        let cf = self.db.cf_handle("registration_tokens").unwrap();
        let Some(bytes) = self.db.get_cf(&cf, token.as_bytes())? else {
            return Ok(false);
        };
        let mut record: Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let uses_allowed = record["uses_allowed"].as_u64().unwrap_or(0);
        let uses_used = record["uses_used"].as_u64().unwrap_or(0);
        let expires_at_ms = record["expires_at_ms"].as_u64().unwrap_or(0);
        if expires_at_ms != 0 && now_ms() >= expires_at_ms {
            return Ok(false);
        }
        if uses_allowed != 0 && uses_used >= uses_allowed {
            return Ok(false);
        }
        if let Some(obj) = record.as_object_mut() {
            obj.insert("uses_used".into(), Value::Number((uses_used + 1).into()));
        }
        self.db
            .put_cf(&cf, token.as_bytes(), record.to_string().as_bytes())?;
        Ok(true)
    }

    // --- Federation outbox ---
    //
    // Persistent per-destination queue of events we still owe a remote
    // server. The in-memory federation_sender channels were lost on
    // restart, which left peers seeing a silent gap. Outbox keys are
    // `(destination, stream_pos_be)` so a prefix scan returns one
    // destination's pending events in send order; values are event_nids.
    //
    // The destination string is bounded length (server_name) so prefix
    // collisions aren't a concern. We pad destination with a 0xff byte
    // separator so a server named "a" can't collide with "ab"+stream_pos.

    /// Append an event to a destination's outbox. Returns the stream_pos
    /// the entry was filed under (caller can use it to delete after
    /// successful send).
    pub fn enqueue_outbound(
        &self,
        destination: &str,
        event_nid: u64,
    ) -> Result<u64, rocksdb::Error> {
        let cf = self.db.cf_handle("federation_outbox").unwrap();
        let pos = self.next_stream_position();
        let key = outbox_key(destination, pos.as_u64());
        self.db.put_cf(&cf, &key, keys::encode_u64(event_nid))?;
        Ok(pos.as_u64())
    }

    /// Batch-enqueue the same event to multiple destinations in one
    /// `WriteBatch`. Shaves N-1 RocksDB write syscalls + WAL appends off
    /// the local-send hot path when broadcasting to many remote peers.
    /// Returns the assigned stream_pos for each destination, in input
    /// order.
    pub fn enqueue_outbound_batch(
        &self,
        destinations: &[&str],
        event_nid: u64,
    ) -> Result<Vec<u64>, rocksdb::Error> {
        if destinations.is_empty() {
            return Ok(Vec::new());
        }
        let cf = self.db.cf_handle("federation_outbox").unwrap();
        let mut batch = WriteBatch::default();
        let mut positions = Vec::with_capacity(destinations.len());
        let nid_bytes = keys::encode_u64(event_nid);
        for dest in destinations {
            let pos = self.next_stream_position();
            let key = outbox_key(dest, pos.as_u64());
            batch.put_cf(&cf, &key, nid_bytes);
            positions.push(pos.as_u64());
        }
        self.db.write(batch)?;
        Ok(positions)
    }

    /// Read up to `limit` pending entries for `destination` in send order.
    /// Returns `(stream_pos, event_nid)` pairs.
    pub fn peek_outbound(
        &self,
        destination: &str,
        limit: usize,
    ) -> Result<Vec<(u64, u64)>, rocksdb::Error> {
        let cf = self.db.cf_handle("federation_outbox").unwrap();
        let prefix = outbox_prefix(destination);
        let mut out = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf, &prefix);
        for item in iter {
            let (key, val) = item?;
            if !key.starts_with(&prefix) {
                break;
            }
            if val.len() != 8 || key.len() < prefix.len() + 8 {
                continue;
            }
            // Stream pos is the trailing 8 bytes after the prefix.
            let pos_bytes = &key[prefix.len()..prefix.len() + 8];
            let mut buf = [0u8; 8];
            buf.copy_from_slice(pos_bytes);
            let pos = u64::from_be_bytes(buf);
            let event_nid = keys::decode_u64(&val);
            out.push((pos, event_nid));
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// Delete the named outbox entries (after successful send).
    pub fn delete_outbound(
        &self,
        destination: &str,
        positions: &[u64],
    ) -> Result<(), rocksdb::Error> {
        if positions.is_empty() {
            return Ok(());
        }
        let cf = self.db.cf_handle("federation_outbox").unwrap();
        let mut batch = WriteBatch::default();
        for &pos in positions {
            batch.delete_cf(&cf, outbox_key(destination, pos));
        }
        self.db.write(batch)
    }

    /// On startup: enumerate every destination that has at least one
    /// pending entry, so the federation sender can spawn a task per
    /// stuck queue without waiting for a fresh broadcast.
    pub fn list_outbound_destinations(&self) -> Result<Vec<String>, rocksdb::Error> {
        // Scan every outbound CF that holds per-destination work, not just
        // the PDU outbox. EDU queues (to-device, device-list updates,
        // signing-key updates) all share the same key shape
        // `<destination> 0xff <pos>`. After a crash with only an EDU
        // pending for some peer, scanning federation_outbox alone would
        // miss that peer entirely; the sender wouldn't start for it and
        // the EDU would sit forever (this was the cause of
        // TestToDeviceMessagesOverFederation/stopped_server failing).
        let cfs = [
            "federation_outbox",
            "to_device_outbound",
            "device_list_outbound",
            "signing_key_update_outbound",
        ];
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut destinations: Vec<String> = Vec::new();
        for cf_name in cfs {
            let Some(cf) = self.db.cf_handle(cf_name) else {
                continue;
            };
            let iter = self.db.iterator_cf(&cf, IteratorMode::Start);
            for item in iter {
                let (key, _) = item?;
                let Some(sep_idx) = key.iter().position(|&b| b == 0xff) else {
                    continue;
                };
                let dest = String::from_utf8_lossy(&key[..sep_idx]).into_owned();
                if seen.insert(dest.clone()) {
                    destinations.push(dest);
                }
            }
        }
        Ok(destinations)
    }

    // --- Server signing key operations ---

    /// Load the server signing key from the server_keys CF.
    /// Returns (key_id, secret_bytes) if present.
    pub fn load_signing_key(
        &self,
    ) -> Result<Option<(String, [u8; 32])>, Box<dyn std::error::Error + Send + Sync>> {
        use base64::Engine;
        let cf = self.db.cf_handle("server_keys").unwrap();
        match self.db.get_cf(&cf, b"signing_key")? {
            Some(val) => {
                let json: serde_json::Value = serde_json::from_slice(&val)?;
                let key_id = json["key_id"]
                    .as_str()
                    .ok_or("missing key_id in stored signing key")?
                    .to_string();
                let secret_b64 = json["secret"]
                    .as_str()
                    .ok_or("missing secret in stored signing key")?;
                let secret_vec = base64::engine::general_purpose::STANDARD.decode(secret_b64)?;
                if secret_vec.len() != 32 {
                    return Err("stored signing key secret is not 32 bytes".into());
                }
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&secret_vec);
                Ok(Some((key_id, secret)))
            }
            None => Ok(None),
        }
    }

    /// Store the server signing key in the server_keys CF.
    pub fn store_signing_key(&self, key_id: &str, secret: &[u8; 32]) -> Result<(), rocksdb::Error> {
        use base64::Engine;
        let cf = self.db.cf_handle("server_keys").unwrap();
        let json = serde_json::json!({
            "key_id": key_id,
            "secret": base64::engine::general_purpose::STANDARD.encode(secret),
        });
        self.db
            .put_cf(&cf, b"signing_key", json.to_string().as_bytes())
    }

    /// Rotate the active server signing key in a single atomic batch:
    /// records the outgoing key under `old_verify_keys` with
    /// `expired_ts = expired_ts_ms`, then overwrites the active key
    /// with `new_key_id` / `new_secret`. The outgoing key's public
    /// component (`outgoing_public_b64`) is the caller's responsibility
    /// because reconstructing it here would require an ed25519 dep in
    /// vela-store. Atomic so peers never observe a half-rotated state.
    pub fn rotate_signing_key(
        &self,
        outgoing_key_id: &str,
        outgoing_public_b64: &str,
        expired_ts_ms: u64,
        new_key_id: &str,
        new_secret: &[u8; 32],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use base64::Engine;
        let cf = self.db.cf_handle("server_keys").unwrap();
        let mut list: Vec<serde_json::Value> = match self.db.get_cf(&cf, b"old_verify_keys")? {
            Some(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            None => Vec::new(),
        };
        list.push(serde_json::json!({
            "key_id": outgoing_key_id,
            "public_key": outgoing_public_b64,
            "expired_ts": expired_ts_ms,
        }));
        let new_active = serde_json::json!({
            "key_id": new_key_id,
            "secret": base64::engine::general_purpose::STANDARD.encode(new_secret),
        });
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(&cf, b"old_verify_keys", serde_json::to_vec(&list)?);
        batch.put_cf(&cf, b"signing_key", new_active.to_string().as_bytes());
        self.db.write(batch)?;
        Ok(())
    }

    /// Append a rotated-out signing key to the historical list. The
    /// `public_key_b64` is the standard-alphabet base64 of the 32-byte
    /// ed25519 public; `expired_ts_ms` is when the rotation took effect
    /// (so peers can decide whether a signature predating that ts is
    /// still acceptable per their own freshness policy).
    pub fn record_rotated_signing_key(
        &self,
        key_id: &str,
        public_key_b64: &str,
        expired_ts_ms: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cf = self.db.cf_handle("server_keys").unwrap();
        let mut list: Vec<serde_json::Value> = match self.db.get_cf(&cf, b"old_verify_keys")? {
            Some(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            None => Vec::new(),
        };
        list.push(serde_json::json!({
            "key_id": key_id,
            "public_key": public_key_b64,
            "expired_ts": expired_ts_ms,
        }));
        self.db
            .put_cf(&cf, b"old_verify_keys", serde_json::to_vec(&list)?)?;
        Ok(())
    }

    /// Load all rotated-out signing keys. Returned as
    /// `Vec<(key_id, public_key_b64, expired_ts_ms)>` in insertion order.
    /// An absent or unparseable record is treated as "no rotated keys".
    pub fn load_rotated_signing_keys(
        &self,
    ) -> Result<Vec<(String, String, u64)>, Box<dyn std::error::Error + Send + Sync>> {
        let cf = self.db.cf_handle("server_keys").unwrap();
        let Some(bytes) = self.db.get_cf(&cf, b"old_verify_keys")? else {
            return Ok(Vec::new());
        };
        let raw: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap_or_default();
        let mut out = Vec::with_capacity(raw.len());
        for entry in raw {
            let key_id = entry
                .get("key_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let public_key = entry
                .get("public_key")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let expired_ts = entry
                .get("expired_ts")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if key_id.is_empty() || public_key.is_empty() {
                continue;
            }
            out.push((key_id, public_key, expired_ts));
        }
        Ok(out)
    }

    // --- Remote server keys (federation key cache) ---

    /// Store remote server keys by server_name.
    /// Value is opaque JSON (the caller defines the schema).
    pub fn store_remote_server_keys(
        &self,
        server_name: &str,
        json_bytes: &[u8],
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("server_keys").unwrap();
        let key = format!("remote:{server_name}");
        self.db.put_cf(&cf, key.as_bytes(), json_bytes)
    }

    /// Load remote server keys JSON bytes by server_name.
    pub fn load_remote_server_keys(
        &self,
        server_name: &str,
    ) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        let cf = self.db.cf_handle("server_keys").unwrap();
        let key = format!("remote:{server_name}");
        self.db.get_cf(&cf, key.as_bytes())
    }

    // --- Soft-fail markers ---

    /// Mark an event as soft-failed. Soft-failed events remain in the events CF
    /// and participate in state resolution, but MUST NOT be added to
    /// room_extremities and MUST NOT be sent to clients via /sync.
    pub fn mark_soft_failed(&self, event_nid: u64) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("soft_failed_events").unwrap();
        self.db.put_cf(&cf, event_nid.to_be_bytes(), [0x01u8])
    }

    pub fn is_soft_failed(&self, event_nid: u64) -> Result<bool, rocksdb::Error> {
        let cf = self.db.cf_handle("soft_failed_events").unwrap();
        Ok(self.db.get_cf(&cf, event_nid.to_be_bytes())?.is_some())
    }

    // --- Rejected event tracking ---

    /// Persist an event_id as "rejected" so future events whose
    /// auth_events reference it cascade-reject (Synapse issue 9595,
    /// MSC TestInboundFederationRejectsEventsWithRejectedAuthEvents).
    /// Stores `reason` as the value for debugging; the key alone
    /// would suffice for the rejection check itself.
    pub fn mark_event_rejected(&self, event_id: &str, reason: &str) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("rejected_events").unwrap();
        self.db.put_cf(&cf, event_id.as_bytes(), reason.as_bytes())
    }

    /// True iff `mark_event_rejected` was called for this event_id.
    pub fn is_event_rejected(&self, event_id: &str) -> Result<bool, rocksdb::Error> {
        let cf = self.db.cf_handle("rejected_events").unwrap();
        Ok(self.db.get_cf(&cf, event_id.as_bytes())?.is_some())
    }

    /// Record the transaction id used to mint `event_nid`, scoped to
    /// the originating `(user_nid, device_id)`. Read back via
    /// `get_event_txn_id_for_user` to attach `unsigned.transaction_id`
    /// on the local-echo path.
    pub fn set_event_txn_id(
        &self,
        event_nid: u64,
        user_nid: u64,
        device_id: &str,
        txn_id: &str,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("event_txn_ids").unwrap();
        let mut value = Vec::with_capacity(8 + device_id.len() + 1 + txn_id.len());
        value.extend_from_slice(&keys::encode_u64(user_nid));
        value.extend_from_slice(device_id.as_bytes());
        value.push(0xff);
        value.extend_from_slice(txn_id.as_bytes());
        self.db.put_cf(&cf, keys::encode_u64(event_nid), value)
    }

    /// Look up the txn_id for `event_nid` if it was sent by
    /// `(user_nid, device_id)`. Returns `None` when the event has no
    /// recorded txn (e.g. it came in over federation, or via
    /// /createRoom which doesn't carry one) or when the requester
    /// isn't the original sender — local-echo MUST NOT leak txn ids
    /// across users.
    pub fn get_event_txn_id_for_user(
        &self,
        event_nid: u64,
        user_nid: u64,
        device_id: &str,
    ) -> Result<Option<String>, rocksdb::Error> {
        let cf = self.db.cf_handle("event_txn_ids").unwrap();
        let Some(value) = self.db.get_cf(&cf, keys::encode_u64(event_nid))? else {
            return Ok(None);
        };
        if value.len() < 8 {
            return Ok(None);
        }
        let stored_user_nid = keys::decode_u64(&value[..8]);
        if stored_user_nid != user_nid {
            return Ok(None);
        }
        let rest = &value[8..];
        let Some(sep) = rest.iter().position(|b| *b == 0xff) else {
            return Ok(None);
        };
        let stored_device = &rest[..sep];
        if stored_device != device_id.as_bytes() {
            return Ok(None);
        }
        let txn = &rest[sep + 1..];
        Ok(Some(String::from_utf8_lossy(txn).into_owned()))
    }

    // --- OpenID tokens ---

    /// Persist an OpenID access token. Value layout: 8 BE bytes of
    /// `expires_at_ms` followed by the UTF-8 user_id. Lookups use
    /// `lookup_openid_token` which checks the timestamp and returns
    /// the user_id when still valid.
    pub fn store_openid_token(
        &self,
        token: &str,
        user_id: &str,
        expires_at_ms: u64,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("openid_tokens").unwrap();
        let mut value = Vec::with_capacity(8 + user_id.len());
        value.extend_from_slice(&expires_at_ms.to_be_bytes());
        value.extend_from_slice(user_id.as_bytes());
        self.db.put_cf(&cf, token.as_bytes(), value)
    }

    /// Look up an OpenID token. Returns `Some(user_id)` when the
    /// token exists and `now_ms` is before its expiry, `None`
    /// otherwise. Expired or unknown tokens look the same to the
    /// caller — federation peers should get a 401 either way.
    pub fn lookup_openid_token(
        &self,
        token: &str,
        now_ms: u64,
    ) -> Result<Option<String>, rocksdb::Error> {
        let cf = self.db.cf_handle("openid_tokens").unwrap();
        let Some(value) = self.db.get_cf(&cf, token.as_bytes())? else {
            return Ok(None);
        };
        if value.len() < 8 {
            return Ok(None);
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&value[..8]);
        let expires_at_ms = u64::from_be_bytes(buf);
        if expires_at_ms <= now_ms {
            // Best-effort cleanup; ignore the error so a parallel
            // delete doesn't surface to the caller.
            let _ = self.db.delete_cf(&cf, token.as_bytes());
            return Ok(None);
        }
        Ok(Some(String::from_utf8_lossy(&value[8..]).into_owned()))
    }

    // --- Federation EDU cursors ---
    //
    // Per-(destination, stream_name) cursor tracking how far this server
    // has fanned out a given EDU stream to a given peer. Each EDU type
    // (receipts, presence, typing) has its own logical stream and its
    // own cursor namespace, so they advance independently.

    /// Read the cursor for `(destination, stream_name)`. Returns 0 if no
    /// cursor has been stored yet — fresh peers start at the beginning of
    /// the stream we maintain for them.
    pub fn get_edu_cursor(
        &self,
        destination: &str,
        stream_name: &str,
    ) -> Result<u64, rocksdb::Error> {
        let cf = self.db.cf_handle("federation_edu_cursor").unwrap();
        let key = edu_cursor_key(destination, stream_name);
        match self.db.get_cf(&cf, &key)? {
            Some(bytes) if bytes.len() == 8 => Ok(keys::decode_u64(&bytes)),
            _ => Ok(0),
        }
    }

    /// Persist a new cursor value. Called only after the corresponding
    /// outbound transaction succeeds — partial writes between cursor
    /// advance and txn ack are safe to re-send (EDUs are idempotent).
    pub fn set_edu_cursor(
        &self,
        destination: &str,
        stream_name: &str,
        cursor: u64,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("federation_edu_cursor").unwrap();
        let key = edu_cursor_key(destination, stream_name);
        self.db.put_cf(&cf, &key, keys::encode_u64(cursor))
    }

    /// Lookup the local user_nid mapped to `(provider, sub)`, or
    /// `None` if no mapping exists yet. The MSC3861 introspection
    /// flow calls this on every authenticated request to skip the
    /// slow first-touch provisioning path.
    pub fn get_external_id_mapping(
        &self,
        provider: &str,
        sub: &str,
    ) -> Result<Option<u64>, rocksdb::Error> {
        let cf = self.db.cf_handle("external_ids").unwrap();
        let key = external_id_key(provider, sub);
        match self.db.get_cf(&cf, &key)? {
            Some(bytes) if bytes.len() == 8 => Ok(Some(keys::decode_u64(&bytes))),
            _ => Ok(None),
        }
    }

    /// Persist the `(provider, sub) -> user_nid` mapping. Idempotent;
    /// callers don't need to check existence first. Writing the same
    /// pair twice is fine — it's the same value.
    pub fn put_external_id_mapping(
        &self,
        provider: &str,
        sub: &str,
        user_nid: u64,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("external_ids").unwrap();
        let key = external_id_key(provider, sub);
        self.db.put_cf(&cf, &key, keys::encode_u64(user_nid))
    }

    /// Remove a `(provider, sub)` mapping. Used when the operator
    /// detaches an external identity from a vela account. Idempotent.
    pub fn delete_external_id_mapping(
        &self,
        provider: &str,
        sub: &str,
    ) -> Result<(), rocksdb::Error> {
        let cf = self.db.cf_handle("external_ids").unwrap();
        let key = external_id_key(provider, sub);
        self.db.delete_cf(&cf, &key)
    }
}

/// Compose the `external_ids` key as `[provider_len_be:2][provider][sub]`.
/// The length prefix keeps `(p1="foo", s="barbaz")` and `(p1="foobar",
/// s="baz")` from colliding when written into the same CF.
fn external_id_key(provider: &str, sub: &str) -> Vec<u8> {
    let plen = provider.len() as u16;
    let mut k = Vec::with_capacity(2 + provider.len() + sub.len());
    k.extend_from_slice(&plen.to_be_bytes());
    k.extend_from_slice(provider.as_bytes());
    k.extend_from_slice(sub.as_bytes());
    k
}

#[derive(Debug, Clone)]
pub struct EventHeader {
    pub type_nid: u64,
    pub sender_nid: u64,
    pub state_key_nid: u64,
    pub origin_server_ts: u64,
    pub depth: u64,
}

// --- Helpers ---

fn configure_cf(opts: &mut Options, name: &str) {
    match name {
        "event_ids" | "memberships" | "tokens" | "nid_map" => {
            opts.set_bloom_locality(10);
            opts.optimize_for_point_lookup(64 * 1024 * 1024);
        }
        "room_timeline" | "room_state" | "user_rooms" => {
            opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(8));
        }
        _ => {}
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

/// Recover max NID from nid_reverse CF (keys are u64 BE, so last key = max).
/// Recover the next NID by scanning every CF whose keys carry a NID
/// allocated from the shared `nid_counter`. Two distinct sources share
/// this counter:
///
///   - `get_or_create_nid()` for **strings** (user_id, room_id, event
///     type, state_key) — writes the new NID into `nid_reverse` and
///     `nid_map`.
///   - `next_nid()` for **events** — writes the NID into `events`
///     (and `event_state`, `event_depth`, `event_id_reverse`, ...).
///
/// The original implementation scanned only `nid_reverse`, missing
/// every event NID. After restart the counter then reset to
/// `max_string_nid + 1`, **far below** `max_event_nid`, and the next
/// `next_nid()` allocations silently collided with already-persisted
/// events — the new event's `put_cf(events, encode_u64(nid), …)`
/// overwrote the old event in place. From that point onwards any
/// reference holding the original event_nid (notably `room_state`'s
/// `(room, type, state_key) → event_nid` mapping) resolved to a
/// completely unrelated event. For a state event reference this
/// surfaced as "sender is not joined": auth_check loaded the
/// overwritten event, found `state_key.is_none()`, skipped inserting
/// it into the state view, and the rule engine concluded the user had
/// no membership.
///
/// Fix: take the max across `nid_reverse` AND `events`. Both keys are
/// big-endian u64, so `IteratorMode::End` is the lex-largest key.
/// One-time repair for `room_state` entries that point at events
/// whose actual (type, state_key) doesn't match the key.
///
/// Background: the `recover_max_nid` bug (now fixed) let `next_nid()`
/// allocate event NIDs that collided with already-persisted events.
/// New writes overwrote the old event row in place. Any reference
/// still holding the original NID — most importantly
/// `room_state`'s `(room, type, state_key) → event_nid` map —
/// dereferenced to a different event from that point on. For state
/// references the user-visible symptom was 403 "sender is not joined"
/// because the rule engine loaded the overwritten event, found no
/// matching state_key in its header, and excluded it from the state
/// view.
///
/// This pass walks `room_state` once, verifies each entry's event
/// has the expected (type, state_key) in its persisted header, and
/// for each mismatch scans the room's timeline for the latest event
/// that does match. If found, the room_state entry is rewritten to
/// point at the replacement.
///
/// Idempotent: a clean DB does no writes; a previously-repaired DB
/// finds no orphans on the next startup.
fn repair_room_state_orphans(db: &DB) -> Result<(), rocksdb::Error> {
    let cf_state = db.cf_handle("room_state").unwrap();
    let cf_events = db.cf_handle("events").unwrap();
    let cf_timeline = db.cf_handle("room_timeline").unwrap();

    let mut scanned: u64 = 0;
    let mut orphans: u64 = 0;
    let mut repaired: u64 = 0;
    let mut unrepairable: u64 = 0;
    let mut repairs: Vec<(Vec<u8>, u64)> = Vec::new();

    for entry in db.iterator_cf(&cf_state, IteratorMode::Start) {
        let (key, val) = entry?;
        // room_state key shape: (room_nid_be:8, type_nid_be:8, state_key_nid_be:8)
        if key.len() != 24 || val.len() != 8 {
            continue;
        }
        scanned += 1;

        let room_nid = keys::decode_u64(&key[0..8]);
        let expected_type_nid = keys::decode_u64(&key[8..16]);
        let expected_skey_nid = keys::decode_u64(&key[16..24]);
        let event_nid = keys::decode_u64(&val);

        let event_bytes = match db.get_cf(&cf_events, keys::encode_u64(event_nid))? {
            Some(b) if b.len() > 40 => b,
            _ => {
                // Event row missing or truncated. Unrepairable from
                // here — leave the entry alone.
                orphans += 1;
                unrepairable += 1;
                continue;
            }
        };

        // events CF row header layout: type_nid:8, sender_nid:8,
        // state_key_nid:8, ts:8, depth:8, then JSON.
        let actual_type_nid = keys::decode_u64(&event_bytes[0..8]);
        let actual_skey_nid = keys::decode_u64(&event_bytes[16..24]);

        if actual_type_nid == expected_type_nid && actual_skey_nid == expected_skey_nid {
            continue;
        }

        orphans += 1;

        // Walk room_timeline for this room and find the event NID
        // with the highest stream_pos whose header matches the
        // expected (type, state_key). Forward iteration; the later
        // entry (higher stream_pos) wins.
        let room_prefix = keys::encode_u64(room_nid);
        let mut best: Option<u64> = None;
        for tl_entry in db.prefix_iterator_cf(&cf_timeline, room_prefix) {
            let (tl_key, tl_val) = match tl_entry {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            if tl_key.len() < 16 || tl_key[..8] != room_prefix[..] || tl_val.len() != 8 {
                break;
            }
            let candidate_nid = keys::decode_u64(&tl_val);
            let candidate_bytes = match db.get_cf(&cf_events, keys::encode_u64(candidate_nid))? {
                Some(b) if b.len() > 40 => b,
                _ => continue,
            };
            let c_type_nid = keys::decode_u64(&candidate_bytes[0..8]);
            let c_skey_nid = keys::decode_u64(&candidate_bytes[16..24]);
            if c_type_nid == expected_type_nid && c_skey_nid == expected_skey_nid {
                best = Some(candidate_nid);
            }
        }

        if let Some(replacement) = best {
            repairs.push((key.to_vec(), replacement));
            repaired += 1;
        } else {
            unrepairable += 1;
        }
    }

    if !repairs.is_empty() {
        let mut batch = WriteBatch::default();
        for (k, replacement_nid) in &repairs {
            batch.put_cf(&cf_state, k, keys::encode_u64(*replacement_nid));
        }
        db.write(batch)?;
    }

    if orphans > 0 {
        tracing::warn!(
            scanned,
            orphans,
            repaired,
            unrepairable,
            "room_state orphan repair completed — legacy damage from the \
             recover_max_nid bug fixed in this release"
        );
    } else {
        tracing::debug!(scanned, "room_state orphan scan: clean");
    }

    Ok(())
}

/// Recover max stream position from room_timeline CF.
/// Recover the next stream position from RocksDB's own monotonic
/// sequence number. RocksDB advances `latest_sequence_number()` once
/// per put within a committed batch and persists it through the WAL,
/// so for any logical position `p` ever written, RocksDB's sequence
/// at the time of (and after) the write is `>= p`. Initialising the
/// in-memory counter to `seq + 1` therefore guarantees every fresh
/// allocation is strictly greater than every previously persisted
/// position — without persisting our own counter alongside writes
/// (the alternative pattern) or scanning every position-using CF on
/// startup (which we used to do, and forgot to update when adding
/// new CFs).
///
/// Position values "skip" across restarts because RocksDB's seq
/// advances on every write op including compactions and internal
/// bookkeeping. Positions are opaque u64 sync tokens; gaps don't
/// affect correctness or client behaviour.
fn recover_max_stream(db: &DB) -> u64 {
    db.latest_sequence_number().saturating_add(1)
}

/// A freshly allocated stream position. Constructed only by
/// `Database::next_stream_position`; the newtype documents that
/// the value originated from the global allocator and was not
/// fabricated by a caller.
///
/// Convert to `u64` via `as_u64()` only at the byte-encoding
/// boundary (e.g. when packing into a RocksDB key/value).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamPosition(u64);

impl StreamPosition {
    /// Borrow the underlying u64. Use only at the byte-encoding
    /// boundary; comparing or doing arithmetic on raw u64s defeats
    /// the type's documentation purpose.
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Big-endian byte encoding for use as a RocksDB key suffix.
    pub fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for StreamPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<StreamPosition> for u64 {
    fn from(p: StreamPosition) -> u64 {
        p.0
    }
}

/// Recover max position from receipts_stream CF (keys are u64 BE).
fn recover_max_receipts_stream(db: &DB) -> Option<u64> {
    let cf = db.cf_handle("receipts_stream")?;
    let mut iter = db.iterator_cf(&cf, IteratorMode::End);
    iter.next()
        .and_then(|r| r.ok())
        .map(|(key, _)| keys::decode_u64(&key) + 1)
}

/// Recover max position from presence_stream CF.
fn recover_max_presence_stream(db: &DB) -> Option<u64> {
    let cf = db.cf_handle("presence_stream")?;
    let mut iter = db.iterator_cf(&cf, IteratorMode::End);
    iter.next()
        .and_then(|r| r.ok())
        .map(|(key, _)| keys::decode_u64(&key) + 1)
}

/// Recover max position from `to_device_outbound`. Keys are
/// `<destination> 0xff <stream_pos_be>`. Lex-largest *key* is not
/// the lex-largest *position* — a destination "z" with pos=10 sorts
/// after "a" with pos=999, so `IteratorMode::End` would return 11
/// and the next enqueue under "a" would land at pos=11 (already
/// delivered, sender skips it; new EDU lost). Scan every entry and
/// take the global max position.
fn recover_max_to_device_outbound(db: &DB) -> Option<u64> {
    let cf = db.cf_handle("to_device_outbound")?;
    let mut max_pos: Option<u64> = None;
    for entry in db.iterator_cf(&cf, IteratorMode::Start) {
        let (key, _) = match entry {
            Ok(kv) => kv,
            Err(_) => continue,
        };
        if key.len() < 8 {
            continue;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&key[key.len() - 8..]);
        let pos = u64::from_be_bytes(buf);
        max_pos = Some(max_pos.map_or(pos, |m| m.max(pos)));
    }
    max_pos.map(|m| m + 1)
}

/// Outbox key prefix for one destination. Includes the trailing 0xff
/// separator so prefix scans are unambiguous (a server `"a"` can't
/// match keys for `"ab"`).
fn outbox_prefix(destination: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(destination.len() + 1);
    p.extend_from_slice(destination.as_bytes());
    p.push(0xff);
    p
}

/// Full outbox key: `<destination> 0xff <stream_pos_be>`.
fn outbox_key(destination: &str, stream_pos: u64) -> Vec<u8> {
    let mut k = outbox_prefix(destination);
    k.extend_from_slice(&keys::encode_u64(stream_pos));
    k
}

/// Activity-index key: `<last_active_ms_be:8> <user_nid_be:8>`.
/// Big-endian on both halves so iterator order matches numeric order
/// — readers do a prefix-bounded walk to find all users whose
/// activity is older than a threshold.
fn presence_activity_key(last_active_ms: u64, user_nid: u64) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[0..8].copy_from_slice(&keys::encode_u64(last_active_ms));
    k[8..16].copy_from_slice(&keys::encode_u64(user_nid));
    k
}

/// Receipts CF key:
/// `<room_nid_be:8> <receipt_type> 0x00 <user_nid_be:8> 0x00 <thread_id?>`.
///
/// Trailing thread_id is empty for unthreaded receipts and `main` /
/// `<thread_root_event_id>` for threaded receipts (CS-API §receipts).
/// Empty thread_id is a separate key from any threaded receipt, so a
/// user can carry both an unthreaded receipt AND multiple per-thread
/// receipts simultaneously — which is what TestThreadedReceipts
/// exercises.
fn receipt_key(
    room_nid: u64,
    receipt_type: &str,
    user_nid: u64,
    thread_id: Option<&str>,
) -> Vec<u8> {
    let tid = thread_id.unwrap_or("");
    let mut k = Vec::with_capacity(8 + receipt_type.len() + 1 + 8 + 1 + tid.len());
    k.extend_from_slice(&keys::encode_u64(room_nid));
    k.extend_from_slice(receipt_type.as_bytes());
    k.push(0);
    k.extend_from_slice(&keys::encode_u64(user_nid));
    k.push(0);
    k.extend_from_slice(tid.as_bytes());
    k
}

/// `stream_positions` key for "max receipt stream pos in this room".
/// Prefix `r:` so future use-cases can occupy `f:` (fully_read), etc.
/// — single CF, scoped by prefix, no schema growth per gap.
fn receipts_room_pos_key(room_nid: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + 8);
    k.extend_from_slice(b"r:");
    k.extend_from_slice(&keys::encode_u64(room_nid));
    k
}

/// `stream_positions` key for "max room-account-data stream pos for
/// this (user, room)". Prefix `a:` to coexist with other purposes.
fn room_account_data_pos_key(user_nid: u64, room_nid: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + 16);
    k.extend_from_slice(b"a:");
    k.extend_from_slice(&keys::encode_u64(user_nid));
    k.extend_from_slice(&keys::encode_u64(room_nid));
    k
}

// --- Key backup: per-row keys for the `key_backup` CF -----------------------
//
// Three logical sub-stores share one CF, distinguished by a one-byte
// prefix:
//
//   b"v" + user_nid_be         → versions metadata JSON blob (small,
//                                 infrequently written; one per user)
//   b"s" + user_nid_be
//       + version_len_be:u16 + version_bytes
//       + room_len_be:u16 + room_id_bytes
//       + session_id_bytes      → session JSON blob (one per session)
//   b"c" + user_nid_be
//       + version_len_be:u16 + version_bytes
//                               → packed (count_u64_be, etag_u64_be)
//
// Length-prefixing version + room_id is required because session_ids
// contain `/` and other arbitrary bytes — without an explicit length
// prefix the keys would be ambiguous. With it, prefix scans for "all
// sessions in (user, version)" or "all sessions in (user, version,
// room)" work cleanly.

fn key_backup_versions_key(user_nid: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 8);
    k.push(b'v');
    k.extend_from_slice(&keys::encode_u64(user_nid));
    k
}

fn key_backup_session_key(
    user_nid: u64,
    version: &str,
    room_id: &str,
    session_id: &str,
) -> Vec<u8> {
    let vlen = version.len() as u16;
    let rlen = room_id.len() as u16;
    let mut k =
        Vec::with_capacity(1 + 8 + 2 + version.len() + 2 + room_id.len() + session_id.len());
    k.push(b's');
    k.extend_from_slice(&keys::encode_u64(user_nid));
    k.extend_from_slice(&vlen.to_be_bytes());
    k.extend_from_slice(version.as_bytes());
    k.extend_from_slice(&rlen.to_be_bytes());
    k.extend_from_slice(room_id.as_bytes());
    k.extend_from_slice(session_id.as_bytes());
    k
}

fn key_backup_room_prefix(user_nid: u64, version: &str, room_id: &str) -> Vec<u8> {
    let vlen = version.len() as u16;
    let rlen = room_id.len() as u16;
    let mut k = Vec::with_capacity(1 + 8 + 2 + version.len() + 2 + room_id.len());
    k.push(b's');
    k.extend_from_slice(&keys::encode_u64(user_nid));
    k.extend_from_slice(&vlen.to_be_bytes());
    k.extend_from_slice(version.as_bytes());
    k.extend_from_slice(&rlen.to_be_bytes());
    k.extend_from_slice(room_id.as_bytes());
    k
}

fn key_backup_version_prefix(user_nid: u64, version: &str) -> Vec<u8> {
    let vlen = version.len() as u16;
    let mut k = Vec::with_capacity(1 + 8 + 2 + version.len());
    k.push(b's');
    k.extend_from_slice(&keys::encode_u64(user_nid));
    k.extend_from_slice(&vlen.to_be_bytes());
    k.extend_from_slice(version.as_bytes());
    k
}

fn key_backup_stats_key(user_nid: u64, version: &str) -> Vec<u8> {
    let vlen = version.len() as u16;
    let mut k = Vec::with_capacity(1 + 8 + 2 + version.len());
    k.push(b'c');
    k.extend_from_slice(&keys::encode_u64(user_nid));
    k.extend_from_slice(&vlen.to_be_bytes());
    k.extend_from_slice(version.as_bytes());
    k
}

/// Parse the `(session_id, value)` pair from a `b"s"`-prefixed row
/// inside a (user, version, room) scope. Returns `None` when the key
/// doesn't match the expected prefix shape — defensive against stray
/// bytes in the CF.
fn key_backup_parse_session_row(
    expected_prefix: &[u8],
    key: &[u8],
    val: &[u8],
) -> Option<(String, Value)> {
    let session_bytes = key.strip_prefix(expected_prefix)?;
    let session_id = std::str::from_utf8(session_bytes).ok()?.to_string();
    let value: Value = serde_json::from_slice(val).ok()?;
    Some((session_id, value))
}

/// Parse the `(room_id, session_id, value)` triple from a `b"s"`-prefixed
/// row inside a (user, version) scope. Used when iterating ALL sessions
/// within a version (across rooms).
fn key_backup_parse_version_row(
    expected_prefix: &[u8],
    key: &[u8],
    val: &[u8],
) -> Option<(String, String, Value)> {
    let rest = key.strip_prefix(expected_prefix)?;
    if rest.len() < 2 {
        return None;
    }
    let room_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    if rest.len() < 2 + room_len {
        return None;
    }
    let room_id = std::str::from_utf8(&rest[2..2 + room_len])
        .ok()?
        .to_string();
    let session_bytes = &rest[2 + room_len..];
    let session_id = std::str::from_utf8(session_bytes).ok()?.to_string();
    let value: Value = serde_json::from_slice(val).ok()?;
    Some((room_id, session_id, value))
}

/// To-device outbound prefix: `<destination> 0xff`. Same trick as the
/// PDU outbox — `<dest>+0xff` ensures `"a"` doesn't collide with `"ab"`.
fn to_device_outbound_prefix(destination: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(destination.len() + 1);
    p.extend_from_slice(destination.as_bytes());
    p.push(0xff);
    p
}

fn to_device_outbound_key(destination: &str, stream_pos: u64) -> Vec<u8> {
    let mut k = to_device_outbound_prefix(destination);
    k.extend_from_slice(&keys::encode_u64(stream_pos));
    k
}

/// Transaction-cache key. Layout: `<user_nid:8> 0xff <device_id> 0xff
/// <scope> 0xff <txn_id>`. The two-byte separators keep variable-
/// length fields unambiguous so a `device_id` containing the
/// "scope/txn" delimiter can't collide with a different request.
fn transaction_key(user_nid: u64, device_id: &str, scope: &str, txn_id: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(8 + 1 + device_id.len() + 1 + scope.len() + 1 + txn_id.len());
    k.extend_from_slice(&keys::encode_u64(user_nid));
    k.push(0xff);
    k.extend_from_slice(device_id.as_bytes());
    k.push(0xff);
    k.extend_from_slice(scope.as_bytes());
    k.push(0xff);
    k.extend_from_slice(txn_id.as_bytes());
    k
}

/// EDU cursor key: `<destination> 0xff <stream_name>`. Same 0xff
/// separator trick as the outbox to keep prefixes unambiguous.
fn edu_cursor_key(destination: &str, stream_name: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(destination.len() + 1 + stream_name.len());
    k.extend_from_slice(destination.as_bytes());
    k.push(0xff);
    k.extend_from_slice(stream_name.as_bytes());
    k
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod stream_recovery_tests {
    use super::*;

    /// Read the stream position recorded by `set_account_data` for a
    /// (user, data_type) — the value cell in the `account_data_pos` CF.
    /// Used by tests to assert against real persisted positions
    /// without exposing a public API.
    fn read_persisted_account_data_pos(db: &Database, user_nid: u64, data_type: &str) -> u64 {
        let cf = db.db.cf_handle("account_data_pos").unwrap();
        let key = keys::encode_u64_bytes(user_nid, data_type.as_bytes());
        let bytes = db.db.get_cf(&cf, &key).unwrap().unwrap();
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes);
        u64::from_be_bytes(buf)
    }

    /// After a write-then-restart cycle, the recovered counter must
    /// be strictly greater than the position that write persisted.
    /// This is the property whose violation caused the /sync hot-loop
    /// the multi-CF-scan recovery used to mishandle.
    #[test]
    fn counter_after_reopen_exceeds_all_persisted_positions() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let user_id = "@alice:example.com";

        // First open: do a real write that allocates and persists a
        // stream position. set_account_data is a representative
        // position-using path.
        let persisted_pos = {
            let db = Database::open(path).unwrap();
            let user_nid = db.get_or_create_nid(user_id).unwrap();
            db.set_account_data(user_nid, "m.test", &serde_json::json!({"k": "v"}))
                .unwrap();
            read_persisted_account_data_pos(&db, user_nid, "m.test")
        };

        // Second open: recovery must put the counter strictly above
        // the position written before the close.
        let db = Database::open(path).unwrap();
        assert!(
            db.current_stream_position() >= persisted_pos,
            "current_stream_position ({}) < persisted ({persisted_pos})",
            db.current_stream_position()
        );
        let next = db.next_stream_position().as_u64();
        assert!(
            next > persisted_pos,
            "next allocation ({next}) must be > persisted ({persisted_pos})"
        );
    }

    /// Stream positions allocated by real-world write paths
    /// (set_account_data, set_membership) across two restarts are
    /// strictly monotonic — never reused, never decreasing.
    #[test]
    fn real_writes_produce_monotonic_positions_across_restarts() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let user_id = "@alice:example.com";
        let room_id = "!room:example.com";

        let mut positions = Vec::new();
        for round in 0..3 {
            let db = Database::open(path).unwrap();
            let user_nid = db.get_or_create_nid(user_id).unwrap();
            let room_nid = db.get_or_create_nid(room_id).unwrap();

            // Two real writes per round, each allocating and
            // persisting a position. Different data_type / room each
            // round so we don't overwrite the previous row's pos.
            let dtype = format!("m.test.{round}");
            db.set_account_data(user_nid, &dtype, &serde_json::json!({"r": round}))
                .unwrap();
            positions.push(read_persisted_account_data_pos(&db, user_nid, &dtype));

            db.set_membership(room_nid, user_nid, 1).unwrap();
            let cf = db.db.cf_handle("user_membership_pos").unwrap();
            let key = keys::encode_u64_pair(user_nid, room_nid);
            let bytes = db.db.get_cf(&cf, key).unwrap().unwrap();
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes);
            positions.push(u64::from_be_bytes(buf));
        }

        for window in positions.windows(2) {
            assert!(
                window[0] < window[1],
                "non-monotonic across restarts: {positions:?}"
            );
        }
    }

    /// A fresh DB allocates monotonically.
    #[test]
    fn fresh_db_allocations_are_monotonic() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(tmp.path()).unwrap();
        let p1 = db.next_stream_position().as_u64();
        let p2 = db.next_stream_position().as_u64();
        let p3 = db.next_stream_position().as_u64();
        assert!(p1 < p2 && p2 < p3, "monotonic: {p1} < {p2} < {p3}");
    }

    /// Counter recovery for `to_device_outbound` must take the max
    /// across all destinations, not just the lex-last key. With
    /// destination "z" holding a small pos and "a" holding a large
    /// pos, a wrong recovery would resume at the small pos+1 and
    /// new enqueues under "a" would silently overwrite-or-skip
    /// already-delivered slots.
    #[test]
    fn to_device_outbound_recovers_global_max_across_destinations() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();

        let high_pos_under_a = {
            let db = Database::open(path).unwrap();
            // 5 enqueues for "a" (gets pos 1..=5), then 1 for "z" (pos 6).
            // Without the fix, recovery picks "z" + pos 6 -> counter=7.
            // With the fix, max is 6 -> counter=7. Same here, so we
            // arrange the opposite: enqueue under "z" first so its pos
            // is small, then under "a" so its pos is large. lex-end
            // returns "z"'s key (small pos), broken recovery jumps
            // counter back to that.
            for _ in 0..1 {
                db.enqueue_to_device_outbound("z.example.com", &serde_json::json!({"first": true}))
                    .unwrap();
            }
            let mut last_a = 0;
            for i in 0..5 {
                last_a = db
                    .enqueue_to_device_outbound("a.example.com", &serde_json::json!({"i": i}))
                    .unwrap();
            }
            last_a
        };

        // Reopen — counter must be strictly above the highest
        // persisted pos under any destination.
        let db = Database::open(path).unwrap();
        let next = db
            .enqueue_to_device_outbound("a.example.com", &serde_json::json!({"new": true}))
            .unwrap();
        assert!(
            next > high_pos_under_a,
            "next pos ({next}) must exceed highest persisted ({high_pos_under_a})"
        );
    }

    /// Mark/lookup roundtrip on `rejected_events`. The cascade
    /// rejection in process_pdu reads is_event_rejected on every
    /// auth_event of an inbound PDU; this verifies the underlying
    /// store contract before that wiring depends on it.
    #[test]
    fn rejected_events_marker_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(tmp.path()).unwrap();

        let event_id = "$rejected:example.com";
        assert!(
            !db.is_event_rejected(event_id).unwrap(),
            "fresh DB has no rejection marker"
        );

        db.mark_event_rejected(event_id, "auth_events check failed")
            .unwrap();
        assert!(
            db.is_event_rejected(event_id).unwrap(),
            "marked event_id is detected"
        );
        // Adjacent event_ids stay unmarked — the lookup must be exact.
        assert!(
            !db.is_event_rejected("$other:example.com").unwrap(),
            "non-marked event_id stays clean"
        );
    }

    /// Rotating a signing key atomically replaces the active key and
    /// records the outgoing one under old_verify_keys with the
    /// supplied expiry. Reopening must see the new active key and the
    /// full historical list.
    #[test]
    fn rotate_signing_key_records_outgoing_and_replaces_active() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let db = Database::open(path).unwrap();

        db.store_signing_key("ed25519:v1", &[1u8; 32]).unwrap();
        db.rotate_signing_key(
            "ed25519:v1",
            "PUBV1",
            1_700_000_000_000,
            "ed25519:v2",
            &[2u8; 32],
        )
        .unwrap();
        db.rotate_signing_key(
            "ed25519:v2",
            "PUBV2",
            1_750_000_000_000,
            "ed25519:v3",
            &[3u8; 32],
        )
        .unwrap();

        let (active_id, active_secret) = db.load_signing_key().unwrap().unwrap();
        assert_eq!(active_id, "ed25519:v3");
        assert_eq!(active_secret, [3u8; 32]);

        let history = db.load_rotated_signing_keys().unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(
            history[0],
            (
                "ed25519:v1".to_string(),
                "PUBV1".to_string(),
                1_700_000_000_000u64
            )
        );
        assert_eq!(
            history[1],
            (
                "ed25519:v2".to_string(),
                "PUBV2".to_string(),
                1_750_000_000_000u64
            )
        );
    }

    /// `set_receipt` MUST bump the room's max-receipt stream position
    /// in the generic `stream_positions` CF. Without this, /sync can't
    /// tell whether anything new happened in the room and emits the
    /// full receipt snapshot on every poll — the 0.5s storm we saw on
    /// the first real deployment.
    #[test]
    fn set_receipt_bumps_room_max_pos() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(tmp.path()).unwrap();

        let room_nid = 42;
        let user_nid = 7;

        // Fresh: no receipt has ever been written here.
        assert_eq!(db.get_room_receipts_max_pos(room_nid).unwrap(), None);

        db.set_receipt(room_nid, "m.read", user_nid, "$e1", 1_000, None)
            .unwrap();
        let pos1 = db.get_room_receipts_max_pos(room_nid).unwrap();
        assert!(pos1.is_some(), "first write must populate the position");

        // Second write strictly advances the position so the
        // `since >= max_pos` check on /sync sees the change.
        db.set_receipt(room_nid, "m.read", user_nid, "$e2", 2_000, None)
            .unwrap();
        let pos2 = db.get_room_receipts_max_pos(room_nid).unwrap();
        assert!(
            pos2.unwrap() > pos1.unwrap(),
            "second write must advance: pos1={pos1:?} pos2={pos2:?}"
        );

        // Other rooms stay at their original (None) — the bump is
        // scoped per-room, not global.
        assert_eq!(db.get_room_receipts_max_pos(999).unwrap(), None);
    }

    /// `set_local_receipt` (the locally-originated write path) must
    /// also bump the room max-pos, otherwise outbound receipts wouldn't
    /// wake other devices' long-polls and Element on the sender's
    /// other devices would not see the read marker update.
    #[test]
    fn set_local_receipt_bumps_room_max_pos() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(tmp.path()).unwrap();

        let room_nid = 99;
        assert_eq!(db.get_room_receipts_max_pos(room_nid).unwrap(), None);

        let _ = db
            .set_local_receipt(room_nid, "m.read", 7, "$e1", 1_000, None)
            .unwrap();
        let pos = db.get_room_receipts_max_pos(room_nid).unwrap();
        assert!(pos.is_some(), "set_local_receipt must populate room pos");
    }

    /// `set_room_account_data` MUST bump the per-(user, room) max-pos
    /// in `stream_positions`. Without this, m.fully_read / room-tag
    /// snapshots leak into every incremental /sync.
    #[test]
    fn set_room_account_data_bumps_per_user_room_max_pos() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(tmp.path()).unwrap();

        let user_nid = 7;
        let room_nid = 42;

        assert_eq!(
            db.get_room_account_data_max_pos(user_nid, room_nid)
                .unwrap(),
            None
        );

        db.set_room_account_data(
            user_nid,
            room_nid,
            "m.fully_read",
            &serde_json::json!({"event_id": "$e1"}),
        )
        .unwrap();
        let pos1 = db
            .get_room_account_data_max_pos(user_nid, room_nid)
            .unwrap();
        assert!(pos1.is_some());

        db.set_room_account_data(
            user_nid,
            room_nid,
            "m.fully_read",
            &serde_json::json!({"event_id": "$e2"}),
        )
        .unwrap();
        let pos2 = db
            .get_room_account_data_max_pos(user_nid, room_nid)
            .unwrap();
        assert!(pos2.unwrap() > pos1.unwrap(), "second write must advance");

        // Scope: another (user, room) is untouched.
        assert_eq!(
            db.get_room_account_data_max_pos(7, 9999).unwrap(),
            None,
            "different room — not affected"
        );
        assert_eq!(
            db.get_room_account_data_max_pos(9999, room_nid).unwrap(),
            None,
            "different user — not affected"
        );
    }

    /// Auto-repair: a `room_state` entry pointing at an overwritten
    /// event (one whose actual header type / state_key no longer
    /// matches the room_state key) is detected on startup and
    /// repaired to point at the latest valid matching event from
    /// the room's timeline.
    #[test]
    fn repair_room_state_orphans_replaces_corrupted_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();

        let (room_nid, member_type_nid, alice_skey_nid, replacement_event_nid) = {
            let db = Database::open(path).unwrap();
            let _ = db.get_or_create_nid("@alice:example.com").unwrap();
            let room_nid = db.get_or_create_nid("!room:example.com").unwrap();
            let member_type_nid = db.get_or_create_nid("m.room.member").unwrap();
            let msg_type_nid = db.get_or_create_nid("m.room.message").unwrap();
            let alice_nid = db.get_nid("@alice:example.com").unwrap().unwrap();

            // Persist Alice's first join member event. Goes into events
            // CF + room_state CF + room_timeline CF.
            let join_nid_1 = db.next_nid().unwrap();
            let join_json_1 = serde_json::json!({
                "type": "m.room.member",
                "sender": "@alice:example.com",
                "state_key": "@alice:example.com",
                "content": {"membership": "join"},
            });
            db.persist_event(
                join_nid_1,
                "$j1:example.com",
                room_nid,
                member_type_nid,
                alice_nid,
                alice_nid,
                1000,
                1,
                serde_json::to_vec(&join_json_1).unwrap().as_slice(),
                &[],
                &[],
                true,
                false,
            )
            .unwrap();

            // Persist a SECOND join member event (e.g. a profile update —
            // same (type, state_key), newer event). This is the "valid
            // replacement" the repair should find.
            let join_nid_2 = db.next_nid().unwrap();
            let join_json_2 = serde_json::json!({
                "type": "m.room.member",
                "sender": "@alice:example.com",
                "state_key": "@alice:example.com",
                "content": {"membership": "join", "displayname": "Alice"},
            });
            db.persist_event(
                join_nid_2,
                "$j2:example.com",
                room_nid,
                member_type_nid,
                alice_nid,
                alice_nid,
                2000,
                2,
                serde_json::to_vec(&join_json_2).unwrap().as_slice(),
                &[],
                &[],
                true,
                false,
            )
            .unwrap();
            // join_nid_2 is now the room_state entry for Alice.

            // Simulate the recover_max_nid corruption: overwrite the
            // events row at join_nid_2 with a totally unrelated event
            // (a message with no state_key), as if a post-restart
            // next_nid() collision had landed there. This is the exact
            // damage pattern: room_state still points to join_nid_2,
            // but events[join_nid_2] now decodes as something else.
            let cf_events = db.db.cf_handle("events").unwrap();
            let mut bad_value = Vec::new();
            bad_value.extend_from_slice(&keys::encode_u64(msg_type_nid)); // type
            bad_value.extend_from_slice(&keys::encode_u64(alice_nid)); // sender
            bad_value.extend_from_slice(&keys::encode_u64(0)); // state_key_nid = 0
            bad_value.extend_from_slice(&keys::encode_u64(3000)); // ts
            bad_value.extend_from_slice(&keys::encode_u64(3)); // depth
            bad_value.extend_from_slice(b"{\"corrupted\": true}");
            db.db
                .put_cf(&cf_events, keys::encode_u64(join_nid_2), &bad_value)
                .unwrap();

            // Confirm room_state is now broken: dereferences to a
            // type-mismatched event.
            assert_eq!(
                db.get_state_event_nid(room_nid, member_type_nid, alice_nid)
                    .unwrap(),
                Some(join_nid_2)
            );

            // `join_nid_1` is the only valid m.room.member event left
            // in the timeline. Repair must find it.
            (room_nid, member_type_nid, alice_nid, join_nid_1)
        };

        // Reopen triggers the auto-repair pass. room_state should now
        // point at join_nid_1 (the valid, unoverwritten member event).
        let db = Database::open(path).unwrap();
        let after = db
            .get_state_event_nid(room_nid, member_type_nid, alice_skey_nid)
            .unwrap();
        assert_eq!(
            after,
            Some(replacement_event_nid),
            "auto-repair must replace the corrupted room_state entry"
        );
    }

    /// Regression: `next_nid()` after a restart must be strictly
    /// greater than every NID ever stored in the `events` CF.
    ///
    /// The `nid_counter` is shared between two allocation paths —
    /// `get_or_create_nid()` for string NIDs (user_id, room_id, etc.)
    /// and `next_nid()` for event NIDs. Recovery used to scan only
    /// `nid_reverse`, missing every event NID. After restart the
    /// counter then reset below `max_event_nid` and the next allocation
    /// silently collided with an existing event row in `events`, the
    /// `put_cf(events, encode_u64(nid), …)` overwriting the old event
    /// in place. The flow-on damage: every reference holding the old
    /// `event_nid` (notably the `room_state` (room, type, state_key)
    /// → event_nid map) now resolves to a different event. For state
    /// references this manifests as 403 "sender is not joined" in
    /// `vela-api::send::send_message`, because the auth-rule engine
    /// loads the overwritten event, finds no `state_key`, and
    /// excludes it from the state view.
    #[test]
    fn next_nid_after_reopen_exceeds_max_event_nid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();

        // First open: allocate several event NIDs and persist a row
        // under each in the `events` CF. Use the persist helper rather
        // than touching the CF directly so the test exercises the
        // actual write path.
        let last_event_nid = {
            let db = Database::open(path).unwrap();
            // Burn a few string NIDs first so the `nid_reverse` max
            // sits below the event-NID max — the configuration the
            // bug actually appeared under.
            for s in ["@alice:example.com", "!room:example.com", "m.room.message"] {
                let _ = db.get_or_create_nid(s).unwrap();
            }
            let room_nid = db.get_or_create_nid("!room:example.com").unwrap();
            let type_nid = db.get_or_create_nid("m.room.message").unwrap();
            let sender_nid = db.get_or_create_nid("@alice:example.com").unwrap();

            let mut last = 0u64;
            for i in 0..10 {
                let event_nid = db.next_nid().unwrap();
                last = event_nid;
                let event_id = format!("$ev{i}:example.com");
                let json = serde_json::json!({
                    "type": "m.room.message",
                    "sender": "@alice:example.com",
                    "content": {"body": format!("msg {i}")},
                });
                db.persist_event(
                    event_nid,
                    &event_id,
                    room_nid,
                    type_nid,
                    sender_nid,
                    0,
                    1000 + i,
                    i + 1,
                    serde_json::to_vec(&json).unwrap().as_slice(),
                    &[],
                    &[],
                    false,
                    false,
                )
                .unwrap();
            }
            last
        };

        // Second open: every fresh allocation must be strictly above
        // every previously-persisted event NID. Before the fix the
        // counter resumed below `last_event_nid` and the next 10
        // allocations would collide with existing event rows.
        let db = Database::open(path).unwrap();
        let n1 = db.next_nid().unwrap();
        let n2 = db.next_nid().unwrap();
        let n3 = db.next_nid().unwrap();
        for n in [n1, n2, n3] {
            assert!(
                n > last_event_nid,
                "next_nid()={n} must be > max_event_nid={last_event_nid} after restart",
            );
        }
    }

    /// `presence_activity_due(cutoff)` returns exactly the users whose
    /// stored `last_active_ms < cutoff`. The activity index is
    /// maintained atomically with every `set_local_presence` /
    /// `touch_presence` / `set_presence` write, so newer entries
    /// supersede older ones — no stale index rows linger.
    #[test]
    fn presence_activity_due_walks_only_past_threshold() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(tmp.path()).unwrap();
        let alice = db.get_or_create_nid("@alice:example.com").unwrap();
        let bob = db.get_or_create_nid("@bob:example.com").unwrap();
        let carol = db.get_or_create_nid("@carol:example.com").unwrap();

        // Alice: very old activity. Bob: recent. Carol: in between.
        let now = 100_000_000u64;
        db.set_local_presence(
            alice,
            &serde_json::json!({"presence": "online", "last_active_ms": now - 1_000_000}),
        )
        .unwrap();
        db.set_local_presence(
            bob,
            &serde_json::json!({"presence": "online", "last_active_ms": now - 1_000}),
        )
        .unwrap();
        db.set_local_presence(
            carol,
            &serde_json::json!({"presence": "online", "last_active_ms": now - 100_000}),
        )
        .unwrap();

        // Cutoff between bob's and carol's activity ts.
        let due = db.presence_activity_due(now - 10_000).unwrap();
        // Both alice and carol are older than the cutoff. Order is
        // by ascending last_active_ms (alice first, then carol).
        assert_eq!(due, vec![alice, carol]);
    }

    /// Re-writing the record updates the index: the OLD activity-ms
    /// entry must be cleared so a stale row doesn't make a now-
    /// recently-active user appear in `due()` queries.
    #[test]
    fn presence_activity_index_clears_stale_entries_on_rewrite() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(tmp.path()).unwrap();
        let alice = db.get_or_create_nid("@alice:example.com").unwrap();
        let now = 100_000_000u64;

        // Stale: alice was last active long ago.
        db.set_local_presence(
            alice,
            &serde_json::json!({"presence": "online", "last_active_ms": now - 1_000_000}),
        )
        .unwrap();
        assert_eq!(db.presence_activity_due(now - 10_000).unwrap(), vec![alice]);

        // Now active again: re-write with a fresh timestamp. The old
        // stale index entry must be deleted in the same batch, else
        // `due()` would still report her.
        db.touch_presence(alice, now - 100).unwrap();
        assert_eq!(
            db.presence_activity_due(now - 10_000).unwrap(),
            Vec::<u64>::new(),
            "stale activity-index entry must clear on touch_presence",
        );
    }

    /// Existing v0.1.1 DBs have `user_presence` records but no
    /// `presence_activity_index` entries. The open-time migration
    /// populates the index so the sweeper's walk works on upgrade.
    #[test]
    fn open_time_migration_populates_activity_index() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let alice;
        let now = 100_000_000u64;
        {
            let db = Database::open(path).unwrap();
            alice = db.get_or_create_nid("@alice:example.com").unwrap();
            // Bypass set_local_presence (which would also write the
            // index) to simulate a v0.1.1 record: write the raw
            // user_presence CF directly without touching the index.
            let cf = db.db.cf_handle("user_presence").unwrap();
            let rec = serde_json::json!({
                "presence": "online",
                "last_active_ms": now - 1_000_000
            });
            db.db
                .put_cf(&cf, keys::encode_u64(alice), rec.to_string().as_bytes())
                .unwrap();
            // Confirm the index is empty before close.
            assert_eq!(
                db.presence_activity_due(now).unwrap(),
                Vec::<u64>::new(),
                "no index entries written yet"
            );
        }

        // Re-open: open-time migration scans user_presence and
        // populates the index.
        let db = Database::open(path).unwrap();
        assert_eq!(
            db.presence_activity_due(now).unwrap(),
            vec![alice],
            "open-time migration must populate index for legacy records",
        );
    }

    /// After reopen, next_nid must exceed every previously-allocated
    /// NID — that's the whole point of persisting the high water mark.
    #[test]
    fn hilo_event_nid_persists_across_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();

        let last = {
            let db = Database::open(path).unwrap();
            let mut last = 0u64;
            for _ in 0..5 {
                last = db.next_nid().unwrap();
            }
            last
        };

        let db = Database::open(path).unwrap();
        let after = db.next_nid().unwrap();
        assert!(after > last, "next_nid {after} must exceed last={last}");
    }

    /// First boot seeds the counter at `u64::MAX/2`, above any NID an
    /// older binary might have allocated below that threshold.
    #[test]
    fn hilo_event_nid_first_boot_starts_at_high_water_mark() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(tmp.path()).unwrap();
        assert_eq!(db.next_nid().unwrap(), u64::MAX / 2);
        assert_eq!(db.next_nid().unwrap(), u64::MAX / 2 + 1);
    }

    /// Event NIDs and string NIDs come from independent counters — the
    /// same numeric value can appear in both namespaces because their
    /// CFs don't share key space.
    #[test]
    fn hilo_event_and_string_namespaces_are_independent() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(tmp.path()).unwrap();
        let event_first = db.next_nid().unwrap();
        let string_first = db.get_or_create_nid("@alice:example.com").unwrap();
        assert_eq!(event_first, u64::MAX / 2);
        assert_eq!(string_first, u64::MAX / 2);
    }

    /// `fetch_add` hands out a unique value per call regardless of how
    /// many threads cross a block boundary at the same time — only the
    /// disk write is serialised by the claim lock.
    #[test]
    fn hilo_concurrent_allocations_are_unique() {
        use std::collections::HashSet;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let num_threads = 8;
        let allocs_per_thread = 500;

        let mut handles = Vec::new();
        for _ in 0..num_threads {
            let db = db.clone();
            handles.push(std::thread::spawn(move || {
                let mut local = Vec::with_capacity(allocs_per_thread);
                for _ in 0..allocs_per_thread {
                    local.push(db.next_nid().unwrap());
                }
                local
            }));
        }

        let mut all: HashSet<u64> = HashSet::new();
        let mut total = 0usize;
        for h in handles {
            for nid in h.join().unwrap() {
                total += 1;
                assert!(all.insert(nid), "duplicate NID across threads: {nid}");
            }
        }
        assert_eq!(total, num_threads * allocs_per_thread);
        assert_eq!(all.len(), total);
    }

    /// Allocations spanning multiple block claims persist their high
    /// water mark forward — reopen sees the latest claimed range, not
    /// just the first.
    #[test]
    fn hilo_event_nid_block_claim_persists_new_high_water() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let last = {
            let db = Database::open(path).unwrap();
            let mut last = 0u64;
            for _ in 0..2500 {
                last = db.next_nid().unwrap();
            }
            last
        };
        let db = Database::open(path).unwrap();
        let after = db.next_nid().unwrap();
        assert!(after > last);
    }

    /// Upgrade shape: a 0.1.1-or-older DB has event rows under low
    /// (u64) NIDs because the pre-HiLo counter started at 1. On first
    /// boot of a HiLo binary the seed must land above those rows so
    /// the new allocator never collides with the legacy keyspace —
    /// that's the whole reason for seeding at `u64::MAX/2` instead of
    /// scanning the events CF on every open.
    #[test]
    fn hilo_first_boot_seeds_above_existing_low_nids() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();

        // Stage 1: open the DB and write three rows to `events` under
        // raw low NIDs (100, 200, 300) without going through the HiLo
        // allocator. Mimics the on-disk shape an older binary left
        // behind. Then *delete* the hilo meta key so the next open
        // looks like a true first boot of the new binary against legacy
        // data — Database::open seeds the counter on the first
        // PersistedCounter::open call only when no key is present.
        {
            let db = Database::open(path).unwrap();
            let cf_events = db.db.cf_handle("events").unwrap();
            for nid in [100u64, 200, 300] {
                db.db
                    .put_cf(&cf_events, keys::encode_u64(nid), b"legacy-row")
                    .unwrap();
            }
            let cf_meta = db.db.cf_handle("meta").unwrap();
            db.db
                .delete_cf(&cf_meta, b_meta::EVENT_NID.as_bytes())
                .unwrap();
        }

        // Stage 2: reopen — first boot for the HiLo counter. The seed
        // must be above the legacy rows so next_nid() can't overwrite
        // them.
        let db = Database::open(path).unwrap();
        let first = db.next_nid().unwrap();
        assert!(
            first > 300,
            "first HiLo allocation ({first}) must exceed legacy max NID (300)"
        );
        assert_eq!(
            first,
            u64::MAX / 2,
            "first HiLo allocation must equal the documented seed"
        );

        // And the legacy rows must still be intact — no in-place write
        // could possibly have hit them.
        let cf_events = db.db.cf_handle("events").unwrap();
        for nid in [100u64, 200, 300] {
            assert_eq!(
                db.db.get_cf(&cf_events, keys::encode_u64(nid)).unwrap(),
                Some(b"legacy-row".to_vec())
            );
        }
    }
}

#[cfg(test)]
mod external_id_tests {
    use super::*;

    fn fresh_db() -> (Database, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(tmp.path()).unwrap();
        (db, tmp)
    }

    #[test]
    fn put_then_get_roundtrip() {
        let (db, _tmp) = fresh_db();
        db.put_external_id_mapping("oauth-delegated", "user-abc", 42)
            .unwrap();
        assert_eq!(
            db.get_external_id_mapping("oauth-delegated", "user-abc")
                .unwrap(),
            Some(42)
        );
    }

    #[test]
    fn get_missing_returns_none() {
        let (db, _tmp) = fresh_db();
        assert!(
            db.get_external_id_mapping("oauth-delegated", "never-seen")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn delete_idempotent() {
        let (db, _tmp) = fresh_db();
        db.put_external_id_mapping("oauth-delegated", "user-abc", 42)
            .unwrap();
        db.delete_external_id_mapping("oauth-delegated", "user-abc")
            .unwrap();
        // Second delete on already-absent key is fine.
        db.delete_external_id_mapping("oauth-delegated", "user-abc")
            .unwrap();
        assert!(
            db.get_external_id_mapping("oauth-delegated", "user-abc")
                .unwrap()
                .is_none()
        );
    }

    /// The length-prefixed key encoding must keep two providers from
    /// colliding when their `(provider, sub)` concatenations would
    /// otherwise produce the same byte string. Without the prefix,
    /// (`"a", "bc"`) and (`"ab", "c"`) collide; with it they don't.
    #[test]
    fn length_prefix_prevents_provider_collisions() {
        let (db, _tmp) = fresh_db();
        db.put_external_id_mapping("a", "bc", 1).unwrap();
        db.put_external_id_mapping("ab", "c", 2).unwrap();
        assert_eq!(db.get_external_id_mapping("a", "bc").unwrap(), Some(1));
        assert_eq!(db.get_external_id_mapping("ab", "c").unwrap(), Some(2));
    }

    /// Two providers can claim the same `sub` for different users.
    /// Realistic when an operator migrates from one IdP to another
    /// and keeps both attached briefly.
    #[test]
    fn distinct_providers_isolate_subs() {
        let (db, _tmp) = fresh_db();
        db.put_external_id_mapping("idp-old", "shared-sub", 1)
            .unwrap();
        db.put_external_id_mapping("idp-new", "shared-sub", 2)
            .unwrap();
        assert_eq!(
            db.get_external_id_mapping("idp-old", "shared-sub").unwrap(),
            Some(1)
        );
        assert_eq!(
            db.get_external_id_mapping("idp-new", "shared-sub").unwrap(),
            Some(2)
        );
    }
}

#[cfg(test)]
mod partial_state_tests {
    use super::*;

    fn fresh_db() -> (Database, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(tmp.path()).unwrap();
        (db, tmp)
    }

    #[test]
    fn defaults_to_full_state() {
        let (db, _tmp) = fresh_db();
        let nid = db.get_or_create_nid("!r:x").unwrap();
        db.create_room_meta(nid, "!r:x", "12").unwrap();
        let (partial, servers) = db.get_partial_state_info(nid).unwrap();
        assert!(!partial);
        assert!(servers.is_empty());
    }

    #[test]
    fn set_and_clear_roundtrip() {
        let (db, _tmp) = fresh_db();
        let nid = db.get_or_create_nid("!r:x").unwrap();
        db.create_room_meta(nid, "!r:x", "12").unwrap();
        db.set_partial_state_join(nid, &["a.example".into(), "b.example".into()])
            .unwrap();
        let (partial, servers) = db.get_partial_state_info(nid).unwrap();
        assert!(partial);
        assert_eq!(servers, vec!["a.example".to_string(), "b.example".into()]);
        db.clear_partial_state(nid).unwrap();
        let (partial, servers) = db.get_partial_state_info(nid).unwrap();
        assert!(!partial);
        assert!(servers.is_empty());
        // room_id + version must survive the clear.
        assert_eq!(db.get_room_version(nid).unwrap().as_deref(), Some("12"));
    }

    #[test]
    fn set_before_create_meta_still_works() {
        let (db, _tmp) = fresh_db();
        let nid = db.get_or_create_nid("!r:x").unwrap();
        // Caller (outbound join) may set partial state before
        // create_room_meta in the bootstrap sequence. The function
        // merges into whatever meta record already exists; absent →
        // creates a minimal one.
        db.set_partial_state_join(nid, &["x.example".into()])
            .unwrap();
        let (partial, servers) = db.get_partial_state_info(nid).unwrap();
        assert!(partial);
        assert_eq!(servers, vec!["x.example".to_string()]);
    }

    #[test]
    fn list_partial_state_rooms_only_returns_partial() {
        let (db, _tmp) = fresh_db();
        let r1 = db.get_or_create_nid("!r1:x").unwrap();
        let r2 = db.get_or_create_nid("!r2:x").unwrap();
        db.create_room_meta(r1, "!r1:x", "12").unwrap();
        db.create_room_meta(r2, "!r2:x", "12").unwrap();
        db.set_partial_state_join(r1, &["a.example".into()])
            .unwrap();
        let listed = db.list_partial_state_rooms().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, r1);
        assert_eq!(listed[0].1, "!r1:x");
        assert_eq!(listed[0].2, vec!["a.example".to_string()]);
    }

    #[test]
    fn clear_partial_state_is_idempotent() {
        let (db, _tmp) = fresh_db();
        let nid = db.get_or_create_nid("!r:x").unwrap();
        db.create_room_meta(nid, "!r:x", "12").unwrap();
        db.clear_partial_state(nid).unwrap();
        db.clear_partial_state(nid).unwrap();
    }
}
