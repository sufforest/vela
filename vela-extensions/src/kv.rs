//! The `kv` capability seam — a small per-plugin key→value store.
//!
//! Same injection pattern as [`crate::emit`]: vela-extensions defines the
//! `KvStore` interface; vela-api implements it over RocksDB (resolving the
//! plugin's namespace, enforcing TTL + the byte quota) and injects it into the
//! [`Runtime`](crate::Runtime). Always-compiled (public API, injected regardless
//! of the `wasmtime-runtime` feature); only the wasmtime binding that *calls* it
//! is feature-gated.

/// Why a kv operation failed. Mirrors the WIT `kv-error` variant.
#[derive(Debug, Clone)]
pub enum KvError {
    /// Not granted, or the key/value exceeded a per-op size cap.
    NotPermitted(String),
    /// This plugin is over its byte budget — it should free space.
    QuotaExceeded,
    /// Internal store failure (logged host-side).
    Internal,
}

/// Host service backing the `kv` capability. Implemented by vela-api, injected
/// into the `Runtime`. `plugin` is the calling plugin's configured name — the
/// implementation namespaces every key under it (hard per-plugin isolation).
/// `ttl_ms` on `set` is a *relative* time-to-live (`None` = no expiry); the
/// implementation converts it to an absolute deadline against its own clock.
pub trait KvStore: Send + Sync {
    fn get(&self, plugin: &str, key: &[u8]) -> Result<Option<Vec<u8>>, KvError>;
    fn set(
        &self,
        plugin: &str,
        key: &[u8],
        value: &[u8],
        ttl_ms: Option<u64>,
    ) -> Result<(), KvError>;
    fn delete(&self, plugin: &str, key: &[u8]) -> Result<(), KvError>;
}
