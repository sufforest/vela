//! TTL-bounded memo of introspection outcomes. One in-memory map
//! `token -> (outcome, expires_at)`. Lookups are O(1); a background
//! sweep isn't needed because every `get` re-checks the entry's
//! freshness and drops it lazily.
//!
//! Rationale for caching at all: an authenticated /sync long-poll
//! that emits 20 PDUs in a tight burst would otherwise hit the IdP's
//! introspection endpoint 20 times in seconds. Synapse chose 2 min;
//! we match because the staleness trade-off (token revoked but still
//! served, capped at TTL) is identical.
//!
//! Bounded staleness is the right model here: an IdP-side revoke
//! propagates within at most TTL seconds, no invalidation protocol
//! between vela and IdP needed. Operators with stricter requirements
//! can shorten the TTL in config (future PR).

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::auth::oidc::introspection::IntrospectionOutcome;

/// Shared, clonable cache. Internally a single Arc'd DashMap keyed
/// by cleartext token (we don't store the token anywhere else, and
/// the map lives only in-memory — restart clears it).
#[derive(Clone)]
pub struct IntrospectionCache {
    inner: Arc<DashMap<String, Entry>>,
    ttl: Duration,
}

struct Entry {
    outcome: IntrospectionOutcome,
    expires_at: Instant,
}

impl IntrospectionCache {
    /// Build a cache with the given hard TTL. Inactive outcomes are
    /// cached for the same window; the assumption is that an IdP
    /// won't un-revoke a token, so reactivating bookkeeping is
    /// unnecessary.
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            ttl,
        }
    }

    /// Cached outcome if still fresh; otherwise `None`. Drops the
    /// stale entry as a side effect to keep the map from growing
    /// without bound during long-running processes.
    pub fn get(&self, token: &str) -> Option<IntrospectionOutcome> {
        if let Some(entry) = self.inner.get(token) {
            if Instant::now() < entry.expires_at {
                return Some(entry.outcome.clone());
            }
            drop(entry);
            self.inner.remove(token);
        }
        None
    }

    /// Insert with the configured TTL. Honours an optional IdP-side
    /// `expires_at` (unix seconds): if the IdP says the token dies
    /// sooner than our TTL, expire the entry sooner. We never extend
    /// past our TTL even if the IdP claims a longer lifetime — that
    /// would let a stolen-then-revoked token live longer than
    /// operator policy.
    pub fn put(&self, token: String, outcome: IntrospectionOutcome) {
        let token_expiry = match &outcome {
            IntrospectionOutcome::Active(r) => r.expires_at,
            IntrospectionOutcome::Inactive => None,
        };
        let ttl_expires = Instant::now() + self.ttl;
        let expires_at = match token_expiry {
            Some(unix_s) => {
                let now_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let remaining = unix_s.saturating_sub(now_unix);
                let idp_capped = Instant::now() + Duration::from_secs(remaining);
                std::cmp::min(idp_capped, ttl_expires)
            }
            None => ttl_expires,
        };
        self.inner.insert(
            token,
            Entry {
                outcome,
                expires_at,
            },
        );
    }

    /// Drop one cached entry — used when the operator explicitly
    /// revokes a token via admin tooling.
    pub fn invalidate(&self, token: &str) {
        self.inner.remove(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::oidc::introspection::IntrospectionResult;

    fn sample_active() -> IntrospectionOutcome {
        IntrospectionOutcome::Active(IntrospectionResult {
            sub: "sub-1".into(),
            username: Some("alice".into()),
            scope: vec!["urn:matrix:client:api:*".into()],
            device_id: Some("DEV1".into()),
            expires_at: None,
        })
    }

    #[test]
    fn miss_then_hit() {
        let cache = IntrospectionCache::new(Duration::from_secs(60));
        assert!(cache.get("tok").is_none());
        cache.put("tok".into(), sample_active());
        assert!(matches!(
            cache.get("tok"),
            Some(IntrospectionOutcome::Active(_))
        ));
    }

    #[test]
    fn expires_after_ttl() {
        let cache = IntrospectionCache::new(Duration::from_millis(50));
        cache.put("tok".into(), sample_active());
        std::thread::sleep(Duration::from_millis(80));
        assert!(cache.get("tok").is_none());
    }

    #[test]
    fn inactive_is_cached() {
        let cache = IntrospectionCache::new(Duration::from_secs(60));
        cache.put("tok".into(), IntrospectionOutcome::Inactive);
        assert!(matches!(
            cache.get("tok"),
            Some(IntrospectionOutcome::Inactive)
        ));
    }

    #[test]
    fn invalidate_drops_entry() {
        let cache = IntrospectionCache::new(Duration::from_secs(60));
        cache.put("tok".into(), sample_active());
        cache.invalidate("tok");
        assert!(cache.get("tok").is_none());
    }

    /// IdP-declared expiry shorter than our TTL caps the cache
    /// lifetime — we never serve a token past the IdP's claimed
    /// lifetime even if our TTL is longer.
    #[test]
    fn idp_exp_caps_cache_lifetime() {
        let cache = IntrospectionCache::new(Duration::from_secs(3600));
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut r = match sample_active() {
            IntrospectionOutcome::Active(r) => r,
            _ => unreachable!(),
        };
        // IdP says token expires in 50ms.
        r.expires_at = Some(now_unix);
        cache.put("tok".into(), IntrospectionOutcome::Active(r));
        // Should already be considered expired.
        std::thread::sleep(Duration::from_millis(60));
        assert!(
            cache.get("tok").is_none(),
            "IdP expiry must override our longer TTL"
        );
    }
}
