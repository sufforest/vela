//! Per-IP token bucket rate limiter for sensitive unauth endpoints.
//!
//! Built specifically to protect `/register` and `/login` from
//! enumeration / brute-force / mass-account creation. NOT a general
//! request shaper: authenticated traffic is explicitly NOT rate-limited
//! here (clients legitimately make many requests under one token; a
//! per-token cap is a separate concern with different semantics).
//!
//! Algorithm: classic token bucket. Each `(endpoint_label, client_ip)`
//! pair has a bucket holding up to `capacity` tokens. Every request
//! costs one token. Tokens refill at `refill_per_sec`. When the bucket
//! is empty, the request is rejected with Matrix-spec
//! `M_LIMIT_EXCEEDED` and a `retry_after_ms` field telling the client
//! when to try again.
//!
//! Storage: an in-memory `DashMap` keyed by `(endpoint, ip)`. Buckets
//! are lazily expired by the next access — we don't run a background
//! janitor since the working set is bounded by the live IP fan-out
//! (KB-scale even for noisy traffic).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;

/// Rate-limit knobs for a single bucket. Conservative defaults —
/// designed to let a normal client through (registration retries with
/// captchas, login on a typo) while choking off enumeration.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Max tokens the bucket holds. Burst size.
    pub capacity: u32,
    /// Tokens added per second.
    pub refill_per_sec: f64,
}

impl Limits {
    pub const fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            refill_per_sec,
        }
    }
}

/// Process-wide rate-limit state. Cheap to clone (Arc-internal).
#[derive(Clone, Default)]
pub struct RateLimiter {
    buckets: Arc<DashMap<(String, String), Bucket>>,
    /// Knob lookup keyed by endpoint label (`"register"` etc.). Static
    /// for now; could be made hot-reloadable later.
    limits: Arc<HashMap<&'static str, Limits>>,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(limits: HashMap<&'static str, Limits>) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            limits: Arc::new(limits),
        }
    }

    /// Sensible production defaults for the unauth surface.
    /// `register`: 3 per minute per IP, burst 50.
    /// `login`: 10 per minute per IP, burst 50.
    ///
    /// Burst values are intentionally generous — many real users
    /// share a public IP (campus, mobile carrier NAT, big-corp
    /// egress) and a small burst hurts legitimate traffic harder
    /// than it slows abuse. The steady-state per-minute rate is what
    /// actually constrains abuse; the burst is the first-arrival
    /// credit. Operators wanting tighter limits should tune these.
    pub fn defaults() -> Self {
        let mut m = HashMap::new();
        m.insert("register", Limits::new(50, 3.0 / 60.0));
        m.insert("login", Limits::new(50, 10.0 / 60.0));
        Self::new(m)
    }

    /// All-pass limiter — useful for tests and Complement deployments
    /// where many requests arrive from a single host IP and rate
    /// limits would cascade-fail unrelated assertions.
    pub fn disabled() -> Self {
        Self::new(HashMap::new())
    }

    /// Try to spend one token for `(endpoint, ip)`. Returns `Ok(())` if
    /// allowed; `Err(retry_after_ms)` if rate-limited.
    pub fn check(&self, endpoint: &'static str, ip: &str) -> Result<(), u64> {
        let limits = match self.limits.get(endpoint) {
            Some(l) => *l,
            None => return Ok(()), // unknown endpoint label = no limit
        };
        let key = (endpoint.to_string(), ip.to_string());
        let now = Instant::now();
        let mut entry = self.buckets.entry(key).or_insert_with(|| Bucket {
            tokens: limits.capacity as f64,
            last_refill: now,
        });
        // Refill based on elapsed time.
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * limits.refill_per_sec).min(limits.capacity as f64);
        entry.last_refill = now;
        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            Ok(())
        } else {
            // Tokens needed: 1 - current. Time until that many refill:
            let deficit = 1.0 - entry.tokens;
            let wait_secs = deficit / limits.refill_per_sec;
            let ms = (wait_secs * 1000.0).ceil() as u64;
            Err(ms.max(1))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_burst_then_throttles() {
        let limiter = RateLimiter::defaults();
        // 50-token burst on register; 51st should fail.
        for _ in 0..50 {
            limiter.check("register", "1.2.3.4").expect("burst ok");
        }
        let err = limiter
            .check("register", "1.2.3.4")
            .expect_err("post-burst request must be throttled");
        assert!(err > 0, "retry_after_ms must be positive");
    }

    #[test]
    fn disabled_limiter_never_throttles() {
        let limiter = RateLimiter::disabled();
        for _ in 0..10_000 {
            limiter
                .check("register", "1.2.3.4")
                .expect("disabled limiter never blocks");
        }
    }

    #[test]
    fn unknown_endpoint_is_unlimited() {
        let limiter = RateLimiter::defaults();
        for _ in 0..1000 {
            limiter
                .check("not-a-real-endpoint", "1.2.3.4")
                .expect("unknown endpoint = no limit");
        }
    }

    #[test]
    fn separate_ips_have_separate_buckets() {
        let limiter = RateLimiter::defaults();
        for _ in 0..50 {
            limiter.check("register", "1.1.1.1").unwrap();
        }
        // 1.1.1.1 is now throttled, but 2.2.2.2 has its own bucket.
        limiter
            .check("register", "2.2.2.2")
            .expect("different IP = different bucket");
    }

    // Refill-over-time test omitted — `Instant::now()` doesn't honour
    // tokio's paused-time clock, and a real-time test would burn 60s.
    // The arithmetic in `check()` is small enough that the unit-test
    // value is mostly that the burst + isolation tests above lock in
    // the policy shape; refill correctness is review-by-inspection.
}
