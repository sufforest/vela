//! Password hashing and verification — the only place argon2 runs.
//!
//! Every caller (register, login, UIA re-auth, password change, admin
//! resets) goes through [`hash`] / [`verify`] so three properties hold
//! everywhere at once:
//!
//! - argon2 (memory-hard, ~19 MiB + tens of ms per run) executes on the
//!   blocking pool, never on a tokio worker;
//! - concurrent runs are capped at the core count. Bare `spawn_blocking`
//!   would let a login flood grow the blocking pool to its 512-thread
//!   default — at 19 MiB per verification that's ~10 GiB of hashing
//!   memory. Capped, excess requests queue instead;
//! - a verification against a missing/empty/unparseable stored hash
//!   (unknown user, AS-minted passwordless account, deactivated account)
//!   still burns exactly one argon2 run against a process-local dummy
//!   hash, so response timing can't distinguish "no such user" from
//!   "wrong password".

use std::sync::OnceLock;

use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use tokio::sync::Semaphore;
use vela_core::error::VelaError;

/// Upper bound on accepted password length, in bytes (Synapse parity).
/// argon2's initial BLAKE2b pass is linear in the input, and no
/// legitimate password needs more.
pub const MAX_PASSWORD_LEN: usize = 512;

/// The error [`hash`] returns above [`MAX_PASSWORD_LEN`]. Exposed so
/// callers that pre-check the length (e.g. register, which validates
/// before running its registration gate) reject with the same error.
pub(crate) fn too_long() -> VelaError {
    VelaError::InvalidParam(format!("password too long (max {MAX_PASSWORD_LEN} bytes)"))
}

/// Global cap on in-flight argon2 computations across all endpoints.
fn permits() -> &'static Semaphore {
    static PERMITS: OnceLock<Semaphore> = OnceLock::new();
    PERMITS.get_or_init(|| {
        let n = std::thread::available_parallelism().map_or(4, |n| n.get());
        Semaphore::new(n)
    })
}

async fn run_argon2<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, VelaError> {
    let permit = permits()
        .acquire()
        .await
        .expect("password semaphore is never closed");
    // The permit moves INTO the blocking task: if the caller's future is
    // dropped (client abort) the argon2 run it started still counts
    // against the cap until it finishes — otherwise open-and-abort
    // floods would bypass the bound this module exists to enforce.
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
    .map_err(|e| VelaError::Unknown(format!("password task: {e}")))
}

/// PHC hash of 32 random bytes, computed once per process, never
/// matchable (the input is unguessable and not retained). Verifying a
/// candidate against it costs the same as a real verification.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_sync_bytes(&rand::random::<[u8; 32]>()))
}

fn hash_sync_bytes(password: &[u8]) -> String {
    let salt: [u8; 16] = rand::random();
    let salt_str = SaltString::encode_b64(&salt).unwrap();
    Argon2::default()
        .hash_password(password, &salt_str)
        .unwrap()
        .to_string()
}

/// Synchronous hash for test setup; production paths use [`hash`].
pub(crate) fn hash_sync(password: &str) -> String {
    hash_sync_bytes(password.as_bytes())
}

fn verify_sync(password: &str, stored: &str) -> bool {
    let parsed = match PasswordHash::new(stored) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Hash a new password. Errors with `M_INVALID_PARAM` above
/// [`MAX_PASSWORD_LEN`].
pub async fn hash(password: &str) -> Result<String, VelaError> {
    if password.len() > MAX_PASSWORD_LEN {
        return Err(too_long());
    }
    let password = password.to_string();
    run_argon2(move || hash_sync(&password)).await
}

/// Check `password` against an account's stored hash.
///
/// Pass `None` (or an empty/unparseable hash) for accounts that can't do
/// password login — the check still runs one argon2 verification against
/// a process-local dummy hash and fails, keeping the timing uniform. Oversized input
/// fails fast: its length is attacker-chosen, so the timing difference
/// reveals nothing about the account.
pub async fn verify(password: &str, stored: Option<&str>) -> bool {
    if password.len() > MAX_PASSWORD_LEN {
        return false;
    }
    let password = password.to_string();
    let stored = stored.map(|s| s.to_string());
    run_argon2(
        move || match stored.as_deref().and_then(|s| PasswordHash::new(s).ok()) {
            Some(parsed) => Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok(),
            None => {
                // A non-empty hash that fails to parse is store corruption,
                // not a passwordless account — surface it in the log (the
                // response stays the uniform generic reject).
                if stored.as_deref().is_some_and(|s| !s.is_empty()) {
                    tracing::warn!("stored password hash failed to parse; refusing login");
                }
                let _ = verify_sync(&password, dummy_hash());
                false
            }
        },
    )
    .await
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let h = hash("s3cret").await.unwrap();
        assert!(h.starts_with("$argon2"));
        assert!(verify("s3cret", Some(&h)).await);
        assert!(!verify("wrong", Some(&h)).await);
    }

    #[tokio::test]
    async fn missing_empty_and_garbage_hashes_all_fail() {
        assert!(!verify("anything", None).await);
        assert!(!verify("anything", Some("")).await);
        assert!(!verify("anything", Some("not-a-phc-string")).await);
        // Even the empty password against an empty hash is a reject.
        assert!(!verify("", Some("")).await);
    }

    #[tokio::test]
    async fn oversized_password_rejected_both_ways() {
        let long = "x".repeat(MAX_PASSWORD_LEN + 1);
        assert!(matches!(hash(&long).await, Err(VelaError::InvalidParam(_))));
        let h = hash("pw").await.unwrap();
        assert!(!verify(&long, Some(&h)).await);
        // At the boundary both directions still work.
        let max = "x".repeat(MAX_PASSWORD_LEN);
        let hm = hash(&max).await.unwrap();
        assert!(verify(&max, Some(&hm)).await);
    }

    #[tokio::test]
    async fn hashes_are_salted() {
        let a = hash("same").await.unwrap();
        let b = hash("same").await.unwrap();
        assert_ne!(a, b);
    }

    /// The concurrency cap must queue, not fail: more concurrent
    /// verifications than permits all complete.
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_verifies_all_complete() {
        let h = std::sync::Arc::new(hash("pw").await.unwrap());
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let h = h.clone();
                tokio::spawn(async move { verify("pw", Some(&h)).await })
            })
            .collect();
        for t in tasks {
            assert!(t.await.unwrap());
        }
    }
}
