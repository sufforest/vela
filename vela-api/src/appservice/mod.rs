//! Matrix Application Service support.
//!
//! Spec: `references/matrix-spec/content/application-service-api.md`.
//!
//! An Application Service is an external HTTP service the operator
//! has registered with vela. The AS reserves a namespace of user IDs,
//! room IDs, and aliases; vela delivers every event matching that
//! namespace to the AS's URL (`PUT /transactions/{txnId}`); the AS
//! can act back as users in its namespace via the standard CS API
//! plus `Authorization: Bearer <as_token>` + `?user_id=…`
//! masquerading.

pub mod admin;
pub mod auth;
pub mod client;
pub mod interest;
pub mod namespace;
pub mod outbox;
pub mod registration;
pub mod registry;

use serde::{Deserialize, Serialize};

pub use namespace::{Namespace, NamespaceMatcher, NamespaceScope};
pub use registration::{ParsedRegistration, RegistrationError};
pub use registry::{AsRegistry, LiveAppService, RegistryError};

/// One registered Application Service. Persisted in the `appservices`
/// CF; the in-memory `AsRegistry` holds these alongside their
/// compiled namespace matchers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppService {
    /// Internal compact id. Stable across renames of `id`.
    pub nid: u64,
    /// Operator-chosen string id from the registration YAML.
    pub id: String,
    /// Configuration extracted from the registration YAML.
    pub config: AppServiceConfig,
    /// Namespaces this AS claims.
    pub namespaces: Vec<Namespace>,
    /// `false` halts delivery without removing the registration.
    pub enabled: bool,
    /// User who registered the AS, if known. `None` for system-
    /// registered (boot import or operator-as-bot dispatch).
    pub owner_nid: Option<u64>,
    /// Wall-clock registration time.
    pub created_at_ms: u64,
}

/// Persisted configuration. Tokens are SHA-256 hashed before
/// storage — cleartext is shown to the operator only at
/// registration time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppServiceConfig {
    pub url: String,
    pub hs_token_hash: String,
    pub as_token_hash: String,
    pub sender_localpart: String,
    /// MSC2409 ephemeral passthrough. Stored for forward compat;
    /// delivery side honours it once that PR lands.
    #[serde(default)]
    pub receive_ephemeral: bool,
}

impl AppService {
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("AppService serialisable")
    }

    pub fn from_value(value: &serde_json::Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value.clone())
    }
}

/// One pending outbound transaction, persisted in `appservice_outbox`.
/// The delivery worker loads event JSON from `events` CF on demand
/// — keeps the outbox row cheap regardless of event size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// AS-visible idempotency key. Same value on retry.
    pub txn_id: String,
    /// Event nids batched into this transaction.
    pub event_nids: Vec<u64>,
    /// `room_id` per event, same length as `event_nids`. Embedded in
    /// the AS transaction body alongside each event.
    pub room_ids: Vec<String>,
}

/// SHA-256 hash of a cleartext token, lowercase hex. Used for both
/// `as_token` and `hs_token` so we never persist cleartext.
pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    let out = h.finalize();
    let mut hex = String::with_capacity(out.len() * 2);
    for b in out {
        use std::fmt::Write;
        write!(&mut hex, "{:02x}", b).unwrap();
    }
    hex
}
