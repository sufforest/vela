//! MSC3861 Phase 2: delegated authentication against an OIDC IdP.
//!
//! Vela does not run the login flow itself when this module is
//! active. Clients authenticate against the configured issuer
//! (Matrix Authentication Service, Keycloak, Okta, etc.); the IdP
//! issues an opaque OAuth 2.0 access token; vela validates the token
//! on each request via RFC 7662 token introspection.
//!
//! The flow on every authenticated request:
//!   1. Client sends `Authorization: Bearer <opaque-oidc-token>`.
//!   2. `introspection::IntrospectionClient` POSTs the token to the
//!      IdP's introspection endpoint with vela's client credentials.
//!   3. `cache::IntrospectionCache` memoises the response for a short
//!      window (default 2 min) so a request burst doesn't fan out to
//!      the IdP one round-trip per call.
//!   4. `mapping::lookup_or_provision` resolves the `sub` claim to a
//!      local user_nid via the `external_ids` CF, provisioning the
//!      user + device row on first touch.
//!
//! This file (`mod.rs`) only re-exports the public surface. The
//! integration with `AuthenticatedUser` is in `middleware/auth.rs`
//! and lands in a follow-on PR.

pub mod cache;
pub mod introspection;
pub mod mapping;

pub use cache::IntrospectionCache;
pub use introspection::{
    IntrospectionClient, IntrospectionError, IntrospectionOutcome, IntrospectionResult,
};

/// Phase-2 plumbing bundled together. `AppState` holds an
/// `Option<Arc<IntrospectionState>>`; the auth extractor takes the
/// `Some` branch when this is populated. Construction belongs in
/// `vela-server` boot — we read it from the validated OidcConfig.
pub struct IntrospectionState {
    pub client: IntrospectionClient,
    pub cache: IntrospectionCache,
}

/// Provider string written into the `external_ids` CF for every
/// MSC3861-delegated user. Stable so re-launches keep finding
/// existing mappings. Distinct from any future SAML/LDAP/etc. flow.
pub const PROVIDER: &str = "oauth-delegated";

/// Required scope on incoming access tokens. Per MSC2967 §"Scopes",
/// the stable form is `urn:matrix:client:api:*`; older clients/IdPs
/// emit the unstable variant. We accept either.
pub const REQUIRED_SCOPES: &[&str] = &[
    "urn:matrix:client:api:*",
    "urn:matrix:org.matrix.msc2967.client:api:*",
];

/// Per-request lock-in default TTL on a cached introspection result.
/// Synapse uses 2 minutes; we match because the trade-off (staleness
/// after IdP-side revoke vs. round-trips per request) is identical.
pub const DEFAULT_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(120);
