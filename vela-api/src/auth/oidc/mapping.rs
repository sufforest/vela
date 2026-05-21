//! Resolve an introspection result to a local `(user_nid, device_id)`,
//! provisioning the user row + device row on first touch.
//!
//! Two responsibilities:
//!   1. Translate the IdP's `sub` claim into a local user_nid via the
//!      `external_ids` CF. On a miss, derive the MXID from the
//!      `username` claim (or fall back to `sub`), create the user
//!      row, and write the mapping.
//!   2. Ensure a device row exists for the `device_id` claim. We
//!      auto-create when absent — see the design doc for why this
//!      diverges from Synapse's "device must pre-exist" model.

use std::sync::Arc;

use thiserror::Error;

use vela_store::db::Database;

use crate::auth::oidc::IntrospectionResult;

/// Outcome of mapping an introspection result to a local session.
#[derive(Debug, Clone)]
pub struct MappedIdentity {
    pub user_nid: u64,
    pub user_id: String,
    pub device_id: String,
    /// `true` when this call created the user row. Used by the auth
    /// middleware to emit a "first-touch" metric and (eventually)
    /// fire the same join-admin-room flow `/register` runs.
    pub first_touch_user: bool,
    /// `true` when this call created the device row. Useful for the
    /// same metric pipeline; clients don't observe it directly.
    pub first_touch_device: bool,
}

#[derive(Debug, Error)]
pub enum MappingError {
    #[error("introspection result has no device_id claim")]
    MissingDeviceId,
    #[error("derived localpart is invalid: {0}")]
    InvalidLocalpart(String),
    #[error("storage error: {0}")]
    Storage(String),
}

/// Resolve the introspection result against vela's state. Idempotent
/// on repeat calls — a returning user goes through the fast path
/// (existing mapping, existing device).
///
/// `provider` is the operator-controlled identifier under which the
/// IdP's `sub` claim is stored. The MSC3861 flow always passes
/// `crate::auth::oidc::PROVIDER`.
///
/// `server_name` is vela's configured `server.name` — used to mint
/// the full MXID from the IdP's localpart.
pub fn lookup_or_provision(
    db: &Arc<Database>,
    provider: &str,
    server_name: &str,
    introspection: &IntrospectionResult,
) -> Result<MappedIdentity, MappingError> {
    let device_id = introspection
        .device_id
        .as_deref()
        .ok_or(MappingError::MissingDeviceId)?
        .to_string();

    // Fast path: returning sub.
    let existing = db
        .get_external_id_mapping(provider, &introspection.sub)
        .map_err(|e| MappingError::Storage(e.to_string()))?;
    let (user_nid, user_id, first_touch_user) = match existing {
        Some(nid) => {
            // The MXID is stored verbatim in `nid_map` keyed by nid; for
            // an already-mapped sub, reading the mapping back is enough.
            let mxid = db
                .resolve_nid(nid)
                .map_err(|e| MappingError::Storage(e.to_string()))?
                .unwrap_or_else(|| {
                    derive_mxid(&introspection.sub, &introspection.username, server_name)
                });
            (nid, mxid, false)
        }
        None => {
            // First-touch: derive the MXID, validate the localpart,
            // create the user row, persist the mapping.
            let mxid = derive_mxid(&introspection.sub, &introspection.username, server_name);
            validate_localpart_from_mxid(&mxid)?;
            let nid = db
                .create_user(&mxid, "")
                .map_err(|e| MappingError::Storage(e.to_string()))?;
            db.put_external_id_mapping(provider, &introspection.sub, nid)
                .map_err(|e| MappingError::Storage(e.to_string()))?;
            (nid, mxid, true)
        }
    };

    // Ensure the device row exists. `create_device` is idempotent: it
    // overwrites with the same {device_id} blob if already present,
    // which is fine. We check existence first so we can report
    // `first_touch_device` honestly.
    let device_existed = db
        .get_device(user_nid, &device_id)
        .map_err(|e| MappingError::Storage(e.to_string()))?
        .is_some();
    if !device_existed {
        db.create_device(user_nid, &device_id)
            .map_err(|e| MappingError::Storage(e.to_string()))?;
    }

    Ok(MappedIdentity {
        user_nid,
        user_id,
        device_id,
        first_touch_user,
        first_touch_device: !device_existed,
    })
}

/// Build the local MXID from the IdP's claims. Preference order:
///   1. `username` claim — what MAS emits, the spec-recommended path.
///   2. `sub` claim — fallback so generic IdPs that don't include a
///      `username` still work; the sub is opaque but stable.
///
/// In both cases we lowercase + apply the Matrix localpart grammar:
/// any character outside `[0-9a-z._=/+-]` is replaced with `_`. This
/// keeps `derive_mxid` total — no Err on weird IdP claims — at the
/// cost of two distinct IdP subs collapsing to the same MXID only
/// if their normalised forms coincide.
fn derive_mxid(sub: &str, username: &Option<String>, server_name: &str) -> String {
    let raw = username.as_deref().unwrap_or(sub);
    let localpart: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-=/+".contains(c) {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("@{localpart}:{server_name}")
}

/// Spot-check the localpart portion of a derived MXID. Rejects the
/// empty case (e.g., a `username` claim that was entirely whitespace).
fn validate_localpart_from_mxid(mxid: &str) -> Result<(), MappingError> {
    let after_at = mxid
        .strip_prefix('@')
        .ok_or_else(|| MappingError::InvalidLocalpart(mxid.into()))?;
    let (localpart, _) = after_at
        .split_once(':')
        .ok_or_else(|| MappingError::InvalidLocalpart(mxid.into()))?;
    if localpart.is_empty() {
        return Err(MappingError::InvalidLocalpart(mxid.into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;

    fn introspection(
        sub: &str,
        username: Option<&str>,
        device: Option<&str>,
    ) -> IntrospectionResult {
        IntrospectionResult {
            sub: sub.into(),
            username: username.map(String::from),
            scope: vec!["urn:matrix:client:api:*".into()],
            device_id: device.map(String::from),
            expires_at: None,
        }
    }

    #[test]
    fn first_touch_provisions_user_device_and_mapping() {
        let (state, _tmp) = build_test_state();
        let r = introspection("sub-1", Some("alice"), Some("DEV-A"));
        let m = lookup_or_provision(&state.db, "oauth-delegated", "example.com", &r).unwrap();
        assert!(m.first_touch_user);
        assert!(m.first_touch_device);
        assert_eq!(m.user_id, "@alice:example.com");
        assert_eq!(m.device_id, "DEV-A");
        // Mapping persisted: second call hits the fast path.
        let m2 = lookup_or_provision(&state.db, "oauth-delegated", "example.com", &r).unwrap();
        assert!(!m2.first_touch_user);
        assert!(!m2.first_touch_device);
        assert_eq!(m2.user_nid, m.user_nid);
    }

    #[test]
    fn missing_device_id_is_rejected() {
        let (state, _tmp) = build_test_state();
        let r = introspection("sub-1", Some("alice"), None);
        let err = lookup_or_provision(&state.db, "oauth-delegated", "example.com", &r).unwrap_err();
        assert!(matches!(err, MappingError::MissingDeviceId));
    }

    #[test]
    fn returning_sub_with_new_device_auto_creates_device() {
        let (state, _tmp) = build_test_state();
        let r1 = introspection("sub-1", Some("alice"), Some("DEV-A"));
        let m1 = lookup_or_provision(&state.db, "oauth-delegated", "example.com", &r1).unwrap();
        let r2 = introspection("sub-1", Some("alice"), Some("DEV-B"));
        let m2 = lookup_or_provision(&state.db, "oauth-delegated", "example.com", &r2).unwrap();
        assert_eq!(m1.user_nid, m2.user_nid);
        assert!(!m2.first_touch_user);
        assert!(m2.first_touch_device);
        assert_eq!(m2.device_id, "DEV-B");
    }

    /// Generic IdPs that omit `username` still work — the sub is
    /// stable and unique, so derivation off the sub is the right
    /// fallback.
    #[test]
    fn falls_back_to_sub_when_username_absent() {
        let (state, _tmp) = build_test_state();
        let r = introspection("alice-id", None, Some("DEV"));
        let m = lookup_or_provision(&state.db, "oauth-delegated", "example.com", &r).unwrap();
        assert_eq!(m.user_id, "@alice-id:example.com");
    }

    #[test]
    fn weird_username_chars_become_underscores() {
        let (state, _tmp) = build_test_state();
        let r = introspection("sub-1", Some("Al!ce 32"), Some("DEV"));
        let m = lookup_or_provision(&state.db, "oauth-delegated", "example.com", &r).unwrap();
        // 'A' lowercased, '!' and ' ' replaced with '_'.
        assert_eq!(m.user_id, "@al_ce_32:example.com");
    }

    #[test]
    fn distinct_providers_isolate_users() {
        let (state, _tmp) = build_test_state();
        let r = introspection("shared", Some("bob"), Some("DEV"));
        let m1 = lookup_or_provision(&state.db, "idp-a", "example.com", &r).unwrap();
        // Same sub under a different provider must mint a different
        // mapping. The MXIDs collide because they share the localpart;
        // create_user is idempotent on the existing nid, so the second
        // call resolves the SAME user_nid but writes its OWN mapping
        // entry under provider="idp-b".
        let m2 = lookup_or_provision(&state.db, "idp-b", "example.com", &r).unwrap();
        // Both providers now have their own mapping rows pointing at
        // the same user — operator-intended migration scenario.
        assert_eq!(
            state.db.get_external_id_mapping("idp-a", "shared").unwrap(),
            Some(m1.user_nid)
        );
        assert_eq!(
            state.db.get_external_id_mapping("idp-b", "shared").unwrap(),
            Some(m2.user_nid)
        );
    }
}
