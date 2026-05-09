//! Signature verification for Matrix JSON objects.
//!
//! Implements the verification algorithm from the spec (appendices.md:380-402):
//! 1. Check signatures object contains entry for entity
//! 2. Filter signing key IDs to understood algorithms (ed25519)
//! 3. Retrieve verification key
//! 4. Base64-decode the signature
//! 5. Remove signatures and unsigned from the JSON
//! 6. Canonical JSON encode the remainder
//! 7. Verify signature against canonical bytes

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::canonical::canonical_json_object;
use crate::events::redact::redact_event_for_version;
use crate::events::room_version::RoomVersion;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("no signatures field in JSON")]
    NoSignaturesField,
    #[error("no signature from entity {0}")]
    NoSignatureFromEntity(String),
    #[error("no signature with key_id {0}")]
    NoSignatureWithKeyId(String),
    #[error("signature is not a string")]
    InvalidSignatureType,
    #[error("signature base64 decode failed: {0}")]
    Base64DecodeFailed(String),
    #[error("signature has wrong length: expected 64 bytes, got {0}")]
    InvalidSignatureLength(usize),
    #[error("verification key has wrong length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("ed25519 verification failed")]
    VerificationFailed,
}

/// Decode a base64 signature string. Matrix spec uses unpadded base64
/// (URL-safe for event signatures, plain for historical reasons).
/// Accept all common variants since different servers have been seen
/// using either URL-safe or standard alphabets with or without padding.
fn decode_signature_b64(s: &str) -> Result<Vec<u8>, SignatureError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| STANDARD.decode(s))
        .map_err(|e| SignatureError::Base64DecodeFailed(e.to_string()))
}

/// Verify an Ed25519 signature over arbitrary JSON.
///
/// The signature is expected at `json.signatures[entity_name][key_id]`.
/// The verification key is provided explicitly — callers are responsible
/// for fetching/caching remote server keys.
pub fn verify_json_signature(
    json: &Map<String, Value>,
    entity_name: &str,
    key_id: &str,
    public_key: &VerifyingKey,
) -> Result<(), SignatureError> {
    let sigs = json
        .get("signatures")
        .and_then(|v| v.as_object())
        .ok_or(SignatureError::NoSignaturesField)?;

    let entity_sigs = sigs
        .get(entity_name)
        .and_then(|v| v.as_object())
        .ok_or_else(|| SignatureError::NoSignatureFromEntity(entity_name.to_string()))?;

    let sig_str = entity_sigs
        .get(key_id)
        .ok_or_else(|| SignatureError::NoSignatureWithKeyId(key_id.to_string()))?
        .as_str()
        .ok_or(SignatureError::InvalidSignatureType)?;

    let sig_bytes = decode_signature_b64(sig_str)?;
    if sig_bytes.len() != 64 {
        return Err(SignatureError::InvalidSignatureLength(sig_bytes.len()));
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_array);

    // Step 5: remove signatures and unsigned from a copy
    let mut copy = json.clone();
    copy.remove("signatures");
    copy.remove("unsigned");

    // Step 6: canonical JSON encode
    let canonical = canonical_json_object(&copy);

    // Step 7: verify
    public_key
        .verify(&canonical, &signature)
        .map_err(|_| SignatureError::VerificationFailed)
}

/// Verify an event signature. Unlike verify_json_signature, this first redacts
/// the event (per the Matrix event signing algorithm), then removes unsigned,
/// then verifies the signature over the canonical redacted form.
///
/// `room_version` selects the redaction shape — must match the version
/// the SENDER used to compute the signature. Mismatched version =
/// mismatched canonical bytes = verify failure even on a valid sig.
/// For locally-emitted events that don't carry a version (own keys
/// signing flow), pass `RoomVersion::V12`.
pub fn verify_event_signature(
    event: &Map<String, Value>,
    entity_name: &str,
    key_id: &str,
    public_key: &VerifyingKey,
    room_version: RoomVersion,
) -> Result<(), SignatureError> {
    let sigs = event
        .get("signatures")
        .and_then(|v| v.as_object())
        .ok_or(SignatureError::NoSignaturesField)?;

    let entity_sigs = sigs
        .get(entity_name)
        .and_then(|v| v.as_object())
        .ok_or_else(|| SignatureError::NoSignatureFromEntity(entity_name.to_string()))?;

    let sig_str = entity_sigs
        .get(key_id)
        .ok_or_else(|| SignatureError::NoSignatureWithKeyId(key_id.to_string()))?
        .as_str()
        .ok_or(SignatureError::InvalidSignatureType)?;

    let sig_bytes = decode_signature_b64(sig_str)?;
    if sig_bytes.len() != 64 {
        return Err(SignatureError::InvalidSignatureLength(sig_bytes.len()));
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_array);

    // Redact, then remove signatures + unsigned (per JSON signing algorithm), then canonical JSON
    let mut redacted = redact_event_for_version(event, room_version);
    redacted.remove("signatures");
    redacted.remove("unsigned");
    let canonical = canonical_json_object(&redacted);

    match public_key.verify(&canonical, &signature) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Diagnostic at TRACE — comparing the original event
            // against the canonical bytes vela computed is the only
            // way to narrow down a redaction-shape mismatch. Enable
            // with `RUST_LOG=vela_core::federation::keys=trace`.
            tracing::trace!(
                entity = %entity_name,
                key_id = %key_id,
                room_version = ?room_version,
                original = %serde_json::to_string(event).unwrap_or_default(),
                canonical = %String::from_utf8_lossy(&canonical),
                "event signature verification failed"
            );
            Err(SignatureError::VerificationFailed)
        }
    }
}

/// Decode an unpadded URL-safe or standard base64 public key string (32 bytes).
pub fn decode_public_key(key_b64: &str) -> Result<VerifyingKey, SignatureError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(key_b64)
        .or_else(|_| URL_SAFE.decode(key_b64))
        .or_else(|_| STANDARD_NO_PAD.decode(key_b64))
        .or_else(|_| STANDARD.decode(key_b64))
        .map_err(|e| SignatureError::Base64DecodeFailed(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(SignatureError::InvalidKeyLength(bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|_| SignatureError::InvalidKeyLength(32))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::sign::ServerSigningKey;
    use serde_json::json;

    #[test]
    fn verify_signed_json_succeeds() {
        let key = ServerSigningKey::generate();
        let mut obj = json!({"server_name": "example.com", "foo": "bar"})
            .as_object()
            .unwrap()
            .clone();
        key.sign_json(&mut obj, "example.com");

        let pub_key = key.verifying_key();
        let result = verify_json_signature(&obj, "example.com", key.key_id(), &pub_key);
        assert!(result.is_ok(), "verification should succeed: {result:?}");
    }

    #[test]
    fn verify_tampered_json_fails() {
        let key = ServerSigningKey::generate();
        let mut obj = json!({"server_name": "example.com", "foo": "bar"})
            .as_object()
            .unwrap()
            .clone();
        key.sign_json(&mut obj, "example.com");

        // Tamper with the content
        obj.insert("foo".into(), json!("tampered"));

        let pub_key = key.verifying_key();
        let result = verify_json_signature(&obj, "example.com", key.key_id(), &pub_key);
        assert!(matches!(result, Err(SignatureError::VerificationFailed)));
    }

    #[test]
    fn verify_missing_signature_fails() {
        let obj = json!({"server_name": "example.com"})
            .as_object()
            .unwrap()
            .clone();
        let key = ServerSigningKey::generate();
        let pub_key = key.verifying_key();
        let result = verify_json_signature(&obj, "example.com", key.key_id(), &pub_key);
        assert!(matches!(result, Err(SignatureError::NoSignaturesField)));
    }

    #[test]
    fn verify_wrong_entity_fails() {
        let key = ServerSigningKey::generate();
        let mut obj = json!({"foo": "bar"}).as_object().unwrap().clone();
        key.sign_json(&mut obj, "example.com");

        let pub_key = key.verifying_key();
        let result = verify_json_signature(&obj, "other.com", key.key_id(), &pub_key);
        assert!(matches!(
            result,
            Err(SignatureError::NoSignatureFromEntity(_))
        ));
    }

    #[test]
    fn verify_event_signature_succeeds() {
        let key = ServerSigningKey::generate();
        let mut event = json!({
            "type": "m.room.message",
            "sender": "@alice:example.com",
            "room_id": "!test:example.com",
            "origin_server_ts": 1234567890,
            "depth": 1,
            "prev_events": [],
            "auth_events": [],
            "content": {"msgtype": "m.text", "body": "hello"},
            "hashes": {"sha256": "abc"}
        })
        .as_object()
        .unwrap()
        .clone();
        key.sign_event(&mut event, "example.com");

        let pub_key = key.verifying_key();
        let result = verify_event_signature(
            &event,
            "example.com",
            key.key_id(),
            &pub_key,
            RoomVersion::V12,
        );
        assert!(result.is_ok(), "event signature should verify: {result:?}");
    }

    #[test]
    fn decode_public_key_roundtrip() {
        let key = ServerSigningKey::generate();
        let pub_b64 = key.public_key_base64();
        let decoded = decode_public_key(&pub_b64).unwrap();
        assert_eq!(decoded.as_bytes(), key.verifying_key().as_bytes());
    }
}
