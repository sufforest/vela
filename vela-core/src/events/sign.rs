//! Ed25519 event signing per Matrix spec.
//! Source: content/server-server-api.md:1549-1592

// Matrix "Signing JSON" appendix defines Unpadded Base64 as the
// **standard** alphabet (RFC 4648 §4) without padding. URL-safe was
// a bug here; switching corrects federation key + signature
// interoperability with strict peers.
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::{Map, Value};

use crate::canonical::canonical_json_object;
use crate::events::redact::redact_event;

/// Server signing key pair.
#[derive(Clone)]
pub struct ServerSigningKey {
    key_id: String,
    signing_key: SigningKey,
}

impl ServerSigningKey {
    /// Generate a new random signing key.
    pub fn generate() -> Self {
        // Use random bytes directly to avoid rand_core version conflicts
        let secret: [u8; 32] = rand::random();
        let signing_key = SigningKey::from_bytes(&secret);
        let public = signing_key.verifying_key();
        let pub_b64 = STANDARD_NO_PAD.encode(public.as_bytes());
        let version = &pub_b64[..6];
        Self {
            key_id: format!("ed25519:{version}"),
            signing_key,
        }
    }

    /// Restore from stored bytes.
    pub fn from_bytes(key_id: String, secret: &[u8; 32]) -> Self {
        Self {
            key_id,
            signing_key: SigningKey::from_bytes(secret),
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn public_key_base64(&self) -> String {
        STANDARD_NO_PAD.encode(self.verifying_key().as_bytes())
    }

    /// Sign an event under a specific room version's redaction shape.
    /// Mismatch with the receiver's verify version produces canonical
    /// bytes that disagree, and the signature fails to verify
    /// downstream. Always pass the room's actual version.
    pub fn sign_event_for_version(
        &self,
        event: &mut Map<String, Value>,
        server_name: &str,
        room_version: crate::events::room_version::RoomVersion,
    ) {
        let mut redacted = crate::events::redact::redact_event_for_version(event, room_version);
        redacted.remove("signatures");
        redacted.remove("unsigned");

        let canonical = canonical_json_object(&redacted);
        let signature = self.signing_key.sign(&canonical);
        let sig_b64 = STANDARD_NO_PAD.encode(signature.to_bytes());

        Self::insert_signature(event, server_name, &self.key_id, sig_b64);
    }

    /// V12-default wrapper. Use `sign_event_for_version` when the room
    /// version is known.
    pub fn sign_event(&self, event: &mut Map<String, Value>, server_name: &str) {
        let mut redacted = redact_event(event);
        redacted.remove("signatures");
        redacted.remove("unsigned");

        let canonical = canonical_json_object(&redacted);
        let signature = self.signing_key.sign(&canonical);
        let sig_b64 = STANDARD_NO_PAD.encode(signature.to_bytes());

        Self::insert_signature(event, server_name, &self.key_id, sig_b64);
    }

    /// Sign arbitrary JSON (non-event) per the Matrix signing algorithm.
    /// Used for key responses, federation request bodies, etc.
    /// Unlike sign_event, this does NOT redact first.
    /// 1. Remove signatures and unsigned from a copy
    /// 2. Canonical JSON encode
    /// 3. Ed25519 sign
    /// 4. Insert signature into original
    pub fn sign_json(&self, json: &mut Map<String, Value>, server_name: &str) {
        let mut copy = json.clone();
        copy.remove("signatures");
        copy.remove("unsigned");

        let canonical = canonical_json_object(&copy);
        let signature = self.signing_key.sign(&canonical);
        let sig_b64 = STANDARD_NO_PAD.encode(signature.to_bytes());

        Self::insert_signature(json, server_name, &self.key_id, sig_b64);
    }

    fn insert_signature(
        json: &mut Map<String, Value>,
        server_name: &str,
        key_id: &str,
        sig_b64: String,
    ) {
        let server_sigs = json
            .entry("signatures")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .unwrap()
            .entry(server_name)
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .unwrap();

        server_sigs.insert(key_id.to_string(), Value::String(sig_b64));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn generate_and_sign() {
        let key = ServerSigningKey::generate();
        assert!(key.key_id().starts_with("ed25519:"));

        let mut event = json!({
            "type": "m.room.message",
            "sender": "@alice:example.com",
            "room_id": "!test:example.com",
            "origin_server_ts": 1234567890,
            "depth": 1,
            "prev_events": [],
            "auth_events": [],
            "content": {"msgtype": "m.text", "body": "hello"},
            "hashes": {"sha256": "testhash"}
        })
        .as_object()
        .unwrap()
        .clone();

        key.sign_event(&mut event, "example.com");

        let sigs = event.get("signatures").unwrap().as_object().unwrap();
        let server_sigs = sigs.get("example.com").unwrap().as_object().unwrap();
        assert!(server_sigs.contains_key(key.key_id()));
    }

    #[test]
    fn signing_is_deterministic() {
        let key = ServerSigningKey::generate();
        let make_event = || {
            json!({
                "type": "m.room.message",
                "sender": "@alice:example.com",
                "origin_server_ts": 1234567890,
                "depth": 1,
                "prev_events": [],
                "auth_events": [],
                "content": {},
                "hashes": {"sha256": "test"}
            })
            .as_object()
            .unwrap()
            .clone()
        };

        let mut e1 = make_event();
        let mut e2 = make_event();
        key.sign_event(&mut e1, "example.com");
        key.sign_event(&mut e2, "example.com");

        let s1 = &e1["signatures"]["example.com"][key.key_id()];
        let s2 = &e2["signatures"]["example.com"][key.key_id()];
        assert_eq!(s1, s2);
    }

    #[test]
    fn key_roundtrip() {
        let key = ServerSigningKey::generate();
        let key_id = key.key_id().to_string();
        let secret = *key.secret_bytes();

        let restored = ServerSigningKey::from_bytes(key_id, &secret);
        assert_eq!(restored.key_id(), key.key_id());
        assert_eq!(restored.public_key_base64(), key.public_key_base64());
    }
}
