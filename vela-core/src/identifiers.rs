use std::fmt;

use serde::{Deserialize, Serialize};

/// Compact numeric identifier used internally. All string identifiers
/// (user IDs, room IDs, event types, state keys) are mapped to Nids
/// on first encounter. Internal operations use Nids exclusively.
/// String forms are only resolved at API boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nid(pub u64);

impl Nid {
    pub fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    pub fn from_be_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }
}

/// Matrix user ID: @localpart:server_name
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(String);

impl UserId {
    pub fn new(localpart: &str, server_name: &str) -> Self {
        Self(format!("@{localpart}:{server_name}"))
    }

    pub fn parse(s: &str) -> Result<Self, &'static str> {
        if !s.starts_with('@') || !s.contains(':') {
            return Err("invalid user ID: must be @localpart:server");
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn localpart(&self) -> &str {
        &self.0[1..self.0.find(':').unwrap()]
    }

    pub fn server_name(&self) -> &str {
        &self.0[self.0.find(':').unwrap() + 1..]
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Matrix room ID: !opaque_id or !hash (v12)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RoomId(String);

impl RoomId {
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        if !s.starts_with('!') {
            return Err("invalid room ID: must start with !");
        }
        Ok(Self(s.to_string()))
    }

    /// Derive room ID from create event's event ID (v12).
    /// Replaces the $ sigil with !
    pub fn from_create_event_id(event_id: &EventId) -> Self {
        let mut s = event_id.as_str().to_string();
        s.replace_range(0..1, "!");
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RoomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Matrix event ID: $hash (v4+)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(String);

impl EventId {
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        if !s.starts_with('$') {
            return Err("invalid event ID: must start with $");
        }
        Ok(Self(s.to_string()))
    }

    /// Create event ID from a reference hash (URL-safe base64, unpadded).
    pub fn from_reference_hash(hash: &str) -> Self {
        Self(format!("${hash}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Device identifier (opaque string)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(String);

impl DeviceId {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::rng();
        let id: String = (0..10)
            .map(|_| {
                let idx = rng.random_range(0..36u8);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'A' + idx - 10) as char
                }
            })
            .collect();
        Self(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_id_parsing() {
        let uid = UserId::parse("@alice:example.com").unwrap();
        assert_eq!(uid.localpart(), "alice");
        assert_eq!(uid.server_name(), "example.com");
        assert_eq!(uid.as_str(), "@alice:example.com");

        assert!(UserId::parse("alice:example.com").is_err());
        assert!(UserId::parse("@alice").is_err());
    }

    #[test]
    fn room_id_from_event_id() {
        let eid = EventId::from_reference_hash("Rqnc-F-dvnEYJTyHq_iKxU2bZ1CI92-kuZq3a5lr5Zg");
        let rid = RoomId::from_create_event_id(&eid);
        assert_eq!(rid.as_str(), "!Rqnc-F-dvnEYJTyHq_iKxU2bZ1CI92-kuZq3a5lr5Zg");
    }

    #[test]
    fn device_id_generation() {
        let d1 = DeviceId::generate();
        let d2 = DeviceId::generate();
        assert_eq!(d1.as_str().len(), 10);
        assert_ne!(d1.as_str(), d2.as_str());
    }

    #[test]
    fn nid_roundtrip() {
        let nid = Nid(12345);
        let bytes = nid.to_be_bytes();
        assert_eq!(Nid::from_be_bytes(bytes), nid);
    }
}
