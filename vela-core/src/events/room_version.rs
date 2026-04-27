/// Supported room versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomVersion {
    V12,
}

impl RoomVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V12 => "12",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "12" => Some(Self::V12),
            _ => None,
        }
    }

    /// In v12, m.room.create MUST NOT be included in auth_events.
    pub fn include_create_in_auth_events(&self) -> bool {
        match self {
            Self::V12 => false,
        }
    }

    /// In v12, room_id is derived from create event's event_id.
    pub fn hash_based_room_ids(&self) -> bool {
        match self {
            Self::V12 => true,
        }
    }

    /// In v12, m.room.create MUST NOT have a room_id field.
    pub fn omit_room_id_from_create(&self) -> bool {
        match self {
            Self::V12 => true,
        }
    }

    /// In v12, creators have infinite power and MUST NOT appear in power_levels users.
    pub fn creators_have_infinite_power(&self) -> bool {
        match self {
            Self::V12 => true,
        }
    }
}
