//! Matrix room version table.
//!
//! Vela supports v6 through v12. Older versions (v1–v5) are refused at
//! load time: v1 and v2 have known auth-rule bugs (float-coerced power
//! levels, signature-failed events accepted) and v3–v5 are
//! soft-deprecated by the spec with no production rooms left in the
//! federation that use them. v12 is what we emit by default for
//! `/createRoom` when the client doesn't ask otherwise.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomVersion {
    V6,
    V7,
    V8,
    V9,
    V10,
    V11,
    V12,
}

impl RoomVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V6 => "6",
            Self::V7 => "7",
            Self::V8 => "8",
            Self::V9 => "9",
            Self::V10 => "10",
            Self::V11 => "11",
            Self::V12 => "12",
        }
    }

    /// Parse a version string from a wire format (createRoom body, /upgrade,
    /// federation `?ver=` etc). Returns `None` for any unsupported value
    /// — including v1–v5, which we deliberately refuse.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "6" => Some(Self::V6),
            "7" => Some(Self::V7),
            "8" => Some(Self::V8),
            "9" => Some(Self::V9),
            "10" => Some(Self::V10),
            "11" => Some(Self::V11),
            "12" => Some(Self::V12),
            _ => None,
        }
    }

    /// All supported versions, oldest first. Used to advertise
    /// `?ver=` on outbound make_join.
    pub fn all_supported() -> &'static [RoomVersion] {
        &[
            Self::V6,
            Self::V7,
            Self::V8,
            Self::V9,
            Self::V10,
            Self::V11,
            Self::V12,
        ]
    }

    /// Returns true if this version is at or above `min`. Used to
    /// implement `[server] minimum_room_version`.
    pub fn at_least(&self, min: RoomVersion) -> bool {
        self.numeric() >= min.numeric()
    }

    fn numeric(&self) -> u8 {
        match self {
            Self::V6 => 6,
            Self::V7 => 7,
            Self::V8 => 8,
            Self::V9 => 9,
            Self::V10 => 10,
            Self::V11 => 11,
            Self::V12 => 12,
        }
    }

    // --- per-version behaviour knobs ---

    /// Pre-v11, `m.room.create` is included in `auth_events` for every
    /// non-create event. v11 dropped this — the create event is always
    /// the root of the auth chain implicitly.
    pub fn include_create_in_auth_events(&self) -> bool {
        !self.at_least(Self::V11)
    }

    /// v12 derives `room_id` from `hash(redacted create event)`. Earlier
    /// versions use `!opaque:server` minted at create time.
    pub fn hash_based_room_ids(&self) -> bool {
        self.at_least(Self::V12)
    }

    /// v12 omits the `room_id` field from `m.room.create` (since the
    /// id is derived from the event itself). Earlier versions include it.
    pub fn omit_room_id_from_create(&self) -> bool {
        self.at_least(Self::V12)
    }

    /// v11+ drops `m.room.create.content.creator`; the creator is
    /// authoritative from `sender`. Pre-v11 events carry the field
    /// and clients still read it.
    pub fn create_event_has_creator_field(&self) -> bool {
        !self.at_least(Self::V11)
    }

    /// v12: creators have effectively-infinite power and MUST NOT
    /// appear in `power_levels.users`. Pre-v12 stores creator power
    /// in `power_levels.users` like any other priv'd user.
    pub fn creators_have_infinite_power(&self) -> bool {
        self.at_least(Self::V12)
    }

    /// v7 introduced `m.room.member.membership = "knock"` and
    /// `m.room.join_rules.join_rule = "knock"`. Pre-v7 rejects.
    pub fn supports_knocking(&self) -> bool {
        self.at_least(Self::V7)
    }

    /// v8 introduced `join_rule = "restricted"` plus the `allow` block
    /// referencing other rooms and `join_authorised_via_users_server`
    /// on member events.
    pub fn supports_restricted_joins(&self) -> bool {
        self.at_least(Self::V8)
    }

    /// v9 added `knock_restricted` (combination of v7 knocking and
    /// v8 restricted).
    pub fn supports_knock_restricted(&self) -> bool {
        self.at_least(Self::V9)
    }

    /// v10 made `power_levels.notifications.room` strict-int (pre-v10
    /// it was occasionally a bool). Auth rules need to coerce.
    pub fn strict_int_power_levels(&self) -> bool {
        self.at_least(Self::V10)
    }

    /// v12 introduced `additional_creators` on `m.room.create`,
    /// promoting other users to creator-equivalent power.
    pub fn supports_additional_creators(&self) -> bool {
        self.at_least(Self::V12)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_supported_versions() {
        for v in ["6", "7", "8", "9", "10", "11", "12"] {
            assert!(RoomVersion::parse(v).is_some(), "expected {v} parseable");
        }
    }

    #[test]
    fn refuse_unsupported_versions() {
        for v in ["1", "2", "3", "4", "5", "13", "abc", ""] {
            assert!(RoomVersion::parse(v).is_none(), "expected {v} refused");
        }
    }

    #[test]
    fn at_least_orders_versions() {
        assert!(RoomVersion::V12.at_least(RoomVersion::V6));
        assert!(RoomVersion::V11.at_least(RoomVersion::V11));
        assert!(!RoomVersion::V6.at_least(RoomVersion::V12));
    }

    #[test]
    fn version_specific_knobs() {
        // v6 is most permissive in old features
        let v6 = RoomVersion::V6;
        assert!(v6.include_create_in_auth_events()); // pre-v11
        assert!(!v6.hash_based_room_ids()); // pre-v12
        assert!(!v6.omit_room_id_from_create()); // pre-v12
        assert!(v6.create_event_has_creator_field()); // pre-v11
        assert!(!v6.supports_knocking()); // pre-v7
        assert!(!v6.supports_restricted_joins()); // pre-v8

        // v12 is most modern
        let v12 = RoomVersion::V12;
        assert!(!v12.include_create_in_auth_events());
        assert!(v12.hash_based_room_ids());
        assert!(v12.omit_room_id_from_create());
        assert!(!v12.create_event_has_creator_field());
        assert!(v12.supports_knocking());
        assert!(v12.supports_restricted_joins());

        // v8 boundary
        assert!(RoomVersion::V8.supports_restricted_joins());
        assert!(!RoomVersion::V7.supports_restricted_joins());

        // v11 boundary on creator field
        assert!(!RoomVersion::V11.include_create_in_auth_events());
        assert!(RoomVersion::V10.include_create_in_auth_events());
    }

    #[test]
    fn all_supported_is_in_order() {
        let all = RoomVersion::all_supported();
        assert_eq!(all.len(), 7);
        assert_eq!(all[0], RoomVersion::V6);
        assert_eq!(all[6], RoomVersion::V12);
    }
}
