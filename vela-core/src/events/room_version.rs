//! Matrix room version table.
//!
//! Vela supports v6 through v12. Older versions (v1–v5) are refused at
//! load time: v1 and v2 have known auth-rule bugs (float-coerced power
//! levels, signature-failed events accepted) and v3–v5 are
//! soft-deprecated by the spec with no production rooms left in the
//! federation that use them. v12 is what we emit by default for
//! `/createRoom` when the client doesn't ask otherwise.
//!
//! `Msc3757V10` is a v10-derived unstable version (`org.matrix.msc3757.10`)
//! that adds "owned state events": state_keys of the form
//! `@<mxid>[<_suffix>]` where the user portion authorises the write.
//! Behaviour-equivalent to v10 except for one auth-rule change (rule 9).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomVersion {
    V6,
    V7,
    V8,
    V9,
    V10,
    V11,
    V12,
    /// MSC3757 owned state events, v10-based.
    Msc3757V10,
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
            Self::Msc3757V10 => "org.matrix.msc3757.10",
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
            "org.matrix.msc3757.10" => Some(Self::Msc3757V10),
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
            Self::Msc3757V10,
        ]
    }

    /// Returns true if this version is at or above `min`. Used to
    /// implement `[server] minimum_room_version`. MSC3757V10 reports
    /// 10 — the base version's auth rules apply except where overridden
    /// by `supports_owned_state_events`.
    pub fn at_least(&self, min: RoomVersion) -> bool {
        self.numeric() >= min.numeric()
    }

    fn numeric(&self) -> u8 {
        match self {
            Self::V6 => 6,
            Self::V7 => 7,
            Self::V8 => 8,
            Self::V9 => 9,
            Self::V10 | Self::Msc3757V10 => 10,
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

    /// v12 uses the "state resolution v2.1" variant of the algorithm: the
    /// iterative auth checks start from an **empty** state map (not the
    /// unconflicted map) and the full conflicted set additionally includes
    /// the *conflicted state subgraph*. Pre-v12 rooms use classic state-res
    /// v2 — start from the unconflicted map, no subgraph. These only diverge
    /// on a genuine state fork, but choosing the wrong variant there can
    /// permanently split resolved state across the federation, so it must
    /// track the room's version.
    pub fn uses_state_res_v21(&self) -> bool {
        self.at_least(Self::V12)
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

    /// MSC3757: state events whose `state_key` matches
    /// `@<mxid>[<_suffix>]` are authorised by the embedded `<mxid>`
    /// (or the room creator), not by exact equality with `sender`.
    /// Only `Msc3757V10` enables this; v10 keeps strict-equality.
    pub fn supports_owned_state_events(&self) -> bool {
        matches!(self, Self::Msc3757V10)
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

    /// state-res v2.1 (empty initial state + conflicted subgraph) is a v12+
    /// feature; every earlier version — including the v10-based MSC3757 —
    /// uses classic state-res v2.
    #[test]
    fn state_res_v21_starts_at_v12() {
        assert!(RoomVersion::V12.uses_state_res_v21());
        for v in [
            RoomVersion::V6,
            RoomVersion::V7,
            RoomVersion::V8,
            RoomVersion::V9,
            RoomVersion::V10,
            RoomVersion::V11,
            RoomVersion::Msc3757V10,
        ] {
            assert!(
                !v.uses_state_res_v21(),
                "{} must use classic state-res v2",
                v.as_str()
            );
        }
    }

    #[test]
    fn all_supported_is_in_order() {
        let all = RoomVersion::all_supported();
        assert_eq!(all.len(), 8);
        assert_eq!(all[0], RoomVersion::V6);
        assert_eq!(all[6], RoomVersion::V12);
        assert_eq!(all[7], RoomVersion::Msc3757V10);
    }

    /// MSC3757 unstable version parses from its `org.matrix.msc3757.10`
    /// string and reports v10's numeric for the inheritance-style
    /// `at_least` checks — the new behaviour rides on the boolean
    /// `supports_owned_state_events` knob, not on numeric ordering.
    #[test]
    fn msc3757_v10_parses_and_orders_as_v10() {
        let v = RoomVersion::parse("org.matrix.msc3757.10").unwrap();
        assert_eq!(v, RoomVersion::Msc3757V10);
        assert_eq!(v.as_str(), "org.matrix.msc3757.10");
        assert!(v.at_least(RoomVersion::V10));
        assert!(!v.at_least(RoomVersion::V11));
        assert!(v.supports_owned_state_events());
        assert!(!RoomVersion::V10.supports_owned_state_events());
    }
}
