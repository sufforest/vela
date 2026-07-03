pub mod builder;
pub mod content;
pub mod hash;
pub mod limits;
pub mod pdu;
pub mod redact;
pub mod room_version;
pub mod sign;
pub mod view;

/// State event types included in an invite/knock stripped-state bundle
/// (federation `invite_room_state`, and `rooms.invite.*.invite_state` /
/// `rooms.knock.*.knock_state` in `/sync`), per the CS-API recommended set.
///
/// `m.room.encryption` lets a client show the "encrypted" badge and
/// `m.room.topic` the room topic before the invitee joins; `m.room.create` is
/// required (CS-API v1.16) so a v12 recipient can verify the hash-derived
/// `room_id`. `m.room.member` is not in the spec's recommended list but is
/// carried so the invitee can render who invited them.
///
/// Single source of truth: the outbound bundle we build and the stripped
/// state a local invitee reads back in `/sync` must agree, or an invitee sees
/// different pre-join chrome depending on which server they're on.
pub const INVITE_STRIPPED_STATE_TYPES: &[&str] = &[
    "m.room.create",
    "m.room.name",
    "m.room.avatar",
    "m.room.topic",
    "m.room.canonical_alias",
    "m.room.join_rules",
    "m.room.encryption",
    "m.room.member",
];

#[cfg(test)]
mod tests {
    use super::INVITE_STRIPPED_STATE_TYPES;

    #[test]
    fn stripped_state_covers_the_recommended_set() {
        // The CS-API recommended stripped-state types — topic + encryption are
        // the ones that were historically missing and drive pre-join chrome.
        for t in [
            "m.room.create",
            "m.room.name",
            "m.room.avatar",
            "m.room.topic",
            "m.room.canonical_alias",
            "m.room.join_rules",
            "m.room.encryption",
        ] {
            assert!(
                INVITE_STRIPPED_STATE_TYPES.contains(&t),
                "stripped state must include {t}"
            );
        }
    }
}
