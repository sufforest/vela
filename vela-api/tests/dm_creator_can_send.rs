//! Repro test for the deployment-surfaced bug "1:1 DM creator can't
//! send any message after server restart" — error 403 "sender is not
//! joined" while the user is clearly joined (their precheck passes,
//! and other clients in the room can both send and receive).
//!
//! What the failing path looks like in code: the precheck reads
//! `memberships` CF, the auth-rule check consults `room_state` CF
//! indirectly via `auth_events`. The two CFs are supposed to agree.
//! If `room_state` is missing the creator's join member event, the
//! 403 surfaces while `memberships` still says JOIN.
//!
//! This test simulates the Element-X 1:1 DM shape: createRoom with
//! preset=trusted_private_chat, is_direct=true, invite=[bob], then
//! the creator sends a message. If the bug is reproducible in-process,
//! this will fail with 403 on the send. If it passes, the issue
//! is environment-specific and we need diagnose-membership against
//! the production DB to localise it.

#![cfg(test)]

mod common;

use serde_json::json;

use common::Harness;

#[tokio::test]
async fn creator_of_1to1_dm_can_send_after_create() {
    let harness = Harness::new();
    let (_alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, _bob_tok) = harness.register("bob", "pw").await;

    let room_id = harness
        .create_room(
            &alice_tok,
            json!({
                "preset": "trusted_private_chat",
                "is_direct": true,
                "invite": [bob_id],
            }),
        )
        .await;

    let _ = harness.send_message(&alice_tok, &room_id, "hello").await;
}

#[tokio::test]
async fn creator_of_1to1_dm_can_send_after_explicit_initial_state() {
    // Variant: some clients pre-populate initial_state with
    // m.room.encryption (Element-X for DMs) or m.room.guest_access.
    // The dedup work in PR #59 made these silent skips of preset
    // emits — this asserts the skip didn't accidentally also skip
    // the creator's own join member event.
    let harness = Harness::new();
    let (_alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, _bob_tok) = harness.register("bob", "pw").await;

    let room_id = harness
        .create_room(
            &alice_tok,
            json!({
                "preset": "trusted_private_chat",
                "is_direct": true,
                "invite": [bob_id],
                "initial_state": [
                    {
                        "type": "m.room.encryption",
                        "state_key": "",
                        "content": {"algorithm": "m.megolm.v1.aes-sha2"},
                    },
                    {
                        "type": "m.room.guest_access",
                        "state_key": "",
                        "content": {"guest_access": "can_join"},
                    },
                ],
            }),
        )
        .await;

    let _ = harness.send_message(&alice_tok, &room_id, "hello").await;
}
