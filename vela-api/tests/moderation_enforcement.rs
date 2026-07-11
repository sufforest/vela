//! End-to-end moderation enforcement: a policy room's `m.policy.rule.*` bans
//! are compiled into the ban list and enforced at the invite/join choke points,
//! and the list refreshes live when a rule is added. Complements the pure unit
//! tests in `vela_api::moderation` (which cover the match logic) by exercising
//! the real DB seed path, the send-path refresh hook, and the HTTP wiring.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::Harness;
use serde_json::json;

const SERVER: &str = "localhost:8008";

fn mxid(local: &str) -> String {
    format!("@{local}:{SERVER}")
}

/// Ban a user in a policy room and confirm the ban lands only after moderation
/// is enabled, then blocks both joins and invites — while leaving everyone else
/// untouched.
#[tokio::test]
async fn banned_user_blocked_from_join_and_invite() {
    let mut h = Harness::new();
    let (_mod_id, mod_tok) = h.register("moderator", "pw").await;
    let (_alice_id, alice_tok) = h.register("alice", "pw").await;
    let (_victim_id, victim_tok) = h.register("victim", "pw").await;
    let (_bob_id, bob_tok) = h.register("bob", "pw").await;

    // Policy room with a ban rule for @victim.
    let policy_room = h.create_room(&mod_tok, json!({})).await;
    let resp = h
        .send_state(
            &mod_tok,
            &policy_room,
            "m.policy.rule.user",
            "rule-victim",
            json!({"entity": mxid("victim"), "recommendation": "m.ban", "reason": "spam"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "policy rule send failed");

    // A public room victim will try to join.
    let public_room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;

    // Before enabling: the rule is inert, victim joins fine.
    join(&h, &victim_tok, &public_room, StatusCode::OK).await;

    // Enable moderation, compiling the policy room's rules.
    h.enable_moderation(&[&policy_room]);

    // A fresh public room (victim isn't already a member of this one).
    let room2 = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;

    // Banned victim can no longer join.
    join(&h, &victim_tok, &room2, StatusCode::FORBIDDEN).await;
    // Non-banned bob is unaffected.
    join(&h, &bob_tok, &room2, StatusCode::OK).await;

    // Banned victim can't be invited anywhere; bob can.
    invite(
        &h,
        &alice_tok,
        &room2,
        &mxid("victim"),
        StatusCode::FORBIDDEN,
    )
    .await;
    invite(&h, &alice_tok, &room2, &mxid("carol"), StatusCode::OK).await;
}

/// Banning a server bans all of its users (invite from a server-glob rule is
/// blocked). Local users on other servers are unaffected.
#[tokio::test]
async fn server_ban_blocks_invite_of_its_users() {
    let mut h = Harness::new();
    let (_mod_id, mod_tok) = h.register("moderator", "pw").await;
    let (_alice_id, alice_tok) = h.register("alice", "pw").await;

    let policy_room = h.create_room(&mod_tok, json!({})).await;
    h.send_state(
        &mod_tok,
        &policy_room,
        "m.policy.rule.server",
        "rule-evil",
        json!({"entity": "evil.com", "recommendation": "m.ban", "reason": "abuse"}),
    )
    .await;
    h.enable_moderation(&[&policy_room]);

    let room = h.create_room(&alice_tok, json!({})).await;
    // A user on the banned server can't be invited (invitee's domain matches).
    invite(
        &h,
        &alice_tok,
        &room,
        "@anyone:evil.com",
        StatusCode::FORBIDDEN,
    )
    .await;
    // A user on a different server is fine.
    invite(&h, &alice_tok, &room, "@friend:good.com", StatusCode::OK).await;
}

/// A banned room id is refused at the join choke point *before* any outbound
/// federation join is attempted (the check keys off the room id string, so a
/// remote/unknown room is still blocked).
#[tokio::test]
async fn banned_room_blocked_before_federation_join() {
    let mut h = Harness::new();
    let (_mod_id, mod_tok) = h.register("moderator", "pw").await;
    let (_alice_id, alice_tok) = h.register("alice", "pw").await;

    let policy_room = h.create_room(&mod_tok, json!({})).await;
    h.send_state(
        &mod_tok,
        &policy_room,
        "m.policy.rule.room",
        "rule-badroom",
        json!({"entity": "!banned:remote.example", "recommendation": "m.ban"}),
    )
    .await;
    h.enable_moderation(&[&policy_room]);

    // Not local, not joined — a normal outcome here would be a federation
    // attempt (and failure). Moderation must short-circuit to 403 first.
    join(
        &h,
        &alice_tok,
        "!banned:remote.example",
        StatusCode::FORBIDDEN,
    )
    .await;
}

/// Adding a rule to a watched policy room refreshes the live ban list via the
/// send-path observation hook — no restart needed.
#[tokio::test]
async fn adding_a_rule_refreshes_the_ban_list() {
    let mut h = Harness::new();
    let (_mod_id, mod_tok) = h.register("moderator", "pw").await;
    let (_alice_id, alice_tok) = h.register("alice", "pw").await;
    let (_victim_id, victim_tok) = h.register("victim", "pw").await;

    // Empty policy room, moderation enabled from the start.
    let policy_room = h.create_room(&mod_tok, json!({})).await;
    h.enable_moderation(&[&policy_room]);

    let room1 = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    // Not banned yet — victim joins fine.
    join(&h, &victim_tok, &room1, StatusCode::OK).await;

    // Moderator adds a ban rule; the send hook recompiles the list.
    let resp = h
        .send_state(
            &mod_tok,
            &policy_room,
            "m.policy.rule.user",
            "rule-late",
            json!({"entity": mxid("victim"), "recommendation": "m.ban"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Now victim is blocked from a different room.
    let room2 = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    join(&h, &victim_tok, &room2, StatusCode::FORBIDDEN).await;
}

/// A non-ban recommendation (e.g. a mute proposal) is not enforced.
#[tokio::test]
async fn non_ban_recommendation_is_ignored() {
    let mut h = Harness::new();
    let (_mod_id, mod_tok) = h.register("moderator", "pw").await;
    let (_alice_id, alice_tok) = h.register("alice", "pw").await;
    let (_victim_id, victim_tok) = h.register("victim", "pw").await;

    let policy_room = h.create_room(&mod_tok, json!({})).await;
    h.send_state(
        &mod_tok,
        &policy_room,
        "m.policy.rule.user",
        "rule-mute",
        json!({"entity": mxid("victim"), "recommendation": "m.mute"}),
    )
    .await;
    h.enable_moderation(&[&policy_room]);

    let room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    // Only m.ban is enforced — a mute proposal leaves join untouched.
    join(&h, &victim_tok, &room, StatusCode::OK).await;
}

/// One policy room carrying all three rule types (plus the room's own
/// create/member/power_levels state) must partition cleanly: each `check_*`
/// sees only its own bucket. Guards the 16-byte `(room ++ type)` prefix scan
/// against picking up adjacent types.
#[tokio::test]
async fn mixed_rule_types_partition_correctly() {
    let mut h = Harness::new();
    let (_mod_id, mod_tok) = h.register("moderator", "pw").await;
    let (_alice_id, alice_tok) = h.register("alice", "pw").await;
    let (_victim_id, victim_tok) = h.register("victim", "pw").await;

    let policy_room = h.create_room(&mod_tok, json!({})).await;
    h.send_state(
        &mod_tok,
        &policy_room,
        "m.policy.rule.user",
        "u",
        json!({"entity": mxid("victim"), "recommendation": "m.ban"}),
    )
    .await;
    h.send_state(
        &mod_tok,
        &policy_room,
        "m.policy.rule.server",
        "s",
        json!({"entity": "evil.com", "recommendation": "m.ban"}),
    )
    .await;
    h.send_state(
        &mod_tok,
        &policy_room,
        "m.policy.rule.room",
        "r",
        json!({"entity": "!bad:remote.example", "recommendation": "m.ban"}),
    )
    .await;
    h.enable_moderation(&[&policy_room]);

    let room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    // user rule
    join(&h, &victim_tok, &room, StatusCode::FORBIDDEN).await;
    // server rule (invite of a user on the banned server)
    invite(&h, &alice_tok, &room, "@x:evil.com", StatusCode::FORBIDDEN).await;
    // room rule
    join(&h, &alice_tok, "!bad:remote.example", StatusCode::FORBIDDEN).await;
    // an entity matching none of the three buckets is unaffected
    invite(&h, &alice_tok, &room, "@ok:good.com", StatusCode::OK).await;
}

/// A raw `PUT /state/m.room.member/{target}` invite must be gated too — it
/// doesn't pass through the /invite handler, so without a check here a
/// PL-holder could invite a banned user around the policy.
#[tokio::test]
async fn state_api_invite_of_banned_user_is_blocked() {
    let mut h = Harness::new();
    let (_mod_id, mod_tok) = h.register("moderator", "pw").await;
    let (_alice_id, alice_tok) = h.register("alice", "pw").await;

    let policy_room = h.create_room(&mod_tok, json!({})).await;
    h.send_state(
        &mod_tok,
        &policy_room,
        "m.policy.rule.user",
        "u",
        json!({"entity": mxid("victim"), "recommendation": "m.ban"}),
    )
    .await;
    h.enable_moderation(&[&policy_room]);

    let room = h.create_room(&alice_tok, json!({})).await;
    // Invite via the state API (bypasses the /invite choke point) → 403.
    let resp = h
        .send_state(
            &alice_tok,
            &room,
            "m.room.member",
            &mxid("victim"),
            json!({"membership": "invite"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "state-api invite");

    // Inviting a non-banned user via the state API still works.
    let resp = h
        .send_state(
            &alice_tok,
            &room,
            "m.room.member",
            &mxid("carol"),
            json!({"membership": "invite"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "state-api invite non-banned");
}

/// createRoom's initial `invite` list must be gated — local invitees are built
/// inline (not via the /invite handler), so without an up-front check a banned
/// user could be invited at room creation.
#[tokio::test]
async fn createroom_invite_of_banned_user_is_blocked() {
    let mut h = Harness::new();
    let (_mod_id, mod_tok) = h.register("moderator", "pw").await;
    let (_alice_id, alice_tok) = h.register("alice", "pw").await;
    let (_victim_id, _victim_tok) = h.register("victim", "pw").await;

    let policy_room = h.create_room(&mod_tok, json!({})).await;
    h.send_state(
        &mod_tok,
        &policy_room,
        "m.policy.rule.user",
        "u",
        json!({"entity": mxid("victim"), "recommendation": "m.ban"}),
    )
    .await;
    h.enable_moderation(&[&policy_room]);

    // createRoom inviting the banned user → 403, room not created.
    let resp = h
        .request(
            Request::post("/_matrix/client/v3/createRoom")
                .header("authorization", format!("Bearer {alice_tok}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"invite": [mxid("victim")]}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "createRoom w/ banned invite"
    );

    // Inviting only non-banned users still works.
    let resp = h
        .request(
            Request::post("/_matrix/client/v3/createRoom")
                .header("authorization", format!("Bearer {alice_tok}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"invite": [mxid("carol")]}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "createRoom w/ clean invite");
}

/// A banned local user can't knock, and nobody can knock on a banned room.
#[tokio::test]
async fn banned_user_and_room_blocked_from_knock() {
    let mut h = Harness::new();
    let (_mod_id, mod_tok) = h.register("moderator", "pw").await;
    let (_alice_id, alice_tok) = h.register("alice", "pw").await;
    let (_victim_id, victim_tok) = h.register("victim", "pw").await;

    let policy_room = h.create_room(&mod_tok, json!({})).await;
    h.send_state(
        &mod_tok,
        &policy_room,
        "m.policy.rule.user",
        "u",
        json!({"entity": mxid("victim"), "recommendation": "m.ban"}),
    )
    .await;
    h.send_state(
        &mod_tok,
        &policy_room,
        "m.policy.rule.room",
        "r",
        json!({"entity": "!bad:remote.example", "recommendation": "m.ban"}),
    )
    .await;
    h.enable_moderation(&[&policy_room]);

    // A knock-enabled room alice hosts.
    let room = h
        .create_room(
            &alice_tok,
            json!({"preset": "public_chat", "initial_state": [
                {"type": "m.room.join_rules", "state_key": "", "content": {"join_rule": "knock"}}
            ]}),
        )
        .await;

    // Banned victim can't knock.
    knock(&h, &victim_tok, &room, StatusCode::FORBIDDEN).await;
    // Nobody can knock on a banned (remote) room — blocked before federation.
    knock(&h, &alice_tok, "!bad:remote.example", StatusCode::FORBIDDEN).await;
}

// ---- helpers ----

async fn knock(h: &Harness, token: &str, room_id: &str, expect: StatusCode) {
    let resp = h
        .request(
            Request::post(format!("/_matrix/client/v3/knock/{room_id}"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), expect, "knock {room_id} status");
}

async fn join(h: &Harness, token: &str, room_id: &str, expect: StatusCode) {
    let resp = h
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{room_id}/join"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), expect, "join {room_id} status");
}

async fn invite(h: &Harness, token: &str, room_id: &str, target: &str, expect: StatusCode) {
    let resp = h
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{room_id}/invite"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"user_id": target}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), expect, "invite {target} status");
}
