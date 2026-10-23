//! Membership paths the first scenarios left out: knocking, restricted
//! joins through a space, and invites that originate on the Synapse side.
//! Each is signed by one server and verified by the other, which is the
//! shape every finding so far has had.

use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use vela_interop::{
    InteropEnv, User, assert_membership, assert_state_converged, cell, eventually, register,
    room_body, users, version_matrix,
};

version_matrix!(
    knock_on_vela_room >= 7,
    knock_on_synapse_room >= 7,
    restricted_join_into_vela_space >= 8,
    restricted_join_into_synapse_space >= 8,
    invite_from_synapse,
);

/// Two knockers from the far side: one is let in, one is turned away.
/// `resident` owns the room; `observer` is a second user on the far
/// server who ends up joined, so the far server's view can be read.
async fn knock_dance(
    version: Option<&str>,
    resident: &User,
    resident_name: &str,
    far_cs: &str,
    far_label: &str,
) -> Result<()> {
    let accepted = register(far_label, far_cs, "knock-in").await?;
    let refused = register(far_label, far_cs, "knock-out").await?;

    let room = resident
        .create_room(room_body(
            version,
            json!({
                "preset": "private_chat",
                "name": "knock",
                "initial_state": [{
                    "type": "m.room.join_rules",
                    "state_key": "",
                    "content": {"join_rule": "knock"},
                }],
            }),
        ))
        .await?;

    accepted.knock(&room, resident_name, "let me in").await?;
    assert_membership(resident, &room, &accepted.user_id, "knock").await?;
    eventually("knocker to see the knock in /sync", || async {
        accepted.is_knocking_on(&room).await
    })
    .await?;

    // Accept: the resident invites, the knocker joins.
    resident.invite(&room, &accepted.user_id).await?;
    eventually("accepted knocker to be invited", || async {
        accepted.is_invited_to(&room).await
    })
    .await?;
    accepted.join(&room, resident_name).await?;
    assert_membership(resident, &room, &accepted.user_id, "join").await?;

    // Refuse: the resident kicks the second knocker back to leave.
    refused.knock(&room, resident_name, "me too").await?;
    assert_membership(resident, &room, &refused.user_id, "knock").await?;
    assert_membership(&accepted, &room, &refused.user_id, "knock").await?;
    resident.kick(&room, &refused.user_id).await?;
    assert_membership(resident, &room, &refused.user_id, "leave").await?;
    assert_membership(&accepted, &room, &refused.user_id, "leave").await?;

    let label = format!("knock-{}-{}", resident.hs, cell(version));
    assert_state_converged(resident, &accepted, &room, &label).await
}

async fn knock_on_vela_room(env: &InteropEnv, version: Option<&str>) -> Result<()> {
    let v = register("vela", &env.vela_cs, "vuser").await?;
    knock_dance(version, &v, &env.vela_name, &env.synapse_cs, "synapse").await
}

async fn knock_on_synapse_room(env: &InteropEnv, version: Option<&str>) -> Result<()> {
    let s = register("synapse", &env.synapse_cs, "suser").await?;
    knock_dance(version, &s, &env.synapse_name, &env.vela_cs, "vela").await
}

/// A space and a room restricted to its members, both on `resident`'s
/// server. A far-side user joins the space, then the room, so the far
/// server must get the join authorised by the resident; a far-side user
/// outside the space must be refused by both.
async fn restricted_dance(
    version: Option<&str>,
    resident: &User,
    resident_name: &str,
    far_cs: &str,
    far_label: &str,
) -> Result<()> {
    let member = register(far_label, far_cs, "space-member").await?;
    let outsider = register(far_label, far_cs, "space-outsider").await?;

    let space = resident
        .create_room(room_body(
            version,
            json!({
                "preset": "public_chat",
                "name": "space",
                "creation_content": {"type": "m.space"},
            }),
        ))
        .await?;
    let room = resident
        .create_room(room_body(
            version,
            json!({
                "preset": "private_chat",
                "name": "restricted",
                "initial_state": [{
                    "type": "m.room.join_rules",
                    "state_key": "",
                    "content": {
                        "join_rule": "restricted",
                        "allow": [{"type": "m.room_membership", "room_id": space}],
                    },
                }],
            }),
        ))
        .await?;

    member.join(&space, resident_name).await?;
    assert_membership(resident, &space, &member.user_id, "join").await?;
    member.join(&room, resident_name).await?;
    assert_membership(resident, &room, &member.user_id, "join").await?;

    // The join was authorised by a resident-server user, and both servers
    // must hold that authorisation in the same member event.
    for u in [resident, &member] {
        let content = u
            .state_event(&room, "m.room.member", &member.user_id)
            .await?
            .ok_or_else(|| anyhow!("{} has no member event for the joiner", u.hs))?;
        let authoriser = content["join_authorised_via_users_server"]
            .as_str()
            .ok_or_else(|| {
                anyhow!(
                    "{}: restricted join lacks join_authorised_via_users_server: {content}",
                    u.hs
                )
            })?;
        if !authoriser.ends_with(&format!(":{resident_name}")) {
            return Err(anyhow!(
                "{}: authoriser {authoriser} is not on the resident server",
                u.hs
            ));
        }
    }

    let err = outsider.join_expect_error(&room, resident_name).await?;
    eprintln!("outsider correctly refused: {err}");
    if resident.membership_of(&room, &outsider.user_id).await? == Some("join".into()) {
        return Err(anyhow!(
            "{} let the outsider into the restricted room",
            resident.hs
        ));
    }

    let label = format!("restricted-{}-{}", resident.hs, cell(version));
    assert_state_converged(resident, &member, &room, &label).await
}

async fn restricted_join_into_vela_space(env: &InteropEnv, version: Option<&str>) -> Result<()> {
    let v = register("vela", &env.vela_cs, "vuser").await?;
    restricted_dance(version, &v, &env.vela_name, &env.synapse_cs, "synapse").await
}

async fn restricted_join_into_synapse_space(env: &InteropEnv, version: Option<&str>) -> Result<()> {
    let s = register("synapse", &env.synapse_cs, "suser").await?;
    restricted_dance(version, &s, &env.synapse_name, &env.vela_cs, "vela").await
}

/// Synapse invites a vela user: vela receives the invite over federation,
/// shows it with its stripped state, and the invitee joins.
async fn invite_from_synapse(env: &InteropEnv, version: Option<&str>) -> Result<()> {
    let (v, s) = users(env).await?;
    let room = s
        .create_room(room_body(
            version,
            json!({"preset": "private_chat", "name": "from synapse"}),
        ))
        .await?;

    s.invite(&room, &v.user_id).await?;
    assert_membership(&s, &room, &v.user_id, "invite").await?;
    eventually("vela to deliver the invite via /sync", || async {
        v.is_invited_to(&room).await
    })
    .await?;

    let stripped = v.invite_state(&room).await?;
    let has = |ty: &str, sk: &str| {
        stripped
            .iter()
            .any(|e| e["type"] == ty && e["state_key"] == sk)
    };
    if !has("m.room.create", "") || !has("m.room.member", &v.user_id) {
        return Err(anyhow!(
            "invite_state lacks create or the invitee's membership: {}",
            Value::Array(stripped)
        ));
    }

    v.join(&room, &env.synapse_name).await?;
    assert_membership(&s, &room, &v.user_id, "join").await?;
    let label = format!("invite-from-synapse-{}", cell(version));
    assert_state_converged(&v, &s, &room, &label).await
}
