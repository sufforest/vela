//! Differential federation scenarios: vela ↔ Synapse.
//!
//! Env-gated — each test skips unless `run.sh` has exported the rig's
//! coordinates. Synapse is the oracle: assertions require both servers to
//! converge to the same view, and a timeout is reported as DIVERGENCE with
//! evidence dumped under `target/interop-evidence/`.

use anyhow::Result;
use serde_json::json;
use vela_interop::{
    InteropEnv, User, assert_membership, assert_state_converged, assert_timeline_contains,
    eventually, register,
};

/// Skip (returning None) unless the rig is up.
fn rig() -> Option<InteropEnv> {
    let env = InteropEnv::from_env();
    if env.is_none() {
        eprintln!("skipped: interop rig not running (use tools/testing/interop/run.sh)");
    }
    env
}

async fn users(env: &InteropEnv) -> Result<(User, User)> {
    let v = register("vela", &env.vela_cs, "vuser").await?;
    let s = register("synapse", &env.synapse_cs, "suser").await?;
    Ok((v, s))
}

/// vela-created room; Synapse user joins over federation; messages flow
/// both ways; timelines and state converge.
#[tokio::test]
async fn vela_room_synapse_joins() -> Result<()> {
    let Some(env) = rig() else { return Ok(()) };
    let (v, s) = users(&env).await?;

    let room = v
        .create_room(json!({"preset": "public_chat", "name": "vela-origin"}))
        .await?;
    s.join(&room, &env.vela_name).await?;
    assert_membership(&v, &room, &s.user_id, "join").await?;

    let mut sent = Vec::new();
    for i in 0..3 {
        sent.push(v.send_message(&room, &format!("from vela {i}")).await?);
        sent.push(s.send_message(&room, &format!("from synapse {i}")).await?);
    }
    assert_timeline_contains(&v, &room, &sent).await?;
    assert_timeline_contains(&s, &room, &sent).await?;
    assert_state_converged(&v, &s, &room, "vela-room-synapse-joins").await
}

/// Synapse-created room; vela joins over federation (real make_join /
/// send_join against Synapse, foreign auth chains); messages both ways.
#[tokio::test]
async fn synapse_room_vela_joins() -> Result<()> {
    let Some(env) = rig() else { return Ok(()) };
    let (v, s) = users(&env).await?;

    let room = s
        .create_room(json!({"preset": "public_chat", "name": "synapse-origin"}))
        .await?;
    v.join(&room, &env.synapse_name).await?;
    assert_membership(&s, &room, &v.user_id, "join").await?;

    let mut sent = Vec::new();
    for i in 0..3 {
        sent.push(s.send_message(&room, &format!("from synapse {i}")).await?);
        sent.push(v.send_message(&room, &format!("from vela {i}")).await?);
    }
    assert_timeline_contains(&s, &room, &sent).await?;
    assert_timeline_contains(&v, &room, &sent).await?;
    assert_state_converged(&v, &s, &room, "synapse-room-vela-joins").await
}

/// Both sides write the same state pair near-simultaneously, repeatedly.
/// State resolution must land both servers on the SAME winner every round —
/// this is the classic cross-implementation divergence probe.
#[tokio::test]
async fn conflicting_state_converges() -> Result<()> {
    let Some(env) = rig() else { return Ok(()) };
    let (v, s) = users(&env).await?;

    // Let any joined member set the topic so both sides can race.
    let room = v
        .create_room(json!({
            "preset": "public_chat",
            "power_level_content_override": {"events": {"m.room.topic": 0}},
        }))
        .await?;
    s.join(&room, &env.vela_name).await?;
    assert_membership(&v, &room, &s.user_id, "join").await?;

    for round in 0..3 {
        // Fire both writes concurrently; both are locally valid, federation
        // crosses them, and state res picks one winner.
        let (rv, rs) = tokio::join!(
            v.send_state(
                &room,
                "m.room.topic",
                "",
                json!({"topic": format!("vela topic r{round}")}),
            ),
            s.send_state(
                &room,
                "m.room.topic",
                "",
                json!({"topic": format!("synapse topic r{round}")}),
            ),
        );
        rv?;
        rs?;
        assert_state_converged(&v, &s, &room, &format!("topic-race-round-{round}")).await?;
    }
    Ok(())
}

/// Invite → join → kick → rejoin → ban → rejected rejoin → unban → rejoin,
/// asserting membership agreement on both servers at every step.
///
/// Synapse-side views are read through a second Synapse user who stays
/// joined the whole dance ("observer"): departed users' ability to read
/// room state is an implementation visibility policy (Synapse allows a
/// kicked user, refuses a banned one), and the property under test is
/// what each SERVER believes, not what a departed user may see.
#[tokio::test]
async fn membership_dance() -> Result<()> {
    let Some(env) = rig() else { return Ok(()) };
    let (v, s) = users(&env).await?;
    let observer = register("synapse", &env.synapse_cs, "sobserver").await?;

    let room = v
        .create_room(json!({"preset": "public_chat", "name": "dance"}))
        .await?;
    observer.join(&room, &env.vela_name).await?;
    assert_membership(&v, &room, &observer.user_id, "join").await?;

    // Federated invite, accepted. The invitee can't read room state before
    // joining, so invite delivery is asserted via the invitee's /sync.
    v.invite(&room, &s.user_id).await?;
    assert_membership(&v, &room, &s.user_id, "invite").await?;
    eventually("synapse to deliver the invite via /sync", || async {
        s.is_invited_to(&room).await
    })
    .await?;
    s.join(&room, &env.vela_name).await?;
    assert_membership(&v, &room, &s.user_id, "join").await?;
    assert_membership(&observer, &room, &s.user_id, "join").await?;

    // Kick over federation; both sides agree; kicked user rejoins (public).
    v.kick(&room, &s.user_id).await?;
    assert_membership(&v, &room, &s.user_id, "leave").await?;
    assert_membership(&observer, &room, &s.user_id, "leave").await?;
    s.join(&room, &env.vela_name).await?;
    assert_membership(&v, &room, &s.user_id, "join").await?;

    // Ban; both sides agree; rejoin must fail from the Synapse side.
    v.ban(&room, &s.user_id).await?;
    assert_membership(&v, &room, &s.user_id, "ban").await?;
    assert_membership(&observer, &room, &s.user_id, "ban").await?;
    let err = s.join_expect_error(&room, &env.vela_name).await?;
    eprintln!("banned rejoin correctly refused: {err}");

    // Unban; the previously banned user can come back.
    v.unban(&room, &s.user_id).await?;
    assert_membership(&observer, &room, &s.user_id, "leave").await?;
    s.join(&room, &env.vela_name).await?;
    assert_membership(&v, &room, &s.user_id, "join").await?;
    assert_membership(&observer, &room, &s.user_id, "join").await?;

    assert_state_converged(&v, &observer, &room, "membership-dance").await
}
