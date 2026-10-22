//! Differential scenarios for history and state surfaces: backfill after a
//! late join, redaction propagation (including cross-server moderation),
//! and room upgrade across federation. Same room-version matrix and
//! env-gating as `federation.rs`.

use anyhow::Result;
use serde_json::json;
use vela_interop::{
    InteropEnv, User, assert_event_redacted, assert_membership, assert_state_converged,
    assert_timeline_contains, cell, eventually, room_body, users, version_matrix,
};

version_matrix!(
    backfill_vela_history,
    backfill_synapse_history,
    redactions_propagate,
    upgrade_from_vela,
    upgrade_from_synapse,
);

const HISTORY_LEN: usize = 30;

/// `origin` creates a room and fills it with history before `joiner` joins
/// via `via`; the joiner must then paginate every pre-join event out of
/// its own `/messages`, which it can only do by backfilling from the origin.
async fn backfill(
    origin: &User,
    joiner: &User,
    via: &str,
    version: Option<&str>,
    label: &str,
) -> Result<()> {
    let room = origin
        .create_room(room_body(
            version,
            json!({"preset": "public_chat", "name": "history"}),
        ))
        .await?;
    let mut sent = Vec::with_capacity(HISTORY_LEN);
    for i in 0..HISTORY_LEN {
        sent.push(origin.send_message(&room, &format!("history {i}")).await?);
    }
    joiner.join(&room, via).await?;
    assert_membership(origin, &room, &joiner.user_id, "join").await?;
    assert_timeline_contains(joiner, &room, &sent).await?;
    // And the join itself travelled back: a message after the join is seen
    // by both, proving the joiner's DAG is attached, not just backfilled.
    let after = joiner.send_message(&room, "after join").await?;
    assert_timeline_contains(origin, &room, &[after]).await?;
    assert_state_converged(origin, joiner, &room, label).await
}

async fn backfill_vela_history(env: &InteropEnv, version: Option<&str>) -> Result<()> {
    let (v, s) = users(env).await?;
    let label = format!("backfill-vela-history-{}", cell(version));
    backfill(&v, &s, &env.vela_name, version, &label).await
}

async fn backfill_synapse_history(env: &InteropEnv, version: Option<&str>) -> Result<()> {
    let (v, s) = users(env).await?;
    let label = format!("backfill-synapse-history-{}", cell(version));
    backfill(&s, &v, &env.synapse_name, version, &label).await
}

/// Self-redaction from each side, then the vela creator redacting the
/// Synapse user's message (cross-server moderation: needs the redact power
/// level and the per-version redaction algorithm to agree). Every
/// redaction is asserted on both servers.
async fn redactions_propagate(env: &InteropEnv, version: Option<&str>) -> Result<()> {
    let (v, s) = users(env).await?;
    let room = v
        .create_room(room_body(
            version,
            json!({"preset": "public_chat", "name": "redactions"}),
        ))
        .await?;
    s.join(&room, &env.vela_name).await?;
    assert_membership(&v, &room, &s.user_id, "join").await?;

    let v_msg = v.send_message(&room, "vela says").await?;
    let s_msg = s.send_message(&room, "synapse says").await?;
    let s_msg2 = s.send_message(&room, "synapse says again").await?;
    assert_timeline_contains(&v, &room, &[s_msg.clone(), s_msg2.clone()]).await?;
    assert_timeline_contains(&s, &room, std::slice::from_ref(&v_msg)).await?;

    v.redact(&room, &v_msg, "self").await?;
    s.redact(&room, &s_msg, "self").await?;
    v.redact(&room, &s_msg2, "moderation").await?;

    for id in [&v_msg, &s_msg, &s_msg2] {
        assert_event_redacted(&v, &room, id).await?;
        assert_event_redacted(&s, &room, id).await?;
    }
    let label = format!("redactions-{}", cell(version));
    assert_state_converged(&v, &s, &room, &label).await
}

/// `upgrader` upgrades a room both are joined to; the other side must see
/// the tombstone, follow `replacement_room` to the new room via `via`,
/// and both must agree on the new room's state. The target version is the
/// cell's; the default cell leaves it to the upgrader's server.
async fn upgrade(
    upgrader: &User,
    follower: &User,
    via: &str,
    version: Option<&str>,
    label: &str,
) -> Result<()> {
    let old = upgrader
        .create_room(room_body(
            None,
            json!({"preset": "public_chat", "name": "before"}),
        ))
        .await?;
    follower.join(&old, via).await?;
    assert_membership(upgrader, &old, &follower.user_id, "join").await?;

    let new_version = match version {
        Some(v) => v.to_string(),
        None => upgrader
            .state_event(&old, "m.room.create", "")
            .await?
            .and_then(|c| c["room_version"].as_str().map(str::to_string))
            .unwrap_or_else(|| "12".to_string()),
    };
    let new = upgrader.upgrade(&old, &new_version).await?;

    eventually("follower to see the tombstone", || async {
        Ok(follower
            .state_event(&old, "m.room.tombstone", "")
            .await?
            .is_some_and(|t| t["replacement_room"].as_str() == Some(new.as_str())))
    })
    .await?;
    assert_state_converged(upgrader, follower, &old, &format!("{label}-old")).await?;

    follower.join(&new, via).await?;
    assert_membership(upgrader, &new, &follower.user_id, "join").await?;
    let create = follower
        .state_event(&new, "m.room.create", "")
        .await?
        .ok_or_else(|| anyhow::anyhow!("no create event in the new room"))?;
    anyhow::ensure!(
        create["predecessor"]["room_id"].as_str() == Some(old.as_str()),
        "new room's predecessor is {:?}, want {old}",
        create["predecessor"]
    );
    anyhow::ensure!(
        create["room_version"].as_str() == Some(new_version.as_str()),
        "new room version is {:?}, want {new_version}",
        create["room_version"]
    );
    let msg = follower.send_message(&new, "after upgrade").await?;
    assert_timeline_contains(upgrader, &new, &[msg]).await?;
    assert_state_converged(upgrader, follower, &new, &format!("{label}-new")).await
}

async fn upgrade_from_vela(env: &InteropEnv, version: Option<&str>) -> Result<()> {
    let (v, s) = users(env).await?;
    let label = format!("upgrade-from-vela-{}", cell(version));
    upgrade(&v, &s, &env.vela_name, version, &label).await
}

async fn upgrade_from_synapse(env: &InteropEnv, version: Option<&str>) -> Result<()> {
    let (v, s) = users(env).await?;
    let label = format!("upgrade-from-synapse-{}", cell(version));
    upgrade(&s, &v, &env.synapse_name, version, &label).await
}
