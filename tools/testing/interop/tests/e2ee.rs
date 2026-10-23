//! E2EE key federation: device keys, one-time keys, to-device messages and
//! device-list tracking crossing between vela and Synapse. Keys are fake
//! strings; what is compared is what each server hands out.

use anyhow::{Result, bail};
use serde_json::{Value, json};
use vela_interop::{InteropEnv, User, assert_membership, eventually, room_body, users};

fn skip() -> Option<InteropEnv> {
    let env = vela_interop::rig();
    if env.is_none() {
        eprintln!("skipping: interop rig not configured (run via tools/testing/interop/run.sh)");
    }
    env
}

/// Both users in a shared room, keys uploaded on both sides.
async fn shared_room(env: &InteropEnv) -> Result<(User, User, String)> {
    let (v, s) = users(env).await?;
    let room = v
        .create_room(room_body(
            None,
            json!({"preset": "private_chat", "invite": [s.user_id]}),
        ))
        .await?;
    eventually("synapse to deliver the invite", || async {
        s.is_invited_to(&room).await
    })
    .await?;
    s.join(&room, &env.vela_name).await?;
    assert_membership(&v, &room, &s.user_id, "join").await?;
    assert_membership(&s, &room, &s.user_id, "join").await?;
    Ok((v, s, room))
}

fn device_keys_of<'a>(query: &'a Value, user: &str, device: &str) -> Option<&'a Value> {
    let dk = query["device_keys"][user].get(device)?;
    Some(dk)
}

/// Device keys uploaded on one side are visible through /keys/query on the
/// other, byte-for-byte in the fields the uploader controls.
#[tokio::test]
async fn device_keys_query_cross_federation() -> Result<()> {
    let Some(env) = skip() else { return Ok(()) };
    let (v, s, _room) = shared_room(&env).await?;
    v.upload_device_keys("v1", 0).await?;
    s.upload_device_keys("s1", 0).await?;

    for (querier, owner) in [(&v, &s), (&s, &v)] {
        let owner_id = owner.user_id.clone();
        let owner_dev = owner.device_id.clone();
        let label = format!("{} to see {}'s device keys", querier.hs, owner.hs);
        eventually(&label, || async {
            let q = querier.query_keys(&[&owner_id]).await?;
            Ok(device_keys_of(&q, &owner_id, &owner_dev).is_some())
        })
        .await?;
        let remote = querier.query_keys(&[&owner_id]).await?;
        let local = owner.query_keys(&[&owner_id]).await?;
        let r = device_keys_of(&remote, &owner_id, &owner_dev).unwrap();
        let l = device_keys_of(&local, &owner_id, &owner_dev).unwrap();
        for field in ["user_id", "device_id", "algorithms", "keys", "signatures"] {
            if r[field] != l[field] {
                bail!(
                    "DIVERGENCE: {} shows {}'s {field} as {} but the owner shows {}",
                    querier.hs,
                    owner.hs,
                    r[field],
                    l[field]
                );
            }
        }
    }
    Ok(())
}

/// A key re-upload on one side surfaces as `device_lists.changed` on the
/// other side's incremental sync and in /keys/changes.
#[tokio::test]
async fn device_list_change_cross_federation() -> Result<()> {
    let Some(env) = skip() else { return Ok(()) };
    let (v, s, _room) = shared_room(&env).await?;
    v.upload_device_keys("v1", 0).await?;
    s.upload_device_keys("s1", 0).await?;

    for (changer, watcher) in [(&v, &s), (&s, &v)] {
        // Settle: make sure the watcher has already seen the first upload.
        let changer_id = changer.user_id.clone();
        eventually(
            &format!("{} to know {}'s keys", watcher.hs, changer.hs),
            || async {
                let q = watcher.query_keys(&[&changer_id]).await?;
                Ok(q["device_keys"][&changer_id]
                    .as_object()
                    .is_some_and(|d| !d.is_empty()))
            },
        )
        .await?;
        let before = watcher.sync_once().await?;
        let since = before["next_batch"].as_str().unwrap().to_string();

        changer.upload_device_keys("rotated", 0).await?;

        let since2 = since.clone();
        eventually(
            &format!(
                "{} to see {} in device_lists.changed",
                watcher.hs, changer.hs
            ),
            || async {
                let v = watcher.sync_since(Some(&since2)).await?;
                Ok(v["device_lists"]["changed"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|x| x.as_str() == Some(&changer_id))))
            },
        )
        .await?;
        let now = watcher.sync_once().await?;
        let to = now["next_batch"].as_str().unwrap();
        let changed = watcher.key_changes(&since, to).await?;
        if !changed.contains(&changer_id) {
            bail!(
                "DIVERGENCE: {} /keys/changes omits {} after a key rotation: {changed:?}",
                watcher.hs,
                changer.hs
            );
        }
    }
    Ok(())
}

/// One-time keys claimed across federation: each claim hands out exactly
/// one key, keys are not reused, and the owner's count drops.
#[tokio::test]
async fn one_time_key_claim_cross_federation() -> Result<()> {
    let Some(env) = skip() else { return Ok(()) };
    let (v, s, _room) = shared_room(&env).await?;

    for (owner, claimer) in [(&v, &s), (&s, &v)] {
        let counts = owner.upload_device_keys("otk", 2).await?;
        if counts["signed_curve25519"].as_u64() != Some(2) {
            bail!("{}: upload reported counts {counts}", owner.hs);
        }
        let owner_id = owner.user_id.clone();
        let owner_dev = owner.device_id.clone();
        let first = claimer
            .claim_key(&owner_id, &owner_dev, "signed_curve25519")
            .await?;
        let second = claimer
            .claim_key(&owner_id, &owner_dev, "signed_curve25519")
            .await?;
        let third = claimer
            .claim_key(&owner_id, &owner_dev, "signed_curve25519")
            .await?;
        let key_ids = |v: &Value| -> Vec<String> {
            v.as_object()
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default()
        };
        let (k1, k2, k3) = (key_ids(&first), key_ids(&second), key_ids(&third));
        if k1.len() != 1 || k2.len() != 1 || k1 == k2 || !k3.is_empty() {
            bail!(
                "DIVERGENCE: {} claiming from {}: got {k1:?}, {k2:?}, then {k3:?} (want two distinct keys then none)",
                claimer.hs,
                owner.hs
            );
        }
        let after = owner.sync_once().await?;
        let left = after["device_one_time_keys_count"]["signed_curve25519"]
            .as_u64()
            .unwrap_or(0);
        if left != 0 {
            bail!(
                "{}: {left} one-time keys left after two remote claims",
                owner.hs
            );
        }
    }
    Ok(())
}

/// To-device messages to a named device and to `*` cross both ways and
/// arrive intact in the recipient's sync.
#[tokio::test]
async fn to_device_cross_federation() -> Result<()> {
    let Some(env) = skip() else { return Ok(()) };
    let (v, s, _room) = shared_room(&env).await?;
    v.upload_device_keys("v1", 0).await?;
    s.upload_device_keys("s1", 0).await?;

    for (sender, recipient) in [(&v, &s), (&s, &v)] {
        for target in [recipient.device_id.as_str(), "*"] {
            let marker = format!("{}-to-{}-{target}", sender.hs, recipient.hs);
            let before = recipient.sync_once().await?;
            let since = before["next_batch"].as_str().unwrap().to_string();
            sender
                .send_to_device(
                    "m.room_key_request",
                    &recipient.user_id,
                    target,
                    json!({"action": "request", "marker": marker}),
                )
                .await?;
            let sender_id = sender.user_id.clone();
            let marker2 = marker.clone();
            eventually(
                &format!(
                    "{} to receive to-device from {} (device {target})",
                    recipient.hs, sender.hs
                ),
                || async {
                    let v = recipient.sync_since(Some(&since)).await?;
                    Ok(v["to_device"]["events"].as_array().is_some_and(|evs| {
                        evs.iter().any(|e| {
                            e["type"] == "m.room_key_request"
                                && e["sender"] == sender_id
                                && e["content"]["marker"] == marker2
                        })
                    }))
                },
            )
            .await?;
        }
    }
    Ok(())
}
