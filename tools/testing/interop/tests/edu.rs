//! Ephemeral data over federation: typing, read receipts and presence,
//! each sent from one side and read from the other's `/sync`. These are
//! wire-shape checks (a self-consistent misreading of the EDU format only
//! shows against a second implementation), so one cell is enough.

use anyhow::Result;
use serde_json::json;
use vela_interop::{User, assert_membership, eventually, rig, users};

#[tokio::test]
async fn typing_receipts_and_presence_cross_federation() -> Result<()> {
    let Some(env) = rig() else { return Ok(()) };
    let (v, s) = users(&env).await?;

    let room = v
        .create_room(json!({"preset": "public_chat", "name": "edus"}))
        .await?;
    s.join(&room, &env.vela_name).await?;
    assert_membership(&v, &room, &s.user_id, "join").await?;
    // EDUs are best-effort and never resent: make sure the joining side
    // has finished persisting its own join before anything ephemeral is
    // sent its way, or the first typing update lands on a room it does
    // not yet consider itself in.
    assert_membership(&s, &room, &s.user_id, "join").await?;

    // Typing, both directions, start then stop.
    for (typist, reader) in [(&v, &s), (&s, &v)] {
        typist.typing(&room, true).await?;
        eventually(
            &format!("{} to see {} typing", reader.hs, typist.hs),
            || async { Ok(typing_users(reader, &room).await?.contains(&typist.user_id)) },
        )
        .await?;
        typist.typing(&room, false).await?;
        eventually(
            &format!("{} to see {} stop typing", reader.hs, typist.hs),
            || async { Ok(!typing_users(reader, &room).await?.contains(&typist.user_id)) },
        )
        .await?;
    }

    // Read receipts, both directions.
    for (author, reader) in [(&v, &s), (&s, &v)] {
        let event_id = author.send_message(&room, "read me").await?;
        eventually("message to arrive before the receipt", || async {
            Ok(reader.event(&room, &event_id).await.is_ok())
        })
        .await?;
        reader.read_receipt(&room, &event_id).await?;
        eventually(
            &format!("{} to see {}'s read receipt", author.hs, reader.hs),
            || async { read_receipt_present(author, &room, &event_id, &reader.user_id).await },
        )
        .await?;
    }

    // Presence, both directions: the status set on one side is what the
    // other side's sync and /presence endpoint report.
    for (subject, watcher) in [(&v, &s), (&s, &v)] {
        let msg = format!("hello from {}", subject.hs);
        subject.set_presence("online", &msg).await?;
        eventually(
            &format!("{} to see {}'s presence", watcher.hs, subject.hs),
            || async {
                let p = watcher.presence_of(&subject.user_id).await?;
                Ok(p["presence"] == "online" && p["status_msg"] == msg)
            },
        )
        .await?;
        eventually(
            &format!("{}'s sync to carry {}'s presence", watcher.hs, subject.hs),
            || async {
                Ok(watcher
                    .presence_events()
                    .await?
                    .iter()
                    .any(|e| e["sender"] == subject.user_id && e["content"]["status_msg"] == msg))
            },
        )
        .await?;
    }
    Ok(())
}

async fn typing_users(u: &User, room: &str) -> Result<Vec<String>> {
    Ok(u.ephemeral(room)
        .await?
        .iter()
        .filter(|e| e["type"] == "m.typing")
        .flat_map(|e| {
            e["content"]["user_ids"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect())
}

async fn read_receipt_present(u: &User, room: &str, event_id: &str, by: &str) -> Result<bool> {
    Ok(u.ephemeral(room)
        .await?
        .iter()
        .filter(|e| e["type"] == "m.receipt")
        .any(|e| e["content"][event_id]["m.read"][by].is_object()))
}
