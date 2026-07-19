use crate::middleware::json::Json;
use axum::extract::{Path, State};
use serde_json::{Value, json};
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

/// GET /_matrix/client/v3/user/{userId}/account_data/{type}
pub async fn get_account_data(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, data_type)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only access own account data".into()).into());
    }

    let value = state
        .db
        .get_account_data(user.user_nid, &data_type)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("account data not found".into())))?;
    // MSC3391: empty content `{}` is functionally a deletion. Surface
    // it as 404 from the GET endpoint so clients agree the entry is
    // gone, even though /sync still streams the empty-content event
    // (lets other devices catch up).
    if is_empty_object(&value) {
        return Err(VelaError::NotFound("account data not found".into()).into());
    }
    Ok(Json(value))
}

/// True when `v` is a JSON object with no keys (`{}`).
fn is_empty_object(v: &Value) -> bool {
    v.as_object().is_some_and(|o| o.is_empty())
}

/// Guard-rail on one account-data value's serialized size, from
/// `[limits] max_account_data_bytes` (0 = disabled). See the config
/// field's doc for the rationale; the warn keeps a legitimate
/// rejection diagnosable, since no other homeserver enforces this.
pub(crate) fn check_value_size(state: &AppState, body: &Value) -> Result<(), ApiError> {
    let max = state.config.max_account_data_bytes;
    if max == 0 {
        return Ok(());
    }
    let size = serde_json::to_vec(body)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    if size > max {
        tracing::warn!(size, max, "refused oversized account data value");
        return Err(ApiError(VelaError::EventTooLarge(format!(
            "account data value too large ({size} > {max} bytes)"
        ))));
    }
    Ok(())
}

/// PUT /_matrix/client/v3/user/{userId}/account_data/{type}
pub async fn set_account_data(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, data_type)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only set own account data".into()).into());
    }
    check_value_size(&state, &body)?;

    state
        .db
        .set_account_data(user.user_nid, &data_type, &body)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Wake any pending /sync so the writer sees their own change on the
    // next poll without waiting for the long-poll timeout. Element's
    // cross-signing setup writes m.cross_signing.* and waits for them
    // to stream back before continuing; without this wake, the whole
    // flow stalls for up to 30s per write.
    crate::router::notify_user(&state, user.user_nid);

    Ok(Json(json!({})))
}

/// GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}
pub async fn get_room_account_data(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, room_id, data_type)): Path<(String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only access own account data".into()).into());
    }

    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    let value = state
        .db
        .get_room_account_data(user.user_nid, room_nid, &data_type)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("account data not found".into())))?;
    if is_empty_object(&value) {
        return Err(VelaError::NotFound("account data not found".into()).into());
    }
    Ok(Json(value))
}

/// PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}
pub async fn set_room_account_data(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, room_id, data_type)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only set own account data".into()).into());
    }
    check_value_size(&state, &body)?;

    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    state
        .db
        .set_room_account_data(user.user_nid, room_nid, &data_type, &body)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    crate::router::notify_user(&state, user.user_nid);
    Ok(Json(json!({})))
}

/// DELETE /_matrix/client/unstable/org.matrix.msc3391/user/{userId}/account_data/{type}
///
/// MSC3391 explicit-deletion endpoint. Semantically equivalent to
/// `PUT` with an empty `{}` body — the entry stays in the user's
/// account data with empty content so `/sync` surfaces the change to
/// other devices.
pub async fn delete_account_data(
    state: State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, data_type)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    set_account_data(state, user, Path((user_id, data_type)), Json(json!({}))).await
}

/// DELETE /_matrix/client/unstable/org.matrix.msc3391/user/{userId}/rooms/{roomId}/account_data/{type}
pub async fn delete_room_account_data(
    state: State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, room_id, data_type)): Path<(String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    set_room_account_data(
        state,
        user,
        Path((user_id, room_id, data_type)),
        Json(json!({})),
    )
    .await
}

// ----- Room tags (m.tag account data) -----

/// GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags
pub async fn list_tags(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, room_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only access own tags".into()).into());
    }
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;
    let tags = state
        .db
        .get_room_account_data(user.user_nid, room_nid, "m.tag")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .and_then(|v| v.get("tags").cloned())
        .unwrap_or_else(|| json!({}));
    Ok(Json(json!({"tags": tags})))
}

/// PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}
///
/// Body is the tag content blob (typically `{order: <float>}`); we store
/// it under `m.tag.tags.{tag}` in room account data, preserving any other
/// tags already set.
pub async fn put_tag(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, room_id, tag)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only set own tags".into()).into());
    }
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    let mut current = state
        .db
        .get_room_account_data(user.user_nid, room_nid, "m.tag")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .unwrap_or_else(|| json!({"tags": {}}));
    let tags = current
        .as_object_mut()
        .unwrap()
        .entry("tags".to_string())
        .or_insert_with(|| json!({}));
    tags.as_object_mut().unwrap().insert(tag, body);
    // The cap applies to the MERGED blob: tags accumulate via
    // read-modify-write, so checking only the incoming body would let
    // the stored value grow past the limit one tag at a time.
    check_value_size(&state, &current)?;

    state
        .db
        .set_room_account_data(user.user_nid, room_nid, "m.tag", &current)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    crate::router::notify_user(&state, user.user_nid);
    Ok(Json(json!({})))
}

/// DELETE /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}
pub async fn delete_tag(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, room_id, tag)): Path<(String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only delete own tags".into()).into());
    }
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    let mut current = match state
        .db
        .get_room_account_data(user.user_nid, room_nid, "m.tag")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(v) => v,
        None => return Ok(Json(json!({}))),
    };
    if let Some(tags) = current.get_mut("tags").and_then(|v| v.as_object_mut()) {
        tags.remove(&tag);
    }
    state
        .db
        .set_room_account_data(user.user_nid, room_nid, "m.tag", &current)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    crate::router::notify_user(&state, user.user_nid);
    Ok(Json(json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;
    use axum::extract::{Path, State};

    fn auth(nid: u64) -> AuthenticatedUser {
        AuthenticatedUser {
            user_nid: nid,
            user_id: "@u:example.com".into(),
            device_id: "DEV".into(),
            appservice_nid: None,
        }
    }

    #[tokio::test]
    async fn oversized_value_refused_small_value_lands() {
        let (state, _tmp) = build_test_state();
        let nid = state.db.create_user("@u:example.com", "h").unwrap();

        let big = json!({"blob": "x".repeat(state.config.max_account_data_bytes + 1)});
        let err = set_account_data(
            State(state.clone()),
            auth(nid),
            Path(("@u:example.com".into(), "m.test".into())),
            Json(big.clone()),
        )
        .await
        .expect_err("oversized user account data");
        assert!(matches!(err.0, VelaError::EventTooLarge(_)));

        set_account_data(
            State(state.clone()),
            auth(nid),
            Path(("@u:example.com".into(), "m.test".into())),
            Json(json!({"ok": true})),
        )
        .await
        .expect("small value lands");

        // Room-scoped endpoint enforces the same cap (before the room
        // lookup, so the room only needs to exist for the happy path).
        state.db.get_or_create_nid("!r:example.com").unwrap();
        let err = set_room_account_data(
            State(state.clone()),
            auth(nid),
            Path((
                "@u:example.com".into(),
                "!r:example.com".into(),
                "m.test".into(),
            )),
            Json(big),
        )
        .await
        .expect_err("oversized room account data");
        assert!(matches!(err.0, VelaError::EventTooLarge(_)));

        // The tag read-modify-write path enforces the cap on the
        // merged m.tag blob, not just the incoming body.
        let err = put_tag(
            State(state.clone()),
            auth(nid),
            Path((
                "@u:example.com".into(),
                "!r:example.com".into(),
                "huge".into(),
            )),
            Json(json!({"order": "x".repeat(state.config.max_account_data_bytes + 1)})),
        )
        .await
        .expect_err("oversized tag");
        assert!(matches!(err.0, VelaError::EventTooLarge(_)));
    }
}
