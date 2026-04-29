//! Regression tests for the spec-bundle bug fixes — register UIA,
//! UTF-8 body validation, device-delete UIA identifier check,
//! createRoom `is_direct` propagation, createRoom `room_alias_name`,
//! and `initial_device_display_name` persistence on register/login.
//!
//! Each test asserts a behaviour required by the Matrix spec that we
//! previously got wrong (or didn't implement at all). Without these
//! tests, the corresponding handler logic could silently regress and
//! Complement would either flag it 30 minutes later, or — worse —
//! drift past in a parallel test that doesn't exercise the path.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn post_register(harness: &Harness, body: Value) -> (StatusCode, Value) {
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/register")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    let status = resp.status();
    let body = read_json(resp).await;
    (status, body)
}

async fn post_register_raw(harness: &Harness, raw: Vec<u8>) -> (StatusCode, Value) {
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/register")
                .header("content-type", "application/json")
                .body(Body::from(raw))
                .unwrap(),
        )
        .await;
    let status = resp.status();
    let body = read_json(resp).await;
    (status, body)
}

async fn post_login(harness: &Harness, body: Value) -> (StatusCode, Value) {
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/login")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    let status = resp.status();
    let body = read_json(resp).await;
    (status, body)
}

async fn get_device(harness: &Harness, token: &str, device_id: &str) -> (StatusCode, Value) {
    let resp = harness
        .request(
            Request::get(format!("/_matrix/client/v3/devices/{device_id}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let status = resp.status();
    let body = read_json(resp).await;
    (status, body)
}

async fn delete_device(
    harness: &Harness,
    token: &str,
    device_id: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let body_bytes = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    let resp = harness
        .request(
            Request::delete(format!("/_matrix/client/v3/devices/{device_id}"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(body_bytes)
                .unwrap(),
        )
        .await;
    let status = resp.status();
    let body = read_json(resp).await;
    (status, body)
}

async fn get_state_content(
    harness: &Harness,
    token: &str,
    room: &str,
    event_type: &str,
    state_key: &str,
) -> (StatusCode, Value) {
    let resp = harness
        .request(
            Request::get(format!(
                "/_matrix/client/v3/rooms/{room}/state/{event_type}/{state_key}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
    let status = resp.status();
    let body = read_json(resp).await;
    (status, body)
}

// ---- /register UIA-always-required ------------------------------------

#[tokio::test]
async fn register_without_auth_returns_uia_challenge_even_with_username() {
    // Spec: register MUST use UIA. A submission carrying username +
    // password but no `auth` block must get 401 + flows, NOT a
    // success response. Our previous implementation only challenged
    // when BOTH username AND auth were missing — losing the
    // m.login.dummy round-trip the spec requires.
    let h = Harness::new();
    let (status, body) = post_register(
        &h,
        json!({
            "username": "alice",
            "password": "alice-pw",
        }),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        body.get("flows").is_some(),
        "challenge must include flows: {body}"
    );
    assert!(
        body.get("session").is_some(),
        "challenge must include session: {body}"
    );
}

#[tokio::test]
async fn register_with_dummy_auth_creates_user() {
    // Sanity check: the UIA pathway accepts m.login.dummy and
    // proceeds to actually register the user.
    let h = Harness::new();
    let (status, body) = post_register(
        &h,
        json!({
            "username": "alice",
            "password": "alice-pw",
            "auth": {"type": "m.login.dummy"},
        }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "registration should succeed: {body}"
    );
    assert!(body.get("access_token").is_some());
    assert!(body.get("user_id").is_some());
}

#[tokio::test]
async fn register_rejects_invalid_utf8_body_with_m_not_json() {
    // Spec mandates 400 M_NOT_JSON when the body isn't valid JSON.
    // serde_json's slice deserializer can otherwise accept invalid
    // UTF-8 bytes inside fields the target struct ignores — drifting
    // past with a bogus 401. This is the test case Complement
    // exercises in TestRequestEncodingFails.
    let h = Harness::new();
    // `{"test":"a\x81"}` — \x81 is a continuation byte without a lead.
    let mut bytes = Vec::from(br#"{"test":"a"#.as_slice());
    bytes.push(0x81);
    bytes.extend_from_slice(br#""}"#.as_slice());

    let (status, body) = post_register_raw(&h, bytes).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("errcode").and_then(|v| v.as_str()),
        Some("M_NOT_JSON")
    );
}

// ---- DELETE /devices/{deviceId} UIA identifier check ------------------

#[tokio::test]
async fn delete_device_with_no_body_returns_uia_challenge() {
    // Spec: first DELETE call (no `auth`) gets a 401 + flows. Without
    // this, our previous handler returned 400 M_BAD_JSON because
    // axum's Json<Value> failed to parse an empty body.
    let h = Harness::new();
    let (_alice_id, alice_tok) = h.register("alice", "alice-pw").await;
    let (status, body) = delete_device(&h, &alice_tok, "some-device", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.get("flows").is_some(), "expected UIA flows: {body}");
    assert!(
        body.get("session").is_some(),
        "expected UIA session: {body}"
    );
}

#[tokio::test]
async fn delete_device_rejects_uia_identity_mismatch() {
    // Spec: UIA must authenticate the *caller*, not just any user.
    // Alice cannot supply Bob's password to delete one of Alice's
    // own devices — the auth.identifier.user must equal the caller.
    // This is a security-sensitive rule (otherwise a leaked
    // password from any user weakens every other user's session).
    let h = Harness::new();
    let (alice_id, alice_tok) = h.register("alice", "alice-pw").await;
    let (bob_id, _bob_tok) = h.register("bob", "bob-pw").await;

    // Alice spawns a second device for herself. We want to delete it.
    let (_status, second) = post_login(
        &h,
        json!({
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": alice_id},
            "password": "alice-pw",
            "device_id": "second-device",
        }),
    )
    .await;
    let target_device = second
        .get("device_id")
        .and_then(|v| v.as_str())
        .expect("login returned device_id");

    // Alice (using her access token) tries to delete the device,
    // but supplies BOB's identity in the UIA block. Must 403.
    let (status, _body) = delete_device(
        &h,
        &alice_tok,
        target_device,
        Some(json!({
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": bob_id},
                "password": "bob-pw",
            }
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "UIA identifier mismatch must 403, not 200"
    );

    // Confirm the device was NOT deleted by the rejected request.
    let (status, _body) = get_device(&h, &alice_tok, target_device).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "device must still exist after the rejected delete"
    );

    // And the legitimate delete (alice's own creds) succeeds.
    let (status, _body) = delete_device(
        &h,
        &alice_tok,
        target_device,
        Some(json!({
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": alice_id},
                "password": "alice-pw",
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ---- createRoom is_direct propagation --------------------------------

#[tokio::test]
async fn create_room_with_is_direct_propagates_to_invite_member_event() {
    // Spec: when createRoom is called with `is_direct: true` and an
    // `invite` list, the per-invitee m.room.member event MUST carry
    // `content.is_direct: true`. DM client UIs depend on this to
    // recognise the room as a direct chat at first sight.
    let h = Harness::new();
    let (_alice_id, alice_tok) = h.register("alice", "alice-pw").await;
    let (bob_id, _bob_tok) = h.register("bob", "bob-pw").await;

    let room = h
        .create_room(
            &alice_tok,
            json!({
                "preset": "private_chat",
                "is_direct": true,
                "invite": [bob_id],
            }),
        )
        .await;

    let (status, content) =
        get_state_content(&h, &alice_tok, &room, "m.room.member", &bob_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        content.get("membership").and_then(|v| v.as_str()),
        Some("invite")
    );
    assert_eq!(
        content.get("is_direct").and_then(|v| v.as_bool()),
        Some(true),
        "invite member event for DM must carry is_direct=true: {content}"
    );
}

#[tokio::test]
async fn create_room_without_is_direct_does_not_set_flag() {
    // Negative case: a non-DM room must NOT have is_direct set on
    // invitee member events.
    let h = Harness::new();
    let (_alice_id, alice_tok) = h.register("alice", "alice-pw").await;
    let (bob_id, _bob_tok) = h.register("bob", "bob-pw").await;

    let room = h
        .create_room(
            &alice_tok,
            json!({
                "preset": "private_chat",
                "invite": [bob_id],
            }),
        )
        .await;

    let (status, content) =
        get_state_content(&h, &alice_tok, &room, "m.room.member", &bob_id).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        content.get("is_direct").is_none(),
        "non-DM invite must not set is_direct: {content}"
    );
}

// ---- createRoom room_alias_name ---------------------------------------

#[tokio::test]
async fn create_room_with_alias_name_registers_alias_and_canonical_alias() {
    // Spec: `room_alias_name` on createRoom must (1) bind the alias
    // to the new room in the directory, (2) emit an
    // m.room.canonical_alias state event. /publicRooms uses (2) to
    // surface the alias in directory listings.
    let h = Harness::new();
    let (_alice_id, alice_tok) = h.register("alice", "alice-pw").await;

    let room = h
        .create_room(
            &alice_tok,
            json!({
                "preset": "public_chat",
                "room_alias_name": "my-room",
            }),
        )
        .await;

    // Alias resolution: /directory/room/{#alias} returns the room id.
    let resp = h
        .request(
            Request::get("/_matrix/client/v3/directory/room/%23my-room:localhost:8008")
                .header("authorization", format!("Bearer {alice_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(
        body.get("room_id").and_then(|v| v.as_str()),
        Some(room.as_str())
    );

    // Canonical alias state event was emitted.
    let (status, content) =
        get_state_content(&h, &alice_tok, &room, "m.room.canonical_alias", "").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "canonical_alias must be set: {content}"
    );
    assert_eq!(
        content.get("alias").and_then(|v| v.as_str()),
        Some("#my-room:localhost:8008")
    );
}

#[tokio::test]
async fn create_room_with_duplicate_alias_name_rejects() {
    // The second createRoom attempting to claim an existing alias
    // must fail (BAD_REQUEST). Otherwise we'd silently rebind the
    // alias to the new room — a directory hijack.
    let h = Harness::new();
    let (_alice_id, alice_tok) = h.register("alice", "alice-pw").await;

    let _first = h
        .create_room(
            &alice_tok,
            json!({"preset": "public_chat", "room_alias_name": "claimed"}),
        )
        .await;

    let resp = h
        .request(
            Request::post("/_matrix/client/v3/createRoom")
                .header("authorization", format!("Bearer {alice_tok}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"preset": "public_chat", "room_alias_name": "claimed"}).to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "duplicate alias must reject"
    );
}

// ---- initial_device_display_name persistence --------------------------

#[tokio::test]
async fn login_persists_initial_device_display_name() {
    // Spec: clients send `initial_device_display_name` on login;
    // GET /devices/{deviceId} must surface it as `display_name`.
    let h = Harness::new();
    let (alice_id, _alice_tok) = h.register("alice", "alice-pw").await;

    let (status, login_body) = post_login(
        &h,
        json!({
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": alice_id},
            "password": "alice-pw",
            "device_id": "labelled-device",
            "initial_device_display_name": "Alice's Phone",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = login_body
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap();

    let (status, body) = get_device(&h, token, "labelled-device").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.get("display_name").and_then(|v| v.as_str()),
        Some("Alice's Phone"),
        "display_name must persist from initial_device_display_name: {body}"
    );
}

#[tokio::test]
async fn register_persists_initial_device_display_name() {
    let h = Harness::new();
    let (status, body) = post_register(
        &h,
        json!({
            "username": "alice",
            "password": "alice-pw",
            "device_id": "phone1",
            "initial_device_display_name": "Alice's Phone",
            "auth": {"type": "m.login.dummy"},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = body.get("access_token").and_then(|v| v.as_str()).unwrap();

    let (status, body) = get_device(&h, token, "phone1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.get("display_name").and_then(|v| v.as_str()),
        Some("Alice's Phone")
    );
}
