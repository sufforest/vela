//! POST /user_directory/search — substring search over local users.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

/// Put the caller + `others` all into a shared room so the privacy-
/// default filter lets the search see them. Returns the room id.
async fn shared_room(
    harness: &Harness,
    host_tok: &str,
    others: &[(&str, &str)], // (user_id, token) pairs to join the room
) -> String {
    let invites: Vec<String> = others.iter().map(|(uid, _)| (*uid).to_string()).collect();
    let room = harness
        .create_room(
            host_tok,
            serde_json::json!({"preset": "public_chat", "invite": invites}),
        )
        .await;
    for (_uid, tok) in others {
        harness.join(tok, &room).await;
    }
    room
}

async fn search(harness: &Harness, token: &str, term: &str, limit: Option<usize>) -> Value {
    let mut body = json!({"search_term": term});
    if let Some(l) = limit {
        body["limit"] = json!(l);
    }
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/user_directory/search")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    read_json(resp).await
}

async fn set_displayname(harness: &Harness, token: &str, user_id: &str, name: &str) {
    let resp = harness
        .request(
            Request::put(format!("/_matrix/client/v3/profile/{user_id}/displayname"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"displayname": name}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "set_displayname failed");
}

/// Spec: a directory search must not return the requester themselves.
/// Synapse and Element clients depend on this — without the filter,
/// a query like "find users containing 'alice'" echoes alice back to
/// herself which surprises every UI.
#[tokio::test]
async fn search_excludes_the_caller() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;
    shared_room(&harness, &alice_tok, &[(&bob_id, &bob_tok)]).await;

    // Both alice and bob's user_ids contain "alice"-vs-"bob" so we
    // search a substring that matches both ("user-" is in the harness
    // localpart format) and verify alice is filtered out.
    let result = search(&harness, &alice_tok, "user-", None).await;
    let user_ids: Vec<&str> = result["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["user_id"].as_str().unwrap())
        .collect();
    assert!(
        !user_ids.iter().any(|u| *u == alice_id),
        "alice (the searcher) must not appear in her own results: {result}"
    );
}

/// Spec: members of public-directory rooms are globally findable —
/// the requester does not need to share a room with them. This is
/// what makes "find a user by name before adding them" work.
#[tokio::test]
async fn finds_user_in_a_public_room_via_display_name() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (_eve_id, eve_tok) = harness.register("eve", "pw").await;

    set_displayname(&harness, &alice_tok, &alice_id, "Alice Cooper").await;

    // Alice creates a public room. Eve does NOT join it.
    harness
        .create_room(
            &alice_tok,
            json!({"preset": "public_chat", "visibility": "public"}),
        )
        .await;

    let result = search(&harness, &eve_tok, "Alice Cooper", None).await;
    let entries = result["results"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly Alice in results: {result}"
    );
    assert_eq!(entries[0]["user_id"], alice_id);
    assert_eq!(entries[0]["display_name"], "Alice Cooper");
}

#[tokio::test]
async fn matches_user_id_substring_when_sharing_a_room() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;
    shared_room(&harness, &alice_tok, &[(&bob_id, &bob_tok)]).await;

    let result = search(&harness, &alice_tok, "bob", None).await;
    let users: Vec<&str> = result["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["user_id"].as_str().unwrap())
        .collect();
    assert!(
        users.iter().any(|u| u.contains("bob")),
        "bob missing: {result}"
    );
}

#[tokio::test]
async fn matches_display_name_substring_when_sharing_a_room() {
    let harness = Harness::new();
    let (_alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;
    set_displayname(&harness, &bob_tok, &bob_id, "Robert Paulson").await;
    shared_room(&harness, &alice_tok, &[(&bob_id, &bob_tok)]).await;

    let result = search(&harness, &alice_tok, "paulson", None).await;
    let results = result["results"].as_array().unwrap();
    assert!(
        results
            .iter()
            .any(|u| u["display_name"] == "Robert Paulson"),
        "Robert Paulson missing: {result}"
    );
}

#[tokio::test]
async fn hides_users_with_no_shared_room_by_default() {
    // Privacy default: alice cannot find bob if they don't share a room.
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let (_bob, _bob_tok) = harness.register("bob", "pw").await;

    let result = search(&harness, &alice_tok, "bob", None).await;
    let results = result["results"].as_array().unwrap();
    assert!(
        results.is_empty(),
        "bob must not leak to alice without shared room: {result}"
    );
}

#[tokio::test]
async fn search_all_users_flag_bypasses_shared_room_filter() {
    // With the flag on, even strangers surface.
    let harness = Harness::with_search_all_users();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let (_bob, _bob_tok) = harness.register("bob", "pw").await;

    let result = search(&harness, &alice_tok, "bob", None).await;
    let users: Vec<&str> = result["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["user_id"].as_str().unwrap())
        .collect();
    assert!(
        users.iter().any(|u| u.contains("bob")),
        "with search_all_users=true, bob should surface: {result}"
    );
}

#[tokio::test]
async fn empty_term_returns_no_results() {
    let harness = Harness::new();
    let (_, alice_tok) = harness.register("alice", "pw").await;
    let result = search(&harness, &alice_tok, "   ", None).await;
    assert_eq!(result["results"].as_array().unwrap().len(), 0);
    assert_eq!(result["limited"], false);
}

#[tokio::test]
async fn limit_marks_results_as_limited() {
    // Flag is on so the test doesn't need to wire shared rooms for every
    // registered user — we're specifically asserting the limit semantics.
    let harness = Harness::with_search_all_users();
    for name in ["a1", "a2", "a3", "a4"] {
        let _ = harness.register(name, "pw").await;
    }
    let (_, tok) = harness.register("searcher", "pw").await;
    let result = search(&harness, &tok, "a", Some(2)).await;
    let results = result["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(result["limited"], true);
}
