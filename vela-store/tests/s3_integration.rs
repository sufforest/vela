//! Integration tests for `S3MediaStore` against a real MinIO container.
//!
//! Gated behind `--features s3-integration` so the default `cargo test`
//! loop stays fast and RocksDB-only. CI brings up a MinIO sidecar
//! container; locally you can do:
//!
//! ```sh
//! docker run -d --rm --name vela-s3-test \
//!   -e MINIO_ROOT_USER=vela \
//!   -e MINIO_ROOT_PASSWORD=vela-test-secret \
//!   -p 9000:9000 \
//!   minio/minio:RELEASE.2025-04-22T22-12-26Z server /data
//! docker exec vela-s3-test sh -c '
//!   mc alias set local http://localhost:9000 vela vela-test-secret &&
//!   mc mb local/vela-test'
//! cargo test -p vela-store --features s3-integration s3_integration
//! ```
//!
//! What this catches that unit tests don't: S3 wire-protocol bugs —
//! multipart boundary semantics, signing/auth edge cases, content-
//! length encoding, the `abort()` path actually calling the right
//! wire op. Unit tests verify our code; this verifies our code talks
//! to a real S3-compatible server correctly.

#![cfg(feature = "s3-integration")]

use std::env;
use std::io::Cursor;

use rand::RngCore;
use vela_store::media::{MediaStore, S3Config, S3MediaStore};

fn test_config() -> S3Config {
    S3Config {
        bucket: env::var("VELA_TEST_S3_BUCKET").unwrap_or_else(|_| "vela-test".to_string()),
        region: Some(env::var("VELA_TEST_S3_REGION").unwrap_or_else(|_| "us-east-1".to_string())),
        endpoint: Some(
            env::var("VELA_TEST_S3_ENDPOINT")
                .unwrap_or_else(|_| "http://127.0.0.1:9000".to_string()),
        ),
        access_key_id: Some(
            env::var("VELA_TEST_S3_ACCESS_KEY").unwrap_or_else(|_| "vela".to_string()),
        ),
        secret_access_key: Some(
            env::var("VELA_TEST_S3_SECRET_KEY").unwrap_or_else(|_| "vela-test-secret".to_string()),
        ),
        prefix: format!("test-{}", uuid::Uuid::new_v4()),
        // MinIO defaults to plain HTTP for local dev; allow it.
        allow_http: true,
    }
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    buf
}

#[tokio::test]
async fn put_get_roundtrip_small_payload() {
    let store = S3MediaStore::new(&test_config()).expect("S3MediaStore::new");
    let media_id = format!("{}", uuid::Uuid::new_v4().simple());
    let payload = random_bytes(1024);

    store.put(&media_id, &payload).await.expect("put");
    let mut reader = store
        .get(&media_id)
        .await
        .expect("get")
        .expect("must exist after put");
    let mut got = Vec::new();
    tokio::io::copy(&mut reader, &mut got).await.expect("read");
    assert_eq!(got, payload, "small-payload round-trip preserves bytes");

    store.delete(&media_id).await.expect("delete");
    let after = store.get(&media_id).await.expect("get after delete");
    assert!(after.is_none(), "deleted blob must be absent");
}

#[tokio::test]
async fn put_stream_multipart_roundtrip_10mib() {
    // Exercises the streaming-multipart code path that landed in #52.
    // 10 MiB is above the 5 MiB single-part threshold; multipart upload
    // semantics fire. Before the streaming refactor this would buffer
    // the whole thing in memory; we want to confirm it round-trips
    // bit-identical against a real S3 server, not just our trait.
    let store = S3MediaStore::new(&test_config()).expect("S3MediaStore::new");
    let media_id = format!("{}", uuid::Uuid::new_v4().simple());
    let payload = random_bytes(10 * 1024 * 1024);

    // `Cursor<Vec<u8>>` is `AsyncRead + Unpin` — feeds the payload to
    // the streaming uploader without holding a Bytes clone.
    let reader = Cursor::new(payload.clone());
    let written = store
        .put_stream(&media_id, Box::pin(reader))
        .await
        .expect("put_stream multipart");
    assert_eq!(
        written as usize,
        payload.len(),
        "put_stream must return the exact byte count uploaded"
    );

    let mut reader = store
        .get(&media_id)
        .await
        .expect("get")
        .expect("must exist after multipart put");
    let mut got = Vec::new();
    tokio::io::copy(&mut reader, &mut got).await.expect("read");
    assert_eq!(got.len(), payload.len(), "byte-count round-trip");
    assert_eq!(got, payload, "multipart round-trip preserves byte content");

    store.delete(&media_id).await.expect("delete");
}

#[tokio::test]
async fn size_returns_uploaded_byte_count() {
    let store = S3MediaStore::new(&test_config()).expect("S3MediaStore::new");
    let media_id = format!("{}", uuid::Uuid::new_v4().simple());
    let payload = random_bytes(4096);

    store.put(&media_id, &payload).await.expect("put");
    let size = store.size(&media_id).await.expect("size");
    assert_eq!(
        size,
        Some(payload.len() as u64),
        "size() must reflect the uploaded payload"
    );

    store.delete(&media_id).await.expect("delete");
}

#[tokio::test]
async fn get_missing_returns_none_not_error() {
    // The trait contract distinguishes "this object doesn't exist"
    // (`Ok(None)`) from "transport / auth failure" (`Err`). Verify
    // the real-S3 wire behaviour (a 404 from MinIO) maps to the
    // former, not the latter. Without this guarantee, missing-media
    // requests would surface as 500s instead of 404s in the C2S API.
    let store = S3MediaStore::new(&test_config()).expect("S3MediaStore::new");
    let media_id = format!("nonexistent-{}", uuid::Uuid::new_v4().simple());
    let got = store.get(&media_id).await.expect("get must not Err");
    assert!(got.is_none());
    let size = store.size(&media_id).await.expect("size must not Err");
    assert_eq!(size, None);
}
