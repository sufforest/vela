//! Inbound federation media endpoints (MSC3916).
//!
//! - `GET /_matrix/federation/v1/media/download/{mediaId}` — serves
//!   our locally-stored media to remote servers via a
//!   `multipart/mixed` body. Two parts: an `application/json`
//!   metadata block (currently empty per spec — reserved for future
//!   extension) followed by the file content with its original
//!   `Content-Type`.
//!
//! Behind the existing `federation_auth` middleware so only signed
//! requests reach this handler.

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::Response;
use serde::Deserialize;
use tokio_util::io::ReaderStream;

use crate::middleware::federation_auth::XMatrixOrigin;
use crate::router::AppState;

#[derive(Deserialize)]
pub struct MediaDownloadQuery {
    /// Spec optional — receivers MAY honour `timeout_ms` to cap how
    /// long they wait for upstream resolution. Local-only fetch here
    /// so it's safe to ignore.
    #[allow(dead_code)]
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Spec optional — when `false`, servers must not redirect to
    /// alternate sources. We always serve inline, so it's a no-op.
    #[allow(dead_code)]
    #[serde(default)]
    pub allow_redirect: Option<bool>,
}

/// GET /_matrix/federation/v1/media/download/{mediaId}
pub async fn federation_download(
    State(state): State<AppState>,
    Path(media_id): Path<String>,
    Query(_): Query<MediaDownloadQuery>,
    axum::extract::Extension(_origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Response, StatusCode> {
    let metadata = state
        .db
        .get_media_metadata(&media_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let reader = state
        .media_store
        .get(&media_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Read content into memory — multipart wraps the file body inline.
    // Streaming a multipart wrapper around a reader is doable but
    // adds complexity for marginal benefit (federation media transfers
    // are bounded by max_upload_size, already capped on ingest).
    let mut buf = Vec::new();
    let mut stream = ReaderStream::new(reader);
    use futures::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        buf.extend_from_slice(&chunk);
    }

    let content_type = metadata
        .get("content_type")
        .and_then(|v| v.as_str())
        .unwrap_or("application/octet-stream");

    let boundary = format!("vela-{}", uuid::Uuid::new_v4().simple());
    let multipart_ct = format!("multipart/mixed; boundary={boundary}");

    // Body layout per MSC3916: JSON metadata part, then file content
    // part. Trailing `--<boundary>--` closes the message.
    let mut body = Vec::with_capacity(buf.len() + 256);
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
    body.extend_from_slice(b"{}\r\n");
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(&buf);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, multipart_ct)
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// GET /_matrix/federation/v1/media/thumbnail/{mediaId}
///
/// Same multipart wrapper as `federation_download`. Thumbnail
/// generation is not implemented yet, so we return the original
/// (matches the C2S behaviour). Spec query parameters `width` /
/// `height` / `method` / `animated` are accepted-but-ignored.
pub async fn federation_thumbnail(
    state: State<AppState>,
    path: Path<String>,
    query: Query<MediaDownloadQuery>,
    origin: axum::extract::Extension<XMatrixOrigin>,
) -> Result<Response, StatusCode> {
    federation_download(state, path, query, origin).await
}
