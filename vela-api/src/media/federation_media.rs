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

#[derive(Deserialize, Default)]
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
    let filename = metadata.get("filename").and_then(|v| v.as_str());

    let boundary = format!("vela-{}", uuid::Uuid::new_v4().simple());
    let multipart_ct = format!("multipart/mixed; boundary={boundary}");

    // Body layout per MSC3916: JSON metadata part, then file content
    // part. The file part carries Content-Disposition with the
    // original filename when set — receivers re-emit this when they
    // serve the file to their own clients, so Unicode filenames
    // survive a download → federation → download chain. Trailing
    // `--<boundary>--` closes the message.
    let mut body = Vec::with_capacity(buf.len() + 256);
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
    body.extend_from_slice(b"{}\r\n");
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    if let Some(name) = filename
        && !name.is_empty()
    {
        body.extend_from_slice(
            format!(
                "Content-Disposition: {}\r\n",
                crate::media::format_content_disposition(name)
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(b"\r\n");
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
/// Generates a thumbnail the same way as the C2S `/thumbnail` and
/// wraps it in the MSC3916 multipart envelope so the remote server
/// sees the same bytes its own clients would. Non-image content
/// falls through to the original via `federation_download`.
pub async fn federation_thumbnail(
    State(state): State<AppState>,
    Path(media_id): Path<String>,
    Query(query): Query<FederationThumbnailQuery>,
    axum::extract::Extension(_origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Response, StatusCode> {
    let metadata = state
        .db
        .get_media_metadata(&media_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let original_ct = metadata
        .get("content_type")
        .and_then(|v| v.as_str())
        .unwrap_or("application/octet-stream")
        .to_string();
    if !original_ct.starts_with("image/") {
        // Spec allows falling through to the original when we can't
        // resize. The download handler already wraps in multipart.
        return federation_download(
            State(state),
            Path(media_id),
            Query(MediaDownloadQuery::default()),
            axum::extract::Extension(_origin),
        )
        .await;
    }

    let reader = state
        .media_store
        .get(&media_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let mut buf = Vec::new();
    let mut stream = ReaderStream::new(reader);
    use futures::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        buf.extend_from_slice(&chunk);
    }

    let png_bytes = crate::media::resize_to_png_thumbnail(
        &buf,
        query.width.unwrap_or(96),
        query.height.unwrap_or(96),
        query.method.as_deref().unwrap_or("scale"),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let boundary = format!("vela-{}", uuid::Uuid::new_v4().simple());
    let multipart_ct = format!("multipart/mixed; boundary={boundary}");
    // Spec: the second part's Content-Type carries the original
    // file's MIME (`image/png` here, matching what we emit from the
    // resize). The test matches parts by content-type to find the
    // image bytes.
    let mut body = Vec::with_capacity(png_bytes.len() + 256);
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
    body.extend_from_slice(b"{}\r\n");
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Type: image/png\r\n\r\n");
    body.extend_from_slice(&png_bytes);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, multipart_ct)
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Deserialize, Default)]
pub struct FederationThumbnailQuery {
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub method: Option<String>,
    #[allow(dead_code)]
    pub animated: Option<bool>,
    #[allow(dead_code)]
    pub timeout_ms: Option<u64>,
}
