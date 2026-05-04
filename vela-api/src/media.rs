use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_util::io::ReaderStream;
use uuid::Uuid;
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

#[derive(Deserialize)]
pub struct UploadQuery {
    pub filename: Option<String>,
}

/// POST /_matrix/media/v3/upload
pub async fn upload(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<UploadQuery>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    if body.len() as u64 > state.config.max_upload_size {
        return Err(VelaError::Unknown("file too large".into()).into());
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    let media_id = Uuid::new_v4().to_string().replace('-', "");

    // Async write — doesn't block tokio workers
    state
        .media_store
        .put(&media_id, &body)
        .await
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let metadata = json!({
        "content_type": content_type,
        "filename": query.filename.as_deref().unwrap_or(""),
        "size": body.len(),
        "uploader": user.user_id,
        "created_at": now_ms,
    });

    state
        .db
        .set_media_metadata(&media_id, &metadata)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mxc_uri = format!("mxc://{}/{}", state.config.server_name, media_id);

    Ok(Json(json!({"content_uri": mxc_uri})))
}

/// GET /_matrix/client/v1/media/download/{serverName}/{mediaId}
pub async fn download(
    state: State<AppState>,
    _user: AuthenticatedUser,
    path: Path<(String, String)>,
) -> Result<Response, ApiError> {
    let Path((server, media)) = path;
    download_inner(state, Path((server, media, None))).await
}

/// GET /_matrix/client/v1/media/download/{serverName}/{mediaId}/{filename}
pub async fn download_with_filename(
    state: State<AppState>,
    _user: AuthenticatedUser,
    Path((server, media, filename)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    download_inner(state, Path((server, media, Some(filename)))).await
}

/// GET /_matrix/media/v3/download/{serverName}/{mediaId}
///
/// Legacy unauthenticated download per the c2s pre-MSC3916 surface.
/// Many older clients (and matrix.org's directory tooling) still hit
/// this path; we serve it for backward compatibility, calling the
/// same inner logic as the auth'd v1 endpoint.
pub async fn download_legacy(
    state: State<AppState>,
    path: Path<(String, String)>,
) -> Result<Response, ApiError> {
    let Path((server, media)) = path;
    download_inner(state, Path((server, media, None))).await
}

/// GET /_matrix/media/v3/download/{serverName}/{mediaId}/{filename}
///
/// Legacy unauthenticated variant with filename override.
pub async fn download_legacy_with_filename(
    state: State<AppState>,
    Path((server, media, filename)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    download_inner(state, Path((server, media, Some(filename)))).await
}

async fn download_inner(
    State(state): State<AppState>,
    Path((server_name, media_id, filename_override)): Path<(String, String, Option<String>)>,
) -> Result<Response, ApiError> {
    if server_name != state.config.server_name {
        return download_remote(&state, &server_name, &media_id).await;
    }

    let metadata = state
        .db
        .get_media_metadata(&media_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("media not found".into())))?;

    let reader = state
        .media_store
        .get(&media_id)
        .await
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("media file not found".into())))?;

    // Stream the body in chunks — near-zero RAM consumption regardless
    // of backend (filesystem or S3 multipart).
    let stream = ReaderStream::new(reader);
    let body = Body::from_stream(stream);

    let content_type = metadata
        .get("content_type")
        .and_then(|v| v.as_str())
        .unwrap_or("application/octet-stream");

    // Spec: a `{filename}` segment in the URL overrides the stored
    // filename. Otherwise fall back to whatever was provided at upload.
    let filename: &str = match filename_override.as_deref() {
        Some(f) => f,
        None => metadata
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    };

    let size = state.media_store.size(&media_id).await.ok().flatten();

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type);
    if let Some(s) = size {
        builder = builder.header(header::CONTENT_LENGTH, s.to_string());
    }

    if !filename.is_empty() {
        builder = builder.header(
            header::CONTENT_DISPOSITION,
            format_content_disposition(filename),
        );
    }

    builder
        .body(body)
        .map_err(|e| ApiError(VelaError::Unknown(e.to_string())))
}

/// GET /_matrix/client/v1/media/thumbnail/{serverName}/{mediaId}
pub async fn thumbnail(
    state: State<AppState>,
    _user: AuthenticatedUser,
    Path((server, media)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    // For now, return the original file. Proper thumbnail generation
    // requires the `image` crate — defer to a future iteration.
    download_inner(state, Path((server, media, None))).await
}

/// GET /_matrix/media/v3/thumbnail/{serverName}/{mediaId}
///
/// Legacy unauthenticated thumbnail endpoint. Same backward-compat
/// rationale as `download_legacy`.
pub async fn thumbnail_legacy(
    state: State<AppState>,
    Path((server, media)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    download_inner(state, Path((server, media, None))).await
}

/// GET /_matrix/media/v3/config
pub async fn config(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "m.upload.size": state.config.max_upload_size,
    }))
}

/// Build a `Content-Disposition` value for a media download.
///
/// Always uses `inline` disposition (we don't force file save). When
/// the filename is pure ASCII we emit only the `filename=` parameter.
/// When it contains non-ASCII bytes, we additionally emit
/// `filename*=UTF-8''<percent-encoded>` per RFC 5987 so HTTP clients
/// preserve the original Unicode rather than mangling it. The plain
/// `filename=` is kept for legacy clients but with non-ASCII bytes
/// stripped — anything else risks header-injection or invalid
/// header bytes that proxies will reject.
pub(crate) fn format_content_disposition(filename: &str) -> String {
    // Strip control chars and the literals that would break the
    // header value (`"`, `\\`, CR, LF, NUL, etc.).
    fn safe_char(c: char) -> bool {
        !c.is_control() && c != '"' && c != '\\'
    }
    let safe: String = filename.chars().filter(|c| safe_char(*c)).collect();
    let ascii_safe: String = safe
        .chars()
        .filter(|c| c.is_ascii() && safe_char(*c))
        .collect();

    if safe.is_ascii() {
        return format!("inline; filename=\"{safe}\"");
    }

    // RFC 5987 percent-encoding: only unreserved characters are kept
    // verbatim; everything else (including all multibyte UTF-8) gets
    // %HH-encoded.
    let mut encoded = String::with_capacity(safe.len() * 3);
    for byte in safe.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(*byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    format!("inline; filename=\"{ascii_safe}\"; filename*=UTF-8''{encoded}")
}

/// Federate a media download to the home server that owns the
/// `mxc://` namespace. Spec: MSC3916 authenticated multipart download
/// at `/_matrix/federation/v1/media/download/{mediaId}`. We surface
/// the file content with the original `Content-Type`. Failures
/// surface as 404 to clients — there's nothing actionable they can
/// do besides retry, and a leak of upstream errors would be noisy.
async fn download_remote(
    state: &AppState,
    server_name: &str,
    media_id: &str,
) -> Result<Response, ApiError> {
    let media = state
        .federation_client
        .fetch_media(server_name, media_id)
        .await
        .map_err(|e| {
            tracing::debug!(remote = %server_name, %media_id, error = %e, "federation media fetch failed");
            ApiError(VelaError::NotFound("remote media unavailable".into()))
        })?;

    let len = media.bytes.len();
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, media.content_type)
        .header(header::CONTENT_LENGTH, len.to_string());
    // Propagate the original filename from the peer so clients see the
    // Unicode-safe filename whether the file came from us or via
    // federation. Stripping it here would silently lose Unicode names
    // when bob on hs2 downloads alice@hs1's file via hs2.
    if let Some(filename) = media.filename.as_deref()
        && !filename.is_empty()
    {
        builder = builder.header(
            header::CONTENT_DISPOSITION,
            format_content_disposition(filename),
        );
    }
    builder
        .body(Body::from(media.bytes))
        .map_err(|e| ApiError(VelaError::Unknown(e.to_string())))
}
