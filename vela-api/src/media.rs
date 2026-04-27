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
    download_inner(state, path).await
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
    download_inner(state, path).await
}

async fn download_inner(
    State(state): State<AppState>,
    Path((server_name, media_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    if server_name != state.config.server_name {
        return Err(VelaError::NotFound("remote media not supported".into()).into());
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

    let filename = metadata
        .get("filename")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let size = state.media_store.size(&media_id).await.ok().flatten();

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type);
    if let Some(s) = size {
        builder = builder.header(header::CONTENT_LENGTH, s.to_string());
    }

    if !filename.is_empty() {
        // Sanitize filename — remove control chars and quotes to prevent header injection
        let safe_name: String = filename
            .chars()
            .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
            .collect();
        builder = builder.header(
            header::CONTENT_DISPOSITION,
            format!("inline; filename=\"{safe_name}\""),
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
    path: Path<(String, String)>,
) -> Result<Response, ApiError> {
    // For now, return the original file. Proper thumbnail generation
    // requires the `image` crate — defer to a future iteration.
    download_inner(state, path).await
}

/// GET /_matrix/media/v3/thumbnail/{serverName}/{mediaId}
///
/// Legacy unauthenticated thumbnail endpoint. Same backward-compat
/// rationale as `download_legacy`.
pub async fn thumbnail_legacy(
    state: State<AppState>,
    path: Path<(String, String)>,
) -> Result<Response, ApiError> {
    download_inner(state, path).await
}

/// GET /_matrix/media/v3/config
pub async fn config(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "m.upload.size": state.config.max_upload_size,
    }))
}
