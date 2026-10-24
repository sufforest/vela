//! Content repository: client upload/download/thumbnail + the
//! federation-side download/thumbnail endpoints.

pub mod federation_media;

use std::pin::Pin;

use crate::middleware::json::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::Response;
use dashmap::DashMap;
use futures::TryStreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncRead;
use tokio_util::io::ReaderStream;
use uuid::Uuid;
use vela_core::error::VelaError;

use crate::federation::federation_client::MediaResponse;
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
    body: Body,
) -> Result<Json<Value>, ApiError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    let media_id = Uuid::new_v4().to_string().replace('-', "");

    let max = state.config.max_upload_size;
    // Hash the upload in-stream only when a media plugin is configured (free
    // otherwise). Tee the capped reader through SHA-256 as it flows to storage —
    // no extra buffering, works for any size. One runtime snapshot drives both
    // the decision to hash and the check itself, so a concurrent reload can't
    // leave us hashing without checking (or checking a different plugin set).
    let rt = state.extensions.load_full();
    let (reader, hasher) = maybe_hashing_reader(
        body_to_capped_reader(body, max),
        rt.binds_check_media_upload(),
    );

    // Stream straight into the backend — no double buffering. Bytes
    // pass through the size-cap adapter, then `put_stream` writes
    // them to the FS temp file or S3 multipart parts. On overflow
    // the adapter yields an `io::Error` tagged with our 413 marker.
    let written = state
        .media_store
        .put_stream(&media_id, reader)
        .await
        .map_err(stream_io_to_api_err)?;

    // Sandboxed media-upload decision hook, after the bytes are stored but
    // before metadata commits (so a blocked upload is never downloadable). A
    // block deletes the stored bytes and rejects the upload.
    let filename = query.filename.as_deref().unwrap_or("");
    media_gate(
        &state,
        rt.as_ref(),
        &MediaUpload {
            media_id: &media_id,
            content_type: &content_type,
            filename,
            size: written,
            uploader: user.user_id.as_str(),
        },
        hasher,
    )
    .await?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let metadata = json!({
        "content_type": content_type,
        "filename": filename,
        "size": written,
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

/// POST /_matrix/media/v1/create — MSC2246 async upload step 1.
///
/// Reserves an mxc:// URI without taking any bytes. The client then
/// PUTs the actual content to /_matrix/media/v3/upload/{server}/{id}
/// up to `pending_until_ms` from now. Until that PUT lands, downloads
/// return 504 M_NOT_YET_UPLOADED.
pub async fn create_media(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, ApiError> {
    let media_id = Uuid::new_v4().to_string().replace('-', "");
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    // 24-hour upload window — spec says the server "SHOULD" pick a
    // sensible default and surface it in `unused_expires_at`. Clients
    // that don't follow up by then can re-create the placeholder.
    let unused_expires_at = now_ms + 24 * 60 * 60 * 1000;
    let metadata = json!({
        "pending": true,
        "uploader": user.user_id,
        "created_at": now_ms,
        "unused_expires_at": unused_expires_at,
    });
    state
        .db
        .set_media_metadata(&media_id, &metadata)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let content_uri = format!("mxc://{}/{}", state.config.server_name, media_id);
    Ok(Json(json!({
        "content_uri": content_uri,
        "unused_expires_at": unused_expires_at,
    })))
}

/// PUT /_matrix/media/v3/upload/{serverName}/{mediaId} — MSC2246 step 2.
///
/// Fills in the bytes for a media id previously reserved via /create.
/// Spec mandates 409 M_CANNOT_OVERWRITE_MEDIA when the id is already
/// uploaded, and 404 when it was never reserved (we don't allow
/// "pick your own id" uploads).
pub async fn upload_to_id(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((server_name, media_id)): Path<(String, String)>,
    Query(query): Query<UploadQuery>,
    headers: axum::http::HeaderMap,
    body: Body,
) -> Result<Json<Value>, ApiError> {
    if server_name != state.config.server_name {
        return Err(custom_media_err(
            404,
            "M_NOT_FOUND",
            "this server does not own that media id",
        ));
    }
    let Some(meta) = state
        .db
        .get_media_metadata(&media_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Err(custom_media_err(
            404,
            "M_NOT_FOUND",
            "media id was never reserved",
        ));
    };
    if !meta
        .get("pending")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Err(custom_media_err(
            409,
            "M_CANNOT_OVERWRITE_MEDIA",
            "media id already uploaded",
        ));
    }
    // Only the uploader who reserved the id can fill it in. Without
    // this anyone with a valid token could race to claim someone
    // else's placeholder.
    if meta
        .get("uploader")
        .and_then(|v| v.as_str())
        .is_some_and(|u| u != user.user_id)
    {
        return Err(custom_media_err(
            403,
            "M_FORBIDDEN",
            "media id reserved by another user",
        ));
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    let max = state.config.max_upload_size;
    let rt = state.extensions.load_full();
    let (reader, hasher) = maybe_hashing_reader(
        body_to_capped_reader(body, max),
        rt.binds_check_media_upload(),
    );
    let written = state
        .media_store
        .put_stream(&media_id, reader)
        .await
        .map_err(stream_io_to_api_err)?;

    let filename = query.filename.as_deref().unwrap_or("");
    media_gate(
        &state,
        rt.as_ref(),
        &MediaUpload {
            media_id: &media_id,
            content_type: &content_type,
            filename,
            size: written,
            uploader: user.user_id.as_str(),
        },
        hasher,
    )
    .await?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let metadata = json!({
        "content_type": content_type,
        "filename": filename,
        "size": written,
        "uploader": user.user_id,
        "created_at": now_ms,
    });
    state
        .db
        .set_media_metadata(&media_id, &metadata)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    Ok(Json(json!({})))
}

fn custom_media_err(status: u16, errcode: &'static str, msg: &str) -> ApiError {
    ApiError(VelaError::Custom {
        status,
        errcode,
        msg: msg.to_string(),
    })
}

/// An `AsyncRead` that SHA-256-hashes bytes as they flow through, so an upload
/// can be hashed in-stream (no buffering) on the way to storage.
struct HashingReader {
    inner: Pin<Box<dyn AsyncRead + Send + Unpin>>,
    hasher: std::sync::Arc<std::sync::Mutex<sha2::Sha256>>,
}

impl AsyncRead for HashingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use sha2::Digest;
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &r {
            let new = &buf.filled()[before..];
            if !new.is_empty() {
                self.hasher.lock().unwrap().update(new);
            }
        }
        r
    }
}

/// Wrap `reader` to hash as it streams when `enabled`; otherwise pass it through.
/// Returns the (possibly-wrapped) reader and the shared hasher to finalize after.
#[allow(clippy::type_complexity)]
fn maybe_hashing_reader(
    reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
    enabled: bool,
) -> (
    Pin<Box<dyn AsyncRead + Send + Unpin>>,
    Option<std::sync::Arc<std::sync::Mutex<sha2::Sha256>>>,
) {
    use sha2::Digest;
    if !enabled {
        return (reader, None);
    }
    let hasher = std::sync::Arc::new(std::sync::Mutex::new(sha2::Sha256::new()));
    (
        Box::pin(HashingReader {
            inner: reader,
            hasher: hasher.clone(),
        }),
        Some(hasher),
    )
}

/// The identifying facts about a stored upload, handed to the media gate.
/// Bundled (rather than passed positionally) so the `&str` fields can't be
/// transposed at a call site.
struct MediaUpload<'a> {
    media_id: &'a str,
    content_type: &'a str,
    filename: &'a str,
    size: u64,
    uploader: &'a str,
}

/// Sandboxed media-upload decision hook. No-op when no plugin binds it (and
/// `hasher` is then `None`). Called after the bytes are stored but before
/// metadata commits; a block **deletes the stored bytes** (so blocked media is
/// never downloadable) and rejects the upload with the plugin's errcode. `rt` is
/// the same runtime snapshot used to decide whether to hash, so the decision and
/// the check always see one plugin set.
async fn media_gate(
    state: &AppState,
    rt: &vela_extensions::Runtime,
    upload: &MediaUpload<'_>,
    hasher: Option<std::sync::Arc<std::sync::Mutex<sha2::Sha256>>>,
) -> Result<(), ApiError> {
    use sha2::Digest;
    use std::fmt::Write as _;
    let Some(hasher) = hasher else {
        return Ok(());
    };
    let digest = hasher.lock().unwrap().clone().finalize();
    let mut sha256 = String::with_capacity(64);
    for b in digest {
        let _ = write!(sha256, "{b:02x}");
    }

    let ctx = vela_extensions::MediaContext {
        content_type: upload.content_type,
        filename: upload.filename,
        size: upload.size,
        uploader: upload.uploader,
        sha256: &sha256,
    };
    match rt.check_media_upload(&ctx) {
        vela_extensions::Decision::Allow => Ok(()),
        vela_extensions::Decision::Block { errcode, reason } => {
            // Blocked media must never be servable — drop the bytes we streamed.
            // Even if the delete fails the upload stays unreachable (metadata is
            // never written), but log it so an operator can reap the orphan.
            if let Err(e) = state.media_store.delete(upload.media_id).await {
                tracing::warn!(media_id = upload.media_id, error = %e, "failed to delete blocked media");
            }
            tracing::info!(media_id = upload.media_id, uploader = upload.uploader, %errcode, %reason, "extension blocked media upload");
            Err(ApiError(VelaError::ExtensionBlocked { errcode, reason }))
        }
    }
}

/// Sentinel string carried inside `io::Error` when the request body
/// crosses the configured upload cap. Picked at the boundary instead
/// of an `io::ErrorKind` because we need to distinguish "client sent
/// too much" (413) from "disk write failed" (500) at the trait return
/// site without inventing a new error variant on `MediaStore`.
const TOO_LARGE_TAG: &str = "vela:media:too-large";

/// Build an `AsyncRead` over the request body that errors as soon as
/// the cumulative byte count crosses `max`. The byte count is checked
/// chunk-by-chunk on the read path so the failure surfaces BEFORE the
/// last bytes hit the storage backend — i.e. before `complete()` on
/// S3 multipart, before the FS rename — letting the abort/cleanup
/// path in `put_stream` reclaim partial uploads.
fn body_to_capped_reader(body: Body, max: u64) -> Pin<Box<dyn AsyncRead + Send + Unpin>> {
    let mut seen: u64 = 0;
    let stream = body.into_data_stream().map_err(std::io::Error::other);
    let stream = stream.and_then(move |chunk| {
        let len = chunk.len() as u64;
        let next = seen.saturating_add(len);
        let res = if next > max {
            Err(std::io::Error::other(TOO_LARGE_TAG))
        } else {
            seen = next;
            Ok(chunk)
        };
        std::future::ready(res)
    });
    Box::pin(tokio_util::io::StreamReader::new(stream))
}

/// Convert an `io::Error` returned by `MediaStore::put_stream` into an
/// `ApiError`. The 413 path is signalled in-band by the size-cap
/// adapter via `TOO_LARGE_TAG`; the tower-http `RequestBodyLimitLayer`
/// uses `http_body_util::LengthLimitError` (`"length limit exceeded"`)
/// when the inbound body crosses its own ceiling — both map to 413.
/// Everything else is an internal store failure.
fn stream_io_to_api_err(e: std::io::Error) -> ApiError {
    let msg = e.to_string();
    if msg.contains(TOO_LARGE_TAG) || msg.contains("length limit exceeded") {
        return custom_media_err(
            413,
            "M_TOO_LARGE",
            "upload exceeds the homeserver size limit",
        );
    }
    ApiError(VelaError::Store(msg))
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

/// Apply the spec-recommended media security headers (content-repository
/// §security). The sandboxing `Content-Security-Policy` + `nosniff` stop a
/// blob served with an attacker-chosen `Content-Type` (e.g. `text/html`, or
/// `image/svg+xml` carrying `<script>`) from executing as active content in
/// the media origin; the v1.4 `Cross-Origin-Resource-Policy: cross-origin`
/// keeps media embeddable by web clients. Applied on every media response.
fn with_media_security_headers(
    builder: axum::http::response::Builder,
) -> axum::http::response::Builder {
    builder
        .header(
            "Content-Security-Policy",
            "sandbox; default-src 'none'; script-src 'none'; plugin-types application/pdf; style-src 'unsafe-inline'; object-src 'self';",
        )
        .header("X-Content-Type-Options", "nosniff")
        .header("Cross-Origin-Resource-Policy", "cross-origin")
}

async fn download_inner(
    State(state): State<AppState>,
    Path((server_name, media_id, filename_override)): Path<(String, String, Option<String>)>,
) -> Result<Response, ApiError> {
    if server_name != state.config.server_name {
        return download_remote(
            &state,
            &server_name,
            &media_id,
            filename_override.as_deref(),
        )
        .await;
    }

    let metadata = state
        .db
        .get_media_metadata(&media_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("media not found".into())))?;

    // MSC2246: a reservation exists but no bytes were uploaded yet.
    // Spec wants 504 with M_NOT_YET_UPLOADED here, NOT 404 — clients
    // distinguish "still waiting on the sender" from "never existed".
    if metadata
        .get("pending")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Err(custom_media_err(
            504,
            "M_NOT_YET_UPLOADED",
            "media is reserved but not yet uploaded",
        ));
    }

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

    let mut builder = with_media_security_headers(Response::builder().status(StatusCode::OK))
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
    Query(q): Query<ThumbnailQuery>,
) -> Result<Response, ApiError> {
    thumbnail_inner(state, server, media, q).await
}

/// GET /_matrix/media/v3/thumbnail/{serverName}/{mediaId}
///
/// Legacy unauthenticated thumbnail endpoint. Same backward-compat
/// rationale as `download_legacy`.
pub async fn thumbnail_legacy(
    state: State<AppState>,
    Path((server, media)): Path<(String, String)>,
    Query(q): Query<ThumbnailQuery>,
) -> Result<Response, ApiError> {
    thumbnail_inner(state, server, media, q).await
}

/// Spec query params: `width`, `height`, `method` (`scale` | `crop`).
/// `animated` is best-effort (we always return a static frame). The
/// `allow_remote`, `allow_redirect`, `timeout_ms` params are accepted
/// but unused — we always serve from the store and never redirect.
#[derive(serde::Deserialize, Default)]
pub struct ThumbnailQuery {
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub method: Option<String>,
    #[allow(dead_code)]
    pub animated: Option<bool>,
    #[allow(dead_code)]
    pub allow_remote: Option<bool>,
    #[allow(dead_code)]
    pub allow_redirect: Option<bool>,
    #[allow(dead_code)]
    pub timeout_ms: Option<u64>,
}

async fn thumbnail_inner(
    State(state): State<AppState>,
    server_name: String,
    media_id: String,
    q: ThumbnailQuery,
) -> Result<Response, ApiError> {
    if server_name != state.config.server_name {
        return download_remote_thumbnail(&state, &server_name, &media_id, &q).await;
    }

    // Reservation-only media (MSC2246 placeholder, no bytes yet):
    // spec uses 504 M_NOT_YET_UPLOADED, same as the download path.
    let metadata = state
        .db
        .get_media_metadata(&media_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("media not found".into())))?;
    if metadata
        .get("pending")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Err(custom_media_err(
            504,
            "M_NOT_YET_UPLOADED",
            "media is reserved but not yet uploaded",
        ));
    }

    let content_type = metadata
        .get("content_type")
        .and_then(|v| v.as_str())
        .unwrap_or("application/octet-stream")
        .to_string();

    // We only thumbnail image/* content. Anything else gets served as
    // the original — the spec allows the server to fall through to
    // the original when it can't render a thumbnail.
    if !content_type.starts_with("image/") {
        return download_inner(State(state), Path((server_name, media_id, None))).await;
    }

    // Spec clamp: server SHOULD pick the smallest cached thumbnail
    // size at-or-above the requested dimensions. We don't pre-bucket;
    // we just clamp the requested size to a sane ceiling so a
    // malicious request can't ask us to render 100k×100k.
    let req_w = q.width.unwrap_or(96).clamp(1, 1600);
    let req_h = q.height.unwrap_or(96).clamp(1, 1600);
    let method = q.method.as_deref().unwrap_or("scale");

    // Load original bytes via the same path as /download.
    let mut reader = state
        .media_store
        .get(&media_id)
        .await
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("media file not found".into())))?;
    let mut buf = Vec::new();
    use tokio::io::AsyncReadExt;
    reader
        .read_to_end(&mut buf)
        .await
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Decode → resize → encode. We always emit PNG because:
    //   - lossless (no second round of JPEG quality loss),
    //   - alpha channel preserved (some chat clients render PNGs for
    //     stickers and emoji),
    //   - decoders are universally available.
    let img = decode_image_limited(&buf)
        .map_err(|e| ApiError(VelaError::Unknown(format!("decode image: {e}"))))?;
    let resized = match method {
        "crop" => crop_to(&img, req_w, req_h),
        _ => img.thumbnail(req_w, req_h),
    };
    let mut out_bytes = Vec::new();
    resized
        .write_to(
            &mut std::io::Cursor::new(&mut out_bytes),
            image::ImageFormat::Png,
        )
        .map_err(|e| ApiError(VelaError::Unknown(format!("encode thumbnail: {e}"))))?;

    let body = Body::from(out_bytes.clone());
    with_media_security_headers(Response::builder().status(StatusCode::OK))
        .header(header::CONTENT_TYPE, "image/png")
        .header(header::CONTENT_LENGTH, out_bytes.len().to_string())
        .body(body)
        .map_err(|e| ApiError(VelaError::Unknown(e.to_string())))
}

/// Resize the given image bytes to a PNG thumbnail. Used by the
/// /thumbnail handler AND by the federation thumbnail endpoint so
/// both surfaces emit identical bytes for the same input — the
/// federation test compares the two byte-for-byte.
pub(crate) fn resize_to_png_thumbnail(
    bytes: &[u8],
    width: u32,
    height: u32,
    method: &str,
) -> Result<Vec<u8>, image::ImageError> {
    let w = width.clamp(1, 1600);
    let h = height.clamp(1, 1600);
    let img = decode_image_limited(bytes)?;
    let resized = match method {
        "crop" => crop_to(&img, w, h),
        _ => img.thumbnail(w, h),
    };
    let mut out = Vec::new();
    resized.write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)?;
    Ok(out)
}

/// Decode an image with explicit resource limits. A "decompression bomb" is
/// a tiny compressed file that expands into an enormous bitmap; the decoder
/// default caps allocation at 512 MiB and places NO ceiling on dimensions,
/// so we tighten both. Bounds the worst-case memory per thumbnail request.
fn decode_image_limited(bytes: &[u8]) -> Result<image::DynamicImage, image::ImageError> {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(256 * 1024 * 1024);
    let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .map_err(image::ImageError::IoError)?;
    reader.limits(limits);
    reader.decode()
}

/// `method=crop` returns an image of exactly the requested
/// dimensions (or the smallest valid crop above them). We scale the
/// shorter side to fit and crop the longer side from the centre.
fn crop_to(img: &image::DynamicImage, w: u32, h: u32) -> image::DynamicImage {
    let (iw, ih) = (img.width(), img.height());
    if iw == 0 || ih == 0 {
        return img.clone();
    }
    let scale = (w as f32 / iw as f32).max(h as f32 / ih as f32);
    let new_w = ((iw as f32) * scale).ceil() as u32;
    let new_h = ((ih as f32) * scale).ceil() as u32;
    let scaled = img.resize_exact(
        new_w.max(w),
        new_h.max(h),
        image::imageops::FilterType::Triangle,
    );
    let (sw, sh) = (scaled.width(), scaled.height());
    let x = sw.saturating_sub(w) / 2;
    let y = sh.saturating_sub(h) / 2;
    scaled.crop_imm(x, y, w.min(sw), h.min(sh))
}

/// GET /_matrix/media/v3/config
pub async fn config(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "m.upload.size": state.config.max_upload_size,
    }))
}

/// `GET /_matrix/media/v3/preview_url?url=<URL>`
/// `GET /_matrix/client/v1/media/preview_url?url=<URL>`
///
/// Fetch the URL, parse OpenGraph `<meta>` tags out of any HTML body,
/// upload the og:image referent into our media store (so the client
/// can render it via the regular mxc:// path), and return the spec's
/// json blob keyed by og:* property names.
///
/// We intentionally keep parsing line-by-line / regex-free here:
/// the meta tags we care about are simple `<meta property="og:X"
/// content="Y" />` shapes — no JS, no nested DOM — and an HTML5
/// dependency would dwarf the rest of the handler.
pub async fn preview_url(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<PreviewUrlQuery>,
) -> Result<Json<Value>, ApiError> {
    let url = query
        .url
        .ok_or_else(|| ApiError(VelaError::BadJson("missing `url` query parameter".into())))?;

    // SSRF-guarded fetch: refuses non-public targets (loopback / RFC1918 /
    // link-local incl. 169.254.169.254 cloud-metadata), pins the connection
    // to the validated IPs, re-validates each redirect hop, and caps the
    // body. The client-supplied `url` must never make the server reach into
    // its own network. Returns a uniform error so we don't leak whether an
    // internal host exists.
    let allow_private = state.config.url_preview_allow_private_ips;
    let (final_url, content_type, bytes) =
        fetch_preview(&url, allow_private).await.map_err(|e| {
            tracing::debug!(%url, error = %e, "url preview fetch refused");
            ApiError(VelaError::Unknown(
                "could not fetch the requested URL".into(),
            ))
        })?;

    // If the URL points directly at an image, the spec wants us to
    // upload it and return the size + dimensions under the og:* keys
    // as if a synthetic HTML had og:image: <self>.
    let mut out = serde_json::Map::new();
    if content_type.starts_with("image/") {
        let (mxc, size, w, h) = ingest_remote_image(&state, &user, &bytes, &content_type).await?;
        out.insert("og:image".into(), json!(mxc));
        out.insert("matrix:image:size".into(), json!(size));
        if let Some(w) = w {
            out.insert("og:image:width".into(), json!(w));
        }
        if let Some(h) = h {
            out.insert("og:image:height".into(), json!(h));
        }
        return Ok(Json(Value::Object(out)));
    }

    // Otherwise treat as HTML. Even malformed HTML walks fine through
    // the meta extractor — we just won't find anything useful.
    let html = String::from_utf8_lossy(&bytes);
    let metas = extract_og_meta(&html);
    for (k, v) in &metas {
        out.insert(k.clone(), json!(v));
    }

    // If the page advertises an og:image, fetch it relative to the
    // final URL, ingest it, and rewrite og:image to the mxc:// uri.
    // The Complement test depends on this: it serves `og:image =
    // "test.png"` and expects our response to point at our own
    // mxc://.
    if let Some(raw_img) = metas.get("og:image")
        && let Some(img_url) = resolve_relative(&final_url, raw_img)
        && let Ok((_img_final, img_ct, img_bytes)) = fetch_preview(&img_url, allow_private).await
        && let Ok((mxc, size, w, h)) = ingest_remote_image(&state, &user, &img_bytes, &img_ct).await
    {
        out.insert("og:image".into(), json!(mxc));
        out.insert("matrix:image:size".into(), json!(size));
        if let Some(w) = w {
            out.insert("og:image:width".into(), json!(w));
        }
        if let Some(h) = h {
            out.insert("og:image:height".into(), json!(h));
        }
    }

    Ok(Json(Value::Object(out)))
}

#[derive(serde::Deserialize)]
pub struct PreviewUrlQuery {
    pub url: Option<String>,
    #[allow(dead_code)]
    pub ts: Option<u64>,
}

/// Max bytes vela will read from a preview target (HTML page or image).
const PREVIEW_MAX_BYTES: usize = 10 * 1024 * 1024;
/// Max redirect hops followed during a preview fetch.
const PREVIEW_MAX_REDIRECTS: usize = 5;

/// Fetch a URL for link preview with SSRF protection and a hard body cap.
///
/// For the initial request and every redirect hop: refuse non-http(s),
/// resolve the host and require all addresses be public (unless
/// `allow_private`), and pin the connection to those validated addresses so
/// a DNS-rebinding race can't swap in an internal address between the check
/// and the connect. Follows at most `PREVIEW_MAX_REDIRECTS` and reads at
/// most `PREVIEW_MAX_BYTES`. Returns `(final_url, content_type, body)`.
async fn fetch_preview(url: &str, allow_private: bool) -> Result<(String, String, Bytes), String> {
    let mut current = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    for _ in 0..=PREVIEW_MAX_REDIRECTS {
        if current.scheme() != "http" && current.scheme() != "https" {
            return Err(format!("scheme `{}` not allowed", current.scheme()));
        }
        let host = current
            .host_str()
            .ok_or_else(|| "URL has no host".to_string())?
            .to_string();
        let port = current.port_or_known_default().unwrap_or(443);
        let addrs = resolve_public_or_reject(&host, port, allow_private).await?;

        // Pin to the validated addresses (reqwest won't re-resolve) and
        // disable automatic redirects so we can re-validate each hop.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("vela-preview/0.1")
            .resolve_to_addrs(&host, &addrs)
            .build()
            .map_err(|e| format!("http client: {e}"))?;

        let resp = client
            .get(current.clone())
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if resp.status().is_redirection() {
            let loc = resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| "redirect without Location".to_string())?;
            current = current
                .join(loc)
                .map_err(|e| format!("bad redirect target: {e}"))?;
            continue;
        }

        let final_url = resp.url().to_string();
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = read_body_capped(resp, PREVIEW_MAX_BYTES).await?;
        return Ok((final_url, content_type, body));
    }
    Err("too many redirects".to_string())
}

/// Resolve `host:port` and require every resolved address be public unless
/// `allow_private`. Returns the socket addresses (for connection pinning).
/// Fails CLOSED: an empty resolution or any non-public address is rejected.
///
/// Shared with push delivery: resolving once here and pinning the resulting
/// addresses onto the client (`resolve_to_addrs`) is what closes the
/// DNS-rebinding TOCTOU — the connect uses these checked addresses, not a
/// fresh re-resolution.
pub(crate) async fn resolve_public_or_reject(
    host: &str,
    port: u16,
    allow_private: bool,
) -> Result<Vec<std::net::SocketAddr>, String> {
    // `Url::host_str()` brackets IPv6 literals (`[::1]`); strip them so the
    // literal parses and the unbracketed form is handed to the resolver.
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        if !allow_private && crate::federation::federation_resolver::is_blocked_ip(ip) {
            return Err(format!("host `{host}` is not a public address"));
        }
        return Ok(vec![std::net::SocketAddr::new(ip, port)]);
    }
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((bare, port))
        .await
        .map_err(|e| format!("DNS lookup failed: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("host `{host}` did not resolve"));
    }
    if !allow_private {
        for sa in &addrs {
            if crate::federation::federation_resolver::is_blocked_ip(sa.ip()) {
                return Err(format!("host `{host}` resolves to a non-public address"));
            }
        }
    }
    Ok(addrs)
}

/// Read a response body, failing if it exceeds `cap` bytes — checks the
/// advertised Content-Length first, then enforces during streaming so a
/// lying or chunked body can't blow past the cap.
async fn read_body_capped(mut resp: reqwest::Response, cap: usize) -> Result<Bytes, String> {
    if let Some(len) = resp.content_length()
        && len as usize > cap
    {
        return Err(format!("response too large: {len} > {cap}"));
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("read failed: {e}"))?
    {
        if buf.len() + chunk.len() > cap {
            return Err("response exceeded size cap".to_string());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(buf))
}

/// Parse the bytes as an image, save it via the regular media store,
/// register metadata, and return `(mxc, size, width, height)`.
/// Width/height are None for image formats we don't probe (everything
/// except PNG today; expand as needed).
///
/// Deliberately not run through `media_gate`: this is the server's own
/// URL-preview thumbnail cache, not a user upload. The `check_media_upload`
/// point scopes to client uploads; if scanning preview images is wanted later,
/// gate here too.
async fn ingest_remote_image(
    state: &AppState,
    user: &AuthenticatedUser,
    bytes: &Bytes,
    content_type: &str,
) -> Result<(String, usize, Option<u32>, Option<u32>), ApiError> {
    let media_id = Uuid::new_v4().to_string().replace('-', "");
    state
        .media_store
        .put(&media_id, bytes)
        .await
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let metadata = json!({
        "content_type": content_type,
        "filename": "",
        "size": bytes.len(),
        "uploader": user.user_id,
        "created_at": now_ms,
    });
    state
        .db
        .set_media_metadata(&media_id, &metadata)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mxc = format!("mxc://{}/{}", state.config.server_name, media_id);
    let (w, h) = png_dimensions(bytes);
    Ok((mxc, bytes.len(), w, h))
}

/// Read width/height from a PNG IHDR chunk. Returns (None, None) when
/// the bytes don't look like a PNG. The Complement upload uses a PNG
/// so this is enough to satisfy the test; for production, gate on
/// `image` crate or similar to support JPEG/WebP/AVIF.
fn png_dimensions(bytes: &[u8]) -> (Option<u32>, Option<u32>) {
    // PNG signature is 8 bytes; IHDR length+type+w+h starts at offset 8.
    // Width at bytes 16..20, height at 20..24 (big-endian u32).
    if bytes.len() < 24 || &bytes[0..8] != b"\x89PNG\r\n\x1a\n" {
        return (None, None);
    }
    let w = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
    let h = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
    (Some(w), Some(h))
}

/// Pull `og:*` and a few useful sibling meta tags out of raw HTML
/// without dragging in a full HTML parser. We accept attributes in
/// any order, allow single OR double quotes, and ignore everything
/// outside `<meta ...>` tags.
fn extract_og_meta(html: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let lower = html.to_lowercase();
    let mut cursor = 0;
    while let Some(off) = lower[cursor..].find("<meta") {
        let start = cursor + off;
        let Some(end_rel) = html[start..].find('>') else {
            break;
        };
        let tag = &html[start..start + end_rel + 1];
        cursor = start + end_rel + 1;
        let property = attr_value(tag, "property")
            .or_else(|| attr_value(tag, "name"))
            .unwrap_or_default();
        if !property.starts_with("og:") && property != "matrix:image:size" {
            continue;
        }
        if let Some(content) = attr_value(tag, "content") {
            out.insert(property, content);
        }
    }
    out
}

/// Quote-aware attribute extractor for a single tag. Returns the
/// content of `<...attr="value"...>` or `<...attr='value'...>`. Not
/// HTML-spec strict — fine for the simple meta tags we extract.
fn attr_value(tag: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=");
    let lower = tag.to_lowercase();
    let start_lower = lower.find(&needle)?;
    let after = start_lower + needle.len();
    let bytes = tag.as_bytes();
    if after >= bytes.len() {
        return None;
    }
    let (quote, value_start) = match bytes[after] {
        b'"' => (b'"', after + 1),
        b'\'' => (b'\'', after + 1),
        _ => return None,
    };
    let mut value_end = value_start;
    while value_end < bytes.len() && bytes[value_end] != quote {
        value_end += 1;
    }
    if value_end >= bytes.len() {
        return None;
    }
    Some(tag[value_start..value_end].to_string())
}

/// Resolve `href` relative to `base`. Absolute http(s) URLs are
/// returned unchanged; protocol-relative `//host/path` inherits the
/// base scheme; everything else is joined onto the base via
/// `reqwest::Url`. Bad inputs return None and the caller silently
/// skips the og:image.
fn resolve_relative(base: &str, href: &str) -> Option<String> {
    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_string());
    }
    let base_url = reqwest::Url::parse(base).ok()?;
    base_url.join(href).ok().map(|u| u.to_string())
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
    filename_override: Option<&str>,
) -> Result<Response, ApiError> {
    check_remote_media_ref(server_name, media_id)?;
    // Cache hit: stream the blob, as the local path does; only a miss
    // (and the thumbnailer) needs the whole file in memory.
    if let Some((row, reader)) = lookup_remote_cache(state, server_name, media_id).await? {
        let size = row.get("size").and_then(|v| v.as_u64());
        let content_type = row_content_type(&row);
        let filename = filename_override
            .map(str::to_string)
            .or_else(|| row_filename(&row));
        let mut builder = with_media_security_headers(Response::builder().status(StatusCode::OK))
            .header(header::CONTENT_TYPE, content_type);
        if let Some(size) = size {
            builder = builder.header(header::CONTENT_LENGTH, size.to_string());
        }
        if let Some(filename) = filename.filter(|f| !f.is_empty()) {
            builder = builder.header(
                header::CONTENT_DISPOSITION,
                format_content_disposition(&filename),
            );
        }
        return builder
            .body(Body::from_stream(ReaderStream::new(reader)))
            .map_err(|e| ApiError(VelaError::Unknown(e.to_string())));
    }
    let media = fetch_remote_original(state, server_name, media_id).await?;
    media_response(media, filename_override)
}

/// Thumbnail of remote media: take the original from the cache (fetching
/// it over federation on a miss) and resize it with the same thumbnailer
/// as local media, so a client gets one size policy whichever server
/// holds the file. Non-image content and undecodable bytes are served as
/// the original, as the local path does. Thumbnails themselves are not
/// cached, matching the local path.
async fn download_remote_thumbnail(
    state: &AppState,
    server_name: &str,
    media_id: &str,
    q: &ThumbnailQuery,
) -> Result<Response, ApiError> {
    check_remote_media_ref(server_name, media_id)?;
    let media = fetch_remote_original(state, server_name, media_id).await?;
    if !media.content_type.starts_with("image/") {
        return media_response(media, None);
    }
    let width = q.width.unwrap_or(96);
    let height = q.height.unwrap_or(96);
    let method = q.method.as_deref().unwrap_or("scale");
    match resize_to_png_thumbnail(&media.bytes, width, height, method) {
        Ok(png) => {
            let len = png.len();
            with_media_security_headers(Response::builder().status(StatusCode::OK))
                .header(header::CONTENT_TYPE, "image/png")
                .header(header::CONTENT_LENGTH, len.to_string())
                .body(Body::from(png))
                .map_err(|e| ApiError(VelaError::Unknown(e.to_string())))
        }
        Err(e) => {
            tracing::debug!(remote = %server_name, %media_id, error = %e, "remote media not thumbnailable; serving the original");
            media_response(media, None)
        }
    }
}

/// Reject references we would never have handed out ourselves before
/// they reach federation or the cache: the spec recommends restricting
/// media ids to `[A-Za-z0-9_-]`, and the origin must parse as a server
/// name. Anything else cannot exist, so it is a plain 404.
fn check_remote_media_ref(origin: &str, media_id: &str) -> Result<(), ApiError> {
    let id_ok = !media_id.is_empty()
        && media_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    let origin_ok = crate::federation::federation_client::check_destination(origin).is_ok();
    if !id_ok || !origin_ok {
        return Err(ApiError(VelaError::NotFound("media not found".into())));
    }
    Ok(())
}

/// `last_access_at` on a cached remote row is rewritten at most this
/// often, so a hot file does not cost a store write per read. The
/// retention sweeper evicts on this field, so the cache ages by last use
/// at hour granularity.
const REMOTE_ACCESS_TOUCH_MS: u64 = 60 * 60 * 1000;

fn remote_media_lock_key(origin: &str, media_id: &str) -> String {
    format!("{origin}\0{media_id}")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn store_err(e: impl std::fmt::Display) -> ApiError {
    ApiError(VelaError::Store(e.to_string()))
}

fn row_content_type(row: &Value) -> String {
    row.get("content_type")
        .and_then(|v| v.as_str())
        .unwrap_or("application/octet-stream")
        .to_string()
}

fn row_filename(row: &Value) -> Option<String> {
    row.get("filename")
        .and_then(|v| v.as_str())
        .filter(|f| !f.is_empty())
        .map(str::to_string)
}

/// Why a federation fetch of a remote file failed, in client terms.
/// `Copy` so one fetch's failure can be handed to every request that
/// queued behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteFetchFailure {
    /// Peer said 404 with a real not-found code.
    NotFound,
    /// Peer said 504: an MSC2246 reservation without bytes yet.
    NotYetUploaded,
    /// Peer said 413, or the body crossed our cap.
    TooLarge,
    /// Peer answered 404 M_UNRECOGNIZED: it predates authenticated media
    /// and we have no legacy fallback, so the file may well exist.
    LegacyPeer,
    /// Transport failure, 5xx, unparsable body.
    Unavailable,
}

impl RemoteFetchFailure {
    fn into_error(self) -> ApiError {
        match self {
            Self::NotFound => ApiError(VelaError::NotFound("remote media not found".into())),
            Self::NotYetUploaded => custom_media_err(
                504,
                "M_NOT_YET_UPLOADED",
                "remote media is reserved but not yet uploaded",
            ),
            Self::TooLarge => {
                custom_media_err(502, "M_TOO_LARGE", "remote media exceeds the size limit")
            }
            Self::LegacyPeer => custom_media_err(
                502,
                "M_UNKNOWN",
                "remote server does not serve authenticated media",
            ),
            Self::Unavailable => custom_media_err(502, "M_UNKNOWN", "remote media unavailable"),
        }
    }
}

#[derive(Debug, Clone)]
enum RemoteFetchOutcome {
    /// The bytes themselves, so waiters are answered even when the file
    /// could not be cached (over budget, storage failure).
    Fetched(MediaResponse),
    Failed(RemoteFetchFailure),
}

/// Single-flight slot for one `(origin, media_id)`. The first request
/// through the mutex fetches and records the outcome; requests that were
/// already queued behind it get that outcome instead of fetching again,
/// so a dead peer costs one timeout, not one per waiting client. The
/// slot leaves the map when the last request holding it finishes.
pub struct RemoteFetchSlot(tokio::sync::Mutex<Option<RemoteFetchOutcome>>);

/// Holds a slot for the duration of one request and removes it from the
/// map on drop, including when the request is cancelled or errors out
/// early. The map entry is only removed once no other request holds it:
/// a newcomer clones under the shard lock before our check runs.
struct SlotGuard {
    map: std::sync::Arc<DashMap<String, std::sync::Arc<RemoteFetchSlot>>>,
    key: String,
    slot: Option<std::sync::Arc<RemoteFetchSlot>>,
}

impl SlotGuard {
    fn acquire(state: &AppState, origin: &str, media_id: &str) -> Self {
        let key = remote_media_lock_key(origin, media_id);
        let slot = state
            .remote_media_locks
            .entry(key.clone())
            .or_insert_with(|| std::sync::Arc::new(RemoteFetchSlot(tokio::sync::Mutex::new(None))))
            .clone();
        Self {
            map: state.remote_media_locks.clone(),
            key,
            slot: Some(slot),
        }
    }

    fn slot(&self) -> &RemoteFetchSlot {
        self.slot.as_ref().expect("slot held until drop")
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        // Release our reference first, then drop the entry if it was the
        // last one: the map's own count is the one that remains.
        self.slot.take();
        self.map
            .remove_if(&self.key, |_, s| std::sync::Arc::strong_count(s) <= 1);
    }
}

/// The original bytes of a remote file, from the local cache when we have
/// them and over federation otherwise. Failures are never cached beyond
/// the requests already waiting on the same fetch: a 404 today may be an
/// MSC2246 upload that completes tomorrow.
pub(crate) async fn fetch_remote_original(
    state: &AppState,
    origin: &str,
    media_id: &str,
) -> Result<MediaResponse, ApiError> {
    if let Some(media) = read_remote_cache(state, origin, media_id).await? {
        return Ok(media);
    }
    let guard = SlotGuard::acquire(state, origin, media_id);
    let mut outcome = guard.slot().0.lock().await;
    match &*outcome {
        Some(RemoteFetchOutcome::Fetched(media)) => return Ok(media.clone()),
        Some(RemoteFetchOutcome::Failed(failure)) => return Err(failure.into_error()),
        None => {}
    }
    match fetch_and_store_remote(state, origin, media_id).await {
        Ok(media) => {
            *outcome = Some(RemoteFetchOutcome::Fetched(media.clone()));
            Ok(media)
        }
        Err(failure) => {
            *outcome = Some(RemoteFetchOutcome::Failed(failure));
            Err(failure.into_error())
        }
    }
}

/// Cache row plus an open reader on its blob, with `last_access_at`
/// touched. `None` on a miss, including a row whose blob has gone.
async fn lookup_remote_cache(
    state: &AppState,
    origin: &str,
    media_id: &str,
) -> Result<Option<(Value, vela_store::media::MediaReader)>, ApiError> {
    let Some(row) = state
        .db
        .get_remote_media(origin, media_id)
        .map_err(store_err)?
    else {
        return Ok(None);
    };
    let Some(blob_id) = row.get("blob_id").and_then(|v| v.as_str()) else {
        let _ = state.db.delete_remote_media(origin, media_id);
        return Ok(None);
    };
    let Some(reader) = state.media_store.get(blob_id).await.map_err(store_err)? else {
        // Blob removed behind our back (manual cleanup, storage lifecycle
        // rule). Forget the row and fetch again.
        tracing::warn!(%origin, %media_id, %blob_id, "cached remote media blob missing; refetching");
        let _ = state.db.delete_remote_media(origin, media_id);
        return Ok(None);
    };
    touch_last_access(state, origin, media_id, &row);
    Ok(Some((row, reader)))
}

/// Rewrite `last_access_at` when it is older than the touch interval.
/// Re-reads the row first so a refetch that raced us (new `blob_id`) is
/// not overwritten with the stale one.
fn touch_last_access(state: &AppState, origin: &str, media_id: &str, row: &Value) {
    let now = now_ms();
    let last = row
        .get("last_access_at")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if now.saturating_sub(last) < REMOTE_ACCESS_TOUCH_MS {
        return;
    }
    let current = match state.db.get_remote_media(origin, media_id) {
        Ok(Some(current)) => current,
        _ => return,
    };
    if current.get("blob_id") != row.get("blob_id") {
        return;
    }
    let mut touched = current;
    touched["last_access_at"] = json!(now);
    if let Err(e) = state.db.set_remote_media(origin, media_id, &touched) {
        tracing::debug!(%origin, %media_id, error = %e, "remote media access touch failed");
    }
}

async fn read_remote_cache(
    state: &AppState,
    origin: &str,
    media_id: &str,
) -> Result<Option<MediaResponse>, ApiError> {
    let Some((row, mut reader)) = lookup_remote_cache(state, origin, media_id).await? else {
        return Ok(None);
    };
    let size = row.get("size").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let mut bytes = Vec::with_capacity(size);
    use tokio::io::AsyncReadExt;
    reader.read_to_end(&mut bytes).await.map_err(store_err)?;
    Ok(Some(MediaResponse {
        content_type: row_content_type(&row),
        filename: row_filename(&row),
        bytes: Bytes::from(bytes),
    }))
}

/// Fetch over federation and cache. Only the peer's verdict is an error
/// here; our own storage failing is logged and the bytes are still served.
async fn fetch_and_store_remote(
    state: &AppState,
    origin: &str,
    media_id: &str,
) -> Result<MediaResponse, RemoteFetchFailure> {
    let media = state
        .federation_client
        .fetch_media(origin, media_id, state.config.max_upload_size as usize)
        .await
        .map_err(|e| classify_fetch_error(origin, media_id, e))?;

    // From here on the bytes are in hand; a storage problem is logged and
    // the response still succeeds, it just is not cached.
    let size = media.bytes.len() as u64;
    if !make_room_in_remote_cache(state, size).await {
        return Ok(media);
    }
    let blob_id = Uuid::new_v4().simple().to_string();
    if let Err(e) = state.media_store.put(&blob_id, &media.bytes).await {
        tracing::warn!(%origin, %media_id, error = %e, "remote media blob write failed; serving uncached");
        return Ok(media);
    }
    let now = now_ms();
    let row = json!({
        "blob_id": blob_id,
        "content_type": media.content_type,
        "filename": media.filename.as_deref().unwrap_or(""),
        "size": size,
        "cached_at": now,
        "last_access_at": now,
    });
    if let Err(e) = state.db.set_remote_media(origin, media_id, &row) {
        tracing::warn!(%origin, %media_id, error = %e, "remote media row write failed; dropping blob");
        let _ = state.media_store.delete(&blob_id).await;
    }
    Ok(media)
}

/// Enforce `remote_media_cache_max_bytes` before storing `incoming`
/// bytes: evict least recently read files until the new one fits.
/// Returns false when the file cannot be cached at all (larger than the
/// whole budget). A budget of 0 means unbounded.
async fn make_room_in_remote_cache(state: &AppState, incoming: u64) -> bool {
    let budget = state.config.remote_media_cache_max_bytes;
    if budget == 0 {
        return true;
    }
    if incoming > budget {
        return false;
    }
    let rows = match state.db.list_remote_media() {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "remote media cache listing failed; storing without eviction");
            return true;
        }
    };
    let mut total: u64 = rows
        .iter()
        .map(|(_, _, r)| r.get("size").and_then(|v| v.as_u64()).unwrap_or(0))
        .sum();
    if total + incoming <= budget {
        return true;
    }
    let mut by_age: Vec<_> = rows
        .into_iter()
        .map(|(origin, media_id, row)| {
            let last = row
                .get("last_access_at")
                .or_else(|| row.get("cached_at"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            (last, origin, media_id, row)
        })
        .collect();
    by_age.sort_by_key(|(last, ..)| *last);
    for (_, origin, media_id, row) in by_age {
        if total + incoming <= budget {
            break;
        }
        let size = row.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
        if let Some(blob_id) = row.get("blob_id").and_then(|v| v.as_str())
            && let Err(e) = state.media_store.delete(blob_id).await
        {
            tracing::warn!(%origin, %media_id, error = %e, "remote media eviction: blob delete failed");
            continue;
        }
        if let Err(e) = state.db.delete_remote_media(&origin, &media_id) {
            tracing::warn!(%origin, %media_id, error = %e, "remote media eviction: row delete failed");
            continue;
        }
        tracing::debug!(%origin, %media_id, size, "remote media cache: evicted for space");
        total = total.saturating_sub(size);
    }
    true
}

/// Map a federation media fetch failure onto the client-facing class.
/// Only a genuine peer 404 becomes a 404; everything else says so
/// honestly, since the media may well exist.
fn classify_fetch_error(
    origin: &str,
    media_id: &str,
    e: crate::federation::federation_client::FederationClientError,
) -> RemoteFetchFailure {
    use crate::federation::federation_client::FederationClientError as E;
    tracing::debug!(remote = %origin, %media_id, error = %e, "federation media fetch failed");
    match e {
        E::Status { code: 404, errcode } => {
            if errcode.as_deref() == Some("M_UNRECOGNIZED") {
                RemoteFetchFailure::LegacyPeer
            } else {
                RemoteFetchFailure::NotFound
            }
        }
        E::Status { code: 504, .. } => RemoteFetchFailure::NotYetUploaded,
        E::Status { code: 413, .. } | E::TooLarge { .. } => RemoteFetchFailure::TooLarge,
        _ => RemoteFetchFailure::Unavailable,
    }
}

fn media_response(
    media: MediaResponse,
    filename_override: Option<&str>,
) -> Result<Response, ApiError> {
    let len = media.bytes.len();
    let mut builder = with_media_security_headers(Response::builder().status(StatusCode::OK))
        .header(header::CONTENT_TYPE, media.content_type)
        .header(header::CONTENT_LENGTH, len.to_string());
    // Spec: a `{filename}` URL segment overrides the stored name. Otherwise
    // propagate the peer's filename so clients see the Unicode-safe name
    // whether the file came from us or via federation.
    let filename = filename_override.or(media.filename.as_deref());
    if let Some(filename) = filename
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

#[cfg(test)]
mod remote_media_cache_tests {
    use super::*;
    use crate::test_helpers::build_test_state;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ORIGIN: &str = "remote.example";

    fn png(width: u32, height: u32) -> Vec<u8> {
        let img = image::RgbaImage::from_pixel(width, height, image::Rgba([10, 200, 30, 255]));
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
            .unwrap();
        out
    }

    fn png_dims(bytes: &[u8]) -> (u32, u32) {
        let img = image::load_from_memory(bytes).unwrap();
        (img.width(), img.height())
    }

    /// A peer serving `bytes` for `media_id` on the federation download
    /// endpoint, on the legacy non-multipart path, expecting exactly
    /// `expect` fetches.
    async fn peer(state: &AppState, media_id: &str, bytes: Vec<u8>, expect: u64) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/_matrix/federation/v1/media/download/{media_id}"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "image/png")
                    .insert_header("content-disposition", "inline; filename=\"cat.png\"")
                    .set_body_bytes(bytes),
            )
            .expect(expect)
            .mount(&server)
            .await;
        state
            .federation_client
            .set_base_url_override(ORIGIN, &server.uri());
        server
    }

    async fn download(
        state: &AppState,
        media_id: &str,
        name: Option<&str>,
    ) -> Result<Response, ApiError> {
        download_inner(
            State(state.clone()),
            Path((
                ORIGIN.to_string(),
                media_id.to_string(),
                name.map(str::to_string),
            )),
        )
        .await
    }

    async fn thumbnail(
        state: &AppState,
        media_id: &str,
        w: u32,
        h: u32,
    ) -> Result<Response, ApiError> {
        thumbnail_inner(
            State(state.clone()),
            ORIGIN.to_string(),
            media_id.to_string(),
            ThumbnailQuery {
                width: Some(w),
                height: Some(h),
                method: Some("scale".into()),
                animated: None,
                allow_remote: None,
                allow_redirect: None,
                timeout_ms: None,
            },
        )
        .await
    }

    fn header(resp: &Response, name: header::HeaderName) -> Option<String> {
        resp.headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    }

    async fn body(resp: Response) -> Vec<u8> {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn second_download_is_served_from_cache() {
        let (state, _tmp) = build_test_state();
        let bytes = png(40, 30);
        let server = peer(&state, "m1", bytes.clone(), 1).await;

        for _ in 0..2 {
            let resp = download(&state, "m1", None).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                header(&resp, header::CONTENT_TYPE).as_deref(),
                Some("image/png")
            );
            assert!(
                header(&resp, header::CONTENT_DISPOSITION)
                    .unwrap()
                    .contains("cat.png")
            );
            assert_eq!(body(resp).await, bytes);
        }
        let row = state.db.get_remote_media(ORIGIN, "m1").unwrap().unwrap();
        assert_eq!(row["size"], bytes.len());
        assert_eq!(row["content_type"], "image/png");
        assert_eq!(row["filename"], "cat.png");
        server.verify().await;
    }

    #[tokio::test]
    async fn thumbnail_after_download_does_not_refetch() {
        let (state, _tmp) = build_test_state();
        let bytes = png(400, 300);
        let server = peer(&state, "m2", bytes.clone(), 1).await;

        download(&state, "m2", None).await.unwrap();
        let resp = thumbnail(&state, "m2", 96, 96).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            header(&resp, header::CONTENT_TYPE).as_deref(),
            Some("image/png")
        );
        let thumb = body(resp).await;
        let local = resize_to_png_thumbnail(&bytes, 96, 96, "scale").unwrap();
        assert_eq!(png_dims(&thumb), png_dims(&local));
        assert!(png_dims(&thumb).0 < 400);
        server.verify().await;
    }

    #[tokio::test]
    async fn concurrent_first_requests_share_one_fetch() {
        let (state, _tmp) = build_test_state();
        let bytes = png(40, 30);
        let server = peer(&state, "m3", bytes.clone(), 1).await;

        let mut tasks = Vec::new();
        for _ in 0..32 {
            let st = state.clone();
            tasks.push(tokio::spawn(async move {
                body(download(&st, "m3", None).await.unwrap()).await
            }));
        }
        for t in tasks {
            assert_eq!(t.await.unwrap(), bytes);
        }
        assert!(
            state.remote_media_locks.is_empty(),
            "single-flight entries must not outlive the requests"
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn peer_404_is_not_cached() {
        let (state, _tmp) = build_test_state();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .expect(2)
            .mount(&server)
            .await;
        state
            .federation_client
            .set_base_url_override(ORIGIN, &server.uri());

        for _ in 0..2 {
            let err = download(&state, "gone", None).await.unwrap_err();
            assert_eq!(err.0.status_code(), 404);
        }
        assert!(state.db.get_remote_media(ORIGIN, "gone").unwrap().is_none());
        server.verify().await;
    }

    /// Requests queued behind one failing fetch share its verdict instead
    /// of each timing out in turn; requests after the slot is gone retry.
    #[tokio::test]
    async fn concurrent_misses_share_one_failure() {
        let (state, _tmp) = build_test_state();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(404).set_delay(std::time::Duration::from_millis(300)),
            )
            .expect(2)
            .mount(&server)
            .await;
        state
            .federation_client
            .set_base_url_override(ORIGIN, &server.uri());

        let started = std::time::Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let st = state.clone();
            tasks.push(tokio::spawn(async move {
                download(&st, "gone", None)
                    .await
                    .unwrap_err()
                    .0
                    .status_code()
            }));
        }
        for t in tasks {
            assert_eq!(t.await.unwrap(), 404);
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "waiters must not serialise 32 fetches"
        );
        assert!(state.remote_media_locks.is_empty());
        // Fresh request after the slot is gone fetches again.
        assert_eq!(
            download(&state, "gone", None)
                .await
                .unwrap_err()
                .0
                .status_code(),
            404
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn cancelled_request_leaves_no_slot_behind() {
        let (state, _tmp) = build_test_state();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "image/png")
                    .set_body_bytes(png(10, 10))
                    .set_delay(std::time::Duration::from_secs(5)),
            )
            .mount(&server)
            .await;
        state
            .federation_client
            .set_base_url_override(ORIGIN, &server.uri());

        let st = state.clone();
        let task = tokio::spawn(async move { download(&st, "slow", None).await.map(|_| ()) });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(state.remote_media_locks.len(), 1);
        task.abort();
        let _ = task.await;
        assert!(state.remote_media_locks.is_empty());
    }

    #[tokio::test]
    async fn malformed_references_never_reach_federation() {
        let (state, _tmp) = build_test_state();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        state
            .federation_client
            .set_base_url_override(ORIGIN, &server.uri());
        for (origin, id) in [
            (ORIGIN, "../../_matrix/key/v2/server"),
            (ORIGIN, "a/b"),
            (ORIGIN, "a\0b"),
            (ORIGIN, ""),
            ("bad\0name", "abc"),
            ("remote.example:http", "abc"),
        ] {
            let err = download_inner(
                State(state.clone()),
                Path((origin.to_string(), id.to_string(), None)),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0.status_code(), 404, "{origin}/{id}");
            let err = thumbnail_inner(
                State(state.clone()),
                origin.to_string(),
                id.to_string(),
                ThumbnailQuery {
                    width: None,
                    height: None,
                    method: None,
                    animated: None,
                    allow_remote: None,
                    allow_redirect: None,
                    timeout_ms: None,
                },
            )
            .await
            .unwrap_err();
            assert_eq!(err.0.status_code(), 404, "{origin}/{id}");
        }
        server.verify().await;
    }

    #[tokio::test]
    async fn legacy_peer_404_is_not_reported_as_not_found() {
        let (state, _tmp) = build_test_state();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "errcode": "M_UNRECOGNIZED",
                "error": "Unrecognized request"
            })))
            .mount(&server)
            .await;
        state
            .federation_client
            .set_base_url_override(ORIGIN, &server.uri());
        let err = download(&state, "old", None).await.unwrap_err();
        assert_eq!(err.0.status_code(), 502);
    }

    fn with_budget(state: &AppState, budget: u64) -> AppState {
        let mut st = state.clone();
        let mut cfg = (*st.config).clone();
        cfg.remote_media_cache_max_bytes = budget;
        st.config = std::sync::Arc::new(cfg);
        st
    }

    #[tokio::test]
    async fn budget_evicts_least_recently_read_first() {
        let (base, _tmp) = build_test_state();
        let a = png(20, 20);
        let size = a.len() as u64;
        // Room for two files, not three.
        let state = with_budget(&base, size * 2 + size / 2);
        let server = MockServer::start().await;
        for id in ["a", "b", "c"] {
            Mock::given(method("GET"))
                .and(path(format!("/_matrix/federation/v1/media/download/{id}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "image/png")
                        .set_body_bytes(a.clone()),
                )
                .mount(&server)
                .await;
        }
        state
            .federation_client
            .set_base_url_override(ORIGIN, &server.uri());

        download(&state, "a", None).await.unwrap();
        download(&state, "b", None).await.unwrap();
        // Make "a" the stale one and "b" freshly read.
        let mut row = state.db.get_remote_media(ORIGIN, "a").unwrap().unwrap();
        row["last_access_at"] = json!(now_ms() - 10 * REMOTE_ACCESS_TOUCH_MS);
        state.db.set_remote_media(ORIGIN, "a", &row).unwrap();
        let a_blob = row["blob_id"].as_str().unwrap().to_string();

        download(&state, "c", None).await.unwrap();
        assert!(state.db.get_remote_media(ORIGIN, "a").unwrap().is_none());
        assert!(state.media_store.get(&a_blob).await.unwrap().is_none());
        assert!(state.db.get_remote_media(ORIGIN, "b").unwrap().is_some());
        assert!(state.db.get_remote_media(ORIGIN, "c").unwrap().is_some());
    }

    #[tokio::test]
    async fn file_larger_than_budget_is_served_but_not_cached() {
        let (base, _tmp) = build_test_state();
        let bytes = png(20, 20);
        let state = with_budget(&base, bytes.len() as u64 - 1);
        let server = peer(&state, "big", bytes.clone(), 2).await;
        for _ in 0..2 {
            let resp = download(&state, "big", None).await.unwrap();
            assert_eq!(body(resp).await, bytes);
        }
        assert!(state.db.get_remote_media(ORIGIN, "big").unwrap().is_none());
        server.verify().await;
    }

    /// Waiters behind a successful fetch get its bytes even when the file
    /// never made it into the cache.
    #[tokio::test]
    async fn concurrent_requests_for_uncacheable_file_share_one_fetch() {
        let (base, _tmp) = build_test_state();
        let bytes = png(20, 20);
        let state = with_budget(&base, bytes.len() as u64 - 1);
        let server = peer(&state, "big2", bytes.clone(), 1).await;
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let st = state.clone();
            tasks.push(tokio::spawn(async move {
                body(download(&st, "big2", None).await.unwrap()).await
            }));
        }
        for t in tasks {
            assert_eq!(t.await.unwrap(), bytes);
        }
        server.verify().await;
    }

    #[tokio::test]
    async fn peer_errors_map_to_honest_statuses() {
        let (state, _tmp) = build_test_state();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/_matrix/federation/v1/media/download/pending"))
            .respond_with(ResponseTemplate::new(504))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/_matrix/federation/v1/media/download/big"))
            .respond_with(ResponseTemplate::new(413))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/_matrix/federation/v1/media/download/down"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        state
            .federation_client
            .set_base_url_override(ORIGIN, &server.uri());

        let err = download(&state, "pending", None).await.unwrap_err();
        assert_eq!(err.0.status_code(), 504);
        assert_eq!(err.0.errcode(), "M_NOT_YET_UPLOADED");
        let err = download(&state, "big", None).await.unwrap_err();
        assert_eq!(err.0.status_code(), 502);
        assert_eq!(err.0.errcode(), "M_TOO_LARGE");
        let err = download(&state, "down", None).await.unwrap_err();
        assert_eq!(err.0.status_code(), 502);
    }

    #[tokio::test]
    async fn oversized_body_is_too_large_and_not_cached() {
        let (state, _tmp) = build_test_state();
        let too_big = vec![0u8; state.config.max_upload_size as usize + 1];
        let server = peer(&state, "huge", too_big, 1).await;
        let err = download(&state, "huge", None).await.unwrap_err();
        assert_eq!(err.0.status_code(), 502);
        assert_eq!(err.0.errcode(), "M_TOO_LARGE");
        assert!(state.db.get_remote_media(ORIGIN, "huge").unwrap().is_none());
        server.verify().await;
    }

    #[tokio::test]
    async fn missing_blob_triggers_refetch_and_row_repair() {
        let (state, _tmp) = build_test_state();
        let bytes = png(40, 30);
        let server = peer(&state, "m5", bytes.clone(), 2).await;

        download(&state, "m5", None).await.unwrap();
        let row = state.db.get_remote_media(ORIGIN, "m5").unwrap().unwrap();
        let old_blob = row["blob_id"].as_str().unwrap().to_string();
        state.media_store.delete(&old_blob).await.unwrap();

        let resp = download(&state, "m5", None).await.unwrap();
        assert_eq!(body(resp).await, bytes);
        let row = state.db.get_remote_media(ORIGIN, "m5").unwrap().unwrap();
        let new_blob = row["blob_id"].as_str().unwrap();
        assert_ne!(new_blob, old_blob);
        assert!(state.media_store.get(new_blob).await.unwrap().is_some());
        server.verify().await;
    }

    #[tokio::test]
    async fn cached_blob_is_not_servable_as_local_media() {
        let (state, _tmp) = build_test_state();
        let _server = peer(&state, "m6", png(40, 30), 1).await;
        download(&state, "m6", None).await.unwrap();
        let row = state.db.get_remote_media(ORIGIN, "m6").unwrap().unwrap();
        let blob_id = row["blob_id"].as_str().unwrap().to_string();

        let err = download_inner(
            State(state.clone()),
            Path((state.config.server_name.clone(), blob_id.clone(), None)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0.status_code(), 404);

        let status = federation_media::federation_download(
            State(state.clone()),
            Path(blob_id),
            Query(federation_media::MediaDownloadQuery::default()),
            axum::extract::Extension(crate::middleware::federation_auth::XMatrixOrigin(
                "other.example".into(),
            )),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn url_filename_segment_overrides_peer_filename() {
        let (state, _tmp) = build_test_state();
        let _server = peer(&state, "m7", png(40, 30), 1).await;
        let resp = download(&state, "m7", Some("mine.png")).await.unwrap();
        let cd = header(&resp, header::CONTENT_DISPOSITION).unwrap();
        assert!(cd.contains("mine.png"), "{cd}");
        assert!(!cd.contains("cat.png"), "{cd}");
    }

    #[tokio::test]
    async fn last_access_is_touched_hourly_not_per_read() {
        let (state, _tmp) = build_test_state();
        let _server = peer(&state, "m8", png(40, 30), 1).await;
        download(&state, "m8", None).await.unwrap();
        let fresh = state.db.get_remote_media(ORIGIN, "m8").unwrap().unwrap();
        download(&state, "m8", None).await.unwrap();
        let again = state.db.get_remote_media(ORIGIN, "m8").unwrap().unwrap();
        assert_eq!(fresh["last_access_at"], again["last_access_at"]);

        let mut stale = again.clone();
        stale["last_access_at"] = json!(now_ms() - REMOTE_ACCESS_TOUCH_MS - 1);
        state.db.set_remote_media(ORIGIN, "m8", &stale).unwrap();
        download(&state, "m8", None).await.unwrap();
        let touched = state.db.get_remote_media(ORIGIN, "m8").unwrap().unwrap();
        assert!(
            touched["last_access_at"].as_u64().unwrap() > stale["last_access_at"].as_u64().unwrap()
        );
    }
}

#[cfg(all(test, feature = "extensions"))]
mod media_extension_tests {
    use super::*;
    use crate::test_helpers::build_test_state;
    use axum::extract::Query;

    // Gitignored fixture — run vela-extensions/tests/fixtures/build.sh first (CI does).
    const MEDIA: &[u8] = include_bytes!("../../../vela-extensions/tests/fixtures/media_guest.wasm");

    fn user() -> AuthenticatedUser {
        AuthenticatedUser {
            user_nid: 1,
            user_id: "@a:test".into(),
            device_id: "D".into(),
            appservice_nid: None,
        }
    }

    /// A media plugin blocks an upload whose content hashes to a known-bad value
    /// (sha256 of "bad") — proving the gate runs, the in-stream hash is computed,
    /// and a clean upload still goes through.
    #[tokio::test]
    async fn upload_blocked_by_known_hash() {
        let (state, _tmp) = build_test_state();
        let rt = vela_extensions::Runtime::new(vec![vela_extensions::PluginConfig {
            name: "media".into(),
            wasm: MEDIA.to_vec(),
            fail_policy: vela_extensions::FailPolicy::Closed,
            fuel: 50_000_000,
            wall_ms: 0,
            memory_pages: 256,
            event_types: None,
            points: vela_extensions::Points {
                check_event: false,
                on_event: false,
                check_registration: false,
                check_media_upload: true,
                check_profile_update: false,
                check_room_create: false,
                filter_sync_event: false,
                check_login: false,
            },
            capabilities: Default::default(),
            client_ip: Default::default(),
            config: serde_json::json!({ "mode": "block_hash" }),
        }])
        .expect("media plugin loads");
        state.extensions.store(std::sync::Arc::new(rt));

        // "bad" hashes to the fixture's blocklisted value → rejected.
        let err = upload(
            State(state.clone()),
            user(),
            Query(UploadQuery { filename: None }),
            axum::http::HeaderMap::new(),
            Body::from("bad"),
        )
        .await
        .expect_err("known-bad upload blocked");
        assert!(matches!(err.0, VelaError::ExtensionBlocked { .. }));

        // A clean upload still succeeds (different hash → allowed).
        let ok = upload(
            State(state.clone()),
            user(),
            Query(UploadQuery { filename: None }),
            axum::http::HeaderMap::new(),
            Body::from("good"),
        )
        .await
        .expect("clean upload allowed");
        assert!(ok.0.get("content_uri").is_some());
    }
}

#[cfg(test)]
mod preview_ssrf_tests {
    use super::*;

    /// The SSRF guard refuses every flavour of internal/reserved address.
    #[tokio::test]
    async fn rejects_internal_ip_literals() {
        for bad in [
            "127.0.0.1",       // loopback
            "169.254.169.254", // link-local / cloud metadata
            "10.0.0.5",        // RFC1918
            "192.168.1.1",     // RFC1918
            "100.64.0.1",      // CGNAT
            "0.0.0.0",         // unspecified
            "[::1]",           // v6 loopback (bracketed, as host_str yields)
            "[fe80::1]",       // v6 link-local (bracketed)
            "[::ffff:7f00:1]", // v4-mapped loopback (bracketed)
        ] {
            assert!(
                resolve_public_or_reject(bad, 80, false).await.is_err(),
                "{bad} must be rejected by the SSRF guard"
            );
        }
    }

    /// A public literal passes (v4 and bracketed v6); the operator opt-out
    /// re-permits internal.
    #[tokio::test]
    async fn allows_public_and_honours_optout() {
        assert!(
            resolve_public_or_reject("8.8.8.8", 443, false)
                .await
                .is_ok()
        );
        assert!(
            resolve_public_or_reject("[2606:4700::1111]", 443, false)
                .await
                .is_ok(),
            "a public IPv6 literal must be accepted"
        );
        assert!(
            resolve_public_or_reject("127.0.0.1", 80, true)
                .await
                .is_ok(),
            "allow_private must re-permit internal targets"
        );
    }

    /// Non-http(s) schemes are refused before any connection.
    #[tokio::test]
    async fn rejects_non_http_scheme() {
        assert!(fetch_preview("file:///etc/passwd", false).await.is_err());
        assert!(fetch_preview("gopher://example.com/", false).await.is_err());
    }

    /// End to end: a loopback target (wiremock binds 127.0.0.1) is blocked
    /// by default and fetched only when the operator opts in.
    #[tokio::test]
    async fn blocks_loopback_target_unless_opted_in() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("<html>ok</html>", "text/html"))
            .mount(&server)
            .await;
        let url = server.uri();

        assert!(
            fetch_preview(&url, false).await.is_err(),
            "loopback target must be blocked by default"
        );
        let (_final, ct, body) = fetch_preview(&url, true)
            .await
            .expect("allowed with opt-in");
        assert!(ct.starts_with("text/html"), "unexpected content-type: {ct}");
        assert_eq!(&body[..], b"<html>ok</html>");
    }

    /// Redirects are followed manually and each hop is re-validated; the
    /// final body comes back.
    #[tokio::test]
    async fn follows_validated_redirect() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/a"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/b"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/b"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/plain")
                    .set_body_string("final"),
            )
            .mount(&server)
            .await;

        let (final_url, _ct, body) = fetch_preview(&format!("{}/a", server.uri()), true)
            .await
            .expect("redirect followed");
        assert!(final_url.ends_with("/b"));
        assert_eq!(&body[..], b"final");
    }
}
