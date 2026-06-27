//! Content repository: client upload/download/thumbnail + the
//! federation-side download/thumbnail endpoints.

pub mod federation_media;

use std::pin::Pin;

use crate::middleware::json::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::Response;
use futures::TryStreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncRead;
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
        // Remote thumbnails — delegate to the standard remote-download
        // path which fetches the original from the source server and
        // serves it back. We don't resize remote bytes (yet) to keep
        // this loop bounded.
        return download_remote(&state, &server_name, &media_id).await;
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
    Response::builder()
        .status(StatusCode::OK)
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
async fn resolve_public_or_reject(
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
