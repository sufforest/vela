//! Media blob storage backends.
//!
//! All operators talk to a `dyn MediaStore`. Filesystem is the default
//! single-pod backend; S3 (via `object_store`, so any S3-compatible:
//! AWS, MinIO, R2, B2) is the multi-pod / off-host backend. The trait
//! is intentionally tiny — `put` / `get` / `delete` / `size` — so a
//! future GCS or Azure backend is a one-file addition.

use std::path::{Path, PathBuf};
use std::pin::Pin;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::TryStreamExt;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Boxed async reader returned by `MediaStore::get`. Backends stream
/// the body chunk-by-chunk to keep RSS bounded for large media. The
/// upload-side reader passed to `put_stream` uses the same shape;
/// callers (vela-api) construct it from the axum body stream.
pub type MediaReader = Pin<Box<dyn AsyncRead + Send + Unpin>>;

/// Storage backend for uploaded media blobs. All methods are
/// async and idempotent on the read side; `put` overwrites.
#[async_trait]
pub trait MediaStore: Send + Sync + 'static {
    /// Store `data` under `media_id`. Overwrites any existing blob with
    /// the same id (callers MUST generate fresh ids).
    async fn put(&self, media_id: &str, data: &[u8]) -> std::io::Result<()>;

    /// Stream `reader` into `media_id`, returning the byte count.
    ///
    /// The default impl reads `reader` fully into RAM and delegates to
    /// `put` — fine for tiny callers (federation cache) but defeats
    /// the OOM-safe guarantee for large uploads. Backends override
    /// this to plumb bytes straight through to durable storage:
    /// filesystem temp-rename, S3 multipart, etc.
    async fn put_stream(
        &self,
        media_id: &str,
        mut reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
    ) -> std::io::Result<u64> {
        let mut buf = Vec::new();
        let n = reader.read_to_end(&mut buf).await? as u64;
        self.put(media_id, &buf).await?;
        Ok(n)
    }

    /// Open `media_id` for streaming reads. Returns `None` if the
    /// blob doesn't exist; backends that can't distinguish "missing"
    /// from "transport error" should map both to `Err`.
    async fn get(&self, media_id: &str) -> std::io::Result<Option<MediaReader>>;

    /// Best-effort size in bytes. Used to populate `Content-Length` on
    /// download responses. Returning `None` is fine; the response then
    /// uses chunked transfer encoding.
    async fn size(&self, media_id: &str) -> std::io::Result<Option<u64>>;

    /// Remove `media_id`. No-op if absent.
    async fn delete(&self, media_id: &str) -> std::io::Result<()>;
}

// --- Filesystem backend ---------------------------------------------------

pub struct FilesystemMediaStore {
    base_path: PathBuf,
}

/// RAII cleanup for the `.tmp.<uuid>` sibling file used by
/// `FilesystemMediaStore::put_stream`. If the streaming copy errors
/// (network drop mid-upload, byte-count cap, disk-full), Drop deletes
/// the half-written tmp file synchronously via `std::fs` — we can't
/// await in Drop. On the success path the caller invokes `commit()`
/// after the atomic rename, which disarms the deletion.
struct TmpFileGuard {
    path: Option<PathBuf>,
}

impl TmpFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn commit(&mut self) {
        self.path = None;
    }
}

impl Drop for TmpFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl FilesystemMediaStore {
    pub fn new(base_path: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(base_path)?;
        Ok(Self {
            base_path: base_path.to_path_buf(),
        })
    }

    fn file_path(&self, media_id: &str) -> PathBuf {
        let shard1 = if media_id.len() >= 2 {
            &media_id[..2]
        } else {
            "00"
        };
        let shard2 = if media_id.len() >= 4 {
            &media_id[2..4]
        } else {
            "00"
        };
        self.base_path.join(shard1).join(shard2).join(media_id)
    }
}

#[async_trait]
impl MediaStore for FilesystemMediaStore {
    async fn put(&self, media_id: &str, data: &[u8]) -> std::io::Result<()> {
        let path = self.file_path(media_id);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&path, data).await
    }

    async fn put_stream(
        &self,
        media_id: &str,
        mut reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
    ) -> std::io::Result<u64> {
        let final_path = self.file_path(media_id);
        if let Some(parent) = final_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        // Sibling `.tmp.<uuid>` so two uploads of the same id (rare but
        // possible: client retry collides with the original) don't
        // truncate each other's in-flight bytes. The UUID is plenty
        // of entropy — collision odds are non-existent in practice.
        let tmp_path = match final_path.parent() {
            Some(parent) => parent.join(format!(
                "{}.tmp.{}",
                media_id,
                uuid::Uuid::new_v4().simple()
            )),
            None => PathBuf::from(format!("{media_id}.tmp.{}", uuid::Uuid::new_v4().simple())),
        };
        let mut guard = TmpFileGuard::new(tmp_path.clone());

        let file = tokio::fs::File::create(&tmp_path).await?;
        let mut writer = tokio::io::BufWriter::new(file);
        let copied = tokio::io::copy(&mut reader, &mut writer).await?;
        // Flush BufWriter into the file, then fsync the file for
        // durability before the rename publishes it. Without the
        // fsync a power loss between rename and writeback can
        // surface as a zero-length file at the final path.
        use tokio::io::AsyncWriteExt;
        writer.flush().await?;
        let file = writer.into_inner();
        file.sync_all().await?;
        drop(file);

        tokio::fs::rename(&tmp_path, &final_path).await?;
        // Rename succeeded — the publish is atomic from this point.
        // Defuse the guard so Drop doesn't try to delete the path
        // we just consumed.
        guard.commit();
        Ok(copied)
    }

    async fn get(&self, media_id: &str) -> std::io::Result<Option<MediaReader>> {
        let path = self.file_path(media_id);
        match tokio::fs::File::open(&path).await {
            Ok(file) => Ok(Some(Box::pin(file))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn size(&self, media_id: &str) -> std::io::Result<Option<u64>> {
        let path = self.file_path(media_id);
        match tokio::fs::metadata(&path).await {
            Ok(m) => Ok(Some(m.len())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, media_id: &str) -> std::io::Result<()> {
        let path = self.file_path(media_id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

// --- S3 (and S3-compatible) backend ---------------------------------------

/// S3 / S3-compatible (MinIO, Cloudflare R2, Backblaze B2) backend.
/// Wraps `object_store::aws::AmazonS3` so the trait surface for the
/// rest of vela stays small.
pub struct S3MediaStore {
    client: object_store::aws::AmazonS3,
    /// Optional prefix prepended to every key. Useful when the bucket
    /// is shared with other workloads ("vela/" namespace).
    prefix: String,
}

/// Operator-facing knobs for the S3 backend. Loaded from `[media.s3]`
/// in vela.toml.
#[derive(Debug, Clone)]
pub struct S3Config {
    pub bucket: String,
    pub region: Option<String>,
    /// Override for non-AWS S3-compatible services (MinIO, R2, B2).
    /// Example: `"https://s3.us-east-005.backblazeb2.com"`.
    pub endpoint: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    /// Key prefix; "" means "use the bucket root."
    pub prefix: String,
    /// True for MinIO/R2 path-style addressing; false for AWS
    /// virtual-hosted addressing.
    pub allow_http: bool,
}

impl S3MediaStore {
    pub fn new(cfg: &S3Config) -> Result<Self, object_store::Error> {
        use object_store::aws::AmazonS3Builder;
        let mut b = AmazonS3Builder::new()
            .with_bucket_name(&cfg.bucket)
            .with_allow_http(cfg.allow_http);
        if let Some(r) = &cfg.region {
            b = b.with_region(r);
        }
        if let Some(ep) = &cfg.endpoint {
            b = b.with_endpoint(ep);
        }
        if let (Some(k), Some(s)) = (&cfg.access_key_id, &cfg.secret_access_key) {
            b = b.with_access_key_id(k).with_secret_access_key(s);
        }
        let client = b.build()?;
        Ok(Self {
            client,
            prefix: cfg.prefix.clone(),
        })
    }

    fn path(&self, media_id: &str) -> object_store::path::Path {
        // Same shard scheme as the FS backend so a switchover preserves
        // the on-disk-vs-S3 layout from the operator's perspective.
        let shard1 = if media_id.len() >= 2 {
            &media_id[..2]
        } else {
            "00"
        };
        let shard2 = if media_id.len() >= 4 {
            &media_id[2..4]
        } else {
            "00"
        };
        let p = if self.prefix.is_empty() {
            format!("{shard1}/{shard2}/{media_id}")
        } else {
            format!("{}/{shard1}/{shard2}/{media_id}", self.prefix)
        };
        object_store::path::Path::from(p)
    }
}

/// Multipart chunk size. S3 (and most S3-compatible stores) require
/// every part except the last to be at least 5 MiB; smaller parts get
/// rejected at `complete_multipart`. We pick exactly 5 MiB so the
/// per-part RAM ceiling on the homeserver matches the protocol floor.
const S3_MULTIPART_CHUNK_SIZE: usize = 5 * 1024 * 1024;

#[async_trait]
impl MediaStore for S3MediaStore {
    async fn put(&self, media_id: &str, data: &[u8]) -> std::io::Result<()> {
        use object_store::ObjectStore;
        let body = Bytes::copy_from_slice(data);
        self.client
            .put(&self.path(media_id), body.into())
            .await
            .map_err(io_err)?;
        Ok(())
    }

    async fn put_stream(
        &self,
        media_id: &str,
        mut reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
    ) -> std::io::Result<u64> {
        use object_store::ObjectStore;
        let path = self.path(media_id);
        let mut upload = self.client.put_multipart(&path).await.map_err(io_err)?;

        let mut total: u64 = 0;
        let mut buf = BytesMut::with_capacity(S3_MULTIPART_CHUNK_SIZE);
        // Read into the buffer until we have a full 5 MiB chunk or hit
        // EOF, then flush. `read_buf` will fill into the spare
        // capacity without realloc as long as we top it up.
        loop {
            // Grow back to chunk capacity after a previous flush split
            // the buffer off; `BytesMut::reserve` is a no-op when we
            // already have room.
            buf.reserve(S3_MULTIPART_CHUNK_SIZE - buf.len());
            let n = match reader.read_buf(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    // Reader failed mid-stream — abort the multipart
                    // so S3 doesn't keep (and charge for) orphan parts.
                    let _ = upload.abort().await;
                    return Err(e);
                }
            };
            if n == 0 {
                // EOF. Flush the tail (if any) then complete.
                if !buf.is_empty() {
                    let part = buf.split().freeze();
                    if let Err(e) = upload.put_part(part.into()).await {
                        let _ = upload.abort().await;
                        return Err(io_err(e));
                    }
                }
                if let Err(e) = upload.complete().await {
                    // complete() itself may invalidate the upload on
                    // some backends; abort is best-effort.
                    let _ = upload.abort().await;
                    return Err(io_err(e));
                }
                return Ok(total);
            }
            total += n as u64;
            if buf.len() >= S3_MULTIPART_CHUNK_SIZE {
                let part = buf.split().freeze();
                if let Err(e) = upload.put_part(part.into()).await {
                    let _ = upload.abort().await;
                    return Err(io_err(e));
                }
            }
        }
    }

    async fn get(&self, media_id: &str) -> std::io::Result<Option<MediaReader>> {
        use object_store::{Error as OsErr, ObjectStore};
        match self.client.get(&self.path(media_id)).await {
            Ok(resp) => {
                let stream = resp.into_stream().map_err(io_err);
                let reader = tokio_util::io::StreamReader::new(stream);
                Ok(Some(Box::pin(reader)))
            }
            Err(OsErr::NotFound { .. }) => Ok(None),
            Err(e) => Err(io_err(e)),
        }
    }

    async fn size(&self, media_id: &str) -> std::io::Result<Option<u64>> {
        use object_store::{Error as OsErr, ObjectStore};
        match self.client.head(&self.path(media_id)).await {
            Ok(meta) => Ok(Some(meta.size as u64)),
            Err(OsErr::NotFound { .. }) => Ok(None),
            Err(e) => Err(io_err(e)),
        }
    }

    async fn delete(&self, media_id: &str) -> std::io::Result<()> {
        use object_store::{Error as OsErr, ObjectStore};
        match self.client.delete(&self.path(media_id)).await {
            Ok(()) => Ok(()),
            Err(OsErr::NotFound { .. }) => Ok(()),
            Err(e) => Err(io_err(e)),
        }
    }
}

fn io_err(e: object_store::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

// --- Tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    async fn read_all(mut r: MediaReader) -> Vec<u8> {
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn fs_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let s = FilesystemMediaStore::new(tmp.path()).unwrap();
        s.put("abcdef", b"hello").await.unwrap();
        let r = s.get("abcdef").await.unwrap().expect("present");
        assert_eq!(read_all(r).await, b"hello");
        assert_eq!(s.size("abcdef").await.unwrap(), Some(5));
        s.delete("abcdef").await.unwrap();
        assert!(s.get("abcdef").await.unwrap().is_none());
        assert!(s.size("abcdef").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn fs_get_missing_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let s = FilesystemMediaStore::new(tmp.path()).unwrap();
        assert!(s.get("nope").await.unwrap().is_none());
        assert!(s.size("nope").await.unwrap().is_none());
        // delete is idempotent
        s.delete("nope").await.unwrap();
    }

    #[tokio::test]
    async fn fs_short_id_doesnt_panic() {
        // Internal shard logic uses byte slices on the id; a one-char
        // id used to risk a slice-bounds panic. Should now fall through
        // to the "00" shard pads.
        let tmp = tempfile::tempdir().unwrap();
        let s = FilesystemMediaStore::new(tmp.path()).unwrap();
        s.put("a", b"x").await.unwrap();
        let r = s.get("a").await.unwrap().expect("present");
        assert_eq!(read_all(r).await, b"x");
    }

    #[tokio::test]
    async fn fs_put_stream_roundtrip_10mib() {
        // The streaming path must produce byte-identical output to
        // `put`. 10 MiB exercises BufWriter flush + multiple read_buf
        // refills, the cases small payloads wouldn't catch.
        use std::io::Cursor;
        let tmp = tempfile::tempdir().unwrap();
        let s = FilesystemMediaStore::new(tmp.path()).unwrap();
        let mut payload = vec![0u8; 10 * 1024 * 1024];
        // Deterministic non-zero fill so a "wrote zeros somewhere"
        // bug can't pass by accident.
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let reader: Pin<Box<dyn AsyncRead + Send + Unpin>> = Box::pin(Cursor::new(payload.clone()));
        let n = s.put_stream("streamid01", reader).await.unwrap();
        assert_eq!(n as usize, payload.len());
        let r = s.get("streamid01").await.unwrap().expect("present");
        assert_eq!(read_all(r).await, payload);
        // No leftover tmp files in the shard dir — the rename consumed
        // the .tmp.<uuid> entry and the guard would have deleted it
        // on any error.
        let shard_dir = tmp.path().join("st").join("re");
        let leftovers: Vec<_> = std::fs::read_dir(&shard_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "tmp files left behind: {leftovers:?}");
    }

    #[tokio::test]
    async fn fs_put_stream_error_cleans_up_tmp() {
        // If the reader errors mid-stream, the .tmp.<uuid> sibling
        // must not survive. Use a reader that returns Ok then Err to
        // ensure the file was created before the failure.
        struct FailAfter {
            chunk: Vec<u8>,
            sent: bool,
        }
        impl tokio::io::AsyncRead for FailAfter {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                if !self.sent {
                    buf.put_slice(&self.chunk);
                    self.sent = true;
                    std::task::Poll::Ready(Ok(()))
                } else {
                    std::task::Poll::Ready(Err(std::io::Error::other("simulated reader failure")))
                }
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let s = FilesystemMediaStore::new(tmp.path()).unwrap();
        let reader: Pin<Box<dyn AsyncRead + Send + Unpin>> = Box::pin(FailAfter {
            chunk: vec![0xab; 1024],
            sent: false,
        });
        let err = s.put_stream("failid0001", reader).await.unwrap_err();
        assert_eq!(err.to_string(), "simulated reader failure");
        // Final path should not exist.
        assert!(s.get("failid0001").await.unwrap().is_none());
        // No `.tmp.<uuid>` sibling left over.
        let shard_dir = tmp.path().join("fa").join("il");
        if shard_dir.exists() {
            let leftovers: Vec<_> = std::fs::read_dir(&shard_dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .collect();
            assert!(
                leftovers.is_empty(),
                "tmp files left behind on error: {leftovers:?}"
            );
        }
    }
}
