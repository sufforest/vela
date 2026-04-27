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
use bytes::Bytes;
use futures::TryStreamExt;
use tokio::io::AsyncRead;

/// Boxed async reader returned by `MediaStore::get`. Backends stream
/// the body chunk-by-chunk to keep RSS bounded for large media.
pub type MediaReader = Pin<Box<dyn AsyncRead + Send + Unpin>>;

/// Storage backend for uploaded media blobs. All methods are
/// async and idempotent on the read side; `put` overwrites.
#[async_trait]
pub trait MediaStore: Send + Sync + 'static {
    /// Store `data` under `media_id`. Overwrites any existing blob with
    /// the same id (callers MUST generate fresh ids).
    async fn put(&self, media_id: &str, data: &[u8]) -> std::io::Result<()>;

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
}
