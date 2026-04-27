//! Periodic database backup, in-process.
//!
//! When `[backup] enabled = true`, a background tokio task wakes every
//! `interval`, runs a RocksDB checkpoint into a tempdir, uploads the
//! files to the configured target, and prunes older backups beyond
//! `keep`. Both disk and S3 targets ride the same `object_store::ObjectStore`
//! trait — same code path, different backend.
//!
//! The existing `vela-backup` binary still exists for ad-hoc /
//! out-of-band snapshots; this scheduler handles the routine cadence.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use futures::StreamExt;
use object_store::ObjectStore;
use tracing::{debug, info, warn};

use vela_store::db::Database;

/// Operator-facing config for the periodic backup task.
#[derive(Debug, Clone)]
pub struct BackupConfig {
    pub enabled: bool,
    pub interval: Duration,
    /// `"disk:/var/lib/vela/backups"` or `"s3://bucket/prefix"`. The
    /// disk path is created on first backup if missing.
    pub target: String,
    /// Keep this many most-recent backups; older are deleted after
    /// each successful run. `0` disables retention (keep forever).
    pub keep: usize,
    /// Optional S3 credentials when `target` is an `s3://` URL. When
    /// `None`, the SDK falls back to environment variables / instance
    /// metadata as usual.
    pub s3: Option<S3BackupConfig>,
}

#[derive(Debug, Clone)]
pub struct S3BackupConfig {
    pub region: Option<String>,
    pub endpoint: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub allow_http: bool,
}

/// Parse a target URL into the bucket-or-path component. Returns
/// `Ok((store, prefix))` where `prefix` is the path inside the store
/// at which to write backup directories.
fn build_target(
    target: &str,
    s3: Option<&S3BackupConfig>,
) -> anyhow::Result<(Arc<dyn ObjectStore>, object_store::path::Path)> {
    if let Some(rest) = target.strip_prefix("disk:") {
        let path = PathBuf::from(rest);
        std::fs::create_dir_all(&path).with_context(|| format!("create backup root {path:?}"))?;
        let store = object_store::local::LocalFileSystem::new_with_prefix(&path)
            .with_context(|| format!("open backup target {path:?}"))?;
        return Ok((Arc::new(store), object_store::path::Path::from("")));
    }
    if let Some(rest) = target.strip_prefix("s3://") {
        let (bucket, prefix) = match rest.split_once('/') {
            Some((b, p)) => (b.to_string(), p.to_string()),
            None => (rest.to_string(), String::new()),
        };
        use object_store::aws::AmazonS3Builder;
        let mut b = AmazonS3Builder::new().with_bucket_name(&bucket);
        if let Some(s3) = s3 {
            b = b.with_allow_http(s3.allow_http);
            if let Some(r) = &s3.region {
                b = b.with_region(r);
            }
            if let Some(ep) = &s3.endpoint {
                b = b.with_endpoint(ep);
            }
            if let (Some(k), Some(sk)) = (&s3.access_key_id, &s3.secret_access_key) {
                b = b.with_access_key_id(k).with_secret_access_key(sk);
            }
        }
        let store = b.build().context("build S3 client for backup target")?;
        return Ok((Arc::new(store), object_store::path::Path::from(prefix)));
    }
    anyhow::bail!("unsupported backup target {target:?}: must start with disk: or s3://")
}

/// Spawn the periodic backup task. Holds a clone of the `Database`
/// internally; the caller doesn't need to keep the returned handle
/// alive (we abort it on shutdown via `tokio::select!` from the main
/// task — callers that don't need that can drop the handle).
pub fn spawn_backup_task(db: Arc<Database>, config: BackupConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if !config.enabled {
            return;
        }
        let (store, prefix) = match build_target(&config.target, config.s3.as_ref()) {
            Ok(s) => s,
            Err(e) => {
                warn!(target = %config.target, error = %e, "backup target init failed; task exiting");
                return;
            }
        };
        info!(
            interval_secs = config.interval.as_secs(),
            target = %config.target,
            keep = config.keep,
            "backup scheduler running"
        );
        // Initial wait so a fresh server doesn't snapshot immediately.
        tokio::time::sleep(config.interval).await;
        loop {
            let started = std::time::Instant::now();
            match run_one_backup(db.clone(), store.as_ref(), &prefix, config.keep).await {
                Ok(name) => {
                    info!(
                        name = %name,
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "backup ok"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "backup failed");
                }
            }
            tokio::time::sleep(config.interval).await;
        }
    })
}

/// Run a single backup: checkpoint the DB into a temp dir, upload all
/// files to `<store>/<prefix>/<timestamp>/`, then prune older backups
/// down to `keep`. Returns the timestamp string used as the backup id.
pub async fn run_one_backup(
    db: Arc<Database>,
    store: &dyn ObjectStore,
    prefix: &object_store::path::Path,
    keep: usize,
) -> anyhow::Result<String> {
    let ts = utc_timestamp();
    let tmp = tempfile::tempdir().context("backup tempdir")?;
    let checkpoint_path = tmp.path().join("checkpoint");
    // RocksDB checkpoint is a sync FFI call (hard-link based, near
    // instant) but not async; isolate from the runtime via spawn_blocking
    // so we don't stall axum workers.
    let cp_path = checkpoint_path.clone();
    tokio::task::spawn_blocking(move || db.checkpoint(&cp_path))
        .await
        .context("join checkpoint task")?
        .context("checkpoint failed")?;

    upload_dir(store, prefix, &ts, &checkpoint_path).await?;
    drop(tmp);

    if keep > 0 {
        prune_old(store, prefix, keep).await?;
    }
    Ok(ts)
}

async fn upload_dir(
    store: &dyn ObjectStore,
    prefix: &object_store::path::Path,
    ts: &str,
    src: &Path,
) -> anyhow::Result<()> {
    // Walk `src` and upload every regular file at its relative path,
    // anchored under `<prefix>/<ts>/`.
    let mut stack = vec![src.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut rd = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = rd.next_entry().await? {
            let path = entry.path();
            let ft = entry.file_type().await?;
            if ft.is_dir() {
                stack.push(path);
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let rel = path
                .strip_prefix(src)
                .context("strip checkpoint prefix")?
                .to_string_lossy()
                .to_string();
            let key = if prefix.as_ref().is_empty() {
                format!("{ts}/{rel}")
            } else {
                format!("{prefix}/{ts}/{rel}", prefix = prefix.as_ref())
            };
            let bytes = tokio::fs::read(&path).await?;
            let body = Bytes::from(bytes);
            store
                .put(&object_store::path::Path::from(key.clone()), body.into())
                .await
                .with_context(|| format!("upload {key}"))?;
            debug!(key, "backup file uploaded");
        }
    }
    Ok(())
}

/// List backup directories at `prefix` and delete all but the newest
/// `keep`. Backup names are timestamp-prefixed so lexicographic sort
/// = chronological sort.
pub async fn prune_old(
    store: &dyn ObjectStore,
    prefix: &object_store::path::Path,
    keep: usize,
) -> anyhow::Result<()> {
    // Flat listing + group by first segment. More portable than
    // list_with_delimiter, whose behaviour with an empty prefix
    // varies between backends.
    let list_prefix = if prefix.as_ref().is_empty() {
        None
    } else {
        Some(prefix)
    };
    let mut stream = store.list(list_prefix);
    let mut name_set = std::collections::BTreeSet::new();
    while let Some(item) = stream.next().await {
        let meta = item.context("list backup prefixes")?;
        let s = meta.location.as_ref();
        let rest = if !prefix.as_ref().is_empty() {
            match s.strip_prefix(prefix.as_ref()) {
                Some(r) => r.trim_start_matches('/'),
                None => continue,
            }
        } else {
            s
        };
        let first = rest.split('/').next().unwrap_or("");
        if !first.is_empty() {
            name_set.insert(first.to_string());
        }
    }
    let names: Vec<String> = name_set.into_iter().collect(); // BTreeSet → sorted
    if names.len() <= keep {
        return Ok(());
    }
    let drop_count = names.len() - keep;
    let to_drop: Vec<String> = names.into_iter().take(drop_count).collect();
    for name in to_drop {
        let dir_prefix = if prefix.as_ref().is_empty() {
            object_store::path::Path::from(name.clone())
        } else {
            object_store::path::Path::from(format!("{}/{}", prefix.as_ref(), name))
        };
        delete_recursive(store, &dir_prefix).await?;
        info!(%name, "pruned old backup");
    }
    Ok(())
}

async fn delete_recursive(
    store: &dyn ObjectStore,
    prefix: &object_store::path::Path,
) -> anyhow::Result<()> {
    let mut stream = store.list(Some(prefix));
    while let Some(item) = stream.next().await {
        let meta = item.context("list during delete")?;
        store.delete(&meta.location).await.context("delete")?;
    }
    Ok(())
}

fn utc_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let secs_in_day: u64 = 86400;
    let days = now / secs_in_day;
    let sod = now % secs_in_day;
    // Cheap epoch → date conversion. Good enough for filename
    // ordering; precision-sensitive code uses chrono. We avoid pulling
    // in chrono just for this.
    let (y, mo, d) = days_to_ymd(days);
    let hh = sod / 3600;
    let mm = (sod % 3600) / 60;
    let ss = sod % 60;
    format!("{y:04}-{mo:02}-{d:02}T{hh:02}-{mm:02}-{ss:02}Z")
}

/// Convert days-since-1970-01-01 into (year, month, day). Civil-from-days
/// algorithm, assumes Gregorian calendar.
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let days = days as i64 + 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = (days - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y as u64, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_disk_target() {
        let tmp = tempfile::tempdir().unwrap();
        let target = format!("disk:{}", tmp.path().display());
        let (_store, prefix) = build_target(&target, None).expect("disk target builds");
        assert_eq!(prefix.as_ref(), "");
    }

    #[test]
    fn parse_s3_target_extracts_prefix() {
        let s3 = S3BackupConfig {
            region: Some("us-east-1".into()),
            endpoint: None,
            access_key_id: Some("k".into()),
            secret_access_key: Some("s".into()),
            allow_http: false,
        };
        let (_store, prefix) =
            build_target("s3://my-bucket/some/prefix", Some(&s3)).expect("s3 target builds");
        assert_eq!(prefix.as_ref(), "some/prefix");

        let (_store, prefix) =
            build_target("s3://my-bucket", Some(&s3)).expect("bare bucket builds");
        assert_eq!(prefix.as_ref(), "");
    }

    #[test]
    fn parse_unknown_target_rejected() {
        let res = build_target("ftp://nope", None);
        assert!(res.is_err());
        let res = build_target("/just/a/path", None);
        assert!(res.is_err());
    }

    #[test]
    fn ymd_known_dates() {
        // Spot-check the days_to_ymd helper against well-known epochs.
        // 1970, 1971 are not leap years; 1972 is.
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        assert_eq!(days_to_ymd(31), (1970, 2, 1));
        assert_eq!(days_to_ymd(365), (1971, 1, 1));
        assert_eq!(days_to_ymd(730), (1972, 1, 1));
        assert_eq!(days_to_ymd(730 + 31 + 28), (1972, 2, 29)); // leap day
    }

    #[test]
    fn timestamp_is_well_formed() {
        let ts = utc_timestamp();
        // YYYY-MM-DDTHH-MM-SSZ → 20 chars
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[tokio::test]
    async fn upload_and_prune_against_local_filesystem() {
        // End-to-end: stage a fake "checkpoint" directory, upload via
        // run_one_backup-equivalent, then run prune and check retention.
        let tmp_root = tempfile::tempdir().unwrap();
        let backup_root = tmp_root.path().join("backups");
        std::fs::create_dir_all(&backup_root).unwrap();
        let store: Arc<dyn ObjectStore> =
            Arc::new(object_store::local::LocalFileSystem::new_with_prefix(&backup_root).unwrap());
        let prefix = object_store::path::Path::from("");

        // Fake checkpoint contents.
        let staging = tempfile::tempdir().unwrap();
        std::fs::write(staging.path().join("MANIFEST"), b"manifest").unwrap();
        std::fs::write(staging.path().join("000123.sst"), b"sst data").unwrap();

        // Upload three "backups" with chronological-ish names.
        for ts in [
            "2026-01-01T00-00-00Z",
            "2026-01-02T00-00-00Z",
            "2026-01-03T00-00-00Z",
        ] {
            upload_dir(store.as_ref(), &prefix, ts, staging.path())
                .await
                .expect("upload");
        }

        // Sanity: all three "directories" appear via flat listing.
        let initial: Vec<String> = collect_top_segments(store.as_ref(), &prefix).await;
        assert_eq!(initial.len(), 3);

        // Prune to keep=2 — the oldest's files must be gone. (The
        // empty directory shell may linger on local fs; we verify
        // by file-existence, not by directory listing.)
        prune_old(store.as_ref(), &prefix, 2).await.expect("prune");

        // Files for 2026-01-01 should no longer exist; 02 and 03 should.
        async fn files_for(store: &dyn ObjectStore, day: &str) -> Vec<String> {
            let p = object_store::path::Path::from(day);
            let mut s = store.list(Some(&p));
            let mut out = vec![];
            while let Some(item) = s.next().await {
                if let Ok(m) = item {
                    out.push(m.location.as_ref().to_string());
                }
            }
            out
        }
        assert_eq!(
            files_for(store.as_ref(), "2026-01-01T00-00-00Z")
                .await
                .len(),
            0
        );
        assert_eq!(
            files_for(store.as_ref(), "2026-01-02T00-00-00Z")
                .await
                .len(),
            2
        );
        assert_eq!(
            files_for(store.as_ref(), "2026-01-03T00-00-00Z")
                .await
                .len(),
            2
        );
    }

    /// Walk a flat list and return the unique first-segment names. Used
    /// in the test instead of `list_with_delimiter` because the latter's
    /// behaviour for "empty dirs after delete" varies between backends.
    async fn collect_top_segments(
        store: &dyn ObjectStore,
        prefix: &object_store::path::Path,
    ) -> Vec<String> {
        let list_prefix = if prefix.as_ref().is_empty() {
            None
        } else {
            Some(prefix)
        };
        let mut stream = store.list(list_prefix);
        let mut set = std::collections::BTreeSet::new();
        while let Some(item) = stream.next().await {
            if let Ok(m) = item {
                let s = m.location.as_ref();
                if let Some(first) = s.split('/').next()
                    && !first.is_empty()
                {
                    set.insert(first.to_string());
                }
            }
        }
        set.into_iter().collect()
    }
}
