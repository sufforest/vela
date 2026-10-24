//! Periodic data retention sweeps.
//!
//! Today this covers media only — local user uploads and cached remote
//! media expire on independent timelines. Event
//! retention via MSC1763 / server-default purge is Pass 5 work; the
//! retention story for events is more delicate (auth chain, state
//! resolution) and gets its own design pass.
//!
//! The scheduler is the same shape as the backup task: a tokio loop
//! that sleeps `interval`, runs one sweep, and sleeps again. Failures
//! are logged per-entry and don't abort the sweep.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use vela_store::db::Database;
use vela_store::media::MediaStore;

/// Operator-facing retention config.
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    pub enabled: bool,
    pub interval: Duration,
    /// Local-uploaded media lifetime. `None` = keep forever.
    pub local_media_lifetime: Option<Duration>,
    /// Remote-cached media lifetime. `None` = keep forever.
    pub remote_media_lifetime: Option<Duration>,
    /// This server's name; used to classify uploaders as local vs remote.
    pub server_name: String,
}

/// Parse a lifetime string into a `Duration`. Special values:
/// `"forever"` / `""` / unset → `None` (keep forever).
/// Otherwise: same suffixes as the backup-interval parser
/// (`365d`, `24h`, `30m`, `15s`, bare seconds).
pub fn parse_lifetime(s: &str) -> anyhow::Result<Option<Duration>> {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("forever") {
        return Ok(None);
    }
    let mult: u64 = if trimmed.ends_with('d') || trimmed.ends_with('D') {
        86400
    } else if trimmed.ends_with('h') || trimmed.ends_with('H') {
        3600
    } else if trimmed.ends_with('m') || trimmed.ends_with('M') {
        60
    } else {
        // 's'/'S' suffix or no suffix at all → seconds.
        1
    };
    let num_str = trimmed
        .trim_end_matches(|c: char| c.is_ascii_alphabetic())
        .trim();
    let n: u64 = num_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid lifetime {s:?}: {e}"))?;
    Ok(Some(Duration::from_secs(n.saturating_mul(mult))))
}

/// True when `uploader_user_id` lives on `our_server_name`.
fn is_local_uploader(uploader: &str, our_server: &str) -> bool {
    uploader
        .split_once(':')
        .map(|(_, server)| server == our_server)
        .unwrap_or(false)
}

/// Spawn the retention scheduler. No-op when disabled.
pub fn spawn_retention_task(
    db: Arc<Database>,
    media_store: Arc<dyn MediaStore>,
    config: RetentionConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if !config.enabled {
            return;
        }
        if config.local_media_lifetime.is_none() && config.remote_media_lifetime.is_none() {
            info!("retention: enabled but both media lifetimes are 'forever' — task exiting");
            return;
        }
        info!(
            interval_secs = config.interval.as_secs(),
            local = ?config.local_media_lifetime.map(|d| d.as_secs()),
            remote = ?config.remote_media_lifetime.map(|d| d.as_secs()),
            "retention scheduler running"
        );
        // Initial sleep so a fresh server doesn't sweep immediately.
        tokio::time::sleep(config.interval).await;
        loop {
            let started = std::time::Instant::now();
            match run_one_media_pass(db.as_ref(), media_store.as_ref(), &config).await {
                Ok(report) => {
                    info!(
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        examined = report.examined,
                        deleted = report.deleted,
                        skipped = report.skipped,
                        "retention sweep ok"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "retention sweep failed");
                }
            }
            tokio::time::sleep(config.interval).await;
        }
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub examined: usize,
    pub deleted: usize,
    pub skipped: usize,
}

/// Run a single media-retention pass. Local uploads: classify each
/// metadata row by uploader's server, compare `created_at` against the
/// matching lifetime, delete blob + metadata if expired. Cached remote
/// media: expire by `last_access_at` against the remote lifetime.
pub async fn run_one_media_pass(
    db: &Database,
    media_store: &dyn MediaStore,
    config: &RetentionConfig,
) -> anyhow::Result<SweepReport> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let entries = db
        .list_media_metadata()
        .map_err(|e| anyhow::anyhow!("list media: {e}"))?;
    let mut report = SweepReport::default();
    for (media_id, meta) in entries {
        report.examined += 1;
        let created_at = meta.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
        let uploader = meta.get("uploader").and_then(|v| v.as_str()).unwrap_or("");
        let lifetime = if is_local_uploader(uploader, &config.server_name) {
            config.local_media_lifetime
        } else {
            config.remote_media_lifetime
        };
        let Some(lifetime) = lifetime else {
            report.skipped += 1;
            continue;
        };
        let age_ms = now_ms.saturating_sub(created_at);
        if age_ms < lifetime.as_millis() as u64 {
            report.skipped += 1;
            continue;
        }
        debug!(%media_id, %uploader, age_ms, "retention: expiring");
        if let Err(e) = media_store.delete(&media_id).await {
            // Log + continue. Storage hiccup shouldn't stall the
            // entire sweep; we'll retry next interval.
            warn!(%media_id, error = %e, "retention: blob delete failed; metadata kept");
            continue;
        }
        if let Err(e) = db.delete_media_metadata(&media_id) {
            warn!(%media_id, error = %e, "retention: metadata delete failed; row will reappear next sweep");
            continue;
        }
        report.deleted += 1;
    }

    // Remote media fetched over federation lives in its own table and
    // ages by last use, not by upload time: a file nobody has opened for
    // `remote_media_lifetime` goes, a file opened yesterday stays.
    if let Some(lifetime) = config.remote_media_lifetime {
        let rows = db
            .list_remote_media()
            .map_err(|e| anyhow::anyhow!("list remote media: {e}"))?;
        for (origin, media_id, row) in rows {
            report.examined += 1;
            let last_access = row
                .get("last_access_at")
                .or_else(|| row.get("cached_at"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if now_ms.saturating_sub(last_access) < lifetime.as_millis() as u64 {
                report.skipped += 1;
                continue;
            }
            debug!(%origin, %media_id, "retention: expiring cached remote media");
            let blob_id = row.get("blob_id").and_then(|v| v.as_str());
            if let Some(blob_id) = blob_id
                && let Err(e) = media_store.delete(blob_id).await
            {
                warn!(%origin, %media_id, error = %e, "retention: remote blob delete failed; row kept");
                continue;
            }
            // A read that raced us may have refetched the file under a new
            // blob; leave that fresh row alone.
            let current = db.get_remote_media(&origin, &media_id).ok().flatten();
            let current_blob = current
                .as_ref()
                .and_then(|r| r.get("blob_id"))
                .and_then(|v| v.as_str());
            if current_blob != blob_id {
                report.skipped += 1;
                continue;
            }
            if let Err(e) = db.delete_remote_media(&origin, &media_id) {
                warn!(%origin, %media_id, error = %e, "retention: remote row delete failed; will retry next sweep");
                continue;
            }
            report.deleted += 1;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    use tempfile::TempDir;
    use vela_store::media::FilesystemMediaStore;

    fn build_db() -> (Arc<Database>, TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).expect("db"));
        (db, tmp)
    }

    #[test]
    fn parse_lifetime_special_values() {
        assert_eq!(parse_lifetime("").unwrap(), None);
        assert_eq!(parse_lifetime("forever").unwrap(), None);
        assert_eq!(parse_lifetime("FOREVER").unwrap(), None);
        assert_eq!(parse_lifetime("  forever  ").unwrap(), None);
    }

    #[test]
    fn parse_lifetime_durations() {
        assert_eq!(
            parse_lifetime("1d").unwrap(),
            Some(Duration::from_secs(86400))
        );
        assert_eq!(
            parse_lifetime("365d").unwrap(),
            Some(Duration::from_secs(365 * 86400))
        );
        assert_eq!(
            parse_lifetime("24h").unwrap(),
            Some(Duration::from_secs(86400))
        );
        assert_eq!(
            parse_lifetime("30m").unwrap(),
            Some(Duration::from_secs(1800))
        );
        assert_eq!(
            parse_lifetime("15s").unwrap(),
            Some(Duration::from_secs(15))
        );
        assert_eq!(parse_lifetime("60").unwrap(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn parse_lifetime_garbage_rejected() {
        assert!(parse_lifetime("nope").is_err());
        assert!(parse_lifetime("d").is_err());
    }

    #[test]
    fn is_local_uploader_split() {
        assert!(is_local_uploader("@alice:matrix.org", "matrix.org"));
        assert!(!is_local_uploader("@alice:other.example", "matrix.org"));
        assert!(!is_local_uploader("@alice", "matrix.org"));
        assert!(!is_local_uploader("", "matrix.org"));
    }

    #[tokio::test]
    async fn local_only_lifetime_keeps_remote_media() {
        // Seed a local upload + a remote-cached upload, both very old.
        // Set local_lifetime = 0s (everything expires), remote = forever.
        // Expect only local to be purged.
        let (db, _tmp) = build_db();
        let media_dir = tempfile::tempdir().unwrap();
        let media_store: Arc<dyn MediaStore> =
            Arc::new(FilesystemMediaStore::new(media_dir.path()).unwrap());

        media_store.put("local0001", b"local body").await.unwrap();
        media_store.put("remote0001", b"remote body").await.unwrap();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let old = now_ms - 10 * 24 * 3600 * 1000; // 10 days ago

        db.set_media_metadata(
            "local0001",
            &json!({
                "uploader": "@alice:vela.example",
                "created_at": old,
                "size": 10,
            }),
        )
        .unwrap();
        db.set_media_metadata(
            "remote0001",
            &json!({
                "uploader": "@bob:remote.example",
                "created_at": old,
                "size": 11,
            }),
        )
        .unwrap();

        let cfg = RetentionConfig {
            enabled: true,
            interval: Duration::from_secs(86400),
            local_media_lifetime: Some(Duration::from_secs(0)), // expire all local
            remote_media_lifetime: None,                        // forever for remote
            server_name: "vela.example".into(),
        };
        let report = run_one_media_pass(db.as_ref(), media_store.as_ref(), &cfg)
            .await
            .unwrap();
        assert_eq!(report.examined, 2);
        assert_eq!(report.deleted, 1);
        assert_eq!(report.skipped, 1);

        assert!(db.get_media_metadata("local0001").unwrap().is_none());
        assert!(media_store.get("local0001").await.unwrap().is_none());
        assert!(db.get_media_metadata("remote0001").unwrap().is_some());
        assert!(media_store.get("remote0001").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn remote_cache_rows_age_by_last_access() {
        let (db, _tmp) = build_db();
        let media_dir = tempfile::tempdir().unwrap();
        let media_store: Arc<dyn MediaStore> =
            Arc::new(FilesystemMediaStore::new(media_dir.path()).unwrap());
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let day = 24 * 3600 * 1000;

        // Cached 40 days ago but opened yesterday: stays. Cached and last
        // opened 40 days ago: goes. Row with no access field falls back
        // to cached_at.
        media_store.put("blobhot0", b"hot").await.unwrap();
        media_store.put("blobcold", b"cold").await.unwrap();
        media_store.put("blobnoac", b"noac").await.unwrap();
        db.set_remote_media(
            "remote.example",
            "hot",
            &json!({"blob_id": "blobhot0", "cached_at": now_ms - 40 * day, "last_access_at": now_ms - day}),
        )
        .unwrap();
        db.set_remote_media(
            "remote.example",
            "cold",
            &json!({"blob_id": "blobcold", "cached_at": now_ms - 40 * day, "last_access_at": now_ms - 40 * day}),
        )
        .unwrap();
        db.set_remote_media(
            "other.example",
            "noaccess",
            &json!({"blob_id": "blobnoac", "cached_at": now_ms - 40 * day}),
        )
        .unwrap();

        let cfg = RetentionConfig {
            enabled: true,
            interval: Duration::from_secs(86400),
            local_media_lifetime: None,
            remote_media_lifetime: Some(Duration::from_secs(30 * 86400)),
            server_name: "vela.example".into(),
        };
        let report = run_one_media_pass(db.as_ref(), media_store.as_ref(), &cfg)
            .await
            .unwrap();
        assert_eq!(report.examined, 3);
        assert_eq!(report.deleted, 2);
        assert_eq!(report.skipped, 1);
        assert!(
            db.get_remote_media("remote.example", "hot")
                .unwrap()
                .is_some()
        );
        assert!(media_store.get("blobhot0").await.unwrap().is_some());
        assert!(
            db.get_remote_media("remote.example", "cold")
                .unwrap()
                .is_none()
        );
        assert!(media_store.get("blobcold").await.unwrap().is_none());
        assert!(
            db.get_remote_media("other.example", "noaccess")
                .unwrap()
                .is_none()
        );
        assert!(media_store.get("blobnoac").await.unwrap().is_none());

        // Lifetime "forever" leaves the remote table alone entirely.
        let forever = RetentionConfig {
            remote_media_lifetime: None,
            ..cfg
        };
        let report = run_one_media_pass(db.as_ref(), media_store.as_ref(), &forever)
            .await
            .unwrap();
        assert_eq!(report.examined, 0);
        assert!(
            db.get_remote_media("remote.example", "hot")
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn fresh_media_under_lifetime_kept() {
        let (db, _tmp) = build_db();
        let media_dir = tempfile::tempdir().unwrap();
        let media_store: Arc<dyn MediaStore> =
            Arc::new(FilesystemMediaStore::new(media_dir.path()).unwrap());
        media_store.put("fresh0001", b"x").await.unwrap();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        db.set_media_metadata(
            "fresh0001",
            &json!({"uploader": "@alice:vela.example", "created_at": now_ms, "size": 1}),
        )
        .unwrap();
        let cfg = RetentionConfig {
            enabled: true,
            interval: Duration::from_secs(60),
            local_media_lifetime: Some(Duration::from_secs(3600)), // 1 hour
            remote_media_lifetime: None,
            server_name: "vela.example".into(),
        };
        let report = run_one_media_pass(db.as_ref(), media_store.as_ref(), &cfg)
            .await
            .unwrap();
        assert_eq!(report.deleted, 0);
        assert_eq!(report.skipped, 1);
        assert!(db.get_media_metadata("fresh0001").unwrap().is_some());
    }

    #[tokio::test]
    async fn malformed_metadata_rows_skipped_not_panicked() {
        // A row missing created_at / uploader still gets walked. A
        // missing created_at defaults to 0 (epoch), which is older
        // than any positive lifetime → would expire. A missing
        // uploader is treated as remote (non-empty server check fails).
        let (db, _tmp) = build_db();
        let media_dir = tempfile::tempdir().unwrap();
        let media_store: Arc<dyn MediaStore> =
            Arc::new(FilesystemMediaStore::new(media_dir.path()).unwrap());
        media_store.put("orphan", b"x").await.unwrap();
        db.set_media_metadata("orphan", &json!({})).unwrap();

        let cfg = RetentionConfig {
            enabled: true,
            interval: Duration::from_secs(60),
            local_media_lifetime: Some(Duration::from_secs(60)),
            remote_media_lifetime: Some(Duration::from_secs(60)),
            server_name: "vela.example".into(),
        };
        let report = run_one_media_pass(db.as_ref(), media_store.as_ref(), &cfg)
            .await
            .unwrap();
        // Treated as remote-with-epoch-zero → expired → deleted.
        assert_eq!(report.deleted, 1);
    }
}
