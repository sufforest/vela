//! Thin wrapper around `vela_store::Database` in RocksDB secondary
//! mode. Exposed as its own module so the per-command modules don't
//! each have to import the vela-store dependency directly — keeps
//! the surface they touch obvious from one place.

use std::path::Path;

use anyhow::Result;
use vela_store::db::Database;

pub fn open_secondary(primary: &Path, secondary_dir: &Path) -> Result<Database> {
    Database::open_secondary(primary, secondary_dir).map_err(|e| {
        anyhow::anyhow!(
            "open vela DB at {} (secondary scratch {}): {}",
            primary.display(),
            secondary_dir.display(),
            e
        )
    })
}
