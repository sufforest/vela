//! `vela-backup` — point-in-time RocksDB snapshot of a Vela data directory.
//!
//! RocksDB's native `CheckpointObject` creates a hard-link-based copy of
//! the live database in a new directory, so the operation is
//! near-instant and costs almost no extra disk on the same filesystem.
//! Restore is a file copy. Known caveats: in-flight outbound federation
//! transactions can be lost between backup and crash; the server signing
//! key lives in the DB so restore brings it back intact.

use std::path::PathBuf;

use clap::Parser;
use vela_store::db::Database;

#[derive(Parser)]
#[command(
    name = "vela-backup",
    version,
    about = "Point-in-time snapshot of a Vela database"
)]
struct Args {
    /// Path to the live Vela database directory.
    #[arg(long)]
    db: PathBuf,

    /// Destination for the snapshot. Must not already exist.
    #[arg(long)]
    out: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let db = Database::open(&args.db)?;
    db.checkpoint(&args.out)?;
    println!("checkpoint written to {}", args.out.display());
    Ok(())
}
