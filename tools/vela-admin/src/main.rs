//! `vela-admin` — read-only inspection CLI for a running vela.
//!
//! Opens the live database in RocksDB secondary mode (no exclusive
//! lock, no writes — vela keeps running). Useful for "what's in my
//! server?" questions without spinning up a Matrix client.
//!
//! Scope is deliberately small: stats, list, and a few targeted
//! `info` commands. Anything that mutates state (deactivate user,
//! purge media, redact event) is a separate code path with its own
//! design review and is intentionally not in this binary yet.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod cmd;
mod db;

#[derive(Parser)]
#[command(
    name = "vela-admin",
    version,
    about = "Read-only inspection for a live vela instance"
)]
struct Cli {
    /// Path to the vela RocksDB directory (the value of `[database]
    /// path` in vela.toml).
    #[arg(long, env = "VELA_DB")]
    db: PathBuf,

    /// Working directory for the secondary's catch-up state. A fresh
    /// temp dir is fine; reusing it across runs makes subsequent runs
    /// catch up faster. Defaults to a per-invocation tempdir.
    #[arg(long)]
    secondary_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Quick global counts: users, rooms, events, media bytes.
    Stats,
    /// List local users + last-seen timestamps.
    Users,
    /// List rooms with member count and human-readable name (if any).
    Rooms,
    /// Top rooms by most-recent activity. Useful for "what's hot
    /// right now" debugging — a quiet friend-group homeserver may
    /// have hundreds of rooms but only a handful are live.
    RoomsTop {
        /// Cap results so a server with thousands of rooms doesn't
        /// pretty-print itself into a hang.
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Show one room's state events.
    Room {
        /// Full `!opaque:server` or v12 `!hash` room id.
        room_id: String,
    },
    /// List stored media files. Useful for spotting orphaned uploads.
    Media {
        /// Cap results so a server with millions of files doesn't
        /// pretty-print itself into a hang.
        #[arg(long, default_value = "100")]
        limit: usize,
    },
    /// Compare `memberships` and `room_state` for one (room, user) —
    /// flags the kind of drift that surfaces as 403 "sender is not
    /// joined" while the pre-check passes.
    DiagnoseMembership { room_id: String, user_id: String },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let scratch = match cli.secondary_dir {
        Some(p) => Scratch::Persistent(p),
        None => Scratch::Temp(tempfile::tempdir()?),
    };
    let db = db::open_secondary(&cli.db, scratch.path())?;
    match cli.cmd {
        Cmd::Stats => cmd::stats::run(&db),
        Cmd::Users => cmd::users::run(&db),
        Cmd::Rooms => cmd::rooms::run(&db),
        Cmd::RoomsTop { limit } => cmd::rooms::run_top(&db, limit),
        Cmd::Room { room_id } => cmd::rooms::run_one(&db, &room_id),
        Cmd::Media { limit } => cmd::media::run(&db, limit),
        Cmd::DiagnoseMembership { room_id, user_id } => {
            cmd::membership::run(&db, &room_id, &user_id)
        }
    }
}

/// Holds the scratch directory across the program's lifetime so a
/// `tempfile::TempDir` doesn't drop mid-run and trash the secondary.
enum Scratch {
    Persistent(PathBuf),
    Temp(tempfile::TempDir),
}

impl Scratch {
    fn path(&self) -> &std::path::Path {
        match self {
            Scratch::Persistent(p) => p,
            Scratch::Temp(t) => t.path(),
        }
    }
}
