//! `vela-admin users` — list local users. Today this iterates the
//! `users` CF and prints one line per nid. Last-seen / device-count
//! columns would need additional indices not yet present in the
//! schema; deferred until those land.

use anyhow::Result;
use vela_store::db::Database;

pub fn run(db: &Database) -> Result<()> {
    let mut rows: Vec<String> = db.list_local_user_ids().map_err(anyhow::Error::msg)?;
    rows.sort();
    println!("{} local user(s)", rows.len());
    for uid in rows {
        println!("{uid}");
    }
    Ok(())
}
