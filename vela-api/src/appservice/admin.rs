//! Admin bot commands for AS lifecycle: `!as register`, `!as list`,
//! `!as unregister`, `!as enable`, `!as disable`, `!as export`.
//!
//! The bot dispatcher (`crate::admin`) forwards `!as <subcmd> ...`
//! here. These functions return the user-visible reply text/HTML;
//! actual message-send is the bot's concern.

use std::sync::Arc;

use vela_store::db::Database;

use crate::appservice::outbox::AsOutbox;
use crate::appservice::registration;
use crate::appservice::registry::{AsRegistry, RegistryError};

/// One reply line + optional HTML version. Mirrors `admin::Reply`
/// without coupling to its private struct.
#[derive(Debug)]
pub struct AsReply {
    pub text: String,
    pub html: Option<String>,
}

impl AsReply {
    fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            html: None,
        }
    }
}

/// Dispatch a parsed `!as <subcmd> [args]` invocation. `body_yaml`
/// is the trailing YAML block for `register` (empty for other
/// subcommands).
pub async fn dispatch(
    registry: &Arc<AsRegistry>,
    outbox: &AsOutbox,
    _db: &Arc<Database>,
    subcmd: &str,
    args: &[String],
    body_yaml: &str,
) -> AsReply {
    match subcmd {
        "register" => cmd_register(registry, outbox, body_yaml),
        "list" => cmd_list(registry),
        "unregister" => cmd_unregister(registry, args),
        "enable" => cmd_set_enabled(registry, args, true),
        "disable" => cmd_set_enabled(registry, args, false),
        other => AsReply::plain(format!(
            "unknown !as subcommand: {other}\n\
             try: register, list, unregister, enable, disable"
        )),
    }
}

fn cmd_register(registry: &Arc<AsRegistry>, outbox: &AsOutbox, body_yaml: &str) -> AsReply {
    if body_yaml.trim().is_empty() {
        return AsReply::plain(
            "usage: !as register followed by the AS registration YAML in a code block",
        );
    }
    let parsed = match registration::parse(body_yaml) {
        Ok(p) => p,
        Err(e) => return AsReply::plain(format!("registration parse failed: {e}")),
    };
    let cleartext_hs = parsed.hs_token_cleartext.clone();
    let cleartext_as = parsed.as_token_cleartext.clone();
    let asv = match registry.register(parsed.appservice) {
        Ok(a) => a,
        Err(e) => return AsReply::plain(format!("registration refused: {e}")),
    };
    outbox.set_hs_token(asv.nid, cleartext_hs);
    outbox.start_worker(asv.nid);
    AsReply::plain(format!(
        "registered AS `{}` (nid {}).\n\
         it will receive transactions at `{}`.\n\
         the as_token vela accepts from this AS: `{}`\n\
         (cleartext shown once — vela stores hashes from now on)",
        asv.id, asv.nid, asv.config.url, cleartext_as
    ))
}

fn cmd_list(registry: &Arc<AsRegistry>) -> AsReply {
    let mut all = registry.list();
    all.sort_by(|a, b| a.appservice.id.cmp(&b.appservice.id));
    if all.is_empty() {
        return AsReply::plain("no Application Services registered");
    }
    let mut text = format!("Application Services ({}):\n", all.len());
    for live in &all {
        let asv = &live.appservice;
        let state = if asv.enabled { "enabled" } else { "DISABLED" };
        text.push_str(&format!(
            "  {}  url={}  ns={}  state={}\n",
            asv.id,
            asv.config.url,
            asv.namespaces.len(),
            state
        ));
    }
    AsReply::plain(text)
}

fn cmd_unregister(registry: &Arc<AsRegistry>, args: &[String]) -> AsReply {
    let Some(id) = args.first() else {
        return AsReply::plain("usage: !as unregister <id>");
    };
    let live = match registry.get_by_id(id) {
        Some(l) => l,
        None => return AsReply::plain(format!("no AS with id `{id}`")),
    };
    let nid = live.appservice.nid;
    match registry.unregister(nid) {
        Ok(true) => AsReply::plain(format!("unregistered AS `{id}` (outbox preserved on disk)")),
        Ok(false) => AsReply::plain(format!("AS `{id}` was not registered")),
        Err(e) => AsReply::plain(format!("unregister failed: {e}")),
    }
}

fn cmd_set_enabled(registry: &Arc<AsRegistry>, args: &[String], enabled: bool) -> AsReply {
    let Some(id) = args.first() else {
        return AsReply::plain(format!(
            "usage: !as {} <id>",
            if enabled { "enable" } else { "disable" }
        ));
    };
    let live = match registry.get_by_id(id) {
        Some(l) => l,
        None => return AsReply::plain(format!("no AS with id `{id}`")),
    };
    match registry.set_enabled(live.appservice.nid, enabled) {
        Ok(true) => AsReply::plain(format!(
            "AS `{id}` {}",
            if enabled { "enabled" } else { "disabled" }
        )),
        Ok(false) => AsReply::plain(format!("no AS with nid {}", live.appservice.nid)),
        Err(e) => AsReply::plain(format!("failed: {e}")),
    }
}

// Bypass `unused` until the registry caller uses it.
#[allow(dead_code)]
fn _ensure_registry_error_used(e: RegistryError) -> RegistryError {
    e
}
