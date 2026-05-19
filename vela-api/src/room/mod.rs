//! Room lifecycle and event surface. createRoom, version upgrades,
//! state CRUD, send / redact / relations, and the messages/context
//! read paths.

pub mod messages;
pub mod redaction;
pub mod relations;
pub mod room_upgrade;
pub mod rooms;
pub mod send;
pub mod state;
