//! Authentication & session lifecycle. Everything that issues,
//! validates, or revokes a session — plus account-level metadata
//! (account_data) that's authentication-adjacent.

pub mod account;
pub mod account_data;
pub mod devices;
pub mod login;
pub mod logout;
pub mod refresh;
pub mod register;
pub mod uia;
pub mod whoami;
