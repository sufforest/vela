//! Authentication & session lifecycle. Everything that issues,
//! validates, or revokes a session — plus account-level metadata
//! (account_data) that's authentication-adjacent.

pub mod account;
pub mod account_data;
pub(crate) mod client_ip;
pub mod devices;
pub mod login;
pub mod logout;
pub mod oidc;
pub mod password;
pub mod refresh;
pub mod register;
pub mod uia;
pub mod whoami;
