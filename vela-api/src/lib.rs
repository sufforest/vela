//! HTTP and federation surface of vela. Organised into ~12 domain
//! modules; cross-cutting concerns (auth_check, rate_limit, metrics,
//! trace_context, health, voip, middleware, router, test_helpers)
//! stay at top level because they have no natural home in any one
//! domain.

pub mod admin;
pub mod appservice;
pub mod auth;
pub mod auth_check;
pub mod directory;
pub mod e2ee;
pub mod federation;
pub mod health;
pub mod media;
pub mod membership;
pub mod metrics;
pub mod middleware;
pub mod presence;
pub mod profile;
pub mod push;
pub mod rate_limit;
pub mod room;
pub mod router;
pub mod sync;
// Exposed out-of-crate under the `test-harness` feature so the
// `tools/testing/smoketest-rs` crate can boot a real listener against
// the same AppState shape the in-crate unit tests use. Inside vela-api,
// every call site lives under `#[cfg(test)]`.
#[cfg(any(test, feature = "test-harness"))]
pub mod test_helpers;
pub mod trace_context;
mod voip;
