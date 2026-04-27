//! Operational health endpoint.
//!
//! `GET /_health` returns a small JSON document describing the running
//! process: build version, on-disk schema version, uptime, and the wall-
//! clock timestamp at which the process bound its listeners. The shape
//! is deliberately small and stable — operator scripts and reverse-proxy
//! liveness probes consume it.
//!
//! The route is unauthenticated. The response carries no per-room or
//! per-user data; all fields are process-level facts that are already
//! discoverable by anyone who can reach the listener (a probe at the
//! load balancer, an `ss -tlnp` on the host). Spec endpoints live under
//! `/_matrix/...`; this is operational and intentionally separate.
//!
//! Returned fields:
//! - `status`: always `"ok"` when this handler responds. The contract
//!   is "the binary is up enough to serve HTTP and read AppState." Any
//!   stronger health signal (DB readable, federation reachable) belongs
//!   on a deeper `/_health/ready` if we ever grow one.
//! - `version`: the cargo package version (`env!("CARGO_PKG_VERSION")`).
//! - `schema_version`: the RocksDB schema stamp the binary expects.
//!   Operators compare this across binaries during upgrades.
//! - `uptime_secs`: seconds since AppState was constructed (monotonic).
//! - `started_at_ms`: milliseconds since the Unix epoch at AppState
//!   construction. Stable across uptime queries — useful for "did the
//!   process restart?" checks.

use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};

use crate::router::AppState;

/// GET /_health — small JSON for operators and probes. See module docs.
pub async fn health(State(state): State<AppState>) -> Json<Value> {
    let uptime_secs = state.started_at.elapsed().as_secs();
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "schema_version": vela_store::db::SCHEMA_VERSION,
        "uptime_secs": uptime_secs,
        "started_at_ms": state.started_at_ms,
    }))
}
