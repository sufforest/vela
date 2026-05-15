//! Real-client smoke-test harness: spawns the full vela router on a
//! `127.0.0.1:0` listener and hands the caller a `base_url` so a real
//! Matrix SDK (here, `ruma-client`) can drive it over HTTP.
//!
//! This bridges the gap between:
//!
//! * `vela-api/tests/` — fast, in-process, drives axum via `oneshot()`.
//!   Catches handler bugs. Misses anything between handler and wire.
//! * Complement — Go-based, Docker-bound, slow. Catches end-to-end
//!   federation flows but rarely surfaces wire-shape regressions
//!   (sync field-name typos, presence defaults, state-event ordering
//!   edges).
//!
//! The crate sits at `tools/testing/smoketest-rs/` and is **not** in the
//! workspace `members` array — the ruma-client transitive graph is
//! heavy enough that we don't want it on every `cargo check` of the
//! homeserver. Invoke explicitly: `cargo test -p vela-smoketest-rs --locked`.

use std::net::SocketAddr;

use tempfile::TempDir;
use tokio::sync::oneshot;
use vela_api::router::build_router;
use vela_api::test_helpers::build_test_state_with_name;

/// Handle to a spawned vela instance. Drop to trigger graceful shutdown.
///
/// Field order matters for Drop semantics: `_shutdown` (the oneshot
/// sender) is declared first so it's dropped *before* `_join` and
/// `_tmp`. Dropping the sender resolves the `with_graceful_shutdown`
/// future on the server task; the join handle is then awaited
/// implicitly via task scheduling, and the TempDir is unlinked last so
/// RocksDB's files are still around if the server happens to flush on
/// shutdown.
pub struct SpawnedHarness {
    /// `http://127.0.0.1:{port}` — point ruma-client (or any SDK) here.
    pub base_url: url::Url,
    /// `server_name` baked into the AppState. Matches the host portion
    /// of `base_url` so MXIDs minted by registration round-trip cleanly.
    pub server_name: String,
    _shutdown: Option<oneshot::Sender<()>>,
    _join: tokio::task::JoinHandle<()>,
    _tmp: TempDir,
}

impl Drop for SpawnedHarness {
    fn drop(&mut self) {
        // Send shutdown signal; ignore "receiver dropped" — that just
        // means the server already exited (panicked or shut down for
        // another reason).
        if let Some(tx) = self._shutdown.take() {
            let _ = tx.send(());
        }
        // We deliberately do NOT block on `_join` here: `Drop` is sync
        // and the caller's runtime is the only thing that can poll the
        // task. Aborting the handle is the cheap, correct fallback.
        self._join.abort();
    }
}

/// Boot a vela instance on an ephemeral port. Caller awaits the result;
/// when the returned `SpawnedHarness` drops, the server stops.
pub async fn spawn() -> SpawnedHarness {
    // `127.0.0.1` so the listener never binds an external interface.
    // `:0` asks the kernel for an ephemeral port; we read it back via
    // `local_addr()` after binding.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let server_name = format!("127.0.0.1:{}", addr.port());

    // Re-uses the same `build_test_state_with_name` the in-crate unit
    // tests use (exposed via the `test-harness` feature). Critically:
    // we DO NOT rebuild the AppState inline here — that would risk
    // drift between this harness and the production handler tests.
    let (state, tmp) = build_test_state_with_name(&server_name);
    let app = build_router(state);

    let (tx, rx) = oneshot::channel::<()>();
    let join = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = rx.await;
        })
        .await;
    });

    let base_url = url::Url::parse(&format!("http://{}", addr)).expect("base_url parse");

    SpawnedHarness {
        base_url,
        server_name,
        _shutdown: Some(tx),
        _join: join,
        _tmp: tmp,
    }
}
