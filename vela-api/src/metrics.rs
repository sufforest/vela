//! Metrics surface — backend-agnostic.
//!
//! `vela-api` only uses the `metrics` facade (counters/histograms are
//! no-ops until a recorder is installed, at ns-level cost). The choice
//! of exporter — Prometheus, StatsD, OpenTelemetry, whatever — lives in
//! the binary crate. `vela-server` gates Prometheus behind a default
//! cargo feature so alternate deployments can opt out and install their
//! own recorder.
//!
//! We carry a `MetricsRenderer` closure on `AppState` that the
//! `/_vela/metrics` endpoint calls to serialize the current snapshot.
//! `None` = endpoint returns 503 (no recorder configured). This keeps
//! the API crate free of exporter dependencies.
//!
//! The endpoint is deliberately on the main HTTP listener and
//! unauthenticated — fine for development and single-node deployments.
//! Production operators should front it with a reverse-proxy ACL or
//! serve from a dedicated admin port (TODO once we grow an ops surface).

use std::sync::Arc;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;

use crate::router::AppState;

/// Trait-object-friendly renderer for metrics. Binaries wire up a
/// concrete impl (e.g. prometheus' `PrometheusHandle::render`) and
/// hand the boxed closure to `AppState`.
pub type MetricsRenderer = Arc<dyn Fn() -> String + Send + Sync>;

/// tower middleware: record request count and latency per
/// `(method, matched_path, status)`. Zero-cost when no recorder is
/// installed; the `metrics` macros short-circuit at the facade layer.
pub async fn record_request(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let start = std::time::Instant::now();
    let method = req.method().as_str().to_string();
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());
    let response = next.run(req).await;
    let status = response.status().as_u16().to_string();
    let elapsed = start.elapsed().as_secs_f64();
    ::metrics::counter!(
        "vela_http_requests_total",
        "method" => method.clone(),
        "route" => route.clone(),
        "status" => status.clone()
    )
    .increment(1);
    ::metrics::histogram!(
        "vela_http_request_duration_seconds",
        "method" => method,
        "route" => route,
        "status" => status
    )
    .record(elapsed);
    response
}

/// GET /_vela/metrics — text-format scrape endpoint. Content type is
/// Prometheus-compatible; whether the renderer actually returns that
/// format is up to whoever installed it. When no renderer is
/// configured, returns 503 with a human-readable note.
pub async fn scrape(State(state): State<AppState>) -> impl IntoResponse {
    match &state.metrics_renderer {
        Some(renderer) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            renderer(),
        )
            .into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, "text/plain")],
            "metrics recorder not installed",
        )
            .into_response(),
    }
}
