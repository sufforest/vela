//! OTLP tracer-provider construction, shared by the server's tracing
//! init (`vela-server`) and the OTLP export integration test
//! (`tests/otlp_export.rs`). Only compiled with the `otel` feature.

use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::SdkTracerProvider;

/// Build an OTLP-over-gRPC tracer provider that exports spans to
/// `endpoint` (e.g. `http://127.0.0.1:4317`) with `service.name = vela`.
///
/// This only constructs the provider — it installs no globals and no
/// `tracing` subscriber, so it's safe to call from tests. The caller is
/// responsible for bridging it into `tracing-subscriber`, setting the
/// global tracer provider / propagator, and calling `.shutdown()` on the
/// returned provider at exit to flush the batch exporter.
pub fn build_tracer_provider(endpoint: &str) -> SdkTracerProvider {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .expect("OTLP exporter builds");
    SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name("vela")
                .build(),
        )
        .build()
}
