//! End-to-end validation of vela's OTLP trace export (`otel` feature).
//!
//! Stands up an in-process mock OTLP gRPC collector on an ephemeral port,
//! points vela's tracer provider (`vela_api::otel::build_tracer_provider`)
//! at it, emits a span, force-flushes, and asserts the collector received
//! the span with `service.name = vela`. This exercises the actual exporter
//! configuration the server uses — not a hand-rolled stand-in.

#![cfg(feature = "otel")]

use std::time::Duration;

use opentelemetry::trace::{Tracer, TracerProvider as _};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
    trace_service_server::{TraceService, TraceServiceServer},
};
use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyVal;
use tokio::sync::mpsc;

struct MockCollector {
    tx: mpsc::UnboundedSender<ExportTraceServiceRequest>,
}

#[tonic::async_trait]
impl TraceService for MockCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        let _ = self.tx.send(request.into_inner());
        Ok(tonic::Response::new(ExportTraceServiceResponse {
            partial_success: None,
        }))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn vela_exports_spans_over_otlp() {
    let (tx, mut rx) = mpsc::unbounded_channel();

    // Grab a free port, then let the tonic server bind it.
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(MockCollector { tx }))
            .serve(addr)
            .await
            .unwrap();
    });
    // Give the server a moment to start listening.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let provider = vela_api::otel::build_tracer_provider(&format!("http://{addr}"));
    let tracer = provider.tracer("vela-test");
    tracer.in_span("vela.test.span", |_cx| {});
    let _ = provider.force_flush();

    let req = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("collector should receive an export within 5s")
        .expect("collector channel closed");

    // Resource carries service.name = vela (set by build_tracer_provider).
    let service_name_ok = req.resource_spans.iter().any(|rs| {
        rs.resource.as_ref().is_some_and(|r| {
            r.attributes.iter().any(|kv| {
                kv.key == "service.name"
                    && matches!(
                        kv.value.as_ref().and_then(|v| v.value.as_ref()),
                        Some(AnyVal::StringValue(s)) if s == "vela"
                    )
            })
        })
    });
    assert!(
        service_name_ok,
        "service.name=vela missing on exported resource"
    );

    // The span we emitted made it through the exporter.
    let names: Vec<String> = req
        .resource_spans
        .iter()
        .flat_map(|rs| rs.scope_spans.iter())
        .flat_map(|ss| ss.spans.iter())
        .map(|s| s.name.clone())
        .collect();
    assert!(
        names.iter().any(|n| n == "vela.test.span"),
        "exported span names: {names:?}"
    );

    let _ = provider.shutdown();
}
