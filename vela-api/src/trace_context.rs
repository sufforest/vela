//! W3C trace-context propagation helpers.
//!
//! Behind the `otel` feature, these functions inject and extract the
//! `traceparent` (and optionally `tracestate`) headers using the
//! globally installed OpenTelemetry text-map propagator. Without the
//! feature, both helpers are no-ops — `inject_traceparent` doesn't
//! touch the request, `set_parent_from_headers` returns unchanged.
//!
//! The binary (`vela-server`) installs the propagator + bridge layer
//! during `init_tracing`. This module is the API-side glue so vela-api
//! stays backend-agnostic but can still propagate context across
//! federation boundaries when the operator opted in.

#[cfg(feature = "otel")]
mod imp {
    use std::collections::HashMap;

    use opentelemetry::global;
    use opentelemetry::propagation::{Extractor, Injector};
    use tracing::Span;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    /// Inject the current span's trace context into outbound HTTP
    /// headers as `traceparent` (+ `tracestate` if applicable). Use on
    /// every outbound federation request so peers can stitch their
    /// spans into our trace.
    pub fn inject_into_request(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let cx = Span::current().context();
        let mut headers: HashMap<String, String> = HashMap::new();
        global::get_text_map_propagator(|p| {
            p.inject_context(&cx, &mut HeaderInjector(&mut headers))
        });
        let mut req = req;
        for (k, v) in headers {
            req = req.header(k, v);
        }
        req
    }

    /// Read trace-context headers from an inbound HTTP request and set
    /// the current span's parent to the extracted context. Use in the
    /// federation_auth middleware after signature verification so the
    /// request span shows up as a child of the remote origin's span
    /// in the collector.
    pub fn set_current_parent_from_headers(headers: &axum::http::HeaderMap) {
        let extractor = HeaderExtractor(headers);
        let parent_cx = global::get_text_map_propagator(|p| p.extract(&extractor));
        Span::current().set_parent(parent_cx);
    }

    struct HeaderInjector<'a>(&'a mut HashMap<String, String>);
    impl Injector for HeaderInjector<'_> {
        fn set(&mut self, key: &str, value: String) {
            self.0.insert(key.to_string(), value);
        }
    }

    struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);
    impl Extractor for HeaderExtractor<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).and_then(|v| v.to_str().ok())
        }
        fn keys(&self) -> Vec<&str> {
            self.0.keys().map(|k| k.as_str()).collect()
        }
    }
}

#[cfg(not(feature = "otel"))]
mod imp {
    /// No-op: outbound request unchanged when otel feature is off.
    pub fn inject_into_request(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req
    }

    /// No-op: inbound headers ignored when otel feature is off.
    pub fn set_current_parent_from_headers(_headers: &axum::http::HeaderMap) {}
}

pub use imp::{inject_into_request, set_current_parent_from_headers};
