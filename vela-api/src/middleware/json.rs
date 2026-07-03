//! `Json<T>` extractor that doesn't reject on a missing or unusual
//! `Content-Type` header.
//!
//! Element X (and at least one other client we've seen in the wild)
//! sends `PUT /_matrix/client/v3/sendToDevice/...` without a
//! `Content-Type` header at all. Axum's stock `Json<T>` rejects with
//! `Expected request with \`Content-Type: application/json\`` and the
//! body — which is valid JSON — never reaches the handler. The whole
//! verify-by-emoji flow stalls because the very first request is
//! `m.key.verification.request` over to-device.
//!
//! The C-S spec says the body MUST be JSON; it does not mandate the
//! header. Synapse parses the body unconditionally. Matching that
//! behaviour is pure interop benefit.
//!
//! This wrapper doubles as a response type so callers can keep the
//! existing `use ... Json;` site-wide — replace `use axum::Json` with
//! `use crate::middleware::json::Json` and both extractor and
//! `IntoResponse` paths keep working.

use std::ops::{Deref, DerefMut};

use axum::body::Bytes;
use axum::extract::{FromRequest, OptionalFromRequest};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;

#[derive(Debug, Clone)]
pub struct Json<T>(pub T);

impl<T> Deref for Json<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for Json<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

pub struct JsonRejection {
    status: StatusCode,
    errcode: &'static str,
    message: String,
}

impl IntoResponse for JsonRejection {
    fn into_response(self) -> Response {
        let body = json!({
            "errcode": self.errcode,
            "error": self.message,
        });
        (self.status, axum::Json(body)).into_response()
    }
}

/// Map a `serde_json` deserialization failure to the right Matrix errcode.
/// `Category::Data` means the bytes ARE valid JSON but don't fit the
/// endpoint's shape — a missing required key or a wrong-typed value — which
/// the spec calls `M_BAD_JSON`. `Syntax`/`Eof`/`Io` mean the body isn't valid
/// JSON at all → `M_NOT_JSON`. (For `Json<Value>` handlers `Data` never fires,
/// so those keep returning `M_NOT_JSON` for genuinely unparseable bodies.)
fn deserialize_rejection(e: serde_json::Error) -> JsonRejection {
    let (errcode, prefix) = match e.classify() {
        serde_json::error::Category::Data => ("M_BAD_JSON", "request body is malformed"),
        _ => ("M_NOT_JSON", "body is not valid JSON"),
    };
    JsonRejection {
        status: StatusCode::BAD_REQUEST,
        errcode,
        message: format!("{prefix}: {e}"),
    }
}

impl<T, S> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = JsonRejection;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| JsonRejection {
                status: StatusCode::BAD_REQUEST,
                errcode: "M_NOT_JSON",
                message: format!("failed to read request body: {e}"),
            })?;
        serde_json::from_slice::<T>(&bytes)
            .map(Json)
            .map_err(deserialize_rejection)
    }
}

impl<T, S> OptionalFromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = JsonRejection;

    async fn from_request(
        req: axum::extract::Request,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| JsonRejection {
                status: StatusCode::BAD_REQUEST,
                errcode: "M_NOT_JSON",
                message: format!("failed to read request body: {e}"),
            })?;
        // An empty body is treated as absent — matches axum::Json's
        // Option behaviour and the receipts handler that does
        // `Option<Json<ReceiptBody>>` to allow `POST` with no body.
        if bytes.is_empty() {
            return Ok(None);
        }
        serde_json::from_slice::<T>(&bytes)
            .map(|v| Some(Json(v)))
            .map_err(deserialize_rejection)
    }
}

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        match serde_json::to_vec(&self.0) {
            Ok(body) => ([(header::CONTENT_TYPE, "application/json")], body).into_response(),
            Err(e) => JsonRejection {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                errcode: "M_UNKNOWN",
                message: format!("failed to serialise response body: {e}"),
            }
            .into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[derive(Debug, serde::Deserialize)]
    struct Req {
        #[allow(dead_code)]
        name: String,
    }

    #[test]
    fn not_json_vs_bad_json_classification() {
        // Not valid JSON at all → M_NOT_JSON.
        let syntax = serde_json::from_slice::<Value>(b"{not json").unwrap_err();
        assert_eq!(deserialize_rejection(syntax).errcode, "M_NOT_JSON");
        // Truncated (eof) → M_NOT_JSON.
        let eof = serde_json::from_slice::<Value>(b"{\"a\":").unwrap_err();
        assert_eq!(deserialize_rejection(eof).errcode, "M_NOT_JSON");

        // Valid JSON, wrong type for the target → M_BAD_JSON.
        let wrong_type = serde_json::from_slice::<u32>(b"\"hello\"").unwrap_err();
        assert_eq!(deserialize_rejection(wrong_type).errcode, "M_BAD_JSON");
        // Valid JSON object missing a required field → M_BAD_JSON.
        let missing = serde_json::from_slice::<Req>(b"{}").unwrap_err();
        assert_eq!(deserialize_rejection(missing).errcode, "M_BAD_JSON");

        // A `Json<Value>` handler accepts any valid JSON, so it only ever
        // rejects genuinely-unparseable bodies (M_NOT_JSON), never M_BAD_JSON.
        assert!(serde_json::from_slice::<Value>(b"{\"anything\": 1}").is_ok());
    }
}
