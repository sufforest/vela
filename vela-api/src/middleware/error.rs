use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use vela_core::error::VelaError;

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // UIA passes its own pre-built JSON body verbatim — challenges and
        // failures both carry `flows`/`session`/etc that the standard
        // `{errcode, error}` shape would clobber.
        if let VelaError::Uia { status, body } = &self.0 {
            let status = StatusCode::from_u16(*status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let parsed: serde_json::Value =
                serde_json::from_str(body).unwrap_or_else(|_| json!({}));
            return (status, Json(parsed)).into_response();
        }
        let body = json!({
            "errcode": self.0.errcode(),
            "error": self.0.to_string(),
        });
        let status =
            StatusCode::from_u16(self.0.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(body)).into_response()
    }
}

/// Wrapper to implement IntoResponse for VelaError in the api crate.
#[derive(Debug)]
pub struct ApiError(pub VelaError);

impl From<VelaError> for ApiError {
    fn from(e: VelaError) -> Self {
        Self(e)
    }
}

impl From<rocksdb::Error> for ApiError {
    fn from(e: rocksdb::Error) -> Self {
        Self(VelaError::Store(e.to_string()))
    }
}
