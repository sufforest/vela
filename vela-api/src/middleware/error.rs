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
            // Parse failure means we produced bad JSON ourselves;
            // pass the original through so the auth flow doesn't
            // break behind an empty object.
            match serde_json::from_str::<serde_json::Value>(body) {
                Ok(parsed) => return (status, Json(parsed)).into_response(),
                Err(e) => {
                    tracing::error!(error = %e, body = %body, "UIA body not parseable as JSON; passing through verbatim");
                    return (status, [("content-type", "application/json")], body.clone())
                        .into_response();
                }
            }
        }
        // M_WRONG_ROOM_KEYS_VERSION carries an extra `current_version` field
        // (spec) that the standard {errcode, error} shape would drop.
        if let VelaError::WrongRoomKeysVersion { current_version } = &self.0 {
            let body = json!({
                "errcode": self.0.errcode(),
                "error": self.0.to_string(),
                "current_version": current_version,
            });
            return (StatusCode::FORBIDDEN, Json(body)).into_response();
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
