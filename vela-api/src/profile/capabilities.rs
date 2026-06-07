use crate::middleware::json::Json;
use axum::extract::State;
use serde_json::{Value, json};

use crate::middleware::auth::AuthenticatedUser;
use crate::router::AppState;

/// GET /_matrix/client/v3/capabilities
///
/// Spec gates this endpoint on auth — clients without a token must get
/// 401 so they know to authenticate before negotiating capabilities.
pub async fn get_capabilities(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
) -> Json<Value> {
    Json(json!({
        "capabilities": {
            "m.change_password": {
                "enabled": true
            },
            "m.room_versions": {
                "default": "12",
                "available": {
                    "12": "stable",
                    "org.matrix.msc3757.10": "unstable",
                }
            },
            "m.set_displayname": {"enabled": true},
            "m.set_avatar_url": {"enabled": true},
            // MSC4133 extended profile fields.
            "uk.tcpip.msc4133.profile_fields": {"enabled": true},
            "m.3pid_changes": {"enabled": false},
            // We don't implement POST /login/get_token (cross-device
            // login token minting); advertise it disabled so clients
            // hide the "sign in on another device" affordance rather
            // than calling an endpoint that 404s.
            "m.get_login_token": {"enabled": false},
            // MSC4140: advertise the upper bound on delayed-event
            // delays so clients can validate before issuing the PUT.
            // Both keys until MSC4140 stabilises — clients during
            // the unstable phase often key off `org.matrix.msc4140`
            // while spec-final clients will look for
            // `m.delayed_events`. Cheap to ship both.
            "org.matrix.msc4140": {
                "max_delay": state.config.max_delay_ms,
                "enabled": state.config.max_delay_ms > 0,
            },
            "m.delayed_events": {
                "max_delay": state.config.max_delay_ms,
                "enabled": state.config.max_delay_ms > 0,
            },
        }
    }))
}
