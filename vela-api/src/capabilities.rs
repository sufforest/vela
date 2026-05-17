use crate::middleware::json::Json;
use serde_json::{Value, json};

use crate::middleware::auth::AuthenticatedUser;

/// GET /_matrix/client/v3/capabilities
///
/// Spec gates this endpoint on auth — clients without a token must get
/// 401 so they know to authenticate before negotiating capabilities.
pub async fn get_capabilities(_user: AuthenticatedUser) -> Json<Value> {
    Json(json!({
        "capabilities": {
            "m.change_password": {
                "enabled": true
            },
            "m.room_versions": {
                "default": "12",
                "available": {
                    "12": "stable"
                }
            },
            "m.set_displayname": {"enabled": true},
            "m.set_avatar_url": {"enabled": true},
            "m.3pid_changes": {"enabled": false},
        }
    }))
}
