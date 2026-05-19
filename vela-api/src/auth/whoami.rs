use crate::middleware::json::Json;
use serde_json::{Value, json};

use crate::middleware::auth::AuthenticatedUser;

/// GET /_matrix/client/v3/account/whoami
pub async fn whoami(user: AuthenticatedUser) -> Json<Value> {
    Json(json!({
        "user_id": user.user_id,
        "device_id": user.device_id,
    }))
}
