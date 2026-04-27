use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};

use crate::router::AppState;

pub async fn well_known(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "m.homeserver": {
            "base_url": format!("http://{}:{}", state.config.bind_host, state.config.bind_port)
        }
    }))
}

pub async fn versions() -> Json<Value> {
    // We implement the v1.18 CS-API surface + sliding sync (MSC4186).
    // Advertising older versions too lets clients pinned to v1.12–v1.17
    // fall through to features they know about instead of bailing.
    Json(json!({
        "versions": [
            "v1.12", "v1.13", "v1.14", "v1.15", "v1.16", "v1.17", "v1.18"
        ],
        "unstable_features": {
            "org.matrix.simplified_msc3575": true,
            "org.matrix.msc3030": false,
            "org.matrix.msc4140": false,
            "org.matrix.msc4222": true
        }
    }))
}
