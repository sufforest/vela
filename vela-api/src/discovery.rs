use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};

use crate::router::AppState;

pub async fn well_known(State(state): State<AppState>) -> Json<Value> {
    let mut out = serde_json::Map::new();
    out.insert(
        "m.homeserver".to_string(),
        json!({
            "base_url": format!("http://{}:{}", state.config.bind_host, state.config.bind_port)
        }),
    );
    // MSC4143: advertise the matrix-rtc SFU as a "focus" clients can
    // use for group calls. Empty config → no entry; clients then
    // fall back to whatever focus another participant brings or the
    // classic m.call.* path.
    if !state.config.rtc.sfu_url.is_empty() {
        out.insert(
            "org.matrix.msc4143.rtc_foci".to_string(),
            json!([{
                "type": "livekit",
                "livekit_service_url": state.config.rtc.sfu_url,
            }]),
        );
    }
    Json(Value::Object(out))
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
            "org.matrix.msc4143": true,
            "org.matrix.msc4222": true,
            "io.element.msc4306": true,
            "io.element.msc4308": true
        }
    }))
}
