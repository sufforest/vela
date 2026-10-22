//! Differential federation interop harness.
//!
//! Drives TWO live homeservers — vela and a reference implementation
//! (Synapse) — through federated scenarios via their client APIs, then
//! asserts both sides converge to the same view. The reference server is
//! the oracle: any disagreement is a finding to triage (not automatically
//! a vela bug, but always worth a look). This catches the class of bug
//! that vela-vs-vela testing (unit suites, Complement) structurally
//! cannot: divergent interpretations of the spec.
//!
//! The tests are env-gated: without `INTEROP_VELA_CS` (etc.) in the
//! environment they skip, so `cargo test --workspace` stays green on
//! machines and CI runners without the rig. `run.sh` in this directory
//! builds vela, boots Synapse in Docker, wires up the TLS trust, exports
//! the env, and runs the suite.
//!
//! Everything here is eventually-consistent by construction — federation
//! delivery is async — so assertions poll via [`eventually`] rather than
//! checking once.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

/// How long a convergence assertion polls before declaring divergence.
/// Local-loopback federation settles in well under a second when healthy;
/// the margin absorbs slow first-request paths (key fetches, TLS setup).
pub const CONVERGE_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(400);

/// Rig coordinates, read from the environment `run.sh` exports.
pub struct InteropEnv {
    /// vela client-API base, e.g. `http://127.0.0.1:8008`.
    pub vela_cs: String,
    /// Synapse client-API base, e.g. `http://127.0.0.1:9008`.
    pub synapse_cs: String,
    /// vela's server_name (what appears in its user IDs / join vias).
    pub vela_name: String,
    /// Synapse's server_name.
    pub synapse_name: String,
}

impl InteropEnv {
    /// `None` unless the rig's env vars are present — callers skip the test.
    pub fn from_env() -> Option<Self> {
        Some(Self {
            vela_cs: std::env::var("INTEROP_VELA_CS").ok()?,
            synapse_cs: std::env::var("INTEROP_SYNAPSE_CS").ok()?,
            vela_name: std::env::var("INTEROP_VELA_NAME").ok()?,
            synapse_name: std::env::var("INTEROP_SYNAPSE_NAME").ok()?,
        })
    }
}

/// A registered user on one of the two homeservers.
pub struct User {
    cs: String,
    http: reqwest::Client,
    pub user_id: String,
    token: String,
    /// Short label for error messages ("vela" / "synapse").
    pub hs: String,
}

/// Register a fresh user. The localpart is suffixed with nanos so reruns
/// against a persistent rig never collide.
pub async fn register(hs_label: &str, cs: &str, localpart: &str) -> Result<User> {
    let username = format!("{localpart}{}", unique());
    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{cs}/_matrix/client/v3/register"))
        .json(&json!({
            "username": username,
            "password": "interop-password",
            "auth": {"type": "m.login.dummy"},
        }))
        .send()
        .await
        .with_context(|| format!("register on {hs_label}"))?;
    let body = check(hs_label, "register", resp).await?;
    Ok(User {
        cs: cs.to_string(),
        http,
        user_id: body["user_id"]
            .as_str()
            .ok_or_else(|| anyhow!("register on {hs_label}: no user_id in {body}"))?
            .to_string(),
        token: body["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("register on {hs_label}: no access_token"))?
            .to_string(),
        hs: hs_label.to_string(),
    })
}

impl User {
    fn url(&self, path: &str) -> String {
        format!("{}/_matrix/client/v3{path}", self.cs)
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value> {
        let resp = self
            .http
            .post(self.url(path))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {path} on {}", self.hs))?;
        check(&self.hs, path, resp).await
    }

    async fn put(&self, path: &str, body: Value) -> Result<Value> {
        let resp = self
            .http
            .put(self.url(path))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("PUT {path} on {}", self.hs))?;
        check(&self.hs, path, resp).await
    }

    async fn get(&self, path: &str) -> Result<Value> {
        let resp = self
            .http
            .get(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("GET {path} on {}", self.hs))?;
        check(&self.hs, path, resp).await
    }

    pub async fn create_room(&self, body: Value) -> Result<String> {
        let v = self.post("/createRoom", body).await?;
        Ok(v["room_id"]
            .as_str()
            .ok_or_else(|| anyhow!("createRoom on {}: no room_id in {v}", self.hs))?
            .to_string())
    }

    /// Join `room_id`, hinting the resident server. Sends both the legacy
    /// `server_name` and the newer `via` query params so either vintage of
    /// homeserver honours the hint.
    pub async fn join(&self, room_id: &str, via: &str) -> Result<()> {
        let path = format!(
            "/join/{}?server_name={}&via={}",
            urlencode(room_id),
            urlencode(via),
            urlencode(via)
        );
        self.post(&path, json!({})).await.map(|_| ())
    }

    /// Join expected to FAIL; returns the error body for assertions.
    pub async fn join_expect_error(&self, room_id: &str, via: &str) -> Result<Value> {
        let path = format!(
            "/join/{}?server_name={}&via={}",
            urlencode(room_id),
            urlencode(via),
            urlencode(via)
        );
        let resp = self
            .http
            .post(self.url(&path))
            .bearer_auth(&self.token)
            .json(&json!({}))
            .send()
            .await
            .with_context(|| format!("POST {path} on {}", self.hs))?;
        if resp.status().is_success() {
            bail!("join of {room_id} on {} unexpectedly succeeded", self.hs);
        }
        resp.json().await.context("error body")
    }

    pub async fn invite(&self, room_id: &str, target: &str) -> Result<()> {
        self.post(
            &format!("/rooms/{}/invite", urlencode(room_id)),
            json!({"user_id": target}),
        )
        .await
        .map(|_| ())
    }

    pub async fn kick(&self, room_id: &str, target: &str) -> Result<()> {
        self.post(
            &format!("/rooms/{}/kick", urlencode(room_id)),
            json!({"user_id": target, "reason": "interop kick"}),
        )
        .await
        .map(|_| ())
    }

    pub async fn ban(&self, room_id: &str, target: &str) -> Result<()> {
        self.post(
            &format!("/rooms/{}/ban", urlencode(room_id)),
            json!({"user_id": target, "reason": "interop ban"}),
        )
        .await
        .map(|_| ())
    }

    pub async fn unban(&self, room_id: &str, target: &str) -> Result<()> {
        self.post(
            &format!("/rooms/{}/unban", urlencode(room_id)),
            json!({"user_id": target}),
        )
        .await
        .map(|_| ())
    }

    pub async fn leave(&self, room_id: &str) -> Result<()> {
        self.post(&format!("/rooms/{}/leave", urlencode(room_id)), json!({}))
            .await
            .map(|_| ())
    }

    /// Send an `m.room.message`; returns the event_id.
    pub async fn send_message(&self, room_id: &str, text: &str) -> Result<String> {
        let txn = format!("txn{}", unique());
        let v = self
            .put(
                &format!("/rooms/{}/send/m.room.message/{txn}", urlencode(room_id)),
                json!({"msgtype": "m.text", "body": text}),
            )
            .await?;
        Ok(v["event_id"]
            .as_str()
            .ok_or_else(|| anyhow!("send on {}: no event_id in {v}", self.hs))?
            .to_string())
    }

    /// Send a state event; returns the event_id.
    pub async fn send_state(
        &self,
        room_id: &str,
        event_type: &str,
        state_key: &str,
        content: Value,
    ) -> Result<String> {
        let v = self
            .put(
                &format!(
                    "/rooms/{}/state/{event_type}/{}",
                    urlencode(room_id),
                    urlencode(state_key)
                ),
                content,
            )
            .await?;
        Ok(v["event_id"]
            .as_str()
            .ok_or_else(|| anyhow!("send_state on {}: no event_id in {v}", self.hs))?
            .to_string())
    }

    /// The room's full current state as this server sees it.
    pub async fn state(&self, room_id: &str) -> Result<Vec<Value>> {
        let v = self
            .get(&format!("/rooms/{}/state", urlencode(room_id)))
            .await?;
        v.as_array()
            .cloned()
            .ok_or_else(|| anyhow!("/state on {} was not an array", self.hs))
    }

    /// This server's view of `user_id`'s membership in the room, if any.
    pub async fn membership_of(&self, room_id: &str, user_id: &str) -> Result<Option<String>> {
        let path = format!(
            "/rooms/{}/state/m.room.member/{}",
            urlencode(room_id),
            urlencode(user_id)
        );
        let resp = self
            .http
            .get(self.url(&path))
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("GET {path} on {}", self.hs))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body = check(&self.hs, &path, resp).await?;
        Ok(body["membership"].as_str().map(str::to_string))
    }

    /// Every event_id this server can paginate out of the room's timeline.
    pub async fn timeline_event_ids(&self, room_id: &str) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        let mut from: Option<String> = None;
        for _ in 0..50 {
            let mut path = format!("/rooms/{}/messages?dir=b&limit=100", urlencode(room_id));
            if let Some(f) = &from {
                path.push_str(&format!("&from={}", urlencode(f)));
            }
            let v = self.get(&path).await?;
            let chunk = v["chunk"].as_array().cloned().unwrap_or_default();
            if chunk.is_empty() {
                break;
            }
            for ev in &chunk {
                if let Some(id) = ev["event_id"].as_str() {
                    ids.push(id.to_string());
                }
            }
            match v["end"].as_str() {
                Some(end) => from = Some(end.to_string()),
                None => break,
            }
        }
        Ok(ids)
    }

    /// Whether this user currently has a pending invite to `room_id`,
    /// per a one-shot `/sync`. Invited-but-not-joined users can't read
    /// room state (servers may 403 previews), so invite delivery is
    /// asserted through the sync invite section — the spec-portable view.
    pub async fn is_invited_to(&self, room_id: &str) -> Result<bool> {
        let v = self.get("/sync?timeout=0").await?;
        Ok(v["rooms"]["invite"]
            .as_object()
            .is_some_and(|rooms| rooms.contains_key(room_id)))
    }
}

/// Status-check a response, returning the parsed JSON body or an error that
/// includes the body text (Matrix errcode etc.) for diagnosis.
async fn check(hs: &str, what: &str, resp: reqwest::Response) -> Result<Value> {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("{what} on {hs}: HTTP {status}: {text}");
    }
    serde_json::from_str(&text).with_context(|| format!("{what} on {hs}: non-JSON body: {text}"))
}

/// Process-unique suffix: wall-clock nanos (uniqueness across reruns of a
/// persistent rig) plus an atomic counter (uniqueness across the concurrent
/// tests of one run — the clock alone collides when tests start in the same
/// tick, which real macOS clocks do).
fn unique() -> u128 {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u128;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    nanos * 1000 + n
}

fn urlencode(s: &str) -> String {
    // Percent-encode the handful of characters that appear in Matrix IDs
    // and pagination tokens and would otherwise break a path/query slot.
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Poll `f` until it returns true or [`CONVERGE_TIMEOUT`] elapses.
/// `what` names the condition in the failure message.
pub async fn eventually<F, Fut>(what: &str, mut f: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    let start = Instant::now();
    let mut last_err: Option<anyhow::Error> = None;
    while start.elapsed() < CONVERGE_TIMEOUT {
        match f().await {
            Ok(true) => return Ok(()),
            Ok(false) => last_err = None,
            // Transient errors (server still catching up) are re-polled.
            Err(e) => last_err = Some(e),
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    match last_err {
        Some(e) => bail!("timed out waiting for {what}; last error: {e:#}"),
        None => bail!("timed out waiting for {what}"),
    }
}

/// `(type, state_key) -> event_id` for a room-state array — the comparison
/// unit for convergence: two servers agree when every state pair resolves
/// to the same event.
pub fn state_fingerprint(state: &[Value]) -> BTreeMap<(String, String), String> {
    let mut map = BTreeMap::new();
    for ev in state {
        let (Some(ty), Some(sk), Some(id)) = (
            ev["type"].as_str(),
            ev["state_key"].as_str(),
            ev["event_id"].as_str(),
        ) else {
            continue;
        };
        map.insert((ty.to_string(), sk.to_string()), id.to_string());
    }
    map
}

/// Assert both servers converge to an identical current-state fingerprint.
/// On divergence, dumps both sides' full state JSON as evidence and reports
/// exactly which `(type, state_key)` pairs disagree.
pub async fn assert_state_converged(a: &User, b: &User, room_id: &str, label: &str) -> Result<()> {
    let result = eventually(&format!("state convergence: {label}"), || async {
        let sa = state_fingerprint(&a.state(room_id).await?);
        let sb = state_fingerprint(&b.state(room_id).await?);
        // A joined member's /state is never legitimately empty (create +
        // own membership at minimum) — an empty fingerprint means the read
        // itself is broken, and two broken reads must not count as
        // agreement.
        Ok(!sa.is_empty() && sa == sb)
    })
    .await;

    if let Err(poll_err) = result {
        // Final snapshot for the evidence dump + a precise diff in the error.
        let sa_raw = a.state(room_id).await.unwrap_or_default();
        let sb_raw = b.state(room_id).await.unwrap_or_default();
        let dir = evidence_dir();
        let _ = std::fs::create_dir_all(&dir);
        let slug = label.replace(|c: char| !c.is_ascii_alphanumeric(), "-");
        let _ = std::fs::write(
            dir.join(format!("{slug}-{}.json", a.hs)),
            serde_json::to_vec_pretty(&sa_raw).unwrap_or_default(),
        );
        let _ = std::fs::write(
            dir.join(format!("{slug}-{}.json", b.hs)),
            serde_json::to_vec_pretty(&sb_raw).unwrap_or_default(),
        );
        let sa = state_fingerprint(&sa_raw);
        let sb = state_fingerprint(&sb_raw);
        let mut diffs = Vec::new();
        for key in sa.keys().chain(sb.keys()) {
            let (va, vb) = (sa.get(key), sb.get(key));
            if va != vb && !diffs.iter().any(|(k, _, _)| k == key) {
                diffs.push((key.clone(), va.cloned(), vb.cloned()));
            }
        }
        // Keep the poll error in the report: when the rig itself is sick
        // (server died mid-test), the diff below is empty-vs-empty and the
        // poll error is the only real signal.
        bail!(
            "DIVERGENCE [{label}] in {room_id}: {} state pair(s) disagree \
             (evidence in {}):\n{}\npoll: {poll_err:#}",
            diffs.len(),
            dir.display(),
            diffs
                .iter()
                .map(|((ty, sk), va, vb)| format!(
                    "  ({ty}, {sk:?}): {}={:?} vs {}={:?}",
                    a.hs, va, b.hs, vb
                ))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

/// Assert this server's timeline eventually contains every id in `ids`.
pub async fn assert_timeline_contains(u: &User, room_id: &str, ids: &[String]) -> Result<()> {
    let what = format!("{} timeline to contain {} event(s)", u.hs, ids.len());
    eventually(&what, || async {
        let have = u.timeline_event_ids(room_id).await?;
        Ok(ids.iter().all(|id| have.contains(id)))
    })
    .await
}

/// Assert this server eventually sees `user_id`'s membership as `want`.
pub async fn assert_membership(u: &User, room_id: &str, user_id: &str, want: &str) -> Result<()> {
    let what = format!("{} to see {user_id} as {want:?}", u.hs);
    eventually(&what, || async {
        Ok(u.membership_of(room_id, user_id).await?.as_deref() == Some(want))
    })
    .await
}

fn evidence_dir() -> PathBuf {
    // <workspace>/target/interop-evidence, derived from this crate's location.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../target/interop-evidence")
}
