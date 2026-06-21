//! Shared client-IP helpers for the extension auth gates (`check_registration`,
//! `check_login`). The IP comes from `X-Forwarded-For` and is exposed to plugins
//! per their privacy tier — raw (`full`) or a non-reversible HMAC token
//! (`hashed`). Each gate uses its own HMAC `purpose` so a token is scoped to one
//! point unless an operator deliberately grants `full`.

use axum::http::HeaderMap;

use crate::router::AppState;

/// The client IP from the first hop of `X-Forwarded-For`.
///
/// IMPORTANT: this is only trustworthy behind a reverse proxy that **overwrites**
/// `X-Forwarded-For` (the standard Matrix deployment). A *direct* client can set
/// the header to anything — and because an auth gate can *block* on this value, a
/// spoofer could both evade an IP-based block and forge a victim's IP. So it's a
/// best-effort key for proxied deployments, never a security boundary; an operator
/// who exposes the homeserver directly should not grant the `hashed`/`full` IP
/// tiers. (vela's request rate-limiter keys on the real TCP peer instead; we use
/// XFF here because, behind a proxy, the peer is the proxy, not the client.
/// Unifying these behind a trusted-proxy config is a future refinement.)
/// Absent/garbage header → `None`.
pub(crate) fn client_ip_from_headers(headers: &HeaderMap) -> Option<String> {
    let xff = headers.get("x-forwarded-for")?.to_str().ok()?;
    let first = xff.split(',').next()?.trim();
    (!first.is_empty()).then(|| first.to_string())
}

/// A non-reversible token for an IP — URL-safe base64 of `HMAC(subkey, ip)`, where
/// `subkey = HMAC(signing_seed, purpose)`. Deriving the subkey from the signing
/// seed (one KDF step) makes the IP-token key **cryptographically independent of
/// the signing key** — one key, one purpose; the subkey is a hash output that
/// can't sign and can't be reversed to the seed. `purpose` scopes the token to a
/// gate (e.g. registration vs login) so the same IP yields different tokens at
/// different points. Stable, server-specific, and unreversible by a plugin (which
/// never holds the subkey, so it can't recompute it for a guessed IP). This is
/// what the `hashed` tier hands a plugin.
pub(crate) fn hash_client_ip(state: &AppState, ip: &str, purpose: &[u8]) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let subkey = {
        let mut mac = <HmacSha256>::new_from_slice(state.signing_key.secret_bytes())
            .expect("HMAC accepts any key length");
        mac.update(purpose);
        mac.finalize().into_bytes()
    };
    let mut mac = <HmacSha256>::new_from_slice(&subkey).expect("HMAC accepts any key length");
    mac.update(ip.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}
