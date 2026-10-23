//! Remote media: a file uploaded on one server, fetched through the other
//! over federation, as a download and as a thumbnail.

use anyhow::{Result, bail};
use vela_interop::{InteropEnv, RawResponse, png_dimensions, solid_png, split_mxc, users};

fn skip() -> Option<InteropEnv> {
    let env = vela_interop::rig();
    if env.is_none() {
        eprintln!("skipping: interop rig not configured (run via tools/testing/interop/run.sh)");
    }
    env
}

/// Bytes, content type and filename survive a federated download, both ways.
#[tokio::test]
async fn remote_media_download() -> Result<()> {
    let Some(env) = skip() else { return Ok(()) };
    let (v, s) = users(&env).await?;
    for (uploader, fetcher) in [(&v, &s), (&s, &v)] {
        let payload = format!("hello from {} {}", uploader.hs, uploader.user_id).into_bytes();
        let mxc = uploader
            .upload_media(payload.clone(), "text/plain", "greeting.txt")
            .await?;
        let (server, id) = split_mxc(&mxc)?;
        let local = uploader.download_media(&server, &id).await?;
        let remote = fetcher.download_media(&server, &id).await?;
        if remote.status != 200 {
            bail!(
                "DIVERGENCE: {} fetching {}'s media: HTTP {} {}",
                fetcher.hs,
                uploader.hs,
                remote.status,
                String::from_utf8_lossy(&remote.body)
            );
        }
        if remote.body != payload {
            bail!(
                "DIVERGENCE: {} served different bytes for {mxc}",
                fetcher.hs
            );
        }
        let ct = |c: &str| c.split(';').next().unwrap_or("").trim().to_string();
        if ct(&remote.content_type) != ct(&local.content_type) {
            bail!(
                "DIVERGENCE: content-type {} on {} vs {} on {}",
                remote.content_type,
                fetcher.hs,
                local.content_type,
                uploader.hs
            );
        }
        let has_name =
            |d: &Option<String>| d.as_deref().is_some_and(|d| d.contains("greeting.txt"));
        if has_name(&local.content_disposition) != has_name(&remote.content_disposition) {
            bail!(
                "DIVERGENCE: content-disposition {:?} on {} vs {:?} on {}",
                remote.content_disposition,
                fetcher.hs,
                local.content_disposition,
                uploader.hs
            );
        }
    }
    Ok(())
}

/// A thumbnail of remote media is a real thumbnail: the spec leaves the
/// exact size to the server (never smaller than asked unless the source
/// is, never upscaled), so the oracle is the fetching server itself. Its
/// thumbnail of remote media must match its thumbnail of the same bytes
/// uploaded locally, and must be smaller than the source.
#[tokio::test]
async fn remote_media_thumbnail() -> Result<()> {
    let Some(env) = skip() else { return Ok(()) };
    let (v, s) = users(&env).await?;
    for (uploader, fetcher) in [(&v, &s), (&s, &v)] {
        let png = solid_png(400, 300);
        let remote_mxc = uploader
            .upload_media(png.clone(), "image/png", "big.png")
            .await?;
        let local_mxc = fetcher.upload_media(png, "image/png", "big.png").await?;
        let (rs, rid) = split_mxc(&remote_mxc)?;
        let (ls, lid) = split_mxc(&local_mxc)?;
        let remote = fetcher.thumbnail_media(&rs, &rid, 96, 96, "scale").await?;
        let local = fetcher.thumbnail_media(&ls, &lid, 96, 96, "scale").await?;
        if remote.status != 200 {
            bail!(
                "DIVERGENCE: {} thumbnailing {}'s media: HTTP {} {}",
                fetcher.hs,
                uploader.hs,
                remote.status,
                String::from_utf8_lossy(&remote.body)
            );
        }
        let dims = |r: &RawResponse, what: &str| -> Result<(u32, u32)> {
            png_dimensions(&r.body).ok_or_else(|| {
                anyhow::anyhow!(
                    "{} served a non-PNG {what} thumbnail ({} bytes, {})",
                    fetcher.hs,
                    r.body.len(),
                    r.content_type
                )
            })
        };
        let (rw, rh) = dims(&remote, "remote")?;
        let (lw, lh) = dims(&local, "local")?;
        if rw >= 400 || rh >= 300 {
            bail!(
                "DIVERGENCE: {} served {rw}x{rh} for a 96x96 thumbnail of {}'s 400x300 media (the original?)",
                fetcher.hs,
                uploader.hs
            );
        }
        if (rw, rh) != (lw, lh) {
            bail!(
                "DIVERGENCE: {} thumbnails {}'s media at {rw}x{rh} but the same bytes locally at {lw}x{lh}",
                fetcher.hs,
                uploader.hs
            );
        }
    }
    Ok(())
}

/// An unknown media id on the other server is a clean 404, both ways.
#[tokio::test]
async fn remote_media_missing() -> Result<()> {
    let Some(env) = skip() else { return Ok(()) };
    let (v, s) = users(&env).await?;
    for (fetcher, remote_name) in [(&v, &env.synapse_name), (&s, &env.vela_name)] {
        let r = fetcher
            .download_media(remote_name, "does-not-exist")
            .await?;
        if r.status != 404 {
            bail!(
                "DIVERGENCE: {} fetching a missing id from {remote_name}: HTTP {} {}",
                fetcher.hs,
                r.status,
                String::from_utf8_lossy(&r.body)
            );
        }
    }
    Ok(())
}
