# Vela

A self-hostable Matrix homeserver written in Rust.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## What it is

A Matrix homeserver targeting Room Version 12. Single binary,
embedded storage.

## Status

0.1.0. See [`CHANGELOG.md`](CHANGELOG.md) for what's in this release
and what's known to be missing.

## Quickstart (Docker)

```sh
docker pull ghcr.io/sufforest/vela:main
docker run -v $PWD/vela.toml:/etc/vela/vela.toml:ro \
           -v vela_data:/data \
           -p 8008:8008 \
           ghcr.io/sufforest/vela:main
```

Images are published on every push to `main` (rolling, may break)
and on every `vX.Y.Z` Git tag (`:X.Y.Z` / `:X.Y` / `:X` / `:latest`,
all immutable once published).

## Admin bootstrap

Vela administers via a server-internal bot in a private Admins room
— no `/_synapse/admin/*` HTTP surface, no `is_admin` user flag.
Membership in the Admins room IS the admin permission. First boot:

1. In `vela.toml` set a one-shot bootstrap token:
   ```toml
   [registration]
   enabled = true
   token   = "pick-any-random-string"
   ```
2. Register your account against vela in any Matrix client (Element
   recommended) using that token. The first registrant is
   auto-invited to the Admins room.
3. Accept the invite, send `!help` in the Admins room. The bot
   replies with the command list.
4. Mint a fresh registration token + revoke the bootstrap one:
   ```
   !token create uses=10 expires=7d
   !token revoke pick-any-random-string
   ```

The static `[registration] token` field is seeded into the registration
tokens table as single-use; subsequent invites are managed dynamically
through the bot.

## Building from source

```sh
cargo build --workspace --release
```

Binaries land in `target/release/`:
- `vela` — the homeserver
- `vela-backup` — point-in-time database checkpoint tool

## Running

```sh
./target/release/vela --config /path/to/vela.toml
```

Pre-flight a config without starting:

```sh
./target/release/vela --config /path/to/vela.toml --validate-config
```

Annotated example configs:
- `tools/deploy/vela.toml.example` — production
- `tools/testing/smoketest/vela.toml.example` — local development

## Deployment

Three patterns by federation needs.

### A. Local evaluation

Run the binary; clients connect via `http://localhost`. No TLS, no
DNS, no federation. Good for trying vela out or single-user use.

```sh
cargo build --release
./target/release/vela --config vela.toml
```

Set `[federation] enabled = false` in `vela.toml`. Element Web
accepts `http://` only when the origin is localhost — point it at
`http://localhost:8008`.

### B. Public, no federation

A public deployment where users on this server talk to each other
but the server doesn't peer with the wider Matrix graph.

- Reverse proxy terminates TLS for the client API (port 443).
- `[federation] enabled = false`.
- No port 8448, no DNS SRV records, no `.well-known/matrix/server`.

Operationally simple: one cert on one port, no federation moving
parts.

### C. Federated

Same as B plus federation TLS reachable on port 8448.

`tools/deploy/` is the reference stack:
- vela (built from this repo via `Dockerfile`)
- Caddy fronting both 443 (clients) and 8448 (federation), with
  automatic Let's Encrypt on both
- Prometheus scraping `/_vela/metrics`
- Grafana with a pre-loaded dashboard
- Alert rules

```sh
cd tools/deploy
# edit `vela.toml` and `Caddyfile` — replace `vela.example.com`
docker compose up -d
```

DNS: an `A` / `AAAA` record pointing to your host is enough; Caddy
serves `/.well-known/matrix/server` so peers learn the federation
port. If you want an `SRV` record instead, that works too.

## Clients

Vela is the server only. Bring any Matrix client — Element Web,
Element X, fluffychat, iamb, gomuks, nheko, etc.

For local end-to-end testing during development, `tools/testing/smoketest/`
bundles vela + Element Web in a Docker Compose stack.

## Licence

Apache License 2.0. See [`LICENSE`](LICENSE).

## Contributing

Open an issue to discuss before sending a PR. By contributing, you
agree your contributions are licensed under Apache 2.0.

The repo ships a pre-commit hook that mirrors CI's fmt + clippy
gates. Enable it once per clone:

```bash
git config core.hooksPath .githooks
```

It only runs when staged changes touch `.rs` files, and skips the
test suite (which CI runs). Bypass with `git commit --no-verify`
if needed.
