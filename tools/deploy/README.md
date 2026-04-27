# vela — production deployment

A working stack: vela + Caddy (TLS + `.well-known`). Edit two strings,
point DNS, run one command. An optional observability overlay
(Prometheus + Grafana) is wired up but **off by default**.

```
tools/deploy/
├── docker-compose.yml          # the stack
├── vela.toml.example           # annotated config — copy to vela.toml
├── Caddyfile                   # reverse proxy, auto Let's Encrypt on
│                               # both 443 (clients) and 8448 (federation)
├── prometheus.yml              # scrape config (only used if --profile observability)
├── alerts.yml                  # operator alert rules (likewise)
└── grafana/                    # auto-provisioned datasource + dashboard
    ├── provisioning/…
    └── dashboards/vela.json
```

## Bring-up

1. **DNS.** See "DNS and `.well-known`" below — pick the scenario that
   matches your setup.
2. **Edit two files.** Replace `vela.example.com` everywhere in
   `vela.toml.example` and `Caddyfile` with your real domain.
3. **Copy + rename:**
   ```sh
   cp vela.toml.example vela.toml
   ```
4. **Bring up the stack:**
   ```sh
   docker compose up -d
   docker compose logs -f vela
   ```
   Caddy obtains Let's Encrypt certs automatically for both ports
   on first start. vela generates a server signing key on first
   start and persists it to the database volume — back that up.

## DNS and `.well-known`

Three scenarios. Pick whichever matches how you want user IDs to look.

### Scenario 1 — host == server_name (simplest)

User IDs look like `@alice:vela.example.com`.

```
DNS:    A    vela.example.com    → your-server-ip
```

That's it. No `.well-known` strictly needed; peers connect directly to
`vela.example.com:8448`. The `Caddyfile` ships a `.well-known` handler
anyway because it's harmless and makes some clients happier.

### Scenario 2 — vanity apex domain (delegation)

User IDs look like `@alice:example.com` (no subdomain), but vela
actually runs at `vela.example.com`.

```
DNS:    A    vela.example.com    → your-server-ip
```

You need the apex `example.com` to serve `.well-known/matrix/server`
returning:
```json
{"m.server": "vela.example.com:8448"}
```

If `example.com` is fronted by the same Caddy, add this to the
`Caddyfile`:
```
example.com {
    handle /.well-known/matrix/server {
        header Content-Type application/json
        respond `{"m.server": "vela.example.com:8448"}` 200
    }
}
```

If `example.com` is served elsewhere (a marketing site, a CDN), add a
location block there. Any HTTPS server returning the JSON works.

In `vela.toml`: `[server] name = "example.com"`.

### Scenario 3 — SRV record (no `.well-known` needed)

If you'd rather avoid serving anything at the apex domain, use a DNS
SRV record:

```
_matrix._tcp.example.com.    IN SRV 10 0 8448 vela.example.com.
```

Peers query SRV first and follow it directly. No `.well-known` JSON
required.

## Verify

```sh
# Client API reachable through Caddy:
curl https://vela.example.com/_matrix/client/versions

# Federation reachable through Caddy:
curl https://vela.example.com:8448/_matrix/key/v2/server

# .well-known (if you serve one):
curl https://vela.example.com/.well-known/matrix/server
```

Then register a user:
```sh
curl -X POST https://vela.example.com/_matrix/client/v3/register \
  -H 'content-type: application/json' \
  -d '{"username": "alice", "password": "secret", "auth": {"type": "m.login.dummy"}}'
```

Open any Matrix client and point it at `https://vela.example.com`.

## Observability (opt-in)

Off by default — bring it up when you want it:

```sh
docker compose --profile observability up -d
```

This adds two containers:

- **Prometheus** (admin only, localhost): `http://localhost:9090`
  Scrapes vela's `/_vela/metrics` every 15s. Alert rules in
  `alerts.yml` cover availability, 5xx ratio, and `/sync` tail
  latency — wire them into your notification system by adding an
  Alertmanager target.
- **Grafana** (admin only, localhost): `http://localhost:3000`
  Default password `changeme` — **change it before exposing**. The
  dashboard auto-loads on first start.

You can leave them out entirely on small deployments — vela still
exposes `/_vela/metrics` if you'd rather scrape it from your own
Prometheus elsewhere.

## Backup

```sh
docker compose exec vela vela-backup \
    --db /data \
    --out /data/backups/$(date +%F)
```

`vela-backup` uses the database's native checkpoint API: hard-linked
snapshot in the same volume, near-zero I/O cost. Restore is a file
copy. Caveats: a federation-outbox gap can lose in-flight outbound
transactions between the backup and a crash; the server signing key
lives in the DB so restore brings it back intact, but losing the DB
entirely (no backup) means peers can't trust your old key anymore.

## Upgrade

```sh
docker compose pull vela
docker compose up -d vela
```

If the binary's `SCHEMA_VERSION` doesn't match the on-disk stamp, vela
refuses to start with a clear error message — that's the contract for
breaking schema changes shipping with a migrator. Until then, revert
to the previous tag.

## What's intentionally NOT in this stack

- **Alertmanager.** Operators have strong opinions on routing
  (PagerDuty, Slack, email). Add the target you want to
  `prometheus.yml`'s `alerting:` block.
- **Multiple vela instances.** Single-binary by design today.
- **An OTLP collector.** Tracing is opt-in via `--features otel` and
  a separate collector container; out of scope for this base stack.
