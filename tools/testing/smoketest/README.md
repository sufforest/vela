# Local smoke-test stack

Vela + Element Web on localhost for end-to-end testing without TLS or
federation. Use this to exercise the client surface from a real browser.

## Run

```sh
cd tools/testing/smoketest
docker compose up -d        # builds vela image, pulls element-web
docker compose logs -f vela # follow server logs
```

Then browse to **http://localhost:8009** and register/login. Element is
pre-configured to talk to Vela at `http://localhost:8008`.

Default server_name is `localhost:8008`, so user IDs look like
`@alice:localhost:8008`.

## Reset state

```sh
docker compose down -v      # -v drops the volumes, wiping the Vela DB
```

## Caveats

- Plain HTTP, localhost-only. No federation (needs HTTPS + public DNS).
- Element Web accepts http:// base_urls when the origin is localhost.
  Other origins would refuse.
- If you change Rust source, rebuild with `docker compose up -d --build
  vela`.

## What to exercise in the browser

Golden paths to walk through after a code change:

1. **Solo**: register, login, create private room, send plaintext, redact,
   edit, upload file, set displayname + avatar, change password, logout,
   log back in.
2. **Two users**: register a second user in an incognito window, invite
   them, both join, send messages, react, thread reply, mark read,
   change typing.
3. **E2EE**: enable encryption in a private room, exchange messages,
   verify devices, share keys, test after logout/login.

File any bugs surfaced as GitHub issues so they don't get lost
between Complement runs.
