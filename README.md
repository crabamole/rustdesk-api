# rustdesk-api

An open-source API server and web console for [RustDesk](https://github.com/rustdesk/rustdesk),
covering the parts of the RustDesk Pro API that a corporate deployment needs: OIDC login,
address books, device and user management, audit logs and device policy.

It is part of the [crabamole](https://github.com/crabamole) RustDesk stack:

| Repo | Role |
|---|---|
| [rustdesk](https://github.com/crabamole/rustdesk) | Native clients (`cRustDesk`) and the web client |
| [rustdesk-server](https://github.com/crabamole/rustdesk-server) | hbbs (rendezvous) and hbbr (relay) |
| **rustdesk-api** (this repo) | API server and web console |
| [rustdesk-charts](https://github.com/crabamole/rustdesk-charts) | Helm chart that deploys all of them |

Status: in development, not yet production-ready.

## Features

- **OIDC-only login** for native clients, the web client and the console. No passwords
  are stored; accounts are keyed on the ID token's `sub`. One provider per deployment.
- **Address books**: personal, shared per group and per user (read-only, read-write, admin).
- **Users, groups and devices**, managed from the web console at `/ui`.
- **Audit logs**: connections, file transfers, alarms and logins, with the viewer's user
  and machine where known ([docs/audit-api-spec.md](docs/audit-api-spec.md)).
- **Device policy**: one global policy of managed client settings, pushed to devices
  through the heartbeat.
- **Viewers**: machines that log in from a native client but never register as devices.

[docs/pro-api-compatibility.md](docs/pro-api-compatibility.md) lists every endpoint and
its status against RustDesk Pro.

## Architecture

- A Rust [Rocket](https://rocket.rs) server listening on port 21114, plus a Vue web
  console embedded in the binary and served at `/ui`.
- PostgreSQL only. The api-server owns the schema: its migrations run at startup.
  hbbs uses the same database for its `peer` table and calls the api-server to check
  login tokens and to mint audit references.
- Sessions, OIDC logins in progress and the legacy address book live in Postgres only, so
  several replicas can run behind one Service. `GET /livez` and `GET /readyz` (database
  reachable, not shutting down) are the Kubernetes probes. Each replica opens up to
  `MAX_DATABASE_CONNECTIONS` connections.

## Deploying

Use the Helm chart in [rustdesk-charts](https://github.com/crabamole/rustdesk-charts). It
wires the api-server, hbbs, hbbr, the web client and Postgres together behind one proxy.
The image is `ghcr.io/crabamole/rustdesk-api`.

## Configuration

| Variable | Meaning |
|---|---|
| `DATABASE_URL` | Required. `postgres://user:pass@host:5432/db` |
| `OAUTH2_CONFIG_FILE` | OIDC provider file (default `./oauth2.toml`); the server refuses to start if it is missing or invalid |
| `OAUTH2_CREATE_USER` | `1`: new OIDC users are active at once. Otherwise they wait for an admin to activate them |
| `PUBLIC_URL` | The origin users open (e.g. `https://rustdesk.example.com`, no path). Set it behind a proxy that rewrites `Host`; otherwise the origin comes from the request headers |
| `TRUSTED_PROXIES` | Comma-separated CIDRs whose `X-Real-IP` / `X-Forwarded-For` are believed. Empty trusts every peer; an invalid value stops startup |
| `MAX_DATABASE_CONNECTIONS` | Pool size (default 4 per CPU) |

### OIDC provider

The provider file holds one `[[provider]]`. For any standard OIDC provider (Entra ID,
Okta, Keycloak, Google, ...) use `Oauth2`:

```toml
[[provider]]
provider = "Oauth2"
authorization_url = "https://idp.example.com/authorize"
token_exchange_url = "https://idp.example.com/token"
issuer = "https://idp.example.com"
app_id = "rustdesk"
app_secret = "..."
scope = "openid email profile"
op = "corp"
op_auth_string = "oidc/corp"
```

`Dex` and `Github` are also implemented. Register `<origin>/api/oidc/callback` as the
redirect URI at the provider. Check a file with `rustdesk-api oidc check`.

### First admin

Admins are made only from the command line, after the user has logged in once:

```bash
kubectl exec deploy/<release>-apiserver -- /app/rustdesk-api admin promote alice@example.com
```

## Command line

The `rustdesk-api` binary runs the server (`serve`) and has admin, policy, OIDC and OpenAPI
subcommands; see `rustdesk-api --help`.

## Development

Requirements: Rust, Node.js (for the console) and Docker (tests start a Postgres container).

```bash
make test                      # unit + integration tests with coverage
cargo build --release          # also builds the web console
```

Run locally against a throwaway database:

```bash
docker run -d --name rustdesk-api-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:17-alpine
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres cargo run -- serve
```

Console development: `cd webconsole && npm ci && npm run dev`, then start the server with
`VITE_DEVELOPMENT=http://localhost:5173` so `/ui` is proxied to the Vite dev server.

After an API change, regenerate the console's TypeScript client with `./swagger-codegen.sh`
(needs Docker) and update [docs/pro-api-compatibility.md](docs/pro-api-compatibility.md).

## Credits and license

Based on [sctgdesk-api-server](https://github.com/sctg-development/sctgdesk-api-server) by
SCTG Development. Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0);
see [LICENSE.md](LICENSE.md).
