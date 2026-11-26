<!--
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
-->

# Architecture Overview

The MCP Gateway is a FastAPI service between AI clients and MCP servers. It
signs users in with an OIDC provider, decides who may use which MCP server,
calls each server with a credential that server accepts, and audits the calls.

```
  MCP clients            Gravitino web UI       Workloads            gravitino-mcp CLI
  (Claude Code,          (MCP pages)            (GCP / EKS           (optional)
   VS Code, Cursor)                              identity)
        │                      │                    │                     │
        └────────────── bearer token from the OIDC provider or the platform ┘
                                     │
┌────────────────────────────────────▼───────────────────────────────────────┐
│                               MCP Gateway                                  │
│                                                                            │
│  Sign-in          browser and device-flow sign-in, bearer JWT validation   │
│                   (JWKS), RFC 9728 metadata, workload identity tokens      │
│  Access control   server registry, access requests and approvals, admins  │
│  Upstream auth    forward the user's token, RFC 8693 token exchange or     │
│                   Entra on-behalf-of, per-user OAuth connect, basic auth,  │
│                   gateway-signed JWT                                       │
│  MCP proxy        /mcp/<server ID>, Streamable HTTP, tool filters          │
│  Audit            one row per call, Prometheus metrics                     │
└──────────────┬────────────────────────────────────────┬────────────────────┘
               │                                        │
       SQLite or MySQL                          MCP servers
       (users, tokens, registry,                (Gravitino's MCP server,
        approvals, audit)                        any Streamable HTTP server)
```

## Components

### Sign-in

- **Bearer tokens**: the API and `/mcp/*` take only bearer tokens. MCP clients,
  the CLI and Gravitino's web UI send a token from the OIDC provider; the
  gateway checks its signature against the provider's JWKS, its issuer, its
  audience (`JWT_AUDIENCE`) and its expiry. Tokens are accepted from the
  gateway's own client, from `GATEWAY_OAUTH_ADDITIONAL_CLIENT_IDS`, or from any
  client when `GATEWAY_OAUTH_ACCEPT_ANY_CLIENT` is set (for clients that
  register themselves with the provider, RFC 7591).
- **Service accounts**: workloads send a GCP or EKS identity token. The issuer
  must be trusted (`TRUSTED_ISSUERS`, or the one pinned on the registration),
  and the identity must be registered by an admin with the servers it may
  call. Every refused token gets the same 401, so tokens can't reveal which
  identities are registered.
- **Browser sign-in** (`/auth/oauth/login`): the authorization code flow
  against the provider. The callback checks the ID token's issuer, audience and
  expiry, stores the provider's tokens, encrypted, and sets a signed, HttpOnly
  `__Host-session` cookie (`session` with `DEBUG=true`). A nonce cookie ties
  the provider's redirect to the browser that started the sign-in. The cookie
  is only for the gateway's own pages: where a sign-in ends, connecting to
  servers with their own sign-in, and the device flow.
- **Device flow** (`/api/v1/device/*`, `/device`): the CLI and the Slack bot get
  the user's gateway token once the user types the code, checks where the
  request came from, and approves it (RFC 8628 section 5.4).
- **Discovery**: `/.well-known/oauth-protected-resource` (RFC 9728) tells MCP
  clients which provider to sign in with. An unauthenticated Streamable HTTP
  request to `/mcp/*` gets a 401 with a `WWW-Authenticate` header that points
  there.

People are created at their first sign-in and found by their verified email.
Admins are the people in `ADMIN_EMAILS` and, with `GRAVITINO_URI` set,
Gravitino's service admins.

### Access control

Admins register MCP servers (`/api/v1/admin/mcp`). A server is open to every
user, or requires an admin to approve each request (`/api/v1/mcp-access/*`).
Approvals can expire, except on open servers. An `admin_only` server is for
admins: to other people it answers as if it did not exist. Service accounts may
call only the servers listed for them, admin-only ones included.

### Upstream authentication

Each server has an auth type, and another one for service accounts:

| Auth type | What the gateway sends |
|---|---|
| `oauth` with single sign-on | The user's own token when the server's audience is the gateway's; otherwise a token exchanged for the server (RFC 8693, or Entra on-behalf-of when `TOKEN_EXCHANGE_STYLE=entra_obo`) |
| `oauth` without single sign-on | A token the user got by connecting to the server's own sign-in (OAuth discovery, PKCE, and RFC 7591 client registration when needed) |
| `basic` | A username and password stored, encrypted, for the server |
| `passthrough` | A short-lived RS256 JWT signed by the gateway, for the server alone; servers verify it with `/.well-known/jwks.json` |
| `credential_forward` | Service accounts only: a secret read from the configured secret storage, whose name must start with `SERVICE_ACCOUNT_SECRET_PREFIX` (`mcp-gateway-sa-`) |

Stored tokens are refreshed a minute before they expire, one refresh at a time
per user and server, or exchanged again.

### MCP proxy

`POST /mcp/<server ID>` speaks MCP over Streamable HTTP. The gateway answers
`initialize` itself and forwards other requests. For servers that return an
`Mcp-Session-Id`, it keeps one upstream session per user and server, and starts
a new one when the server no longer knows the old one; other servers get an
`initialize` before each request. `MCP_TOOL_FILTERS` limits a server's tools by
name prefix; Gravitino's server exposes only its read tools by default.

Tool calls are streamed back with heartbeats, so that long ones aren't cut off
as idle; the request's database connection is released before the upstream
call. Upstream servers must speak Streamable HTTP, and a response is read in
full before the result is returned to the client.

Calls are rate limited per user, server and tool (`rate_limit.py`), by requests
per window and by calls in flight, after the caller's access is checked. The
window counts are rows in `rate_limit_windows`, updated atomically, so they are
shared by every replica without a service besides the database; the in-flight
counts live in each replica's memory, because a database count would outlive a
replica that died mid-call, so those limits are per replica. A call over a
limit gets a 429 with `Retry-After`. Defaults are `RATE_LIMIT_*` settings, and a
server's `rate_limits` in the catalog overrides them.

### Audit and metrics

Every request the gateway passes on is written to `audit_logs` with the caller,
server, tool, arguments, status and duration, and with `AUDIT_LOG_RESPONSES`
the response; calls refused for want of access are written as `unauthorized`,
calls over a rate limit as `rate_limited` (and counted in
`mcp_gateway_rate_limited_total`),
admins' changes to servers and service accounts as `admin`, and tool calls whose
client left as `cancelled`. Arguments with secret-looking names are redacted,
and arguments or responses longer than 10,000 characters keep a
1,000-character preview and the original's SHA-256. A background task deletes
calls older than `AUDIT_RETENTION_DAYS`. Admins see all calls, and other users
see their own. Prometheus metrics are served at `/metrics`.

### Optional parts

- **CLI** (`gravitino-mcp`, in `mcp_gateway_cli/`): signs in with the device flow,
  configures AI clients, and runs a local proxy that adds the user's token to
  MCP calls.
- **Slack**: notifications of access requests with `SLACK_WEBHOOK_URL`, and a
  bot that signs people in from Slack when `SLACK_BOT_TOKEN` and
  `SLACK_APP_TOKEN` are set.

## Storage

The gateway uses SQLAlchemy with SQLite (the default) or MySQL. Tables are
created at startup:

| Table | Holds |
|---|---|
| `users` | People and service accounts |
| `oauth_tokens` | Encrypted tokens, one per user and server, and the person's own gateway token as `gateway` |
| `service_account_credentials` | Registered service-account identities and their servers |
| `mcp_catalog` | Registered MCP servers |
| `mcp_access_requests`, `mcp_user_permissions` | Access requests and grants |
| `audit_logs` | Calls |
| `rate_limit_windows` | Calls counted in the current rate-limit windows |
| `device_codes`, `oauth_states` | Short-lived sign-in state |
| `slack_token_approvals` | Pending Slack approvals |

## Keys

| Setting | Used for |
|---|---|
| `TOKEN_ENCRYPTION_KEY` or `TOKEN_ENCRYPTION_KEY_FILE` | AES-256-GCM encryption of stored tokens and passwords. It can also come from the configured secret storage. |
| `JWT_SECRET_KEY` | Signing the session cookie, sign-in states and MCP session IDs |
| `GATEWAY_RSA_PRIVATE_KEY` or `GATEWAY_RSA_PRIVATE_KEY_FILE` | Signing `passthrough` JWTs. Without it, each process generates its own key, which production refuses. |

## Deployment

`docker build -f docker/Dockerfile .` builds the gateway's image. It
keeps its state in the database, except upstream MCP sessions and the refresh
locks, which each process holds in memory. To run more than one replica, point
them at the same MySQL database and give them the same `JWT_SECRET_KEY`,
encryption key and RSA key. `ENVIRONMENT=production` refuses settings that are
only safe for development.
