---
title: "MCP Gateway"
slug: "/gravitino-mcp-gateway"
keyword: "Gravitino MCP gateway OAuth access audit"
license: "This software is licensed under the Apache License version 2."
---

## Introduction

:::note
The MCP gateway is in beta. Its configuration and APIs may change in later releases.
:::

The Gravitino MCP gateway sits between AI clients and the MCP servers they use, including the
[Gravitino MCP server](https://gravitino.apache.org/docs/latest/gravitino-mcp-server). People sign in once with their organization's
identity provider. The gateway then:

- Calls each MCP server with a credential that server accepts: the caller's own token, a token
  exchanged for the server (RFC 8693, or the Microsoft Entra ID on-behalf-of flow), a short-lived
  token the gateway signs, which the server checks against `<gateway>/.well-known/jwks.json`, a
  token the person connected to the server's own sign-in, or basic auth.
- Decides who may use which MCP server, through access requests that an admin approves, or by
  opening a server to everyone.
- Writes the calls it passes to MCP servers, and the calls it refuses for want of access, to an
  audit log, and serves Prometheus metrics at `/metrics`.

MCP clients reach a server at `<gateway>/mcp/<server ID>` over Streamable HTTP. The gateway
publishes OAuth protected-resource metadata (RFC 9728), so clients that support MCP authorization
find the identity provider and sign in by themselves. The `gravitino-mcp` CLI signs in with the
device flow, configures installed AI clients, and runs a local proxy for clients that cannot sign
in.

For Gravitino's MCP server, Gravitino decides what each person may do: the gateway sends the
person's own token, or one exchanged for Gravitino, so each call runs as that person.

## Requirements

- An OpenID Connect provider, such as Keycloak, Okta, Auth0 or Microsoft Entra ID, which Gravitino
  also uses for [OAuth authentication](https://gravitino.apache.org/docs/latest/security/how-to-authenticate#oauth-mode). People's
  access tokens must be JWTs signed with RS256 that name their client in `azp`, `client_id` or
  `appid`, and carry an `email` claim and an `email_verified` claim that is true. Okta's and
  Auth0's access tokens leave the email out unless a claim or an action adds it. With Microsoft
  Entra ID, set `OIDC_PROVIDER=azure`: the gateway then uses Entra's on-behalf-of flow instead of
  RFC 8693, needs no `email_verified`, and takes `preferred_username`, `upn` or `unique_name`
  for a missing email. Entra doesn't say whether an email was verified, so the gateway trusts
  the tenant's emails as they are.
- A confidential OAuth client for the gateway at the identity provider, with
  `<GATEWAY_BASE_URL>/auth/oauth/callback` as a redirect URI and
  `<GATEWAY_BASE_URL>/auth/oauth/login` as a post-logout redirect URI. With Entra, the gateway's
  app exposes a `user_access` scope, `api://<client ID>/user_access`, which MCP clients ask for.
  For servers that take exchanged tokens, the provider must let this client exchange tokens for
  them: in Keycloak 26.2 or later, standard token exchange on the client; in Entra, an API
  permission to the server's app, with consent.
- Python 3.11 or later, or Docker.
- HTTPS in front of the gateway. Its session and sign-in cookies use the `__Host-` prefix, which
  browsers accept only over HTTPS and, in recent Chrome and Firefox, on `http://localhost`.
- A database: SQLite by default, or MySQL through `DATABASE_URL`. Other databases, such as
  PostgreSQL, are not supported yet.

## Run the gateway

Build the image from this repository. To run the gateway without Docker, follow the
[README](https://github.com/apache/gravitino-mcp-gateway/blob/main/README.md).

```shell
docker build -f docker/Dockerfile -t apache/gravitino-mcp-gateway .
docker run -d -p 8000:8000 --env-file gateway.env \
  -v "$PWD/signing-key.pem:/etc/mcp-gateway/signing-key.pem:ro" \
  apache/gravitino-mcp-gateway
```

The gateway reads its settings from environment variables, here from `gateway.env`:

```text
GATEWAY_BASE_URL=https://mcp-gateway.example.com
OIDC_DISCOVERY_URL=https://idp.example.com/realms/example/.well-known/openid-configuration
GATEWAY_OAUTH_CLIENT_ID=mcp-gateway
GATEWAY_OAUTH_CLIENT_SECRET=<client secret>
JWT_AUDIENCE=gravitino
JWT_SECRET_KEY=<64 random hex characters>
TOKEN_ENCRYPTION_KEY=<32 random bytes, base64-encoded>
GATEWAY_RSA_PRIVATE_KEY_FILE=/etc/mcp-gateway/signing-key.pem
DATABASE_URL=mysql+pymysql://mcp_gateway:<password>@mysql.example.com:3306/mcp_gateway
GRAVITINO_URI=https://gravitino.example.com
GRAVITINO_MCP_URL=http://gravitino-mcp-server:8000/mcp
CORS_ALLOWED_ORIGINS=https://gravitino.example.com
ENVIRONMENT=production
```

The main settings are:

| Setting | Description |
| --- | --- |
| `GATEWAY_BASE_URL` | The gateway's external URL. Sign-in redirects, the OAuth metadata that MCP clients read, and connecting to servers use it. Defaults to `http://localhost:8000`. |
| `OIDC_DISCOVERY_URL` | The identity provider's OpenID configuration URL. |
| `OIDC_PROVIDER` | `azure` for Microsoft Entra ID. Leave it unset for other providers. |
| `OIDC_ISSUER`, `OIDC_JWKS_URI` | Pin the issuer of people's tokens and the keys that sign them, instead of reading them from the identity provider. |
| `GATEWAY_OAUTH_CLIENT_ID`, `GATEWAY_OAUTH_CLIENT_SECRET` | The gateway's OAuth client, for browser sign-in and token exchange. |
| `TOKEN_EXCHANGE_STYLE` | `rfc8693`, or `entra_obo` for Entra's on-behalf-of flow, which is the default with `OIDC_PROVIDER=azure`. |
| `JWT_AUDIENCE` | The audience that people's tokens must carry. Required. |
| `GATEWAY_API_SCOPES` | Scopes that put `JWT_AUDIENCE` in a token, space-separated. MCP clients read them from the gateway's metadata, and the gateway's own sign-in asks for them too. With `OIDC_PROVIDER=azure`, `user_access` by default. |
| `GATEWAY_LOGIN_SCOPES` | Replaces the scopes of the gateway's own sign-in, space-separated: by default `openid profile email offline_access` and `GATEWAY_API_SCOPES`, or `<client ID>/.default` with `OIDC_PROVIDER=azure`. |
| `GATEWAY_OAUTH_ADDITIONAL_CLIENT_IDS` | Other OAuth clients whose tokens the gateway accepts. Comma-separated. |
| `GATEWAY_OAUTH_ACCEPT_ANY_CLIENT` | Accept people's tokens for `JWT_AUDIENCE` from any client of the identity provider, such as MCP clients that register themselves (RFC 7591). They must still come from the configured issuer and carry a verified email. |
| `JWT_SECRET_KEY` | Signs the gateway's sessions and sign-in states. At least 32 characters. Required. |
| `TOKEN_ENCRYPTION_KEY` | Encrypts the tokens and passwords the gateway stores. Required, unless `TOKEN_ENCRYPTION_KEY_FILE` names a file that holds it, or a cloud secret store holds it as `mcp-gateway-encryption-key`. |
| `SECRET_STORAGE_BACKEND` | Where the gateway reads secrets: the encryption key, and the secrets that service accounts forward. `local`, the default, reads `.secrets.json` in the working directory; `gcp_secret_manager` (with `GCP_PROJECT_ID`), `aws_secrets` (with `AWS_SECRETS_REGION`) and `azure_keyvault` (with `AZURE_KEY_VAULT_URL`) read a cloud secret store. |
| `GATEWAY_RSA_PRIVATE_KEY`, `GATEWAY_RSA_PRIVATE_KEY_FILE` | The PEM key that signs the tokens the gateway issues to MCP servers. Without it, each process generates its own, which production refuses. |
| `GRAVITINO_URI` | Gravitino's server. With Gravitino's authorization enabled, its service admins are the gateway's admins. |
| `ADMIN_EMAILS` | More admins, by email. Comma-separated. |
| `USER_ID_CLAIM` | The claim that names people, `email` by default. |
| `GRAVITINO_MCP_URL` | The Gravitino MCP server, registered as `gravitino` and open to everyone. |
| `GRAVITINO_MCP_AUDIENCE` | The audience Gravitino expects, when it differs from `JWT_AUDIENCE` and the gateway must exchange tokens. |
| `CORS_ALLOWED_ORIGINS` | Origins that may call the gateway's API from a browser. Comma-separated. |
| `DATABASE_URL` | The database. MySQL connections use TLS: `DATABASE_SSL_MODE` is `REQUIRED` by default, which doesn't check the server's certificate; `VERIFY_CA` and `VERIFY_IDENTITY` do, and `DISABLED` turns TLS off. Each replica keeps up to `DATABASE_POOL_SIZE` connections open and opens `DATABASE_MAX_OVERFLOW` more when busy, 10 each by default. |
| `UPSTREAM_TLS_VERIFY` | `true`, `false`, or the path of a CA bundle, for MCP servers and their authorization servers with private certificates. For an identity provider with a private certificate, set `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` to a bundle that includes its CA. |
| `MCP_TOOL_FILTERS` | The tools each MCP server exposes. See [Tool filters](#tool-filters). |
| `MCP_TOOL_CALL_TIMEOUT` | Seconds a tool call may take, 1200 by default. |
| `MCP_FORWARD_HEADERS` | Headers of the caller's that the gateway passes on to MCP servers, such as an API key a server needs. Comma-separated. Headers the gateway sets itself, such as `Authorization` and `Cookie`, can't be listed. |
| `AUDIT_LOG_RESPONSES`, `AUDIT_RETENTION_DAYS` | Whether the audit log keeps responses, off by default, and how many days it keeps calls, 90 by default; 0 keeps them for ever. |
| `HOST`, `PORT` | Where the gateway listens, `0.0.0.0` and `8000` by default. |
| `MAX_REQUEST_BYTES` | The largest request body the gateway reads, 10 MiB by default. |
| `ENVIRONMENT` | `production`, which the Docker image sets, turns on the checks in [In production](#in-production). |

`mcp_gateway/config.py` lists every setting and its default.

### In production

With `ENVIRONMENT=production`, the gateway refuses to start with `DEBUG` on, with
`CORS_ALLOWED_ORIGINS=*`, with an `http` `GATEWAY_BASE_URL`, without a signing key or an
encryption key, or with `UPSTREAM_TLS_VERIFY=false`, and it doesn't serve its API docs at `/docs`.
Browsers on the allowed origins call the API with tokens, never with the gateway's cookies.
Also:

- Keep `JWT_SECRET_KEY`, the encryption key and the signing key stable and secret, and give every
  replica the same ones and the same MySQL database. Generate an encryption key with
  `python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"`, and a
  signing key with `openssl genrsa -out signing-key.pem 2048`.
- Use MySQL, or mount a volume at `/opt/mcp-gateway/data`, where the image keeps its SQLite
  database: the container's own files are lost with it. The gateway runs as uid 1000 in group 0,
  so a host directory mounted there must be writable by one of them.
- Behind a load balancer, set `FORWARDED_ALLOW_IPS` to its addresses, so that the audit log
  records the callers' addresses rather than the load balancer's.
- Keep `/metrics` and the Gravitino MCP server off the public network. The gateway does not
  authenticate `/metrics`, and only it should reach the MCP server.
- `GET /health` answers 200 while the gateway can reach its database, and 503 otherwise.

### Tokens and audiences

People's tokens must carry `JWT_AUDIENCE` as their audience. The simplest setup sets `JWT_AUDIENCE`
to Gravitino's `gravitino.authenticator.oauth.serviceAudience`. MCP clients' tokens then work for
both, and the gateway forwards them to Gravitino's MCP server without an exchange. Put that audience
in tokens with a scope, such as a Keycloak client scope with an audience mapper, and list the scope
in `GATEWAY_API_SCOPES`, or make it a default scope of every client that signs people in.

If the gateway has an audience of its own, set `GRAVITINO_MCP_AUDIENCE` to Gravitino's, and the
gateway exchanges each person's token for one that Gravitino accepts (RFC 8693, or on-behalf-of
with Entra).

### Gravitino's MCP server

With `GRAVITINO_MCP_URL` set, the gateway registers Gravitino's MCP server as `gravitino` at each
start where no `gravitino` server exists. Later changes to these settings don't update it; change it
with `PATCH /api/admin/mcp/gravitino` instead. To remove it for good, unset `GRAVITINO_MCP_URL`
before you delete it, or deactivate it. Run the MCP server with `--transport http`, and with
`--no-service-identity-fallback` if it also has a token or OAuth client credentials of its own, so
that every call runs as the person making it, and with `--mcp-url http://0.0.0.0:8000/mcp` in a
container, so that the gateway can reach it. Only Gravitino's read tools are exposed, unless
`MCP_TOOL_FILTERS` says otherwise.

### Admins

`ADMIN_EMAILS` lists the gateway's admins. With `GRAVITINO_URI` set and Gravitino's authorization
enabled, Gravitino's service admins are admins too. The gateway asks Gravitino's
`/api/authn/me` with the token it would send Gravitino's MCP server, so Gravitino must accept that
token. A change to Gravitino's service admins can take five minutes to reach the gateway. While
Gravitino can't be reached, only `ADMIN_EMAILS` count.

Admins hold real power: they read everyone's audit log, and a server's URL decides where the
gateway sends the tokens of the people who use it, so an admin who changes it can collect them.
Give the role to people you would trust with those tokens.

### Name people the way Gravitino does

The gateway finds people by their verified email, and names them by the `USER_ID_CLAIM` claim.
The audit log and the tokens the gateway signs for MCP servers use that name. Set it to the claim
Gravitino reads, the first of `gravitino.authenticator.oauth.principalFields`, so that both use
the same names:

```shell
USER_ID_CLAIM=preferred_username
```

Pick a claim that people cannot change themselves. The names can still differ from Gravitino's if
Gravitino also maps principals (`principalMapper`), or if another account already has the name,
in which case the gateway names the person by their email.

## Register MCP servers

Admins register MCP servers with `POST /api/admin/mcp/`. A server's ID is part of the URL that MCP
clients use, `https://mcp-gateway.example.com/mcp/<server ID>`, and cannot change later. It has 3 to
100 lowercase letters, digits, `.`, `_` and `-`, and starts with a letter or a digit.

### How the gateway signs in to a server

Each server says how the gateway signs in to it for people, and how for service accounts. For
people, the choices are:

| Settings | What the MCP server receives |
| --- | --- |
| `"auth_type": "oauth"`, `"auto_sso_enabled": true`, and the gateway's `JWT_AUDIENCE` or `GATEWAY_OAUTH_CLIENT_ID` as `"audience"` | The person's own token: the one stored at their latest sign-in to the gateway or the CLI, or else the token on the call. Use it for servers that accept the same tokens as the gateway, such as Gravitino's. The token is valid at the gateway too, so the server could call the gateway as the person: give this audience only to servers you trust as much as the gateway. |
| The same, with the server's audience | A token for that audience, which the gateway exchanges for the person's own (RFC 8693, or Entra's on-behalf-of flow). `oauth_scopes` asks for particular scopes. |
| `"auth_type": "oauth"`, `"auto_sso_enabled": false` | A token from the server's own sign-in, which each person connects once. |
| `"auth_type": "passthrough"` | A token the gateway signs for each call, with `iss` `gravitino-mcp-gateway`, `aud` the server ID, `sub` the person's name, their `email`, `name` and `preferred_username`, and `principal_type`, `person` or `service_account`. It expires after 15 minutes. The server checks it against `<gateway>/.well-known/jwks.json`. |
| `"auth_type": "basic"`, `basic_auth_username`, `basic_auth_password` | The same user name and password, whoever calls. |

For servers with their own sign-in, the gateway finds the server's authorization server from the
server's protected resource metadata (RFC 9728), or from the authorization server metadata URL
(`oauth_metadata_url`). The authorization server must use https. Without a client ID
(`oauth_client_id`), the gateway registers itself with that authorization server (RFC 7591). To
register a client yourself, use `<GATEWAY_BASE_URL>/portal/callback/mcp-oauth/<server ID>` as its
redirect URI: each server has its own, so that a code can't come back as another server's. A client
secret (`oauth_client_secret`) needs the metadata URL, so that the secret goes only to an
authorization server an admin named.

For service accounts (`service_auth_type`), the choices are a token from the gateway
(`passthrough`, the default), basic auth with the gateway's credentials (`basic`), or a secret
that the service account's registration names (`credential_forward`, see
[Service accounts](#service-accounts)). Service accounts never reach a server with OAuth.

New servers require approval unless `requires_approval` is false, and single sign-on is off
unless `auto_sso_enabled` is true. For example, a server that takes exchanged tokens:

```shell
curl -X POST https://mcp-gateway.example.com/api/admin/mcp/ \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"service_id": "trino", "name": "Trino", "mcp_url": "https://trino-mcp.example.com/mcp",
       "auth_type": "oauth", "auto_sso_enabled": true, "audience": "trino"}'
```

`$ADMIN_TOKEN` is an admin's access token for the gateway, such as the `access_token` that
`gravitino-mcp login` saves in `~/.gravitino-mcp/tokens`. A server for both people and service
accounts, which checks the gateway's tokens and is open to everyone:

```json
{"service_id": "tools", "name": "Internal tools", "mcp_url": "https://tools.example.com/mcp",
 "auth_type": "passthrough", "service_auth_type": "passthrough", "requires_approval": false}
```

`GET /api/admin/mcp/` lists the servers, and `GET /api/admin/mcp/<server ID>` shows one.
`PATCH /api/admin/mcp/<server ID>` changes a server. Moving it, or changing how people sign in to
it, deletes the tokens people hold for it, and a client the gateway registered with its old sign-in;
a stored client secret or basic-auth password must be given again with the move. `DELETE` deletes
a server, with everyone's access to it and their tokens for it; to take a server out of use for a
while, set `is_active` to false. Every change an admin makes to a server is in the audit log, as
the admin's call, with secrets redacted.

### Who may use a server

- `requires_approval` true: people ask for access, and an admin approves or denies each request.
  Turning it on takes away the access that people got while the server was open; access that an
  admin approved stays.
- `requires_approval` false: the server is open, and anyone signed in may use it.
- `admin_only` true: other people can't see or call the server.
- `is_active` false: the server answers as if it didn't exist.

Service accounts see and reach only the servers their registration lists, and don't ask for
access.

### Tool filters

`MCP_TOOL_FILTERS` limits the tools a server lists and lets people call, by the prefix of their
names. It is JSON keyed by server ID. Servers it doesn't list expose every tool, and a server
listed with no prefixes exposes none. By default it exposes only Gravitino's read tools. Setting
it replaces that default, so keep the `gravitino` entry, or Gravitino's write tools become
available:

```text
MCP_TOOL_FILTERS={"gravitino": ["get_", "list_", "load_", "metadata_"], "trino": ["query_"]}
```

## Review access requests

`GET /api/mcp-access/admin/pending` lists the pending requests, 25 to a page unless `page_size`
says otherwise, up to 100; `page` picks the page. An admin approves or denies one with
`POST /api/mcp-access/admin/review/<request ID>`:

```shell
curl -X POST https://mcp-gateway.example.com/api/mcp-access/admin/review/42 \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"status": "approved", "expires_in_days": 30}'
```

`expires_in_days`, from 1 to 3650, grants access for a while; without it, access doesn't expire.
`admin_notes` explains a decision: a person who is denied sees it in
`GET /api/mcp-access/my-requests`, and can ask again. When two admins review the same request, only
the first decision counts. `GET /api/mcp-access/admin/permissions` lists who has access, paged the
same way, and `DELETE /api/mcp-access/admin/permissions/<permission ID>` takes it away. On an open
server, revoking does nothing lasting: anyone may use it, and the gateway grants access again at the
next call.

## Read the audit log

`GET /api/audit/logs` lists the calls of people and service accounts: every request the gateway
passes to a server, `tools/list` included, with the method as the tool name for anything but a
tool call; every call to a server that it refuses for want of access, as `unauthorized`; every
tool call whose client left before it finished, as `cancelled`, since it may still have run; and
every change an admin makes to a server or a service account. Calls without a valid token, and
calls to servers that don't exist for the caller, are not recorded.

Each person sees their own calls; admins see everyone's, and can narrow the list to one account with
its numeric `user_id`, as the log's entries give it. `service`, `tool_name` and `status` (`success`,
`error`, `unauthorized` or `cancelled`) narrow it further, `start_date` and `end_date` bound the
period, and `limit`, 100 by default and up to 1,000, and `offset` page through it.
`GET /api/audit/logs/export/csv` exports what the caller sees as CSV, with the same filters, up to
the latest 10,000 calls. The log keeps each call's arguments, and with `AUDIT_LOG_RESPONSES` its
response, so admins can read them. Arguments whose names look like secrets, such as `password`,
`token` or `api_key`, are kept as `[redacted]`. Arguments or a response longer than 10,000
characters are kept as their first 1,000, with the original's size and SHA-256. The gateway deletes
calls older than `AUDIT_RETENTION_DAYS`, 90 days by default.

## Service accounts

Workloads on GKE, GCE or EKS call MCP servers through the gateway with their platform's identity
token. An admin registers each one with `POST /api/admin/service-accounts`:

- `oauth_credentials.service_account_name`, its workload identity: the GCP service account's
  email, or for EKS `<namespace>::<service account>::<cluster ID>`, where the cluster ID is the
  part of the cluster's OIDC issuer URL after `/id/`.
- `allowed_services`: the IDs of the only servers the service account reaches.
- `additional_config.iss`: the issuer its tokens must come from, which replaces
  `TRUSTED_ISSUERS` for this account. An EKS identity of the form
  `<namespace>::<service account>` needs it.

```shell
curl -X POST https://mcp-gateway.example.com/api/admin/service-accounts \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "svc-etl", "provider": "google", "allowed_services": ["tools"],
       "oauth_credentials": {"service_account_name": "etl@my-project.iam.gserviceaccount.com"}}'
```

The gateway trusts the issuers in `TRUSTED_ISSUERS`, comma-separated, such as
`https://accounts.google.com` and the EKS cluster's OIDC issuer URL. It finds their signing keys
by discovery, or in `TRUSTED_ISSUER_JWKS` (comma-separated `issuer=https://jwks-uri` pairs). A token's audience must be
`JWT_AUDIENCE` or the gateway itself: `GATEWAY_BASE_URL`, or with `OIDC_PROVIDER=azure` also its
client ID. A token that names the account by email must mark the email verified; EKS tokens name
the Kubernetes service account instead.

A workload gets its token with the SDK in `mcp-gateway`, and sends it on each call. The token is
for the gateway's URL, which must be https, or on `localhost`, unless `audience=` names
`JWT_AUDIENCE` instead:

```python
from mcp_gateway_sdk import get_gateway_sa_token

token = get_gateway_sa_token("https://mcp-gateway.example.com")                # GKE, GCE
token = get_gateway_sa_token("https://mcp-gateway.example.com", source="aws")  # EKS
```

On EKS, the SDK asks the Kubernetes API for a token for the pod's service account, so that
service account needs permission to create `serviceaccounts/token` for itself.

The workload then calls the server:

```shell
curl -X POST https://mcp-gateway.example.com/mcp/tools \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}'
```

To have workloads describe themselves, for example with a team and a pipeline name, list header
names in `SERVICE_ACCOUNT_REQUIRED_HEADERS` and `SERVICE_ACCOUNT_OPTIONAL_HEADERS`,
comma-separated. The gateway refuses a call without a required header, and forwards the headers to
MCP servers and the audit log.

For a server whose `service_auth_type` is `credential_forward`, the registration's
`additional_config` names the secret to send, under the server's ID, and the account must list
the server in `allowed_services`:

```json
{"downstream_credentials": {"etl": {"secret_ref": "mcp-gateway-sa-etl", "auth_header_type": "bearer"}}}
```

The gateway reads the secret from its secret store (`SECRET_STORAGE_BACKEND`) and sends it as a
bearer token, or with `"auth_header_type": "basic"` and a `username`, as basic auth;
`auth_header_type` is required. The gateway refuses to save a secret name that doesn't start with
`SERVICE_ACCOUNT_SECRET_PREFIX`, `mcp-gateway-sa-` by default.

## Connect an MCP client

`gravitino-mcp services` lists the servers you can see. MCP clients reach each one at
`<gateway>/mcp/<server ID>`. For a server that requires approval, ask with
`POST /api/mcp-access/request`: its `mcp_id` is the server's numeric `id` in
`GET /api/catalog/mcps`, and `justification` says why. `GET /api/mcp-access/my-requests` shows the
request as pending until an admin decides. Open servers need no request.

### Clients that sign in themselves

Clients that support MCP authorization, such as Claude Code, VS Code and Cursor, find the
identity provider from the gateway and sign you in. For Claude Code:

```shell
claude mcp add --transport http gravitino https://mcp-gateway.example.com/mcp/gravitino
```

For VS Code, in `mcp.json`:

```json
{"servers": {"gravitino": {"type": "http", "url": "https://mcp-gateway.example.com/mcp/gravitino"}}}
```

For Cursor, in `~/.cursor/mcp.json`:

```json
{"mcpServers": {"gravitino": {"url": "https://mcp-gateway.example.com/mcp/gravitino"}}}
```

These clients register themselves with the identity provider (RFC 7591), so the provider must
allow it, and the gateway must set `GATEWAY_OAUTH_ACCEPT_ANY_CLIENT=true`. Microsoft Entra ID has
no such registration; with Entra, use the CLI.

### The CLI

The `gravitino-mcp` CLI signs you in through the browser and runs a local proxy, at
`http://localhost:8001`, which adds your token to each call. Install it from a checkout of
this repository:

```shell
pip install .
export MCP_GATEWAY_URL=https://mcp-gateway.example.com
gravitino-mcp setup
```

`setup` signs you in: type the code it shows on the page it opens, check where the request comes
from, and approve it. It then points Claude Code, VS Code, Cursor and OpenCode at
`http://localhost:8001/mcp/gravitino`, and starts the proxy, also at login on macOS and Linux.
Other servers are at `http://localhost:8001/mcp/<server ID>`. `setup` replaces a `gravitino` entry
in Claude Code's user settings, VS Code's user `mcp.json`, `~/.cursor/mcp.json` and
`~/.config/opencode/opencode.json`, so a client that signs in itself needs another name there. `gravitino-mcp doctor` diagnoses problems, and
`gravitino-mcp --help` lists the other commands. `setup` doesn't configure Claude Desktop, whose
configuration file holds only servers that it starts itself.

The proxy forwards only MCP calls, and refuses requests from web pages. Any program you run can
use it, and so can other users of the same machine, so on a shared machine use clients that sign
in themselves instead. Keep `~/.gravitino-mcp/tokens` as private as a password.

### Servers with their own sign-in

Connect a server that has its own sign-in before using it, with
`gravitino-mcp connect <server ID>`. `POST /portal/disconnect/<server ID>` removes the
connection. Signing out of the gateway deletes your gateway token and the tokens the gateway got
with it, but not these connections, which you made yourself.

### When a call fails

| The client reports | Do this |
| --- | --- |
| `Access denied. You don't have permission to access <server>. Please request access.` | Request access with `POST /api/mcp-access/request`. |
| `Your permission to access <server> has expired.` | Request access again. |
| `Not connected to <server>.` | For a server with its own sign-in, run `gravitino-mcp connect <server ID>`. For a server with single sign-on, the token exchange failed: an admin checks the gateway's log, and the identity provider's exchange permissions. |
| `Tool '<tool>' is not available on <server>.` | The server's tool filter hides the tool. |
| `Service '<server>' not found or inactive` | Check the server ID. The server may also be inactive, or only for admins. |

## Slack

The gateway uses Slack only when these settings are set:

- `SLACK_WEBHOOK_URL`, an incoming webhook: the gateway posts each new access request, and each
  decision, to its channel.
- `SLACK_BOT_TOKEN` and `SLACK_CHANNEL_ID`: when an admin approves someone's access, the gateway
  invites them to the channel, found by their email. The bot needs the `users:read`,
  `users:read.email` and `channels:write.invites` scopes.
- `SLACK_BOT_TOKEN` and `SLACK_APP_TOKEN`: people sign in to the gateway from Slack with
  `/gravitino-mcp login`, through the device flow, and out with `/gravitino-mcp logout`. The bot
  connects with Socket Mode, and installs with the `/gravitino-mcp` command.
- `SLACK_USER_TOKENS_ENABLED=true`, with the bot's two tokens: a Slack app's service account may ask
  for the gateway token of someone who signed in from Slack (`POST /api/sa/user-tokens`). The person
  approves each request in Slack, which names the service account that asks, and the approval lasts
  30 minutes. The person's approval is what protects them: the request's signature, made with the
  Slack app's own signing secret, proves no more than the service account's token does. The service
  account's `additional_config` holds the Slack app's signing secret, and allows it:
  `{"slack_signing_secret": "<secret>", "token_retrieval_services": "slack_gateway"}`. The app can
  then act as the person until the token expires, so turn this on only for Slack apps you trust with
  people's tokens.

## Limitations

- Gravitino's access control does not decide MCP access yet. The gateway keeps its own access
  approvals, while Gravitino still authorizes each call to its own MCP server.
- Service accounts can't use Gravitino's MCP server yet. The gateway reaches servers for them
  with a token it signs, basic auth or a forwarded secret, and a Gravitino that uses OAuth
  accepts only its identity provider's tokens.
- People are known by their verified email. If the identity provider gives someone's email to
  another person, that person gets the account, with its access and connected servers.
- Deleting a service account doesn't revoke its identity at the identity provider. If its
  tokens come from the provider people sign in with, carry a verified email, and the gateway
  accepts any client (`GATEWAY_OAUTH_ACCEPT_ANY_CLIENT`), the gateway treats them as a person.
  Google service accounts are never treated as people.
- The gateway doesn't limit how often anyone calls it, nor how many calls run at once; put it
  behind a proxy that does.
- Anyone the identity provider signs in becomes a person in the gateway, and may use its open
  servers, Gravitino's included. Limit who may sign in at the identity provider.
- The gateway fetches the sign-in settings that a server with its own sign-in names, from any
  https address, inside your network too. Register only servers you trust to name their sign-in.
- Whoever holds the CLI's refresh token can renew it through the gateway's `/auth/refresh`.
- MCP servers must speak Streamable HTTP, and the gateway reads each response in full before it
  returns the result. It doesn't pass on notifications, in either direction, or open the stream
  for messages a server starts: `GET /mcp/<server ID>` answers 405.
- The gateway answers `initialize` itself and offers only tools, so clients don't see a server's
  prompts or resources.
- The CLI's proxy doesn't start at login on Windows.
- The database schema is created at startup but not migrated between releases: a release that
  changes it needs a new database.
