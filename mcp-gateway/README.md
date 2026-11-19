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

# Gravitino MCP Gateway

Gravitino MCP Gateway sits between AI clients and the MCP servers they use.
Users sign in once with their organization's identity provider. The gateway
calls each MCP server with a credential that server accepts, controls who may
use which server, and writes the calls to an audit log.

> The gateway is in beta in Gravitino 2.0: its configuration and APIs may
> change in later releases.

The [user documentation](../docs/gravitino-mcp-gateway.md) covers deploying the
gateway with an identity provider, registering MCP servers, service accounts,
and connecting MCP clients. [ARCHITECTURE.md](ARCHITECTURE.md) describes the
design.

## Features

- **Sign-in.** Browser sign-in, and the OAuth device flow (RFC 8628) for the CLI.
  The gateway publishes OAuth protected-resource metadata (RFC 9728), so MCP
  clients can find out how to sign in.
- **A credential for each MCP server.** The caller's own token, a token
  exchanged for the server (RFC 8693, or the Microsoft Entra on-behalf-of
  flow), a token the user connected to the server's own sign-in, a short-lived
  token the gateway signs, or basic auth. Stored tokens are encrypted with
  AES-256-GCM.
- **MCP proxy.** Streamable HTTP at `/mcp/<server ID>`, with per-server tool
  filters.
- **Access control.** Users ask for access to a server and an admin approves
  it, or the server is open to everyone. Service accounts authenticate with GCP
  or EKS workload identity tokens.
- **Audit and metrics.** The calls the gateway passes on, the ones it refuses
  for want of access, and admins' changes
  are written to the audit log. Prometheus metrics are served at `/metrics`.
- **Gravitino's web UI** manages the gateway: servers, access requests, service
  accounts and the audit log.
- **CLI** (`gravitino-mcp`). Signs in, configures installed AI clients, and runs
  a local proxy on port 8001 that adds the user's token to each MCP call.

## Layout

| Path | Contents |
| --- | --- |
| `mcp_gateway/` | The gateway (FastAPI): sign-in, MCP proxy, access control, audit |
| `mcp_gateway_cli/` | The `gravitino-mcp` command-line client and its local proxy |
| `mcp_gateway_sdk/` | Helpers for service accounts that call the gateway |
| `dev/keycloak/` | Keycloak, Gravitino and Gravitino's MCP server in Docker, for trying the gateway |
| `tests/` | Unit tests, and integration tests under `tests/integration/` |

## Run the gateway

Python 3.11 or later is required. The commands use [uv](https://docs.astral.sh/uv/);
`pip install -e .` works too.

```bash
cd mcp-gateway
uv sync && source .venv/bin/activate

# Key that encrypts stored OAuth tokens; keep it stable across restarts
export TOKEN_ENCRYPTION_KEY=$(python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())")
export JWT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export GATEWAY_BASE_URL=http://localhost:8000   # the gateway's external URL
export OIDC_DISCOVERY_URL=https://<provider>/.well-known/openid-configuration
export GATEWAY_OAUTH_CLIENT_ID=<client id>
export GATEWAY_OAUTH_CLIENT_SECRET=<client secret>
export JWT_AUDIENCE=<audience of the tokens the gateway accepts>
export ADMIN_EMAILS=you@example.com

uvicorn mcp_gateway.main:app --port 8000
```

Register `http://localhost:8000/auth/oauth/callback` as a redirect URI of the
gateway's client at the identity provider, then open http://localhost:8000 and
sign in. Settings can also go in a `.env` file, or the one `MCP_GATEWAY_ENV_FILE`
names; [mcp_gateway/config.py](mcp_gateway/config.py) lists them all with their
defaults, and the [user documentation](../docs/gravitino-mcp-gateway.md#run-the-gateway)
describes the main ones.

The gateway's session and sign-in cookies use the `__Host-` prefix, which
browsers accept only over HTTPS and, in recent Chrome and Firefox, on
`http://localhost`. To sign in over plain HTTP anywhere else, or from Safari on
`localhost`, set `DEBUG=true`, which drops the prefix and the `Secure` flag;
production refuses it.

The gateway uses SQLite (`./mcp_gateway.db`) unless `DATABASE_URL` points
elsewhere, for example `mysql+pymysql://user:password@host:3306/mcp_gateway`.
Tables are created at startup.

The token encryption key can also come from a file (`TOKEN_ENCRYPTION_KEY_FILE`)
or from a secret store: `SECRET_STORAGE_BACKEND` is `local` (`./.secrets.json`,
which the gateway only reads), `gcp_secret_manager`, `aws_secrets` or
`azure_keyvault`, under the secret name `mcp-gateway-encryption-key`. For
example, in GCP Secret Manager:

```bash
python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode(), end='')" |
  gcloud secrets create mcp-gateway-encryption-key --data-file=-
```

The cloud backends need the `gcp`, `aws` or `azure` extra, for example
`uv sync --extra gcp`.

## Try it with Keycloak

[dev/keycloak](dev/keycloak) runs Keycloak, Gravitino and Gravitino's MCP server
in Docker. Keycloak gets a `gravitino` realm with users `alice` and `bob`, whose
passwords are their names. Alice is Gravitino's service admin and owns the
metalake `demo`, which bob can't see. The passwords and the client secret are
fixed, so use it only on your own machine.

```bash
docker compose -f dev/keycloak/docker-compose.yaml up -d

export OIDC_DISCOVERY_URL=http://localhost:8080/realms/gravitino/.well-known/openid-configuration
export GATEWAY_OAUTH_CLIENT_ID=mcp-gateway
export GATEWAY_OAUTH_CLIENT_SECRET=mcp-gateway-secret
export GATEWAY_OAUTH_ACCEPT_ANY_CLIENT=true
export JWT_AUDIENCE=gravitino
export GATEWAY_API_SCOPES=gravitino
export GRAVITINO_MCP_URL=http://localhost:8100/mcp
export GRAVITINO_URI=http://localhost:8090         # alice, Gravitino's service admin, is an admin
export USER_ID_CLAIM=preferred_username            # the first of Gravitino's principalFields
export CORS_ALLOWED_ORIGINS=http://localhost:3000  # Gravitino's web UI, run with pnpm dev
# TOKEN_ENCRYPTION_KEY and JWT_SECRET_KEY as above
uvicorn mcp_gateway.main:app --port 8000
```

Point an MCP client at http://localhost:8000/mcp/gravitino: it registers itself
with Keycloak, signs you in, and the gateway forwards your token to Gravitino.
To have the gateway exchange tokens instead (RFC 8693), set
`JWT_AUDIENCE=mcp-gateway`, `GATEWAY_API_SCOPES=mcp-gateway` and
`GRAVITINO_MCP_AUDIENCE=gravitino`. [setup-realm.sh](dev/keycloak/setup-realm.sh)
shows the Keycloak settings each needs.

Gravitino signs in with Keycloak too, and points its web UI at the gateway. The
UI in the Gravitino image predates the MCP pages; to see them, run the UI from
this repository with `pnpm install && pnpm dev` in `web-v2/web`, then open
http://localhost:3000 and sign in as alice.

`MCP_GATEWAY_KEYCLOAK_TEST=1 uv run pytest -m integration tests/integration/test_keycloak.py`
tests the gateway against this setup.

## Use the CLI

```bash
pip install ./mcp-gateway   # installs the gravitino-mcp command
export MCP_GATEWAY_URL=https://mcp-gateway.example.com
gravitino-mcp setup    # sign in, configure AI clients, start the local proxy
gravitino-mcp doctor   # diagnose sign-in, gateway, and proxy problems
```

Other commands include `login`, `logout`, `whoami`, `services`,
`connect <server ID>`, `tools <server ID>`, `call <server ID> <tool>`, `proxy`
and `autostart`; run `gravitino-mcp --help` for the full list.

## Service accounts

Workloads on GKE, GCE, or EKS call the gateway with their platform identity
token, once an admin has registered the service account in Gravitino's web UI:

```python
from mcp_gateway_sdk import get_gateway_sa_token

token = get_gateway_sa_token("https://mcp-gateway.example.com")                # GCP
token = get_gateway_sa_token("https://mcp-gateway.example.com", source="aws")  # EKS
```

With no URL, the SDK reads `MCP_GATEWAY_URL`. The token is for the gateway's
URL, unless `audience=` names the gateway's `JWT_AUDIENCE` instead. The
[user documentation](../docs/gravitino-mcp-gateway.md#service-accounts) covers
registering service accounts, the issuers the gateway trusts, workload headers,
and forwarding secrets to MCP servers.

## Development

```bash
uv sync --all-extras
uv run pytest -m "not integration"
```

Tests marked `integration` need running services and are excluded above.
From the Gravitino root, `./gradlew :mcp-gateway:build` checks the formatting
(black and isort), runs pylint and runs the unit tests, as the CI does.
