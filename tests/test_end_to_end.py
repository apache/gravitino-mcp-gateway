# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""End to end: a user of a generic OIDC provider reaches Gravitino's MCP server.

The identity provider and the MCP server are real HTTP servers on localhost, so
discovery, the JWKS fetch, the token exchange and the upstream MCP calls all go
over the wire. Nothing in the gateway is mocked.
"""

import base64
import json
import os
import threading
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from mcp_gateway.catalog_defaults import register_gravitino_mcp
from mcp_gateway.config import settings
from mcp_gateway.oauth import token_encryption
from mcp_gateway.routes import mcp_server, mcp_upstream

GATEWAY_CLIENT_ID = "mcp-gateway"
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KEY_ID = "provider-key"
TOOLS = [{"name": "list_of_catalogs"}, {"name": "drop_catalog"}]


def _issue_token(issuer: str, audience: str, email: str = "alice@example.com"):
    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": audience,
        "azp": GATEWAY_CLIENT_ID,
        "email": email,
        "email_verified": True,
        "iat": now,
        "exp": now + 300,
    }
    return jwt.encode(claims, SIGNING_KEY, algorithm="RS256", headers={"kid": KEY_ID})


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        """Keep the test output quiet."""

    def _read_body(self) -> bytes:
        return self.rfile.read(int(self.headers.get("Content-Length", 0)))

    def _send_json(self, body: dict, headers: dict = None) -> None:
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class _ProviderHandler(_Handler):
    """An OIDC provider: discovery, JWKS, and RFC 8693 token exchange."""

    def do_GET(self):  # pylint: disable=invalid-name
        issuer = self.server.url
        if self.path == "/.well-known/openid-configuration":
            self._send_json(
                {
                    "issuer": issuer,
                    "authorization_endpoint": f"{issuer}/authorize",
                    "token_endpoint": f"{issuer}/token",
                    "jwks_uri": f"{issuer}/jwks",
                }
            )
        elif self.path == "/jwks":
            jwk = json.loads(RSAAlgorithm.to_jwk(SIGNING_KEY.public_key()))
            self._send_json({"keys": [{**jwk, "kid": KEY_ID, "alg": "RS256"}]})
        else:
            self.send_error(404)

    def do_POST(self):  # pylint: disable=invalid-name
        form = {k: v[0] for k, v in parse_qs(self._read_body().decode()).items()}
        self.server.calls.append(form)
        if self.path != "/token" or form.get("grant_type") != TOKEN_EXCHANGE:
            self.send_error(400)
            return
        subject = jwt.decode(form["subject_token"], options={"verify_signature": False})
        self._send_json(
            {
                "access_token": _issue_token(
                    self.server.url, form["audience"], subject["email"]
                ),
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "Bearer",
                "expires_in": 300,
            }
        )


class _McpHandler(_Handler):
    """An MCP server standing in for Gravitino's, over Streamable HTTP."""

    def do_POST(self):  # pylint: disable=invalid-name
        message = json.loads(self._read_body())
        method = message.get("method")
        self.server.calls.append((method, self.headers.get("Authorization")))
        if method == "initialize":
            session = uuid.uuid4().hex
            self.server.sessions.add(session)
        else:
            session = self.headers.get("Mcp-Session-Id")
            if session not in self.server.sessions:
                # What an MCP server answers for a session it does not know.
                self.send_error(404)
                return
        if "id" not in message:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        results = {
            "initialize": {"protocolVersion": "2025-03-26", "capabilities": {}},
            "tools/list": {"tools": TOOLS},
            "tools/call": {"content": [{"type": "text", "text": "[]"}]},
        }
        self._send_json(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": results[method],
            },
            headers={"Mcp-Session-Id": session},
        )


@contextmanager
def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.url = f"http://127.0.0.1:{server.server_port}"
    server.calls = []
    server.sessions = set()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(name="provider")
def fixture_provider():
    with _serve(_ProviderHandler) as server:
        yield server


@pytest.fixture(name="gravitino_mcp")
def fixture_gravitino_mcp():
    with _serve(_McpHandler) as server:
        yield server


@pytest.fixture(name="gateway")
def fixture_gateway(client, provider, gravitino_mcp, monkeypatch):
    """The gateway configured only through the provider's discovery URL."""
    configuration = {
        "OIDC_PROVIDER": "generic",
        "OIDC_DISCOVERY_URL": f"{provider.url}/.well-known/openid-configuration",
        "OIDC_ISSUER": None,
        "OIDC_JWKS_URI": None,
        "OIDC_AUTHORIZATION_ENDPOINT": None,
        "OIDC_TOKEN_ENDPOINT": None,
        "GATEWAY_OAUTH_CLIENT_ID": GATEWAY_CLIENT_ID,
        "GATEWAY_OAUTH_CLIENT_SECRET": "gateway-secret",
        "JWT_AUDIENCE": GATEWAY_CLIENT_ID,
        "GRAVITINO_MCP_URL": f"{gravitino_mcp.url}/mcp",
        "TOKEN_ENCRYPTION_KEY": base64.b64encode(os.urandom(32)).decode(),
    }
    for name, value in configuration.items():
        monkeypatch.setattr(settings, name, value)
    # Process-wide state that must not leak in from other tests.
    monkeypatch.setattr(token_encryption, "_token_encryption", None)
    monkeypatch.setattr(mcp_server, "_mcp_http_client", None)
    monkeypatch.setattr(mcp_upstream, "_upstream_sessions", {})
    return client


def _call(gateway, token: str, method: str, params: dict = None):
    message = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        message["params"] = params
    return gateway.post(
        "/mcp/gravitino", json=message, headers={"Authorization": f"Bearer {token}"}
    )


def _answer(resp) -> dict:
    """The JSON-RPC message the gateway answered with; a tool call's comes as SSE."""
    if resp.headers["content-type"].startswith("text/event-stream"):
        return json.loads(resp.text.split("data: ")[-1])
    return resp.json()


def test_discovery_points_mcp_clients_at_the_provider(gateway, provider):
    resource = gateway.get("/.well-known/oauth-protected-resource").json()
    server = gateway.get("/.well-known/oauth-authorization-server").json()

    assert resource["authorization_servers"] == [provider.url]
    assert server["token_endpoint"] == f"{provider.url}/token"


def test_a_user_reaches_gravitino_with_their_own_token(
    gateway, db_session, provider, gravitino_mcp
):
    register_gravitino_mcp(db_session)
    user_token = _issue_token(provider.url, GATEWAY_CLIENT_ID)

    resp = _call(gateway, user_token, "tools/list")

    assert resp.status_code == 200
    # Only Gravitino's read tools are exposed.
    assert resp.json()["result"]["tools"] == [{"name": "list_of_catalogs"}]
    # Gravitino accepts the gateway's audience, so no exchange was needed.
    assert not provider.calls
    assert {auth for _, auth in gravitino_mcp.calls} == {f"Bearer {user_token}"}


def test_another_gravitino_audience_is_reached_by_token_exchange(
    gateway, db_session, provider, gravitino_mcp, monkeypatch
):
    monkeypatch.setattr(settings, "GRAVITINO_MCP_AUDIENCE", "gravitino")
    register_gravitino_mcp(db_session)
    user_token = _issue_token(provider.url, GATEWAY_CLIENT_ID)

    resp = _call(gateway, user_token, "tools/list")

    assert resp.status_code == 200
    assert resp.json()["result"]["tools"] == [{"name": "list_of_catalogs"}]
    [exchange] = provider.calls
    assert exchange["subject_token"] == user_token
    assert exchange["audience"] == "gravitino"
    assert exchange["client_id"] == GATEWAY_CLIENT_ID
    upstream_tokens = {auth.removeprefix("Bearer ") for _, auth in gravitino_mcp.calls}
    [upstream_token] = upstream_tokens
    claims = jwt.decode(upstream_token, options={"verify_signature": False})
    assert claims["aud"] == "gravitino"
    assert claims["email"] == "alice@example.com"


def test_a_gravitino_write_tool_is_refused_before_it_reaches_gravitino(
    gateway, db_session, provider, gravitino_mcp
):
    register_gravitino_mcp(db_session)
    user_token = _issue_token(provider.url, GATEWAY_CLIENT_ID)

    resp = _call(gateway, user_token, "tools/call", {"name": "drop_catalog"})

    assert resp.json()["error"]["message"] == (
        "Tool 'drop_catalog' is not available on gravitino."
    )
    assert "tools/call" not in [method for method, _ in gravitino_mcp.calls]


def test_a_token_for_another_audience_reaches_nothing(
    gateway, db_session, provider, gravitino_mcp
):
    register_gravitino_mcp(db_session)
    token = _issue_token(provider.url, "some-other-api")

    resp = _call(gateway, token, "tools/list")

    assert "error" in resp.json()
    assert not gravitino_mcp.calls


@pytest.mark.parametrize(
    "method, params, result",
    [
        ("tools/list", None, {"tools": [{"name": "list_of_catalogs"}]}),
        (
            "tools/call",
            {"name": "list_of_catalogs", "arguments": {}},
            {"content": [{"type": "text", "text": "[]"}]},
        ),
    ],
)
def test_a_call_survives_a_restart_of_gravitinos_mcp_server(
    gateway, db_session, provider, gravitino_mcp, method, params, result
):
    register_gravitino_mcp(db_session)
    user_token = _issue_token(provider.url, GATEWAY_CLIENT_ID)
    assert "result" in _call(gateway, user_token, "tools/list").json()
    # Gravitino's MCP server restarted, so it knows no sessions.
    gravitino_mcp.sessions.clear()

    resp = _call(gateway, user_token, method, params)

    assert _answer(resp)["result"] == result
    assert [called for called, _ in gravitino_mcp.calls].count("initialize") == 2
