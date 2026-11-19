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

"""The gateway against a real Keycloak, Gravitino and Gravitino MCP server.

Start them with ``docker compose -f dev/keycloak/docker-compose.yaml up -d``, then
run ``MCP_GATEWAY_KEYCLOAK_TEST=1 pytest -m integration tests/integration``. The
realm, its clients and its users come from dev/keycloak/setup-realm.sh.
"""

import base64
import hashlib
import html
import json
import os
import re
import secrets
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest

from mcp_gateway import gravitino_admins
from mcp_gateway.catalog_defaults import register_gravitino_mcp
from mcp_gateway.config import settings
from mcp_gateway.oauth import token_encryption
from mcp_gateway.routes import mcp_server, mcp_upstream
from mcp_gateway.sessions import cookie_name, session_cookie_name

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("MCP_GATEWAY_KEYCLOAK_TEST") != "1",
        reason="Set MCP_GATEWAY_KEYCLOAK_TEST=1 and start dev/keycloak/docker-compose.yaml",
    ),
]

KEYCLOAK = "http://localhost:8080/realms/gravitino"
GRAVITINO = "http://localhost:8090/api"
GRAVITINO_HEADERS = {"Accept": "application/vnd.gravitino.v1+json"}
# The gateway runs in this process; Keycloak only knows its registered URL.
GATEWAY_URL = "http://localhost:8000"
CLIENT_REDIRECT = "http://localhost:33418/callback"
LIST_CATALOGS = {"name": "get_list_of_catalogs", "arguments": {}}


def _token(user: str, scope: str) -> str:
    """A user's access token for the stand-in MCP client, by the password grant."""
    resp = httpx.post(
        f"{KEYCLOAK}/protocol/openid-connect/token",
        data={
            "client_id": "mcp-client",
            "grant_type": "password",
            "username": user,
            "password": user,
            "scope": f"openid {scope}",
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _sign_in(authorize_url: str, user: str) -> str:
    """Sign in on Keycloak's login page; return where Keycloak redirects next."""
    browser = httpx.Client()
    page = browser.get(authorize_url)
    # Browsers send Secure cookies to http://localhost; Python's cookie jar does not.
    for cookie in browser.cookies.jar:
        cookie.secure = False
    action = re.search(r'id="kc-form-login"[^>]*action="([^"]+)"', page.text)
    resp = browser.post(
        html.unescape(action.group(1)),
        data={"username": user, "password": user, "credentialId": ""},
    )
    assert resp.status_code == 302, resp.text
    return resp.headers["location"]


def _local(url: str) -> str:
    """The path and query of a gateway URL, for the in-process test client."""
    parts = urlsplit(url)
    return f"{parts.path}?{parts.query}"


def _call(gateway, token: str, method: str, params: dict = None) -> dict:
    message = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        message["params"] = params
    resp = gateway.post(
        "/mcp/gravitino",
        json=message,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
        },
    )
    if resp.headers["content-type"].startswith("text/event-stream"):
        [data] = [
            line[6:] for line in resp.text.splitlines() if line.startswith("data: ")
        ]
        return json.loads(data)
    return resp.json()


@pytest.fixture(name="gravitino_metadata", scope="module", autouse=True)
def fixture_gravitino_metadata():
    """Alice, Gravitino's service admin, creates metalake "demo"; bob is not a member."""
    headers = {
        **GRAVITINO_HEADERS,
        "Authorization": f"Bearer {_token('alice', 'gravitino')}",
    }
    for path, body in [
        ("/metalakes", {"name": "demo"}),
        ("/metalakes/demo/catalogs", {"name": "models", "type": "MODEL"}),
    ]:
        resp = httpx.post(
            f"{GRAVITINO}{path}",
            json={**body, "comment": "", "properties": {}},
            headers=headers,
        )
        assert resp.status_code in (200, 409), resp.text


def _gateway(client, db_session, monkeypatch, **configuration):
    configuration = {
        "OIDC_PROVIDER": "keycloak",
        "OIDC_DISCOVERY_URL": f"{KEYCLOAK}/.well-known/openid-configuration",
        "OIDC_ISSUER": None,
        "OIDC_JWKS_URI": None,
        "OIDC_AUTHORIZATION_ENDPOINT": None,
        "OIDC_TOKEN_ENDPOINT": None,
        "GATEWAY_OAUTH_CLIENT_ID": "mcp-gateway",
        "GATEWAY_OAUTH_CLIENT_SECRET": "mcp-gateway-secret",
        "GATEWAY_OAUTH_ACCEPT_ANY_CLIENT": True,
        "GATEWAY_BASE_URL": GATEWAY_URL,
        "GRAVITINO_MCP_URL": "http://localhost:8100/mcp",
        "TOKEN_ENCRYPTION_KEY": base64.b64encode(os.urandom(32)).decode(),
        **configuration,
    }
    for name, value in configuration.items():
        monkeypatch.setattr(settings, name, value)
    # Process-wide state that must not leak in from other tests.
    monkeypatch.setattr(token_encryption, "_token_encryption", None)
    monkeypatch.setattr(mcp_server, "_mcp_http_client", None)
    monkeypatch.setattr(mcp_upstream, "_upstream_sessions", {})
    register_gravitino_mcp(db_session)
    return client


@pytest.fixture(name="forwarding_gateway")
def fixture_forwarding_gateway(client, db_session, monkeypatch):
    """The gateway accepts Gravitino's audience, so it forwards users' tokens."""
    return _gateway(
        client,
        db_session,
        monkeypatch,
        JWT_AUDIENCE="gravitino",
        GATEWAY_API_SCOPES="gravitino",
    )


@pytest.fixture(name="exchanging_gateway")
def fixture_exchanging_gateway(client, db_session, monkeypatch):
    """The gateway has an audience of its own and exchanges tokens for Gravitino's."""
    return _gateway(
        client,
        db_session,
        monkeypatch,
        JWT_AUDIENCE="mcp-gateway",
        GATEWAY_API_SCOPES="mcp-gateway",
        GRAVITINO_MCP_AUDIENCE="gravitino",
    )


def test_a_user_reaches_gravitino_with_their_own_token(forwarding_gateway):
    result = _call(
        forwarding_gateway, _token("alice", "gravitino"), "tools/call", LIST_CATALOGS
    )["result"]

    assert not result["isError"]
    assert json.loads(result["content"][0]["text"])[0]["name"] == "models"


def test_gravitino_decides_what_each_user_may_see(forwarding_gateway):
    result = _call(
        forwarding_gateway, _token("bob", "gravitino"), "tools/call", LIST_CATALOGS
    )["result"]

    assert result["isError"]
    assert "bob is not a member of metalake demo" in result["content"][0]["text"]


def test_a_token_for_the_gateway_is_exchanged_for_gravitino(exchanging_gateway):
    token = _token("alice", "mcp-gateway")
    direct = httpx.get(
        f"{GRAVITINO}/metalakes/demo/catalogs",
        headers={**GRAVITINO_HEADERS, "Authorization": f"Bearer {token}"},
    )

    result = _call(exchanging_gateway, token, "tools/call", LIST_CATALOGS)["result"]

    assert direct.status_code == 401
    assert not result["isError"]


def test_an_mcp_client_that_registers_itself_reaches_gravitino(forwarding_gateway):
    resource = forwarding_gateway.get("/.well-known/oauth-protected-resource").json()
    [issuer] = resource["authorization_servers"]
    provider = httpx.get(f"{issuer}/.well-known/openid-configuration").json()
    registered = httpx.post(
        provider["registration_endpoint"],
        json={
            "client_name": "Integration test",
            "redirect_uris": [CLIENT_REDIRECT],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": " ".join(resource["scopes_supported"]),
        },
    ).json()
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    query = {
        "client_id": registered["client_id"],
        "response_type": "code",
        "redirect_uri": CLIENT_REDIRECT,
        "scope": " ".join(resource["scopes_supported"]),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    redirect = _sign_in(
        f"{provider['authorization_endpoint']}?{urlencode(query)}", "alice"
    )
    tokens = httpx.post(
        provider["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "client_id": registered["client_id"],
            "code": parse_qs(urlsplit(redirect).query)["code"][0],
            "redirect_uri": CLIENT_REDIRECT,
            "code_verifier": verifier,
        },
    ).json()

    result = _call(
        forwarding_gateway, tokens["access_token"], "tools/call", LIST_CATALOGS
    )["result"]

    assert not result["isError"]


def test_a_person_signs_in_in_the_browser_and_then_on_the_cli(forwarding_gateway):
    login = forwarding_gateway.get("/auth/oauth/login", follow_redirects=False)
    # The test client keeps Secure cookies to itself on http, so pass the one
    # that ties the sign-in to this browser by hand.
    nonce_cookie = cookie_name("login_nonce", True)
    browser = login.cookies[nonce_cookie]
    callback = forwarding_gateway.get(
        _local(_sign_in(login.headers["location"], "alice")),
        headers={"Cookie": f"{nonce_cookie}={browser}"},
        follow_redirects=False,
    )
    session = {
        "Cookie": f"{session_cookie_name()}={callback.cookies[session_cookie_name()]}"
    }
    code = forwarding_gateway.post(
        "/api/device/code", json={"client_id": "gravitino-mcp-cli"}
    ).json()
    # The person types the code their CLI shows.
    page = forwarding_gateway.post(
        "/device", data={"user_code": code["user_code"]}, headers=session
    )
    forwarding_gateway.post(
        "/device/approve",
        data={
            "user_code": code["user_code"],
            "approval_csrf": re.search(
                r'name="approval_csrf" value="([^"]+)"', page.text
            ).group(1),
            "action": "approve",
        },
        headers=session,
    )
    tokens = forwarding_gateway.post(
        "/api/device/token",
        json={"device_code": code["device_code"], "client_id": "gravitino-mcp-cli"},
    ).json()

    result = _call(
        forwarding_gateway, tokens["access_token"], "tools/call", LIST_CATALOGS
    )["result"]
    refreshed = forwarding_gateway.post(
        "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )

    assert callback.status_code == 302
    assert not result["isError"]
    assert refreshed.status_code == 200


@pytest.mark.parametrize("gateway_name", ["forwarding_gateway", "exchanging_gateway"])
def test_gravitinos_service_admins_are_the_gateways_admins(
    request, monkeypatch, gateway_name
):
    """Alice is Gravitino's service admin and bob is not; ADMIN_EMAILS is empty."""
    gateway = request.getfixturevalue(gateway_name)
    monkeypatch.setattr(settings, "GRAVITINO_URI", "http://localhost:8090")
    monkeypatch.setattr(settings, "ADMIN_EMAILS", "")
    gravitino_admins.reset_cache()
    scope = "gravitino" if gateway_name == "forwarding_gateway" else "mcp-gateway"

    def is_admin(user):
        headers = {"Authorization": f"Bearer {_token(user, scope)}"}
        return gateway.get("/api/users/me", headers=headers).json()["is_admin"]

    assert is_admin("alice") is True
    assert is_admin("bob") is False
