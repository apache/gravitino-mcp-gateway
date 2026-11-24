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

"""Tests for mcp_gateway/main.py: the MCP error envelope, the OAuth discovery
documents (RFC 9728, RFC 8414), the JWKS, and the application shell.

A mistake in any of these is silent: the app starts, and clients simply
cannot authenticate.
"""

import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from mcp_gateway.body_limit import BodySizeLimitMiddleware
from mcp_gateway.catalog_file import CatalogFileError
from mcp_gateway.config import settings
from mcp_gateway.gateway_keys import get_kid, get_private_key
from mcp_gateway.main import app, cors_options, lifespan

PROTECTED_RESOURCE = "/.well-known/oauth-protected-resource"
AUTH_SERVER = "/.well-known/oauth-authorization-server"
JWKS = "/.well-known/jwks.json"
GATEWAY = settings.GATEWAY_BASE_URL.rstrip("/")
# The challenge is parsed by the client, so it is pinned whole.
CHALLENGE = (
    f'Bearer realm="MCP Gateway", resource_metadata="{GATEWAY}{PROTECTED_RESOURCE}"'
)
_LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


# ------------------------------------------------------- MCP error envelope


def test_a_legacy_json_rpc_client_gets_its_error_inside_a_200_envelope(client):
    """VS Code and Claude Desktop pop an unwanted OAuth window on a real 401."""
    resp = client.post("/mcp/trino", json=_LIST_TOOLS)

    assert resp.status_code == 200
    body = resp.json()
    assert (body["jsonrpc"], body["error"]["code"]) == ("2.0", -32000)
    assert "Authorization" in body["error"]["message"]
    assert "www-authenticate" not in resp.headers


@pytest.mark.parametrize(
    "method,headers",
    [("POST", {"Accept": "application/json, text/event-stream"}), ("GET", {})],
    ids=["streamable-post", "get"],
)
def test_a_client_that_follows_discovery_gets_a_real_401_and_its_challenge(
    client, method, headers
):
    """The POST and GET branches build the challenge separately and can drift apart."""
    body = _LIST_TOOLS if method == "POST" else None

    resp = client.request(method, "/mcp/trino", headers=headers, json=body)

    assert resp.status_code == 401
    assert resp.json()["detail"]
    assert resp.headers["www-authenticate"] == CHALLENGE
    # Advertising the document is worthless if it 404s.
    assert client.get(PROTECTED_RESOURCE).status_code == 200


def test_a_non_401_mcp_error_carries_no_authentication_challenge(client):
    """A challenge on a 404 would send a client round a discovery loop forever."""
    resp = client.get("/mcp/nosuchservice/health")

    assert resp.status_code == 404
    assert "www-authenticate" not in resp.headers


def test_the_rest_api_never_gets_a_json_rpc_envelope(client):
    """A real route: an unmatched path never reaches the handler at all."""
    resp = client.get("/api/v1/users/me")

    assert resp.status_code == 401
    assert resp.json() == {"detail": "Authorization header required"}


# --------------------------------------------- RFC 9728 protected resource


def test_the_protected_resource_is_the_gateway_signed_in_at_the_provider(
    client, oidc_provider
):
    body = client.get(PROTECTED_RESOURCE).json()

    assert (body["resource"], body["resource_name"]) == (
        GATEWAY,
        "Gravitino MCP Gateway",
    )
    assert body["authorization_servers"] == [oidc_provider["issuer"]]
    assert body["resource_documentation"] == f"{GATEWAY}/docs"
    assert body["bearer_methods_supported"] == ["header"]


@pytest.mark.parametrize(
    "provider,client_id,configured,resource,scopes",
    [
        ("generic", "app", None, GATEWAY, []),
        ("generic", "app", "openid gravitino", GATEWAY, ["openid", "gravitino"]),
        ("generic", "app", "  a   b  ", GATEWAY, ["a", "b"]),
        # Entra rejects a URL as the resource (AADSTS90009), and gets full API
        # URIs as scopes, so clients need no configuration.
        ("azure", "app", None, "app", ["api://app/user_access"]),
        (
            "azure",
            "app",
            "user_access admin",
            "app",
            ["api://app/user_access", "api://app/admin"],
        ),
        ("azure", None, "user_access", GATEWAY, ["user_access"]),
    ],
)
def test_the_discovery_documents_name_the_resource_and_scopes_for_the_provider(
    client, monkeypatch, provider, client_id, configured, resource, scopes
):
    """A token minted from one document must be accepted by the other's resource."""
    monkeypatch.setattr(settings, "OIDC_PROVIDER", provider)
    monkeypatch.setattr(settings, "GATEWAY_OAUTH_CLIENT_ID", client_id)
    monkeypatch.setattr(settings, "GATEWAY_API_SCOPES", configured)

    protected = client.get(PROTECTED_RESOURCE).json()

    assert (protected["resource"], protected["scopes_supported"]) == (resource, scopes)
    assert client.get(AUTH_SERVER).json()["scopes_supported"] == scopes


# ----------------------------------------- RFC 8414 authorization server


def test_every_endpoint_comes_from_the_provider(client, oidc_provider):
    """A mismatch fails at the last step of the flow, long after the client committed."""
    body = client.get(AUTH_SERVER).json()

    for key in (
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "device_authorization_endpoint",
        "registration_endpoint",
        "jwks_uri",
    ):
        assert body[key] == oidc_provider[key], key
    # The CLI needs the device code grant; public clients need PKCE.
    assert set(body["grant_types_supported"]) == {
        "authorization_code",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code",
    }
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert body["response_types_supported"] == ["code"]
    assert "none" in body["token_endpoint_auth_methods_supported"]


def test_endpoints_the_provider_lacks_are_left_out(client, oidc_provider):
    del oidc_provider["registration_endpoint"]
    del oidc_provider["device_authorization_endpoint"]

    body = client.get(AUTH_SERVER).json()

    assert "registration_endpoint" not in body
    assert "device_authorization_endpoint" not in body
    assert "urn:ietf:params:oauth:grant-type:device_code" not in str(body)


# ------------------------------------------------------------------- JWKS


def test_the_jwks_publishes_no_private_key_material_and_may_be_cached(client):
    resp = client.get(JWKS)

    key = resp.json()["keys"][0]
    for private_field in ("d", "p", "q", "dp", "dq", "qi", "oth"):
        assert private_field not in key, private_field
    assert (key["kty"], key["use"], key["alg"]) == ("RSA", "sig", "RS256")
    # The route keeps its own cache policy over the no-store default.
    assert resp.headers["cache-control"] == "public, max-age=3600"


def test_a_real_gateway_token_verifies_against_the_published_key(client):
    """Not just some other well-formed RSA key that would fail downstream."""
    key = client.get(JWKS).json()["keys"][0]
    token = jwt.encode(
        {"sub": "someone", "aud": "downstream"},
        get_private_key(),
        algorithm="RS256",
        headers={"kid": get_kid()},
    )

    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
    claims = jwt.decode(token, public_key, algorithms=["RS256"], audience="downstream")

    assert claims["sub"] == "someone"
    assert key["kid"] == get_kid()


# ------------------------------------------------------ shell and middleware


def test_the_root_sends_a_browser_to_the_gateways_page(client):
    resp = client.get("/", follow_redirects=False)

    assert resp.status_code == 302
    assert resp.headers["location"] == "/portal"


def test_health_reveals_nothing_and_is_neither_cached_nor_framed(client):
    resp = client.get("/health")

    assert resp.json() == {"status": "healthy"}
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "no-referrer"


def test_health_fails_when_the_database_is_unreachable(client):
    with patch(
        "mcp_gateway.main.SessionLocal", side_effect=OperationalError("", {}, None)
    ):
        resp = client.get("/health")

    assert resp.status_code == 503


@pytest.mark.parametrize(
    "allowed,origin,expected",
    [
        ("*", "https://evil.example.net", "*"),
        (
            "https://ui.example.com, https://other.example.com",
            "https://ui.example.com",
            "https://ui.example.com",
        ),
        ("https://ui.example.com", "https://evil.example.net", None),
    ],
    ids=["any", "listed", "unlisted"],
)
def test_no_origin_may_call_the_api_with_the_session_cookie(allowed, origin, expected):
    """The API takes bearer tokens; otherwise any site could read it as the person."""
    probe = FastAPI()
    probe.add_middleware(CORSMiddleware, **cors_options(allowed))
    probe.get("/api/v1/users/me")(lambda: {})

    resp = TestClient(probe).options(
        "/api/v1/users/me",
        headers={"Origin": origin, "Access-Control-Request-Method": "GET"},
    )

    assert resp.headers.get("access-control-allow-origin") == expected
    assert "access-control-allow-credentials" not in resp.headers


# ---------------------------------------------------------------- lifespan


@pytest.fixture(name="slack")
def fixture_slack():
    with patch("mcp_gateway.slack.app.start_slack_bot", new_callable=AsyncMock) as m:
        yield m


def _never_ending() -> asyncio.Task:
    return asyncio.get_running_loop().create_task(asyncio.sleep(3600))


async def test_startup_registers_the_gravitino_mcp_server(monkeypatch):
    register = MagicMock()
    monkeypatch.setattr("mcp_gateway.main.register_gravitino_mcp", register)

    async with lifespan(app):
        pass

    register.assert_called_once()


async def test_startup_loads_the_catalog_file_after_the_defaults(monkeypatch):
    calls = MagicMock()
    monkeypatch.setattr(settings, "MCP_CATALOG_FILE", "/etc/catalog.json")
    monkeypatch.setattr("mcp_gateway.main.register_gravitino_mcp", calls.register)
    monkeypatch.setattr("mcp_gateway.main.load_catalog_file", calls.load)

    async with lifespan(app):
        pass

    assert [c[0] for c in calls.mock_calls] == ["register", "load"]
    assert calls.load.call_args.args[1] == "/etc/catalog.json"


async def test_a_bad_catalog_file_stops_the_start(monkeypatch, tmp_path):
    bad = tmp_path / "catalog.json"
    bad.write_text("not json")
    monkeypatch.setattr(settings, "MCP_CATALOG_FILE", str(bad))

    with pytest.raises(CatalogFileError):
        async with lifespan(app):
            pass


async def test_a_fully_configured_slack_bot_is_started_and_stopped(slack, monkeypatch):
    monkeypatch.setattr(settings, "SLACK_BOT_TOKEN", "xoxb-1")
    monkeypatch.setattr(settings, "SLACK_APP_TOKEN", "xapp-1")
    bot = _never_ending()
    slack.return_value = bot

    async with lifespan(app):
        assert not bot.done()

    slack.assert_awaited_once()
    assert bot.cancelled()


@pytest.mark.parametrize(
    "bot,app_token,warning",
    [
        ("xoxb-1", None, "have_bot=True have_app=False"),
        (None, "xapp-1", "have_bot=False have_app=True"),
        (None, None, None),
    ],
)
async def test_a_partial_slack_configuration_starts_nothing_and_says_why(
    slack, monkeypatch, caplog, bot, app_token, warning
):
    """Socket Mode needs both tokens; with neither there is nothing to warn about."""
    monkeypatch.setattr(settings, "SLACK_BOT_TOKEN", bot)
    monkeypatch.setattr(settings, "SLACK_APP_TOKEN", app_token)

    with caplog.at_level(logging.WARNING, logger="mcp_gateway.main"):
        async with lifespan(app):
            pass

    slack.assert_not_awaited()
    if warning:
        assert warning in caplog.text
    else:
        assert "Slack bot not started" not in caplog.text


async def test_the_purge_task_is_stopped_on_shutdown():
    """A leaked background task keeps a DB session alive after shutdown."""
    purge = _never_ending()
    with patch("mcp_gateway.main.start_purge_task", return_value=purge):
        async with lifespan(app):
            assert not purge.done()

    assert purge.cancelled()


@pytest.fixture(name="small_cap")
def fixture_small_cap():
    """The gateway, with a body cap a test can reach."""

    async def echo(scope, receive, send):
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": str(len(body)).encode()})

    return TestClient(BodySizeLimitMiddleware(echo, max_bytes=10))


def test_a_body_within_the_cap_is_read(small_cap):
    assert small_cap.post("/x", content=b"0123456789").text == "10"


@pytest.mark.parametrize(
    "body",
    [b"01234567890", iter([b"012345", b"67890"])],
    ids=["declared", "sent in chunks"],
)
def test_a_body_over_the_cap_is_refused_before_it_is_read_whole(small_cap, body):
    """Some routes read bodies before anyone signs in."""
    assert small_cap.post("/x", content=body).status_code == 413


def test_the_gateway_caps_request_bodies(client):
    huge = b"x" * (settings.MAX_REQUEST_BYTES + 1)

    assert client.post("/auth/refresh", content=huge).status_code == 413
