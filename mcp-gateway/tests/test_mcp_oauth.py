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

"""Connecting a person to an MCP server, and disconnecting them.

Servers with single sign-on get the person's token from the gateway's identity
provider; servers with their own sign-in, from theirs. Someone can start
connecting, then send another person the link the provider redirects to, so a
callback stores a token only for the person who started, in their own browser.
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from sqlalchemy.orm import sessionmaker

from mcp_gateway.config import settings
from mcp_gateway.models import MCPCatalog, OAuthState, OAuthToken
from mcp_gateway.oauth.mcp_oauth_discovery import OAuthServerMetadata
from mcp_gateway.oauth.token_encryption import TokenEncryption
from mcp_gateway.routes import mcp_oauth
from mcp_gateway.routes.mcp_oauth import _resolve_client_id
from mcp_gateway.sessions import SESSION_TYPE, session_cookie_name

REDIRECT_URI = "https://mcp-gateway.example.com/callback"


@pytest.fixture(autouse=True, name="_encryption")
def fixture_encryption(monkeypatch):
    monkeypatch.setattr(
        "mcp_gateway.oauth.token_manager.get_token_encryption",
        AsyncMock(return_value=TokenEncryption(b"k" * 32)),
    )


def _sign_in(client, user_id):
    token = jwt.encode(
        {"user_id": user_id, "type": SESSION_TYPE},
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    client.cookies.set(session_cookie_name(), token)


def _catalog(db, **extra):
    """A server with its own sign-in, unless ``extra`` says otherwise."""
    row = MCPCatalog(
        **{
            "service_id": "docs",
            "name": "Docs",
            "mcp_url": "https://docs.example.com/mcp",
            "auth_type": "oauth",
            "auto_sso_enabled": False,
            "is_active": True,
            **extra,
        }
    )
    db.add(row)
    db.commit()
    return row


def _tokens(db, service):
    return db.query(OAuthToken).filter(OAuthToken.service == service).all()


@pytest.fixture(name="dcr_metadata")
def fixture_dcr_metadata() -> OAuthServerMetadata:
    return OAuthServerMetadata(
        authorization_endpoint="https://auth.example.com/authorize",
        token_endpoint="https://auth.example.com/token",
        registration_endpoint="https://auth.example.com/register",
    )


@pytest.fixture(name="discovered")
def fixture_discovered(monkeypatch, dcr_metadata):
    """The server's authorization server, found without network calls."""
    monkeypatch.setattr(
        "mcp_gateway.routes.mcp_oauth.resolve_oauth_metadata",
        AsyncMock(return_value=dcr_metadata),
    )


@pytest.fixture(name="register")
def fixture_register(monkeypatch):
    """Dynamic client registration (RFC 7591) at the authorization server."""
    register = AsyncMock(return_value="dcr-issued-cid")
    monkeypatch.setattr("mcp_gateway.routes.mcp_oauth.register_oauth_client", register)
    return register


# --- starting to connect ---------------------------------------------------------


def test_a_server_with_its_own_sign_in_is_connected_through_its_discovery(
    client, db_session, regular_user
):
    _catalog(db_session)
    _sign_in(client, regular_user.id)

    resp = client.get("/portal/connect/docs", follow_redirects=False)

    assert resp.status_code in (302, 307)
    assert resp.headers["location"].endswith("/portal/connect-mcp-oauth/docs")


def test_connecting_an_unknown_service_returns_404(client, regular_user):
    _sign_in(client, regular_user.id)

    resp = client.get("/portal/connect/nosuchservice", follow_redirects=False)

    assert resp.status_code == 404
    assert resp.json()["detail"] == "Service 'nosuchservice' not found"


@pytest.mark.parametrize(
    "path", ["/portal/connect/docs", "/portal/connect-mcp-oauth/docs"]
)
def test_a_person_who_is_not_an_admin_cannot_connect_to_an_admin_only_server(
    client, db_session, regular_user, path
):
    """Starting the sign-in would register a client and store a token."""
    _catalog(db_session, oauth_client_id="docs-client", admin_only=True)
    _sign_in(client, regular_user.id)

    resp = client.get(path, follow_redirects=False)

    assert resp.status_code == 404


@pytest.mark.parametrize(
    "provider, server, scope",
    [
        (
            "keycloak",
            {"audience": "gravitino", "oauth_scopes": "gravitino:read"},
            "openid profile email offline_access gravitino:read",
        ),
        # Entra issues a token for one app at a time, so the gateway asks for the server's.
        (
            "azure",
            {"audience": "gravitino-app-id"},
            "api://gravitino-app-id/.default offline_access",
        ),
    ],
)
def test_connecting_with_single_sign_on_asks_for_the_servers_scopes(
    client, db_session, regular_user, monkeypatch, provider, server, scope
):
    monkeypatch.setattr(settings, "OIDC_PROVIDER", provider)
    _catalog(db_session, service_id="gravitino", auto_sso_enabled=True, **server)
    _sign_in(client, regular_user.id)

    resp = client.get("/portal/connect/gravitino", follow_redirects=False)

    assert parse_qs(urlsplit(resp.headers["location"]).query)["scope"] == [scope]


def test_a_signed_out_browser_is_sent_to_sign_in_and_back(client, db_session):
    _catalog(db_session, oauth_client_id="docs-client")

    resp = client.get(
        "/portal/connect/docs",
        params={"return_to": "http://localhost:3000/mcp"},
        follow_redirects=False,
    )

    location = urlsplit(resp.headers["location"])
    assert resp.status_code == 302
    assert location.path == "/auth/oauth/login"
    assert parse_qs(location.query)["next"] == [
        "/portal/connect/docs?return_to=http%3A%2F%2Flocalhost%3A3000%2Fmcp"
    ]


@pytest.mark.parametrize(
    "return_to, kept",
    [
        ("http://localhost:3000/mcp", True),
        ("https://attacker.example/", False),
        ("//attacker.example/", False),
        ("javascript:x", False),
    ],
)
def test_connecting_returns_only_to_an_allowed_origin(
    client, db_session, regular_user, discovered, monkeypatch, return_to, kept
):
    monkeypatch.setattr(settings, "CORS_ALLOWED_ORIGINS", "http://localhost:3000")
    _catalog(db_session, oauth_client_id="docs-client")
    _sign_in(client, regular_user.id)

    resp = client.get(
        "/portal/connect/docs", params={"return_to": return_to}, follow_redirects=True
    )

    state = jwt.decode(
        resp.history[-1].cookies[mcp_oauth.state_cookie()],
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )
    assert json.loads(state["sub"])["return_to"] == (return_to if kept else None)


def test_each_server_has_its_own_redirect_uri(
    client, db_session, regular_user, discovered, register
):
    """So that its authorization server accepts no other server's address."""
    _catalog(db_session)
    _sign_in(client, regular_user.id)

    resp = client.get("/portal/connect-mcp-oauth/docs", follow_redirects=False)

    expected = f"{settings.GATEWAY_BASE_URL}/portal/callback/mcp-oauth/docs"
    query = parse_qs(urlsplit(resp.headers["location"]).query)
    assert query["redirect_uri"] == [expected]
    assert register.await_args.args[1] == expected


def test_a_failed_client_registration_does_not_show_the_servers_urls(
    client, db_session, admin_user, monkeypatch
):
    """Registration errors name the sign-in service's URLs, which are for admins."""
    _catalog(db_session, mcp_url="https://docs.internal.example/mcp")
    _sign_in(client, admin_user.id)
    metadata = MagicMock(registration_endpoint="https://auth.internal.example/reg")
    failure = RuntimeError(
        "Client error '400' for url 'https://auth.internal.example/reg'"
    )
    monkeypatch.setattr(
        mcp_oauth, "resolve_oauth_metadata", AsyncMock(return_value=metadata)
    )
    monkeypatch.setattr(
        mcp_oauth, "register_oauth_client", AsyncMock(side_effect=failure)
    )

    resp = client.get("/portal/connect-mcp-oauth/docs", follow_redirects=False)

    assert resp.status_code == 502
    assert "internal.example" not in resp.text


# --- the server's client id -----------------------------------------------------------


async def test_a_configured_client_id_is_used_as_is(db_session, dcr_metadata, register):
    mcp = _catalog(db_session, oauth_client_id="preconfigured-cid")

    client_id = await _resolve_client_id(mcp, dcr_metadata, REDIRECT_URI, db_session)

    assert client_id == "preconfigured-cid"
    register.assert_not_awaited()


async def test_a_client_is_registered_once_and_kept(db_session, dcr_metadata, register):
    mcp = _catalog(db_session)

    client_id = await _resolve_client_id(mcp, dcr_metadata, REDIRECT_URI, db_session)

    assert client_id == "dcr-issued-cid"
    register.assert_awaited_once_with(dcr_metadata.registration_endpoint, REDIRECT_URI)
    db_session.refresh(mcp)
    assert mcp.oauth_client_id == "dcr-issued-cid"


async def test_a_client_another_connect_just_registered_is_reused(
    db_engine, db_session, dcr_metadata, register
):
    """Two people connecting at once must not register two clients."""
    mcp = _catalog(db_session)
    with sessionmaker(bind=db_engine)() as other_connect:
        other_connect.query(MCPCatalog).filter(MCPCatalog.id == mcp.id).update(
            {"oauth_client_id": "registered-first"}
        )
        other_connect.commit()

    client_id = await _resolve_client_id(mcp, dcr_metadata, REDIRECT_URI, db_session)

    assert client_id == "registered-first"
    register.assert_not_awaited()


async def test_a_registered_client_id_that_is_the_gateways_is_refused(
    db_session, dcr_metadata, register
):
    """The gateway's own tokens go to servers whose client ID is the gateway's."""
    mcp = _catalog(db_session)
    register.return_value = settings.GATEWAY_OAUTH_CLIENT_ID

    with pytest.raises(ValueError, match="gateway's client ID"):
        await _resolve_client_id(mcp, dcr_metadata, REDIRECT_URI, db_session)

    db_session.refresh(mcp)
    assert mcp.oauth_client_id is None


async def test_without_a_client_id_a_server_must_support_registration(db_session):
    mcp = _catalog(db_session)
    metadata = OAuthServerMetadata(
        authorization_endpoint="https://auth.example.com/authorize",
        token_endpoint="https://auth.example.com/token",
    )

    with pytest.raises(ValueError, match="does not support DCR"):
        await _resolve_client_id(mcp, metadata, REDIRECT_URI, db_session)


# --- finishing connecting with single sign-on -------------------------------------


@pytest.fixture(name="connect_state")
def fixture_connect_state(db_session, admin_user):
    """A connect flow started by admin_user, as /portal/connect/{service} stores it."""
    db_session.add(
        OAuthState(
            state="connect-state",
            user_id=admin_user.id,
            service="trino",
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
    )
    db_session.commit()
    return "connect-state"


@pytest.fixture(name="provider_tokens")
def fixture_provider_tokens():
    oidc = MagicMock()
    oidc.exchange_code_for_token.return_value = {
        "access_token": "provider-access",
        "refresh_token": "provider-refresh",
        "expires_in": 3600,
    }
    with patch("mcp_gateway.routes.connect.OIDCClient", return_value=oidc):
        yield oidc


def _finish_connecting(client, state, path="/auth/oauth/callback"):
    return client.get(
        path, params={"code": "auth-code", "state": state}, follow_redirects=False
    )


def test_the_token_is_stored_for_the_person_who_connected(
    client, db_session, admin_user, connect_state, provider_tokens
):
    _sign_in(client, admin_user.id)

    resp = _finish_connecting(client, connect_state)

    assert resp.status_code == 200
    assert [t.user_id for t in _tokens(db_session, "trino")] == [admin_user.id]
    # The code is redeemed with the PKCE verifier of this flow's state.
    assert provider_tokens.exchange_code_for_token.call_args.kwargs["state"] == (
        connect_state
    )


@pytest.mark.parametrize("signed_in", [True, False], ids=["another person", "no one"])
def test_a_callback_in_a_browser_not_signed_in_as_the_connector_stores_nothing(
    client, db_session, regular_user, connect_state, provider_tokens, signed_in
):
    if signed_in:
        _sign_in(client, regular_user.id)

    resp = _finish_connecting(client, connect_state)

    assert resp.status_code == 403
    assert _tokens(db_session, "trino") == []
    assert provider_tokens.exchange_code_for_token.call_count == 0


@pytest.mark.parametrize(
    "error, shown",
    [("access_denied", "(access_denied)"), ("Call 555-0100 to fix", "(no code)")],
)
def test_a_refused_sign_in_shows_only_an_error_code(
    client, db_session, admin_user, connect_state, provider_tokens, error, shown
):
    """Anyone can put text in a link, so text that isn't an error code isn't shown."""
    _sign_in(client, admin_user.id)

    resp = client.get(
        "/auth/oauth/callback", params={"error": error, "state": connect_state}
    )

    assert resp.status_code == 400
    assert shown in resp.text
    assert "555-0100" not in resp.text
    assert _tokens(db_session, "trino") == []
    assert db_session.query(OAuthState).count() == 0


# --- finishing connecting to a server with its own sign-in --------------------------

MCP_CALLBACK = "/portal/callback/mcp-oauth/docs"


@pytest.fixture(name="mcp_oauth_state")
def fixture_mcp_oauth_state(client, db_session, admin_user):
    """A connect flow started by admin_user, as /portal/connect-mcp-oauth sets it."""
    _catalog(db_session)
    payload = {
        "state": "mcp-state",
        "service": "docs",
        "user_id": admin_user.id,
        "code_verifier": "verifier",
        "redirect_uri": "https://gateway.example.com/portal/callback/mcp-oauth/docs",
        "client_id": "docs-client",
        "token_endpoint": "https://auth.docs.example.com/token",
        "issuer": "https://auth.docs.example.com",
        "uses_client_secret": False,
    }
    client.cookies.set(
        mcp_oauth.state_cookie(),
        jwt.encode(
            {
                "sub": json.dumps(payload),
                "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
            },
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        ),
    )
    return "mcp-state"


@pytest.fixture(name="upstream_token_endpoint")
def fixture_upstream_token_endpoint():
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"access_token": "docs-access", "expires_in": 3600}
    http_client = MagicMock()
    http_client.post = AsyncMock(return_value=resp)
    acm = MagicMock()
    acm.__aenter__ = AsyncMock(return_value=http_client)
    acm.__aexit__ = AsyncMock(return_value=False)
    with patch("mcp_gateway.routes.mcp_oauth.httpx.AsyncClient", return_value=acm):
        yield http_client


def test_the_server_token_is_stored_for_the_person_who_connected(
    client, db_session, admin_user, mcp_oauth_state, upstream_token_endpoint
):
    _sign_in(client, admin_user.id)

    resp = _finish_connecting(client, mcp_oauth_state, MCP_CALLBACK)

    assert resp.status_code == 200
    assert "Connected to docs" in resp.text
    assert [t.user_id for t in _tokens(db_session, "docs")] == [admin_user.id]


@pytest.mark.parametrize(
    "path, params",
    [
        ("/portal/callback/mcp-oauth/evil", {}),
        (MCP_CALLBACK, {"iss": "https://evil.example.com"}),
    ],
    ids=["another server's address", "another issuer"],
)
def test_a_code_for_another_servers_flow_is_never_redeemed(
    client,
    db_session,
    admin_user,
    mcp_oauth_state,
    upstream_token_endpoint,
    path,
    params,
):
    """A mix-up attack (RFC 9700 4.4): a server that started the flow bounces the
    browser to another server's sign-in, to have that server's code sent to its
    own token endpoint."""
    _sign_in(client, admin_user.id)

    resp = client.get(
        path,
        params={"code": "auth-code", "state": mcp_oauth_state, **params},
        follow_redirects=False,
    )

    assert resp.status_code == 400
    assert upstream_token_endpoint.post.await_count == 0
    assert _tokens(db_session, "docs") == []


def test_the_issuer_the_server_names_is_accepted(
    client, db_session, admin_user, mcp_oauth_state, upstream_token_endpoint
):
    _sign_in(client, admin_user.id)

    resp = client.get(
        MCP_CALLBACK,
        params={
            "code": "auth-code",
            "state": mcp_oauth_state,
            "iss": "https://auth.docs.example.com",
        },
    )

    assert "Connected to docs" in resp.text


@pytest.mark.parametrize("signed_in", [True, False], ids=["another person", "no one"])
def test_a_server_callback_not_signed_in_as_the_connector_stores_nothing(
    client,
    db_session,
    regular_user,
    mcp_oauth_state,
    upstream_token_endpoint,
    signed_in,
):
    if signed_in:
        _sign_in(client, regular_user.id)

    resp = _finish_connecting(client, mcp_oauth_state, MCP_CALLBACK)

    assert resp.status_code == 403
    assert _tokens(db_session, "docs") == []
    assert upstream_token_endpoint.post.await_count == 0


@pytest.mark.parametrize(
    "answer",
    [
        httpx.ReadTimeout("internal-service-banner timed out"),
        MagicMock(status_code=400, text="internal-service-banner secret-ish"),
    ],
    ids=["a timeout", "an error"],
)
def test_a_failed_token_exchange_does_not_show_the_endpoints_reply(
    client, db_session, admin_user, mcp_oauth_state, upstream_token_endpoint, answer
):
    """The endpoint comes from the server's metadata and could be any address."""
    _sign_in(client, admin_user.id)
    upstream_token_endpoint.post.side_effect = [answer]

    resp = _finish_connecting(client, mcp_oauth_state, MCP_CALLBACK)

    assert resp.status_code == 502
    assert "internal-service-banner" not in resp.text
    assert _tokens(db_session, "docs") == []


# --- disconnecting ----------------------------------------------------------------


@pytest.mark.parametrize(
    "service, left", [("slack", []), ("missing", ["slack"])], ids=["connected", "not"]
)
def test_disconnecting_deletes_only_the_callers_token_for_that_service(
    client, db_session, regular_user, as_user, service, left
):
    db_session.add(
        OAuthToken(
            user_id=regular_user.id,
            service="slack",
            access_token_encrypted="enc::token",
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
    )
    db_session.commit()
    as_user(regular_user)

    resp = client.post(f"/portal/disconnect/{service}")

    assert resp.json() == {"message": f"Disconnected {service} successfully"}
    assert [t.service for t in db_session.query(OAuthToken).all()] == left
