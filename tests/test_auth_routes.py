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

"""Signing in to the gateway and out, renewing the CLI's token, and the session.

These decide who a browser is, so what matters is that no forged, stale or
borrowed session counts; that a sign-in finishes only in the browser that
started it, for a person, with an ID token meant for this gateway; that no
redirect leaves the gateway; and that signing out destroys the stored tokens.
"""

from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
import requests

from mcp_gateway.config import settings
from mcp_gateway.models import User
from mcp_gateway.oauth.oidc_client import pkce_challenge
from mcp_gateway.sessions import SESSION_TYPE, cookie_name, session_cookie_name

HOME_URL = "/portal"
LOGOUT_URL = "/portal/logout"
LOGIN_URL = "/auth/oauth/login"
CALLBACK_URL = "/auth/oauth/callback"
REFRESH_URL = "/auth/refresh"
BROWSER = "browser-nonce"
LOGIN_NONCE = cookie_name("login_nonce", True)
# The emails of conftest's regular_user and service_account.
REGULAR_EMAIL = "testuser@example.com"
SERVICE_ACCOUNT_EMAIL = "svc-test@example.com"


def _query(location: str) -> dict:
    return {
        key: values[0] for key, values in parse_qs(urlsplit(location).query).items()
    }


def _cookies(resp, *, cleared):
    """The names of the cookies a response sets, or tells the browser to drop."""
    return {
        header.split("=")[0]
        for header in resp.headers.get_list("set-cookie")
        if ("Max-Age=0" in header) == cleared
    }


def _sent_to_sign_in(resp):
    return resp.status_code == 302 and resp.headers["location"].startswith(
        "/auth/oauth/login?"
    )


@pytest.fixture(name="sign_in")
def fixture_sign_in(client):
    """Authenticate the way a browser does, through a session cookie."""

    def _sign_in(user_id, secret=None, cookie=None, **claims):
        token = jwt.encode(
            {"user_id": user_id, "type": SESSION_TYPE, **claims},
            secret or settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )
        client.cookies.set(cookie or session_cookie_name(), token)

    return _sign_in


@pytest.fixture(name="token_manager")
def fixture_token_manager(monkeypatch):
    """Stand in for TokenManager, so no token is encrypted or stored."""
    manager = MagicMock()
    manager.delete_all_user_tokens = AsyncMock()
    manager.store_user_oauth_token = AsyncMock()
    monkeypatch.setattr("mcp_gateway.routes.auth.TokenManager", lambda db: manager)
    return manager


# --- the session ---------------------------------------------------------------


def test_the_home_page_names_the_signed_in_person(client, sign_in, regular_user):
    sign_in(regular_user.id)

    resp = client.get(HOME_URL)

    assert resp.status_code == 200
    assert regular_user.username in resp.text


@pytest.mark.parametrize(
    "session",
    [
        pytest.param(None, id="none"),
        pytest.param(
            {"secret": "not-the-gateway-secret-of-32-bytes"}, id="another key"
        ),
        pytest.param({"user_id": 4242}, id="a deleted user"),
        # Another subdomain or port can set a plain "session" cookie, not __Host-.
        pytest.param({"cookie": "session"}, id="no host prefix"),
        # The gateway signs other tokens, such as login states, with the same key.
        pytest.param({"type": "gateway_login"}, id="another kind of token"),
    ],
)
def test_a_browser_without_a_valid_session_is_sent_to_sign_in(
    client, sign_in, regular_user, session
):
    if session is not None:
        sign_in(**{"user_id": regular_user.id, **session})

    assert _sent_to_sign_in(client.get(HOME_URL, follow_redirects=False))


def test_a_session_for_a_deactivated_user_is_no_session(
    client, sign_in, db_session, regular_user
):
    regular_user.is_active = False
    db_session.commit()
    sign_in(regular_user.id)

    assert _sent_to_sign_in(client.get(HOME_URL, follow_redirects=False))


# --- signing out -----------------------------------------------------------------


def test_opening_the_logout_link_only_asks_to_confirm(
    client, sign_in, regular_user, token_manager
):
    """Any site can send a person to a link; only a POST, which SameSite=Lax
    cookies don't accompany from other sites, signs them out."""
    sign_in(regular_user.id)

    resp = client.get(LOGOUT_URL, follow_redirects=False)

    assert resp.status_code == 200
    assert '<form method="post" action="/portal/logout">' in resp.text
    token_manager.delete_all_user_tokens.assert_not_awaited()
    assert not _cookies(resp, cleared=True)


@pytest.mark.parametrize(
    "failure",
    [None, RuntimeError("vault down")],
    ids=["tokens deleted", "deletion fails"],
)
def test_logging_out_destroys_the_stored_tokens_and_the_session(
    client, sign_in, regular_user, token_manager, failure
):
    """Clearing the cookie is not enough, and a broken secret store must not keep
    anyone signed in."""
    token_manager.delete_all_user_tokens.side_effect = failure
    sign_in(regular_user.id)

    resp = client.post(LOGOUT_URL, follow_redirects=False)

    assert resp.status_code == 302
    token_manager.delete_all_user_tokens.assert_awaited_once_with(regular_user.id)
    assert session_cookie_name() in _cookies(resp, cleared=True)


def test_logout_ends_the_provider_session_and_returns_to_the_login_page(
    client, monkeypatch, oidc_provider
):
    """The provider's sign-out must hand the browser back to us, not drop it."""
    monkeypatch.setattr(settings, "GATEWAY_BASE_URL", "https://gw.example.com")

    resp = client.post(LOGOUT_URL, follow_redirects=False)

    location = resp.headers["location"]
    assert location.startswith(oidc_provider["end_session_endpoint"] + "?")
    assert _query(location) == {
        "client_id": settings.GATEWAY_OAUTH_CLIENT_ID,
        "post_logout_redirect_uri": "https://gw.example.com/auth/oauth/login",
    }


def test_logout_without_a_provider_logout_endpoint_returns_to_the_login_page(
    client, monkeypatch
):
    monkeypatch.setattr(settings, "GATEWAY_BASE_URL", "https://gw.example.com")

    resp = client.post(LOGOUT_URL, follow_redirects=False)

    assert resp.status_code == 302
    assert resp.headers["location"] == "https://gw.example.com/auth/oauth/login"


# --- starting to sign in -------------------------------------------------------------


@pytest.fixture(name="oauth_client")
def fixture_oauth_client(monkeypatch):
    monkeypatch.setattr(settings, "GATEWAY_OAUTH_CLIENT_ID", "client-id")
    monkeypatch.setattr(settings, "GATEWAY_OAUTH_CLIENT_SECRET", "shhh")


@pytest.mark.parametrize(
    "client_id, secret, debug",
    [("", "shhh", False), ("", "shhh", True), ("client-id", "", False)],
    ids=["no client id", "no client id, debug mode", "no client secret"],
)
def test_signing_in_is_unavailable_until_oauth_is_configured(
    client, monkeypatch, client_id, secret, debug
):
    """Debug mode used to redirect to /test/login, which doesn't exist."""
    monkeypatch.setattr(settings, "GATEWAY_OAUTH_CLIENT_ID", client_id)
    monkeypatch.setattr(settings, "GATEWAY_OAUTH_CLIENT_SECRET", secret)
    monkeypatch.setattr(settings, "DEBUG", debug)

    resp = client.get(LOGIN_URL, follow_redirects=False)

    assert resp.status_code == 503
    assert "OAuth not configured" in resp.json()["detail"]


def test_signing_in_is_unavailable_without_an_authorization_endpoint(
    client, oauth_client, monkeypatch
):
    monkeypatch.setattr(settings, "OIDC_AUTHORIZATION_ENDPOINT", None)

    resp = client.get(LOGIN_URL, follow_redirects=False)

    assert resp.status_code == 503
    assert "OIDC provider not configured" in resp.json()["detail"]


@pytest.mark.parametrize(
    "params, next_url",
    [({}, "/portal"), ({"next": "/device?user_code=AB-12"}, "/device?user_code=AB-12")],
    ids=["home", "the requested page"],
)
def test_signing_in_sends_the_browser_to_the_provider_with_a_state_tied_to_it(
    client, oauth_client, oidc_provider, params, next_url
):
    resp = client.get(LOGIN_URL, params=params, follow_redirects=False)

    location = resp.headers["location"]
    assert location.startswith(oidc_provider["authorization_endpoint"] + "?")
    assert "shhh" not in location
    query = _query(location)
    assert query["client_id"] == "client-id"
    assert query["response_type"] == "code"
    state = jwt.decode(
        query["state"], settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
    )
    assert state["purpose"] == "gateway_login"
    assert state["next_url"] == next_url
    # __Host- keeps other subdomains and ports from planting the cookie.
    cookie = SimpleCookie(resp.headers["set-cookie"])["__Host-login_nonce"]
    assert cookie.value == state["browser"]
    assert cookie["httponly"]
    assert cookie["secure"]
    assert cookie["path"] == "/"


@pytest.mark.parametrize(
    "configured, scope",
    [
        ({}, "openid profile email offline_access"),
        # Without it Entra issues a Graph token, which can't be exchanged later.
        (
            {"OIDC_PROVIDER": "azure"},
            "openid profile email offline_access client-id/.default",
        ),
        ({"GATEWAY_LOGIN_SCOPES": "openid gravitino"}, "openid gravitino"),
        # The stored token is exchanged like MCP clients', so it needs their audience.
        (
            {"OIDC_PROVIDER": "keycloak", "GATEWAY_API_SCOPES": "mcp-gateway"},
            "openid profile email offline_access mcp-gateway",
        ),
        # Listed for MCP clients that ask for a refresh token; asked for once.
        (
            {
                "OIDC_PROVIDER": "keycloak",
                "GATEWAY_API_SCOPES": "gravitino offline_access",
            },
            "openid profile email offline_access gravitino",
        ),
    ],
    ids=[
        "default",
        "entra",
        "configured",
        "mcp clients' scopes",
        "offline_access listed",
    ],
)
def test_signing_in_asks_for_the_scopes_the_gateway_needs(
    client, oauth_client, monkeypatch, configured, scope
):
    for name, value in configured.items():
        monkeypatch.setattr(settings, name, value)

    location = client.get(LOGIN_URL, follow_redirects=False).headers["location"]

    assert _query(location)["scope"] == scope


# --- finishing signing in ----------------------------------------------------------


def test_a_sign_in_proves_with_pkce_that_it_redeems_its_own_code(
    client, oauth_client, token_endpoint
):
    """A code taken from someone's browser can't be redeemed in another sign-in."""
    login = _query(client.get(LOGIN_URL, follow_redirects=False).headers["location"])
    client.cookies.set(
        LOGIN_NONCE,
        jwt.decode(login["state"], options={"verify_signature": False})["browser"],
    )

    client.get(
        CALLBACK_URL,
        params={"code": "c", "state": login["state"]},
        follow_redirects=False,
    )

    verifier = token_endpoint.post.call_args.kwargs["data"]["code_verifier"]
    assert login["code_challenge_method"] == "S256"
    assert login["code_challenge"] == pkce_challenge(verifier)
    assert verifier not in login["state"]


def _state(next_url="/portal", purpose="gateway_login", expired=False, browser=BROWSER):
    """A signed state like /auth/oauth/login's."""
    now = datetime.now(timezone.utc)
    payload = {
        "purpose": purpose,
        "browser": browser,
        "next_url": next_url,
        "exp": now + timedelta(minutes=-1 if expired else 5),
        "iat": now,
    }
    return jwt.encode(
        payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )


def _id_token(email="alice@example.com", name="Alice", **claims):
    """An ID token; its signature isn't checked, as it came from the token endpoint."""
    if email is not None:
        claims = {"email": email, "email_verified": True, **claims}
    claims.setdefault("iss", settings.OIDC_ISSUER)
    claims.setdefault("aud", settings.GATEWAY_OAUTH_CLIENT_ID)
    claims.setdefault("exp", datetime.now(timezone.utc) + timedelta(minutes=5))
    return jwt.encode({"name": name, **claims}, "u" * 32, algorithm="HS256")


def _tokens_reply(id_token):
    reply = MagicMock()
    reply.json.return_value = {
        "id_token": id_token,
        "access_token": "access-xyz",
        "refresh_token": "refresh-xyz",
        "expires_in": 3600,
    }
    return reply


@pytest.fixture(name="token_endpoint")
def fixture_token_endpoint(monkeypatch, token_manager):
    """The provider's token endpoint, answering with Alice's tokens unless told otherwise."""
    endpoint = MagicMock()
    endpoint.post = MagicMock(return_value=_tokens_reply(_id_token()))
    monkeypatch.setattr("mcp_gateway.oauth.oidc_client.requests.post", endpoint.post)
    return endpoint


def _callback(client, *, nonce=BROWSER, **params):
    """Come back from the provider to a browser with the login cookie ``nonce``."""
    if nonce:
        client.cookies.set(LOGIN_NONCE, nonce)
    params = {"code": "c", "state": _state(), **params}
    return client.get(
        CALLBACK_URL,
        params={key: value for key, value in params.items() if value is not None},
        follow_redirects=False,
    )


@pytest.mark.parametrize(
    "callback",
    [
        pytest.param({"state": None}, id="no state"),
        pytest.param({"state": "not-a-jwt"}, id="a state that isn't a jwt"),
        pytest.param({"state": _state(expired=True)}, id="an expired state"),
        pytest.param({"state": _state(purpose="connect")}, id="another purpose"),
        pytest.param({"code": None}, id="no code"),
        # Someone could otherwise put another person's browser in their session.
        pytest.param({"state": _state(browser="someone-else")}, id="another browser"),
        pytest.param({"nonce": None}, id="no login cookie"),
    ],
)
def test_a_callback_that_doesnt_check_out_signs_no_one_in(
    client, db_session, token_endpoint, callback
):
    resp = _callback(client, **callback)

    assert resp.status_code == 400
    assert session_cookie_name() not in _cookies(resp, cleared=False)
    assert db_session.query(User).count() == 0


@pytest.mark.parametrize(
    "callback, shown",
    [
        (
            {"code": None, "error": "access_denied", "error_description": "555-0100"},
            "(access_denied)",
        ),
        (
            {"code": None, "state": None, "error": "Call 555-0100 to fix"},
            "Missing the state parameter",
        ),
    ],
    ids=["after a valid state", "without one"],
)
def test_a_refused_sign_in_shows_only_the_error_code(client, callback, shown):
    """Anyone can send a browser here with an error and a description of their own."""
    resp = _callback(client, **callback)

    assert resp.status_code == 400
    assert shown in resp.text
    assert "555-0100" not in resp.text


def test_a_failed_code_exchange_hides_the_provider_response(client, token_endpoint):
    token_endpoint.post.return_value.raise_for_status.side_effect = requests.HTTPError(
        "400 Client Error", response=MagicMock(text="AADSTS70008: internals")
    )

    resp = _callback(client)

    assert resp.status_code == 400
    assert resp.json()["detail"] == "Failed to exchange the authorization code"


def test_an_unexpected_failure_hides_the_exception_text(
    client, token_endpoint, monkeypatch
):
    failure = AsyncMock(side_effect=RuntimeError("database at 10.0.0.5 refused"))
    monkeypatch.setattr("mcp_gateway.routes.auth.sync_person", failure)

    resp = _callback(client)

    assert resp.status_code == 500
    assert resp.json()["detail"] == "OAuth callback failed"


@pytest.mark.parametrize(
    "claims",
    [
        # A multi-tenant authority would otherwise let any tenant name an admin.
        pytest.param({"aud": "another-client"}, id="another audience"),
        pytest.param({"iss": "https://attacker.example.com"}, id="another issuer"),
        pytest.param(
            {"exp": datetime.now(timezone.utc) - timedelta(minutes=1)}, id="expired"
        ),
        pytest.param({"email_verified": False}, id="unverified email"),
        pytest.param(
            {"email": None, "preferred_username": "admin@example.com"},
            id="only a login name",
        ),
        # A person must not take over a service account's row or rights.
        pytest.param({"email": SERVICE_ACCOUNT_EMAIL}, id="a service account's email"),
    ],
)
def test_a_sign_in_that_isnt_a_persons_for_this_gateway_signs_no_one_in(
    client, db_session, service_account, token_endpoint, claims
):
    id_token = _id_token(**{"email": "admin@example.com", **claims})
    token_endpoint.post.return_value = _tokens_reply(id_token)

    resp = _callback(client)

    assert resp.status_code == 403
    assert db_session.query(User).count() == 1
    db_session.refresh(service_account)
    assert service_account.is_service_account


@pytest.mark.parametrize(
    "next_url, location",
    [
        ("/portal/keys", "/portal/keys"),
        ("https://attacker.example", "/portal"),
        ("//attacker.example", "/portal"),
    ],
    ids=["a gateway page", "another site", "another site, scheme-relative"],
)
def test_a_sign_in_creates_the_person_and_lands_only_on_a_gateway_page(
    client, db_session, token_endpoint, next_url, location
):
    resp = _callback(client, state=_state(next_url=next_url))

    assert resp.status_code == 302
    assert resp.headers["location"] == location
    user = db_session.query(User).filter(User.email == "alice@example.com").one()
    assert user.is_admin is False
    [session] = [
        header
        for header in resp.headers.get_list("set-cookie")
        if header.startswith(f"{session_cookie_name()}=")
    ]
    # Out of reach of page scripts.
    assert "HttpOnly" in session
    # The sign-in is done; its nonce must not be reused.
    assert LOGIN_NONCE in _cookies(resp, cleared=True)


def test_two_people_with_the_same_display_name_can_both_sign_in(
    client, db_session, token_endpoint
):
    """The display name used to be the username, which must be unique."""
    for email in ("john@a.example", "john@b.example"):
        token_endpoint.post.return_value = _tokens_reply(_id_token(email, "John Smith"))
        assert _callback(client).status_code == 302

    users = db_session.query(User).order_by(User.email).all()
    assert [(u.username, u.full_name) for u in users] == [
        ("john@a.example", "John Smith"),
        ("john@b.example", "John Smith"),
    ]


# --- renewing the CLI's token ------------------------------------------------------


def _provider_token(**claims):
    if "email" in claims:
        claims.setdefault("email_verified", True)
    return jwt.encode(
        claims, "the-providers-key-of-32-bytes-or-more", algorithm="HS256"
    )


@pytest.fixture(name="provider_refresh")
def fixture_provider_refresh(monkeypatch):
    """The provider's refresh grant; tests set what it answers with or raises."""
    oidc = MagicMock(provider="generic")
    monkeypatch.setattr("mcp_gateway.routes.auth.OIDCClient", lambda: oidc)
    return oidc.refresh_access_token


@pytest.mark.parametrize(
    "claims",
    [
        {"email": REGULAR_EMAIL},
        {"email": REGULAR_EMAIL.upper()},
        # Keycloak's preferred_username is a login name such as "alice", not an email.
        {"preferred_username": "someone", "email": REGULAR_EMAIL},
    ],
    ids=["email", "email in another case", "email and a login name"],
)
def test_refreshing_stores_the_persons_new_token_and_keeps_the_refresh_token(
    client, regular_user, token_manager, provider_refresh, claims
):
    """Providers may not rotate the refresh token; dropping it would sign the person out."""
    provider_refresh.return_value = {
        "access_token": _provider_token(**claims),
        "expires_in": 1200,
    }

    resp = client.post(REFRESH_URL, json={"refresh_token": "old-refresh"})

    assert resp.status_code == 200
    body = resp.json()
    assert (body["token_type"], body["expires_in"]) == ("Bearer", 1200)
    assert body["refresh_token"] == "old-refresh"
    stored = token_manager.store_user_oauth_token.await_args.kwargs
    assert (stored["user_id"], stored["service"], stored["refresh_token"]) == (
        regular_user.id,
        "gateway",
        "old-refresh",
    )


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param(
            {"access_token": _provider_token(sub="no-email-here")}, id="no identity"
        ),
        # A stranger's refresh token must not confirm whether an account exists.
        pytest.param(
            {"access_token": _provider_token(email="ghost@example.com")}, id="unknown"
        ),
        pytest.param(RuntimeError("nope at 10.0.0.5"), id="provider failure"),
    ],
)
def test_a_failed_refresh_is_one_opaque_401(client, provider_refresh, answer):
    provider_refresh.side_effect = [answer]

    resp = client.post(REFRESH_URL, json={"refresh_token": "old-refresh"})

    assert resp.status_code == 401
    assert resp.json() == {"detail": "Failed to refresh token. Please log in again."}
