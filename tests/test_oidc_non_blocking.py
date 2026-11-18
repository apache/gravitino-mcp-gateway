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

# pylint: disable=protected-access

"""The synchronous calls to the identity provider never run on the event loop.

The OIDC client uses requests, which blocks its thread for the whole round trip;
on the event loop that would freeze every other request, the liveness probe's
/health among them.
"""

import asyncio
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest

import mcp_gateway.routes.auth as auth_routes
from mcp_gateway import oauth_auth
from mcp_gateway.config import settings
from mcp_gateway.oauth import oidc_client as oidc_module
from mcp_gateway.oauth import token_manager
from mcp_gateway.oauth.oidc_client import reset_discovery_cache
from mcp_gateway.oauth.token_manager import TokenManager

TOKENS = {"access_token": "tok", "refresh_token": "rt", "expires_in": 3600}


@pytest.fixture(autouse=True, name="_clean_discovery_cache")
def fixture_clean_discovery_cache():
    reset_discovery_cache()
    yield
    reset_discovery_cache()


@pytest.fixture(autouse=True, name="_no_discovery")
def fixture_no_discovery(monkeypatch):
    """No discovery fetch, so the tests exercise only the call under test."""
    monkeypatch.setattr(settings, "OIDC_DISCOVERY_URL", None)
    monkeypatch.setattr(
        settings, "OIDC_TOKEN_ENDPOINT", "https://login.example.com/token"
    )


def _blocking(threads, result, seconds=0.3):
    """A stand-in for a blocking call; it records the thread it runs on."""

    def _call(*_args, **_kwargs):
        threads.append(threading.current_thread().name)
        threading.Event().wait(seconds)
        return result

    return _call


async def _ticks_during(awaitable):
    """Await ``awaitable``; also how often the loop ran something else meanwhile."""
    ticks = 0

    async def heartbeat():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.01)
            ticks += 1

    beat = asyncio.create_task(heartbeat())
    try:
        return await awaitable, ticks
    finally:
        beat.cancel()


async def test_refreshing_a_servers_token_keeps_the_loop_running():
    threads = []
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    stored = MagicMock(refresh_token_encrypted="encrypted")
    response = MagicMock(status_code=200)
    response.json.return_value = TOKENS
    encryption = MagicMock()
    encryption.decrypt.return_value = "plain-refresh-token"

    with (
        patch(
            "mcp_gateway.oauth.token_manager.get_token_encryption",
            AsyncMock(return_value=encryption),
        ),
        patch.object(TokenManager, "store_user_oauth_token", AsyncMock()),
        patch.object(
            oidc_module.requests, "post", side_effect=_blocking(threads, response)
        ),
    ):
        refreshed, ticks = await _ticks_during(
            TokenManager(db)._refresh_user_token(1, "trino", stored)
        )

    assert refreshed is True
    assert threads[0] != threading.current_thread().name
    # A blocked loop would leave this at about 0.
    assert ticks > 5


async def test_the_refresh_endpoint_reaches_the_provider_off_the_loop():
    threads = []
    token = jwt.encode(
        {"email": "tester@example.com", "email_verified": True}, "k" * 32, "HS256"
    )
    oidc = MagicMock(provider="generic")
    oidc.refresh_access_token.side_effect = _blocking(
        threads, {**TOKENS, "access_token": token}, seconds=0.1
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = MagicMock(
        id=1, email="tester@example.com"
    )

    with (
        patch("mcp_gateway.routes.auth.OIDCClient", return_value=oidc),
        patch.object(TokenManager, "store_user_oauth_token", AsyncMock()),
    ):
        response = await auth_routes.refresh_access_token(
            auth_routes.RefreshTokenRequest(refresh_token="rt"), db=db
        )

    assert response["access_token"] == token
    assert threads[0] != threading.current_thread().name


async def test_fetching_a_jwt_signing_key_keeps_the_loop_running(monkeypatch):
    """PyJWKClient fetches the key set synchronously whenever its cache expires."""
    monkeypatch.setattr(settings, "OIDC_JWKS_URI", "https://login.example.com/keys")
    # An Entra account name, not an email: the mocked database would call any name taken.
    monkeypatch.setattr(settings, "OIDC_PROVIDER", "azure")
    threads = []
    user = MagicMock(is_service_account=False, is_active=True)
    user.email = "tester@example.com"
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = user
    claims = {"preferred_username": user.email}

    with (
        patch.object(oauth_auth, "_get_jwks_client", return_value=MagicMock()),
        patch.object(
            oauth_auth,
            "_get_signing_key_with_retry",
            side_effect=_blocking(threads, MagicMock(key="signing-key")),
        ),
        patch.object(oauth_auth.jwt, "decode", return_value=claims),
    ):
        result, ticks = await _ticks_during(
            oauth_auth._validate_human_user_jwt(
                token="tok", issuer=settings.OIDC_ISSUER, db=db, request=MagicMock()
            )
        )

    assert result is user
    assert threads[0] != threading.current_thread().name
    assert ticks > 5


async def test_a_token_manager_builds_its_provider_client_off_the_loop(monkeypatch):
    """Building one may fetch the discovery document, for up to OIDC_HTTP_TIMEOUT."""
    threads = []
    monkeypatch.setattr(
        token_manager, "OIDCClient", _blocking(threads, MagicMock(), seconds=0)
    )
    manager = token_manager.TokenManager(MagicMock())
    assert not threads

    await manager._provider()

    assert threads[0] != threading.current_thread().name
