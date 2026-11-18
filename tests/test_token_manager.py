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

"""Tests for TokenManager: people's tokens for MCP servers, stored, renewed and exchanged.

Tokens are encrypted with real AES-256-GCM, so "encrypted at rest" is proven, not mocked.
"""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import requests

from mcp_gateway.config import settings
from mcp_gateway.models import MCPCatalog, OAuthToken
from mcp_gateway.oauth import mcp_oauth_discovery
from mcp_gateway.oauth.token_encryption import TokenEncryption
from mcp_gateway.oauth.token_manager import TokenManager

TOKEN_ENDPOINT = "https://mcp.example.com/v1/token"

# ---------------------------------------------------------------- helpers


class _FakeAsyncClient:
    """Stands in for ``httpx.AsyncClient``, answering every POST with ``response``."""

    def __init__(self, response):
        self.response = response
        self.calls = []

    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


def _http_response(payload, *, status=200):
    resp = MagicMock()
    resp.json.return_value = payload
    if status >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "upstream refused", request=MagicMock(), response=resp
        )
    return resp


def _catalog(db, **overrides):
    mcp = MCPCatalog(
        **{
            "service_id": "svc",
            "name": "Service",
            "mcp_url": "http://svc:8080/mcp",
            "auto_sso_enabled": False,
            "is_active": True,
            "requires_approval": False,
            **overrides,
        }
    )
    db.add(mcp)
    db.commit()
    db.refresh(mcp)
    return mcp


def _own_sign_in(db, **overrides):
    """A server with its own sign-in, whose tokens the gateway's provider never renews."""
    return _catalog(
        db,
        **{
            "service_id": "atlassian",
            "auth_type": "oauth",
            "oauth_client_id": "mcp-cid",
            "mcp_url": "https://mcp.example.com/mcp",
            **overrides,
        },
    )


def _row(db, user_id, service):
    return (
        db.query(OAuthToken)
        .filter(OAuthToken.user_id == user_id, OAuthToken.service == service)
        .first()
    )


async def _store_expired(tm, user_id, service="svc", refresh_token="renew"):
    await tm.store_user_oauth_token(
        user_id, service, "stale", refresh_token=refresh_token, expires_in=-60
    )


def _stub_exchange(tm, user_id, service="svc"):
    """Make the token exchange succeed, storing "exchanged" as the server's token."""

    async def _exchange(**kwargs):
        await tm.store_user_oauth_token(user_id, service, "exchanged")
        return {"success": True}

    tm.connect_mcp_with_obo = AsyncMock(side_effect=_exchange)
    return tm.connect_mcp_with_obo


# ---------------------------------------------------------------- fixtures


@pytest.fixture(autouse=True, name="encryption")
def fixture_encryption():
    enc = TokenEncryption(b"k" * 32)
    with patch(
        "mcp_gateway.oauth.token_manager.get_token_encryption",
        new_callable=AsyncMock,
        return_value=enc,
    ):
        yield enc


@pytest.fixture(name="tm")
def fixture_tm(db_session):
    return TokenManager(db_session)


@pytest.fixture(name="fake_http")
def fixture_fake_http(monkeypatch):
    def _install(response):
        fake = _FakeAsyncClient(response)
        monkeypatch.setattr(httpx, "AsyncClient", fake)
        return fake

    return _install


@pytest.fixture(name="discovery")
def fixture_discovery(monkeypatch):
    """Well-known discovery of a server's sign-in finds TOKEN_ENDPOINT."""

    async def _discover(_mcp_url):
        return MagicMock(token_endpoint=TOKEN_ENDPOINT)

    monkeypatch.setattr(
        "mcp_gateway.oauth.mcp_oauth_discovery.discover_oauth_metadata", _discover
    )


@pytest.fixture(name="entra_obo")
def fixture_entra_obo(monkeypatch):
    monkeypatch.setattr(settings, "TOKEN_EXCHANGE_STYLE", "entra_obo")


# ---------------------------------------------------------------- storage


class TestStorage:
    async def test_tokens_are_encrypted_at_rest(
        self, tm, db_session, regular_user, encryption
    ):
        await tm.store_user_oauth_token(
            regular_user.id, "trino", "super-secret", refresh_token="renew-me"
        )

        row = _row(db_session, regular_user.id, "trino")
        # A database dump must not yield tokens.
        assert "super-secret" not in row.access_token_encrypted
        assert "renew-me" not in row.refresh_token_encrypted
        assert encryption.decrypt(row.refresh_token_encrypted) == "renew-me"
        assert await tm.get_user_oauth_token(regular_user.id, "trino") == "super-secret"

    async def test_reconnecting_replaces_the_token_and_its_refresh_token(
        self, tm, db_session, regular_user
    ):
        await tm.store_user_oauth_token(
            regular_user.id, "trino", "first", refresh_token="old"
        )
        await tm.store_user_oauth_token(regular_user.id, "trino", "second")

        rows = db_session.query(OAuthToken).filter_by(user_id=regular_user.id).all()
        assert len(rows) == 1
        assert rows[0].refresh_token_encrypted is None
        assert await tm.get_user_oauth_token(regular_user.id, "trino") == "second"

    async def test_a_token_stored_concurrently_is_replaced_not_duplicated(
        self, tm, db_session, regular_user
    ):
        await tm.store_user_oauth_token(regular_user.id, "trino", "first")
        real_update = tm._update_stored
        missed = []

        def _miss_once(user_id, service, values):
            # As if another request stored its token after this one looked.
            if not missed:
                missed.append(True)
                return False
            return real_update(user_id, service, values)

        tm._update_stored = _miss_once

        await tm.store_user_oauth_token(regular_user.id, "trino", "second")

        rows = db_session.query(OAuthToken).filter_by(user_id=regular_user.id).all()
        assert len(rows) == 1
        assert await tm.get_user_oauth_token(regular_user.id, "trino") == "second"

    async def test_the_expiry_follows_the_lifetime_the_provider_gave(
        self, tm, db_session, regular_user
    ):
        await tm.store_user_oauth_token(
            regular_user.id, "trino", "access", expires_in=60
        )

        expires_at = _row(db_session, regular_user.id, "trino").expires_at
        assert (
            timedelta(seconds=50)
            < expires_at - datetime.utcnow()
            < timedelta(seconds=70)
        )


# ---------------------------------------------------------------- retrieval and renewal


class TestRetrieval:
    async def test_one_persons_token_is_never_handed_to_another(
        self, tm, regular_user, admin_user
    ):
        await tm.store_user_oauth_token(regular_user.id, "trino", "mine")

        assert await tm.get_user_oauth_token(admin_user.id, "trino") is None

    async def test_a_token_for_one_service_is_not_used_for_another(
        self, tm, regular_user
    ):
        await tm.store_user_oauth_token(regular_user.id, "trino", "trino-token")

        assert await tm.get_user_oauth_token(regular_user.id, "looker") is None

    async def test_a_token_with_no_recorded_expiry_is_still_returned(
        self, tm, db_session, regular_user
    ):
        await tm.store_user_oauth_token(regular_user.id, "trino", "access")
        _row(db_session, regular_user.id, "trino").expires_at = None
        db_session.commit()

        assert await tm.get_user_oauth_token(regular_user.id, "trino") == "access"

    async def test_an_expired_token_with_no_way_to_renew_it_is_refused(
        self, tm, regular_user
    ):
        await _store_expired(tm, regular_user.id, refresh_token=None)

        assert await tm.get_user_oauth_token(regular_user.id, "svc") is None

    @pytest.mark.parametrize(
        "expires_in, catalog",
        [
            pytest.param(-60, None, id="expired"),
            # It would otherwise expire on the way to the server.
            pytest.param(30, None, id="about-to-expire"),
            pytest.param(
                -60,
                {"auth_type": "oauth", "auto_sso_enabled": True},
                id="single-sign-on-server",
            ),
        ],
    )
    async def test_an_expiring_token_is_renewed_by_the_gateways_provider(
        self, tm, db_session, regular_user, expires_in, catalog
    ):
        if catalog is not None:
            _catalog(db_session, **catalog)
        await tm.store_user_oauth_token(
            regular_user.id,
            "svc",
            "stale",
            refresh_token="renew",
            expires_in=expires_in,
        )
        tm.oidc_client.refresh_access_token = MagicMock(
            return_value={"access_token": "fresh", "expires_in": 3600}
        )

        assert await tm.get_user_oauth_token(regular_user.id, "svc") == "fresh"

    @pytest.mark.parametrize(
        "own_sign_in", [False, True], ids=["gateway-provider", "own-sign-in"]
    )
    @pytest.mark.parametrize(
        "answer, kept",
        [
            pytest.param({"access_token": "fresh"}, "renew", id="not-rotated"),
            pytest.param(
                {"access_token": "fresh", "refresh_token": "rotated"},
                "rotated",
                id="rotated",
            ),
        ],
    )
    async def test_a_renewal_keeps_the_refresh_token_unless_the_provider_rotates_it(
        self,
        tm,
        db_session,
        regular_user,
        encryption,
        fake_http,
        discovery,
        own_sign_in,
        answer,
        kept,
    ):
        service = "svc"
        if own_sign_in:
            service = _own_sign_in(db_session).service_id
            fake_http(_http_response(answer))
        else:
            tm.oidc_client.refresh_access_token = MagicMock(return_value=answer)
        await _store_expired(tm, regular_user.id, service)

        assert await tm.get_user_oauth_token(regular_user.id, service) == "fresh"
        # Dropping it would force a full reconnect on the next expiry.
        row = _row(db_session, regular_user.id, service)
        assert encryption.decrypt(row.refresh_token_encrypted) == kept

    async def test_concurrent_requests_renew_a_token_once(self, tm, regular_user):
        """Providers that rotate refresh tokens refuse the second use of one."""
        await _store_expired(tm, regular_user.id)
        calls = []

        async def _refresh(user_id, service, oauth_token):
            calls.append(service)
            await asyncio.sleep(0.01)
            await tm.store_user_oauth_token(user_id, service, "fresh")
            return True

        tm._refresh_user_token = _refresh

        tokens = await asyncio.gather(
            tm.get_user_oauth_token(regular_user.id, "svc"),
            tm.get_user_oauth_token(regular_user.id, "svc"),
        )

        assert tokens == ["fresh", "fresh"]
        assert calls == ["svc"]

    async def test_a_failed_renewal_returns_nothing_rather_than_the_stale_token(
        self, tm, regular_user
    ):
        await _store_expired(tm, regular_user.id)
        tm.oidc_client.refresh_access_token = MagicMock(
            side_effect=requests.HTTPError("invalid_grant")
        )

        assert await tm.get_user_oauth_token(regular_user.id, "svc") is None

    async def test_a_refresh_token_that_cannot_be_decrypted_is_never_sent(
        self, tm, db_session, regular_user
    ):
        await _store_expired(tm, regular_user.id)
        row = _row(db_session, regular_user.id, "svc")
        row.refresh_token_encrypted = TokenEncryption(b"o" * 32).encrypt("renew")
        db_session.commit()
        tm.oidc_client.refresh_access_token = MagicMock()

        assert await tm.get_user_oauth_token(regular_user.id, "svc") is None
        assert tm.oidc_client.refresh_access_token.call_count == 0

    async def test_a_renewal_that_removes_the_row_returns_nothing(
        self, tm, db_session, regular_user
    ):
        await _store_expired(tm, regular_user.id)

        async def _drop(user_id, service, oauth_token):
            db_session.delete(oauth_token)
            db_session.commit()
            return True

        tm._refresh_user_token = _drop

        assert await tm.get_user_oauth_token(regular_user.id, "svc") is None


# ---------------------------------------------------------------- servers with their own sign-in


class TestOwnSignIn:
    async def test_a_renewal_goes_to_the_servers_token_endpoint(
        self, tm, db_session, regular_user, fake_http, discovery
    ):
        mcp = _own_sign_in(db_session)
        await _store_expired(tm, regular_user.id, mcp.service_id)
        http = fake_http(_http_response({"access_token": "fresh"}))
        tm.oidc_client.refresh_access_token = MagicMock()

        assert await tm.get_user_oauth_token(regular_user.id, mcp.service_id) == "fresh"

        url, kwargs = http.calls[0]
        assert url == TOKEN_ENDPOINT
        assert kwargs["data"]["client_id"] == "mcp-cid"
        assert kwargs["data"]["refresh_token"] == "renew"
        assert tm.oidc_client.refresh_access_token.call_count == 0

    async def test_a_configured_metadata_url_is_used_instead_of_discovery(
        self, tm, db_session, regular_user, fake_http, monkeypatch
    ):
        mcp = _own_sign_in(
            db_session,
            oauth_metadata_url="https://auth.example.com/.well-known/oauth-authorization-server",
        )
        seen = []

        async def _fetch_json(url):
            seen.append(url)
            return {
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
            }

        monkeypatch.setattr(
            "mcp_gateway.oauth.mcp_oauth_discovery._fetch_json", _fetch_json
        )
        mcp_oauth_discovery.clear_discovery_cache()
        await _store_expired(tm, regular_user.id, mcp.service_id)
        http = fake_http(_http_response({"access_token": "fresh"}))

        assert await tm.get_user_oauth_token(regular_user.id, mcp.service_id) == "fresh"

        assert seen == [mcp.oauth_metadata_url]
        assert http.calls[0][0] == "https://auth.example.com/token"

    @pytest.mark.parametrize("is_active", [True, False], ids=["active", "deactivated"])
    async def test_a_failed_renewal_never_falls_back_to_the_gateways_provider(
        self, tm, db_session, regular_user, encryption, fake_http, discovery, is_active
    ):
        """That would overwrite the token with one the server can't accept.

        Deactivating the server must not disarm this: nothing could repair the token then.
        """
        mcp = _own_sign_in(db_session, is_active=is_active)
        await _store_expired(tm, regular_user.id, mcp.service_id)
        fake_http(_http_response({}, status=400))
        tm.oidc_client.refresh_access_token = MagicMock(
            return_value={"access_token": "wrong"}
        )

        assert await tm.get_user_oauth_token(regular_user.id, mcp.service_id) is None

        assert tm.oidc_client.refresh_access_token.call_count == 0
        row = _row(db_session, regular_user.id, mcp.service_id)
        assert encryption.decrypt(row.access_token_encrypted) == "stale"

    async def test_an_empty_refresh_token_is_never_sent(
        self, tm, db_session, regular_user, fake_http, discovery
    ):
        mcp = _own_sign_in(db_session)
        http = fake_http(_http_response({"access_token": "fresh"}))

        assert await tm._refresh_mcp_oauth_token(regular_user.id, mcp, "") is False
        assert http.calls == []


# ---------------------------------------------------------------- single sign-on


class TestSingleSignOn:
    async def test_the_gateways_own_token_names_are_never_exchanged_for(
        self, tm, db_session, regular_user
    ):
        # Registered as if they were servers, so only the reserved-name check
        # stands between a gateway token and an exchange.
        internal = ("gateway", "slack_gateway")
        for service in internal:
            _catalog(db_session, service_id=service, auto_sso_enabled=True)
        tm.connect_mcp_with_obo = AsyncMock()

        for service in internal:
            token = await tm.get_user_oauth_token(
                regular_user.id, service, gateway_token="gateway-token"
            )
            assert token is None
        assert tm.connect_mcp_with_obo.await_count == 0

    @pytest.mark.parametrize(
        "gateway_token, auto_connect",
        [
            pytest.param(None, True, id="no-gateway-token"),
            pytest.param("gateway-token", False, id="caller-opts-out"),
        ],
    )
    async def test_no_exchange_without_a_gateway_token_or_when_the_caller_opts_out(
        self, tm, db_session, regular_user, gateway_token, auto_connect
    ):
        _catalog(db_session, auto_sso_enabled=True)
        tm.connect_mcp_with_obo = AsyncMock()

        token = await tm.get_user_oauth_token(
            regular_user.id,
            "svc",
            gateway_token=gateway_token,
            auto_connect=auto_connect,
        )

        assert token is None
        assert tm.connect_mcp_with_obo.await_count == 0

    @pytest.mark.parametrize(
        "catalog, has_expired_token",
        [
            pytest.param(None, False, id="not-in-catalog"),
            pytest.param({}, False, id="single-sign-on-off"),
            pytest.param({}, True, id="expired-token-single-sign-on-off"),
            # Dynamic client registration can set any client ID, the gateway's included.
            pytest.param(
                {"auth_type": "oauth", "audience": settings.GATEWAY_OAUTH_CLIENT_ID},
                False,
                id="own-sign-in-with-the-gateways-client-id",
            ),
        ],
    )
    async def test_a_server_without_single_sign_on_gets_no_exchange_nor_gateway_token(
        self, tm, db_session, regular_user, catalog, has_expired_token
    ):
        if catalog is not None:
            _catalog(db_session, **catalog)
        if has_expired_token:
            await _store_expired(tm, regular_user.id, refresh_token=None)
        tm.connect_mcp_with_obo = AsyncMock()

        token = await tm.get_user_oauth_token(
            regular_user.id, "svc", gateway_token="gateway-token"
        )

        assert token is None
        assert tm.connect_mcp_with_obo.await_count == 0

    @pytest.mark.parametrize(
        "has_stored_token, refresh_token",
        [
            pytest.param(False, None, id="none-stored"),
            # Exchanged tokens often come without a refresh token; Keycloak never sends one.
            pytest.param(True, None, id="expired-without-refresh-token"),
            pytest.param(True, "revoked", id="renewal-refused"),
        ],
    )
    async def test_the_gateway_token_is_exchanged_when_no_stored_token_works(
        self, tm, db_session, regular_user, has_stored_token, refresh_token
    ):
        _catalog(db_session, auto_sso_enabled=True)
        if has_stored_token:
            await _store_expired(tm, regular_user.id, refresh_token=refresh_token)
        tm.oidc_client.refresh_access_token = MagicMock(
            side_effect=requests.HTTPError("invalid_grant")
        )
        exchange = _stub_exchange(tm, regular_user.id)

        token = await tm.get_user_oauth_token(
            regular_user.id, "svc", gateway_token="gateway-token"
        )

        assert token == "exchanged"
        assert exchange.await_args.kwargs["gateway_token"] == "gateway-token"

    async def test_a_refused_exchange_yields_no_token(
        self, tm, db_session, regular_user
    ):
        _catalog(db_session, auto_sso_enabled=True)
        tm.connect_mcp_with_obo = AsyncMock(
            return_value={"success": False, "error": "consent required"}
        )

        token = await tm.get_user_oauth_token(
            regular_user.id, "svc", gateway_token="gateway-token"
        )

        assert token is None

    @pytest.mark.parametrize(
        "audience, stored, expected",
        [
            pytest.param(
                settings.GATEWAY_OAUTH_CLIENT_ID,
                {"gateway": "stored-gateway"},
                "stored-gateway",
                id="stored-gateway-token",
            ),
            # People using MCP clients may never have signed in to the gateway's pages.
            pytest.param(
                settings.GATEWAY_OAUTH_CLIENT_ID, {}, "incoming", id="incoming-token"
            ),
            pytest.param(settings.JWT_AUDIENCE, {}, "incoming", id="gateway-audience"),
            pytest.param(
                settings.GATEWAY_OAUTH_CLIENT_ID,
                {"gateway": "stored-gateway", "same-app": "own"},
                "own",
                id="server-token-first",
            ),
        ],
    )
    async def test_a_server_that_accepts_gateway_tokens_gets_one_without_an_exchange(
        self, tm, db_session, regular_user, audience, stored, expected
    ):
        _catalog(
            db_session, service_id="same-app", audience=audience, auto_sso_enabled=True
        )
        for service, token in stored.items():
            await tm.store_user_oauth_token(regular_user.id, service, token)
        tm.connect_mcp_with_obo = AsyncMock()

        token = await tm.get_user_oauth_token(
            regular_user.id, "same-app", gateway_token="incoming"
        )

        assert token == expected
        assert tm.connect_mcp_with_obo.await_count == 0
        # Nor is a copy of the gateway token stored for the server.
        assert db_session.query(OAuthToken).count() == len(stored)


# ---------------------------------------------------------------- disconnect and sign-out


class TestDisconnectAndSignOut:
    async def test_disconnecting_removes_only_that_persons_token_for_that_service(
        self, tm, db_session, regular_user, admin_user
    ):
        await tm.store_user_oauth_token(regular_user.id, "trino", "t")
        await tm.store_user_oauth_token(regular_user.id, "looker", "l")
        await tm.store_user_oauth_token(admin_user.id, "trino", "theirs")

        await tm.disconnect_user_service_async(regular_user.id, "trino")

        assert _row(db_session, regular_user.id, "trino") is None
        assert _row(db_session, regular_user.id, "looker") is not None
        assert _row(db_session, admin_user.id, "trino") is not None

    async def test_signing_out_deletes_the_gateway_token_and_the_tokens_got_with_it(
        self, tm, db_session, regular_user, admin_user
    ):
        _catalog(db_session, service_id="auto", auto_sso_enabled=True)
        _catalog(db_session, service_id="manual")
        for service in ("gateway", "slack_gateway", "auto", "manual", "orphan"):
            await tm.store_user_oauth_token(regular_user.id, service, "token")
        await tm.store_user_oauth_token(admin_user.id, "gateway", "theirs")

        await tm.delete_all_user_tokens(regular_user.id)

        # A token got with the gateway token must not outlive it; one the person
        # connected themselves is not revoked by signing out, nor is anyone else's.
        remaining = {(row.user_id, row.service) for row in db_session.query(OAuthToken)}
        assert remaining == {
            (regular_user.id, "manual"),
            (regular_user.id, "orphan"),
            (admin_user.id, "gateway"),
        }


# ---------------------------------------------------------------- get_token


class TestGetToken:
    async def test_an_unknown_user_is_an_error_not_a_silent_none(self, tm):
        with pytest.raises(ValueError):
            await tm.get_token(999999, "trino")

    async def test_a_service_account_gets_no_person_token(self, tm, service_account):
        await tm.store_user_oauth_token(service_account.id, "trino", "person-token")

        assert await tm.get_token(service_account.id, "trino") is None

    @pytest.mark.parametrize(
        "bearer_token, expected", [(None, None), ("b", "exchanged")]
    )
    async def test_a_token_is_exchanged_only_for_the_one_the_person_called_with(
        self, tm, db_session, regular_user, bearer_token, expected
    ):
        _catalog(db_session, auto_sso_enabled=True)
        _stub_exchange(tm, regular_user.id)

        token = await tm.get_token(regular_user.id, "svc", bearer_token=bearer_token)

        assert token == expected


# ---------------------------------------------------------------- token exchange


class TestConnectMcpWithObo:
    @pytest.mark.parametrize(
        "is_registered", [False, True], ids=["unknown", "deactivated"]
    )
    async def test_a_server_not_in_the_active_catalog_cannot_be_connected(
        self, tm, db_session, regular_user, is_registered
    ):
        if is_registered:
            _catalog(db_session, audience="app", is_active=False)

        result = await tm.connect_mcp_with_obo(regular_user.id, "svc", "gateway-token")

        assert result["success"] is False
        assert "not found in catalog" in result["error"]

    async def test_on_behalf_of_needs_the_servers_app_id(
        self, tm, db_session, regular_user, entra_obo
    ):
        _catalog(db_session, audience=None)

        result = await tm.connect_mcp_with_obo(regular_user.id, "svc", "gateway-token")

        assert result["success"] is False
        assert "app ID" in result["error"]
        assert _row(db_session, regular_user.id, "svc") is None

    @pytest.mark.parametrize(
        "scopes, target_scope",
        [
            (None, "api://app-123/.default"),
            ("api://custom/.default", "api://custom/.default"),
        ],
        ids=["servers-app", "configured-scopes"],
    )
    async def test_on_behalf_of_exchanges_for_the_servers_scope_and_stores_the_token(
        self, tm, db_session, regular_user, encryption, entra_obo, scopes, target_scope
    ):
        _catalog(db_session, audience="app-123", oauth_scopes=scopes)
        exchange = MagicMock(
            return_value={"access_token": "obo-token", "expires_in": 1200}
        )
        tm.oidc_client.exchange_token_on_behalf_of = exchange

        result = await tm.connect_mcp_with_obo(regular_user.id, "svc", "gateway-token")

        assert result["success"] is True
        assert result["expires_in"] == 1200
        assert exchange.call_args.kwargs["target_scope"] == target_scope
        assert exchange.call_args.kwargs["user_access_token"] == "gateway-token"
        row = _row(db_session, regular_user.id, "svc")
        assert encryption.decrypt(row.access_token_encrypted) == "obo-token"

    async def test_entra_uses_on_behalf_of_by_default(
        self, tm, db_session, regular_user, monkeypatch
    ):
        monkeypatch.setattr(settings, "OIDC_PROVIDER", "azure")
        _catalog(db_session, audience="app-123")
        tm.oidc_client.exchange_token_on_behalf_of = MagicMock(
            return_value={"access_token": "obo-token"}
        )
        tm.oidc_client.exchange_token_rfc8693 = MagicMock()

        result = await tm.connect_mcp_with_obo(regular_user.id, "svc", "gateway-token")

        assert result["success"] is True
        assert tm.oidc_client.exchange_token_rfc8693.call_count == 0

    @pytest.mark.parametrize(
        "audience, scopes, target_audience",
        [
            pytest.param("app-123", None, "app-123", id="servers-audience"),
            pytest.param(None, None, "svc", id="service-id-fallback"),
            # Scopes used to replace the audience, which sent the wrong one.
            pytest.param("app-123", "gravitino:read", "app-123", id="with-scopes"),
        ],
    )
    async def test_other_providers_exchange_by_rfc_8693_for_the_servers_audience(
        self, tm, db_session, regular_user, audience, scopes, target_audience
    ):
        _catalog(db_session, audience=audience, oauth_scopes=scopes)
        rfc = MagicMock(return_value={"access_token": "exchanged"})
        tm.oidc_client.exchange_token_rfc8693 = rfc
        tm.oidc_client.exchange_token_on_behalf_of = MagicMock()

        result = await tm.connect_mcp_with_obo(regular_user.id, "svc", "gateway-token")

        assert result["success"] is True
        assert rfc.call_args.kwargs["target_audience"] == target_audience
        assert rfc.call_args.kwargs["scope"] == scopes
        assert rfc.call_args.kwargs["user_access_token"] == "gateway-token"
        # The Entra-specific request must not be sent to a generic provider.
        assert tm.oidc_client.exchange_token_on_behalf_of.call_count == 0

    async def test_an_unreachable_provider_is_reported_as_such(
        self, tm, db_session, regular_user, entra_obo
    ):
        """Not as an expired sign-in, which would send the person to sign in again."""
        _catalog(db_session, audience="app-123")
        tm.oidc_client.exchange_token_on_behalf_of = MagicMock(
            side_effect=requests.ConnectionError("connection refused")
        )

        result = await tm.connect_mcp_with_obo(regular_user.id, "svc", "gateway-token")

        assert result["success"] is False
        assert "could not be reached" in result["error"]

    @pytest.mark.parametrize(
        "style, method, body, reason, hint",
        [
            pytest.param(
                "entra_obo",
                "exchange_token_on_behalf_of",
                {"error_description": "AADSTS65001: no consent"},
                "AADSTS65001",
                "API permission",
                id="on-behalf-of",
            ),
            pytest.param(
                "rfc8693",
                "exchange_token_rfc8693",
                {"error": "access_denied"},
                "access_denied",
                "exchange tokens",
                id="rfc-8693",
            ),
        ],
    )
    async def test_a_refused_exchange_reports_the_providers_reason_and_what_to_fix(
        self,
        tm,
        db_session,
        regular_user,
        monkeypatch,
        style,
        method,
        body,
        reason,
        hint,
    ):
        monkeypatch.setattr(settings, "TOKEN_EXCHANGE_STYLE", style)
        _catalog(db_session, audience="app-123")
        response = MagicMock()
        response.json.return_value = body
        error = requests.HTTPError("400", response=response)
        setattr(tm.oidc_client, method, MagicMock(side_effect=error))

        result = await tm.connect_mcp_with_obo(regular_user.id, "svc", "gateway-token")

        assert result["success"] is False
        assert reason in result["error"]
        assert hint in result["hint"]
        assert _row(db_session, regular_user.id, "svc") is None

    async def test_an_error_body_that_isnt_json_still_reports_what_went_wrong(
        self, tm, db_session, regular_user, entra_obo
    ):
        """Identity providers answer with an HTML error page often enough."""
        _catalog(db_session, audience="app-123")
        response = MagicMock()
        response.json.side_effect = ValueError("not json")
        tm.oidc_client.exchange_token_on_behalf_of = MagicMock(
            side_effect=requests.HTTPError("403 Forbidden", response=response)
        )

        result = await tm.connect_mcp_with_obo(regular_user.id, "svc", "gateway-token")

        assert result["success"] is False
        assert "403 Forbidden" in result["error"]
        assert _row(db_session, regular_user.id, "svc") is None
