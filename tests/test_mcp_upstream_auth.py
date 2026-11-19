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

"""How the gateway signs in to MCP servers for service accounts
(mcp_gateway.oauth.mcp_service_auth)."""

import base64
from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_gateway.config import settings
from mcp_gateway.models import MCPCatalog, ServiceAccountCredentials, User
from mcp_gateway.oauth import mcp_service_auth

SECRET_REF = "mcp-gateway-sa-trino-creds"


def _forwarding(**trino):
    return {"downstream_credentials": {"trino": trino}}


@pytest.fixture(name="storage")
def fixture_storage(monkeypatch):
    """The secret store, holding the service account's credential."""
    storage = MagicMock()
    storage.get_secret = AsyncMock(return_value="secret-pass")
    monkeypatch.setattr(mcp_service_auth, "get_secret_storage", lambda: storage)
    return storage


@pytest.fixture(name="forward")
def fixture_forward(db_session, service_account, storage):
    """The headers the service account forwards to trino, given its config."""

    async def _forward(additional_config):
        db_session.add(
            ServiceAccountCredentials(
                service_account_id=service_account.id,
                provider="google",
                service_account_name="svc-test@example.iam.gserviceaccount.com",
                allowed_services=["trino"],
                created_by=service_account.id,
                additional_config=additional_config,
            )
        )
        db_session.commit()
        return await mcp_service_auth.build_credential_forward_headers(
            db_session, service_account, "trino"
        )

    return _forward


@pytest.mark.parametrize(
    "is_service_account, service_auth_type, expected",
    [
        (True, "credential_forward", "credential_forward"),
        (True, "", "oauth"),
        (False, "credential_forward", "oauth"),
    ],
)
def test_a_service_account_uses_the_servers_service_auth_type_when_set(
    is_service_account, service_auth_type, expected
):
    mcp = MCPCatalog(auth_type="oauth", service_auth_type=service_auth_type)
    user = User(is_service_account=is_service_account)

    assert mcp_service_auth.effective_auth_type(mcp, user) == expected


@pytest.mark.parametrize(
    "trino, header",
    [
        (
            {"secret_ref": SECRET_REF, "auth_header_type": "basic", "username": "u1"},
            "Basic " + base64.b64encode(b"u1:secret-pass").decode(),
        ),
        (
            {"secret_ref": SECRET_REF, "auth_header_type": "bearer"},
            "Bearer secret-pass",
        ),
    ],
)
async def test_the_secret_is_forwarded_in_the_configured_header(
    forward, storage, trino, header
):
    headers = await forward(_forwarding(**trino))

    assert headers == {"Authorization": header}
    storage.get_secret.assert_awaited_once_with(SECRET_REF)


@pytest.mark.parametrize(
    "config",
    [
        {},
        _forwarding(secret_ref=SECRET_REF),
        _forwarding(secret_ref=SECRET_REF, auth_header_type="digest"),
        _forwarding(secret_ref=SECRET_REF, auth_header_type="basic"),
        _forwarding(auth_header_type="bearer"),
    ],
    ids=["none", "no-header-type", "unknown-header-type", "no-username", "no-secret"],
)
async def test_an_incomplete_forwarding_config_forwards_nothing(
    forward, storage, config
):
    assert await forward(config) is None
    storage.get_secret.assert_not_awaited()


@pytest.mark.parametrize(
    "secret_ref",
    [
        "mcp-gateway-encryption-key",
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:prod-db",
        "projects/other/secrets/db-password",
        "unrelated-secret",
    ],
)
async def test_only_service_account_secrets_are_forwarded(forward, storage, secret_ref):
    """The gateway can read other secrets, its own encryption key among them."""
    headers = await forward(
        _forwarding(secret_ref=secret_ref, auth_header_type="bearer")
    )

    assert headers is None
    storage.get_secret.assert_not_awaited()


def test_the_encryption_key_is_refused_even_without_a_prefix(monkeypatch):
    monkeypatch.setattr(settings, "SERVICE_ACCOUNT_SECRET_PREFIX", "")

    assert mcp_service_auth.refused_secret_refs(
        _forwarding(secret_ref="mcp-gateway-encryption-key")
    ) == ["mcp-gateway-encryption-key"]
    assert not mcp_service_auth.refused_secret_refs(_forwarding(secret_ref="any-name"))


@pytest.mark.parametrize("config", [None, {}, {"downstream_credentials": "junk"}])
def test_configs_without_forwarding_refuse_nothing(config):
    assert not mcp_service_auth.refused_secret_refs(config)
