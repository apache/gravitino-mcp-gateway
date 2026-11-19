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

"""Registering the Gravitino MCP server at startup."""

from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.exc import IntegrityError

from mcp_gateway.catalog_defaults import GRAVITINO_SERVICE_ID, register_gravitino_mcp
from mcp_gateway.config import settings
from mcp_gateway.models import MCPCatalog
from mcp_gateway.oauth.token_manager import TokenManager

GRAVITINO_MCP_URL = "http://gravitino-mcp:8000/mcp"


@pytest.fixture(name="gravitino_mcp_url")
def fixture_gravitino_mcp_url(monkeypatch):
    monkeypatch.setattr(settings, "GRAVITINO_MCP_URL", GRAVITINO_MCP_URL)


def _gravitino(db_session):
    return MCPCatalog.find(db_session, GRAVITINO_SERVICE_ID, active=False)


def test_nothing_is_registered_without_a_url(db_session):
    register_gravitino_mcp(db_session)

    assert _gravitino(db_session) is None


@pytest.mark.parametrize("configured", [None, "gravitino"])
def test_the_server_is_registered_for_every_user(
    db_session, gravitino_mcp_url, monkeypatch, configured
):
    """Gravitino authorizes every call as the calling user, so needs no approval."""
    monkeypatch.setattr(settings, "GRAVITINO_MCP_AUDIENCE", configured)

    register_gravitino_mcp(db_session)

    mcp = _gravitino(db_session)
    assert (mcp.mcp_url, mcp.auth_type) == (GRAVITINO_MCP_URL, "oauth")
    assert mcp.is_active and mcp.auto_sso_enabled and not mcp.requires_approval
    assert mcp.audience == (configured or settings.JWT_AUDIENCE)


def test_an_existing_entry_is_left_as_the_admin_set_it(db_session, gravitino_mcp_url):
    db_session.add(
        MCPCatalog(
            service_id=GRAVITINO_SERVICE_ID,
            name="Our Gravitino",
            mcp_url="http://elsewhere:8000/mcp",
            requires_approval=True,
        )
    )
    db_session.commit()

    register_gravitino_mcp(db_session)

    mcp = _gravitino(db_session)
    assert (mcp.name, mcp.mcp_url) == ("Our Gravitino", "http://elsewhere:8000/mcp")
    assert mcp.requires_approval


def test_losing_a_registration_race_is_not_an_error(db_session, gravitino_mcp_url):
    with patch.object(
        db_session, "commit", side_effect=IntegrityError("insert", {}, None)
    ):
        register_gravitino_mcp(db_session)

    assert _gravitino(db_session) is None


async def test_by_default_users_reach_gravitino_with_their_own_token(
    db_session, regular_user, gravitino_mcp_url
):
    register_gravitino_mcp(db_session)
    tm = TokenManager(db_session)

    with patch.object(tm, "connect_mcp_with_obo", new_callable=AsyncMock) as exchange:
        token = await tm.get_user_oauth_token(
            user_id=regular_user.id,
            service=GRAVITINO_SERVICE_ID,
            gateway_token="users-gateway-token",
            auto_connect=True,
        )

    assert token == "users-gateway-token"
    exchange.assert_not_called()
