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

"""Tests for mcp_gateway.routes.mcp_catalog: the servers a caller can see."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from mcp_gateway.models import MCPCatalog, OAuthToken, ServiceAccountCredentials

CATALOG = "/api/catalog/mcps"


def _mcp(db, service_id, **overrides):
    fields = {
        "service_id": service_id,
        "name": service_id.title(),
        "mcp_url": f"http://{service_id}-mcp:8080/mcp",
        "is_active": True,
        "admin_only": False,
        "requires_approval": False,
        **overrides,
    }
    db.add(MCPCatalog(**fields))
    db.commit()


def _ids(client, **params):
    return {m["service_id"] for m in client.get(CATALOG, params=params).json()}


@pytest.mark.parametrize(
    "caller,expected",
    [("regular_user", {"trino"}), ("admin_user", {"trino", "secret"})],
)
def test_only_admins_see_admin_only_servers(
    client, db_session, as_user, request, caller, expected
):
    _mcp(db_session, "trino")
    _mcp(db_session, "secret", admin_only=True)
    _mcp(db_session, "old", is_active=False)
    as_user(request.getfixturevalue(caller))

    assert _ids(client) == expected


def test_the_catalog_can_be_filtered_by_category(
    client, db_session, regular_user, as_user
):
    _mcp(db_session, "trino", category="data")
    _mcp(db_session, "slack", category="communication")
    as_user(regular_user)

    assert _ids(client, category="data") == {"trino"}


@pytest.mark.parametrize(
    "expires_in,refresh,expired",
    [
        (timedelta(hours=1), None, False),
        (-timedelta(hours=1), None, True),
        # The gateway refreshes it on the next call, so there is nothing to reconnect.
        (-timedelta(hours=1), "enc-refresh", False),
    ],
    ids=["valid", "expired", "expired-but-refreshable"],
)
def test_a_token_marks_its_server_connected_and_says_whether_it_expired(
    client, db_session, regular_user, as_user, expires_in, refresh, expired
):
    _mcp(db_session, "trino")
    _mcp(db_session, "hive")
    db_session.add(
        OAuthToken(
            user_id=regular_user.id,
            service="trino",
            access_token_encrypted="enc",
            refresh_token_encrypted=refresh,
            expires_at=datetime.utcnow() + expires_in,
        )
    )
    db_session.commit()
    as_user(regular_user)

    entries = {m["service_id"]: m for m in client.get(CATALOG).json()}

    assert (entries["trino"]["connected"], entries["trino"]["token_expired"]) == (
        True,
        expired,
    )
    assert entries["hive"]["connected"] is False


def test_a_service_account_sees_only_the_servers_its_registration_lists(
    client, db_session, service_account, as_user
):
    _mcp(db_session, "trino")
    _mcp(db_session, "hive")
    _mcp(db_session, "secret", admin_only=True)
    db_session.add(
        ServiceAccountCredentials(
            service_account_id=service_account.id,
            provider="google",
            service_account_name="svc@test.iam.gserviceaccount.com",
            allowed_services=["trino"],
            created_by=service_account.id,
        )
    )
    db_session.commit()
    as_user(service_account)

    (entry,) = client.get(CATALOG).json()

    assert (entry["service_id"], entry["connected"]) == ("trino", True)


_SERVER_CONFIG = {
    "mcp_url": "https://internal.example.com/mcp",
    "oauth_scopes": "internal:read",
    "oauth_client_id": "internal-client",
    "oauth_metadata_url": "https://auth.example.com/.well-known/oauth-authorization-server",
    "basic_auth_username": "svc-user",
}


@pytest.mark.parametrize("caller", ["regular_user", "admin_user"])
def test_the_catalog_never_says_how_the_gateway_reaches_a_server(
    client, db_session, as_user, request, caller
):
    """Admins read server configuration from /api/admin/mcp."""
    _mcp(db_session, "trino", **_SERVER_CONFIG)
    as_user(request.getfixturevalue(caller))

    (server,) = client.get(CATALOG).json()

    assert not set(_SERVER_CONFIG) & set(server)
