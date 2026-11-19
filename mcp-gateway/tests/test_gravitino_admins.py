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
"""Gravitino's service admins are the gateway's admins too."""

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from mcp_gateway import gravitino_admins
from mcp_gateway.config import settings
from mcp_gateway.oauth_auth import sync_person

ALICE = "alice@example.com"


@pytest.fixture(autouse=True, name="_fresh_answers")
def fixture_fresh_answers():
    gravitino_admins.reset_cache()
    yield
    gravitino_admins.reset_cache()


@pytest.fixture(name="gravitino")
def fixture_gravitino(monkeypatch):
    """A Gravitino server whose /api/authn/me gives ``answer``: serviceAdmin, or an error.

    It is asked with the token the gateway sends Gravitino's MCP server for the
    person. Returns the requests it gets.
    """
    monkeypatch.setattr(settings, "GRAVITINO_URI", "http://gravitino.example:8090/")
    monkeypatch.setattr(settings, "ADMIN_EMAILS", "")
    manager = MagicMock()
    manager.get_user_oauth_token = AsyncMock(return_value="token-for-gravitino")
    monkeypatch.setattr(gravitino_admins, "TokenManager", lambda db: manager)
    calls = []

    def _serve(answer):
        async def _get(url, headers):
            calls.append((url, headers))
            if isinstance(answer, Exception):
                raise answer
            return httpx.Response(
                200,
                json={"code": 0, "principal": "alice", "serviceAdmin": answer},
                request=httpx.Request("GET", url),
            )

        client = MagicMock(get=_get)
        acm = MagicMock()
        acm.__aenter__ = AsyncMock(return_value=client)
        acm.__aexit__ = AsyncMock(return_value=False)
        monkeypatch.setattr(gravitino_admins.httpx, "AsyncClient", lambda **kw: acm)
        return calls

    return _serve


async def test_gravitino_is_asked_with_the_token_for_its_mcp_server(
    db_session, gravitino
):
    calls = gravitino(True)

    await sync_person(db_session, {"email": ALICE}, ALICE, "user-token")

    [(url, headers)] = calls
    assert url == "http://gravitino.example:8090/api/authn/me"
    assert headers["Authorization"] == "Bearer token-for-gravitino"


@pytest.mark.parametrize(
    "answer, is_admin",
    [(True, True), (False, False), (httpx.ConnectError("refused"), False)],
    ids=["a service admin", "not one", "gravitino unreachable"],
)
async def test_gravitinos_answer_decides_and_is_reused_for_a_while(
    db_session, gravitino, answer, is_admin
):
    """An unreachable Gravitino would otherwise hold every request up for its timeout."""
    calls = gravitino(answer)

    for _ in range(3):
        user = await sync_person(db_session, {"email": ALICE}, ALICE, "user-token")

    assert user.is_admin is is_admin
    assert len(calls) == 1


@pytest.mark.parametrize(
    "setting, value", [("ADMIN_EMAILS", ALICE), ("GRAVITINO_URI", None)]
)
async def test_gravitino_is_not_asked_when_admin_emails_decide_or_it_isnt_set(
    db_session, gravitino, monkeypatch, setting, value
):
    calls = gravitino(False)
    monkeypatch.setattr(settings, setting, value)

    user = await sync_person(db_session, {"email": ALICE}, ALICE, "user-token")

    assert user.is_admin is (setting == "ADMIN_EMAILS")
    assert calls == []
