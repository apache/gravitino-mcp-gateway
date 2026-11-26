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

"""Rate limits on /mcp/<server ID> (mcp_gateway.rate_limit): requests per window,
shared through the database, and concurrent calls, counted in the process."""

import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from prometheus_client import REGISTRY

from mcp_gateway import rate_limit
from mcp_gateway.config import settings
from mcp_gateway.models import AuditLog, MCPCatalog, RateLimitWindow
from mcp_gateway.purge import purge_expired_rows
from mcp_gateway.routes import mcp_server

NO_LIMITS = {
    "RATE_LIMIT_USER_REQUESTS": 0,
    "RATE_LIMIT_SERVER_REQUESTS": 0,
    "RATE_LIMIT_TOOL_REQUESTS": 0,
    "RATE_LIMIT_USER_CONCURRENT": 0,
    "RATE_LIMIT_SERVER_CONCURRENT": 0,
    "RATE_LIMIT_TOOL_CONCURRENT": 0,
    "RATE_LIMIT_WINDOW_SECONDS": 60,
}


@pytest.fixture(autouse=True, name="_unlimited")
def fixture_unlimited(monkeypatch):
    """Each test sets the limits it needs, with no calls in flight and a fixed clock."""
    for name, value in NO_LIMITS.items():
        monkeypatch.setattr(settings, name, value)
    monkeypatch.setattr(rate_limit, "_in_flight", {})
    monkeypatch.setattr(rate_limit, "_now", lambda: 1_000_000.0)


def _limit(monkeypatch, **limits):
    for name, value in limits.items():
        monkeypatch.setattr(settings, f"RATE_LIMIT_{name.upper()}", value)


def _refused(db, user, mcp, tool="execute_query"):
    """The RateLimited that admitting one more call raises, or None (the call is released)."""
    try:
        rate_limit.admit(user.id, mcp, tool).release()
    except rate_limit.RateLimited as refusal:
        return refusal
    return None


# ---------------------------------------------------------------------------
# Requests per window
# ---------------------------------------------------------------------------


def test_calls_over_the_user_limit_are_refused_with_the_wait(
    db_session, regular_user, mcp_entry, monkeypatch
):
    _limit(monkeypatch, user_requests=2)

    assert _refused(db_session, regular_user, mcp_entry) is None
    assert _refused(db_session, regular_user, mcp_entry) is None
    refusal = _refused(db_session, regular_user, mcp_entry)

    assert refusal.scope == "user"
    # The window started at a multiple of 60 s; 1,000,000 is 40 s into it.
    assert refusal.retry_after == 20
    assert "retry in 20" in refusal.message.lower()


def test_the_limit_resets_in_the_next_window(
    db_session, regular_user, mcp_entry, monkeypatch
):
    _limit(monkeypatch, user_requests=1)
    assert _refused(db_session, regular_user, mcp_entry) is None
    assert _refused(db_session, regular_user, mcp_entry) is not None

    monkeypatch.setattr(rate_limit, "_now", lambda: 1_000_020.0)

    assert _refused(db_session, regular_user, mcp_entry) is None


def test_the_user_limit_is_per_user(
    db_session, regular_user, admin_user, mcp_entry, monkeypatch
):
    _limit(monkeypatch, user_requests=1)
    assert _refused(db_session, regular_user, mcp_entry) is None

    assert _refused(db_session, admin_user, mcp_entry) is None


def test_the_server_limit_is_shared_by_everyone(
    db_session, regular_user, admin_user, mcp_entry, monkeypatch
):
    _limit(monkeypatch, server_requests=2)
    assert _refused(db_session, regular_user, mcp_entry) is None
    assert _refused(db_session, admin_user, mcp_entry) is None

    assert _refused(db_session, admin_user, mcp_entry).scope == "server"


def test_the_tool_limit_counts_one_tool_of_one_user(
    db_session, regular_user, mcp_entry, monkeypatch
):
    _limit(monkeypatch, tool_requests=1)
    assert _refused(db_session, regular_user, mcp_entry, "a") is None

    assert _refused(db_session, regular_user, mcp_entry, "a").scope == "tool"
    assert _refused(db_session, regular_user, mcp_entry, "b") is None
    # Methods other than tools/call have no tool, so no tool limit.
    assert _refused(db_session, regular_user, mcp_entry, None) is None


def test_a_server_can_override_the_defaults(
    db_session, regular_user, mcp_entry, monkeypatch
):
    _limit(monkeypatch, user_requests=1)
    mcp_entry.rate_limits = {"user_requests": 3}

    assert [_refused(db_session, regular_user, mcp_entry) for _ in range(3)] == [
        None
    ] * 3
    assert _refused(db_session, regular_user, mcp_entry).scope == "user"


def test_a_server_can_override_the_limit_of_one_tool(
    db_session, regular_user, mcp_entry, monkeypatch
):
    _limit(monkeypatch, tool_requests=5)
    mcp_entry.rate_limits = {"tools": {"execute_query": {"requests": 1}}}
    assert _refused(db_session, regular_user, mcp_entry) is None

    assert _refused(db_session, regular_user, mcp_entry).scope == "tool"
    assert _refused(db_session, regular_user, mcp_entry, "other") is None


def test_zero_in_the_catalog_lifts_a_default(
    db_session, regular_user, mcp_entry, monkeypatch
):
    _limit(monkeypatch, user_requests=1)
    mcp_entry.rate_limits = {"user_requests": 0}

    assert [_refused(db_session, regular_user, mcp_entry) for _ in range(5)] == [
        None
    ] * 5


def test_a_database_failure_lets_the_call_through(
    db_session, regular_user, mcp_entry, monkeypatch
):
    """The limiter must not take the gateway down with the database."""
    _limit(monkeypatch, user_requests=1)
    monkeypatch.setattr(rate_limit, "_hit", MagicMock(side_effect=RuntimeError("down")))

    assert _refused(db_session, regular_user, mcp_entry) is None


def test_old_windows_are_purged(db_session, monkeypatch):
    now = rate_limit._now()  # pylint: disable=protected-access
    db_session.add_all(
        [
            RateLimitWindow(key="a", window_start=int(now) - 7300, count=1),
            RateLimitWindow(key="b", window_start=int(now), count=1),
        ]
    )
    db_session.commit()

    purge_expired_rows(db_session)

    assert [w.key for w in db_session.query(RateLimitWindow).all()] == ["b"]


# ---------------------------------------------------------------------------
# Concurrent calls
# ---------------------------------------------------------------------------


def test_calls_over_the_concurrent_limit_are_refused_until_one_ends(
    db_session, regular_user, mcp_entry, monkeypatch
):
    _limit(monkeypatch, user_concurrent=2)
    first = rate_limit.admit(regular_user.id, mcp_entry, "t")
    rate_limit.admit(regular_user.id, mcp_entry, "t")

    refusal = _refused(db_session, regular_user, mcp_entry)
    assert (refusal.scope, refusal.retry_after) == ("user", 1)

    first.release()
    first.release()  # releasing twice frees nothing more
    assert _refused(db_session, regular_user, mcp_entry) is None
    assert _refused(db_session, regular_user, mcp_entry) is None


def test_a_refused_call_holds_no_slot(db_session, regular_user, mcp_entry, monkeypatch):
    _limit(monkeypatch, tool_concurrent=1, user_requests=1)
    held = rate_limit.admit(regular_user.id, mcp_entry, "a")
    held.release()

    assert _refused(db_session, regular_user, mcp_entry, "a").scope == "user"

    assert not any(rate_limit._in_flight.values())  # pylint: disable=protected-access


# ---------------------------------------------------------------------------
# On the endpoint
# ---------------------------------------------------------------------------


def _jsonrpc(method, params=None):
    return {"jsonrpc": "2.0", "id": 7, "method": method, "params": params or {}}


def _tool_call():
    return _jsonrpc("tools/call", {"name": "execute_query"})


@pytest.fixture(name="backend")
def fixture_backend(monkeypatch, regular_user, as_user):
    """A connected person and a server that answers every call."""
    tokens = MagicMock()
    tokens.get_token = AsyncMock(return_value="backend-token")
    monkeypatch.setattr(mcp_server, "TokenManager", lambda db: tokens)
    as_user(regular_user)
    reply = httpx.Response(
        200,
        headers={"Content-Type": "application/json"},
        content=json.dumps(
            {"jsonrpc": "2.0", "id": 7, "result": {"tools": []}}
        ).encode(),
        request=httpx.Request("POST", "http://trino-mcp:8080/mcp"),
    )
    upstream = MagicMock()
    upstream.post = AsyncMock(return_value=reply)
    monkeypatch.setattr(mcp_server, "_get_mcp_http_client", lambda: upstream)
    return upstream


def _count(name, labels):
    return REGISTRY.get_sample_value(name, labels) or 0.0


@pytest.mark.parametrize(
    "body", [_tool_call(), _jsonrpc("tools/list")], ids=["tool-call", "other-method"]
)
def test_a_call_over_the_limit_gets_a_429_and_never_reaches_the_server(
    client, backend, mcp_entry, monkeypatch, body
):
    _limit(monkeypatch, user_requests=1)
    assert client.post("/mcp/trino", json=body).status_code == 200
    sent = backend.post.await_count

    resp = client.post("/mcp/trino", json=body)

    assert resp.status_code == 429
    assert resp.headers["Retry-After"] == "20"
    error = resp.json()
    assert (error["id"], error["error"]["code"]) == (7, -32005)
    assert "rate limit" in error["error"]["message"].lower()
    assert backend.post.await_count == sent


def test_a_refused_call_is_audited_and_counted(
    client, backend, mcp_entry, db_session, monkeypatch
):
    _limit(monkeypatch, user_requests=1)
    labels = {"service": "trino", "scope": "user"}
    before = _count("mcp_gateway_rate_limited_total", labels)
    client.post("/mcp/trino", json=_tool_call())

    client.post("/mcp/trino", json=_tool_call())

    row = db_session.query(AuditLog).order_by(AuditLog.id.desc()).first()
    assert (row.status, row.tool_name, row.method) == (
        "rate_limited",
        "execute_query",
        "tools/call",
    )
    assert "rate limit" in row.error_message.lower()
    assert _count("mcp_gateway_rate_limited_total", labels) == before + 1


def test_initialize_is_not_limited(client, backend, mcp_entry, monkeypatch):
    _limit(monkeypatch, user_requests=1)
    client.post("/mcp/trino", json=_tool_call())

    resp = client.post("/mcp/trino", json=_jsonrpc("initialize"))

    assert resp.status_code == 200


def test_a_call_that_finishes_frees_its_slot(client, backend, mcp_entry, monkeypatch):
    _limit(monkeypatch, user_concurrent=1)

    statuses = [
        client.post("/mcp/trino", json=body).status_code
        for body in (_tool_call(), _jsonrpc("tools/list"), _tool_call())
    ]

    assert statuses == [200, 200, 200]


def test_a_call_that_fails_frees_its_slot(client, backend, mcp_entry, monkeypatch):
    _limit(monkeypatch, user_concurrent=1)
    backend.post.side_effect = httpx.ConnectError("down")

    for body in (_tool_call(), _jsonrpc("tools/list")):
        client.post("/mcp/trino", json=body)

    assert not any(rate_limit._in_flight.values())  # pylint: disable=protected-access


def test_a_call_while_the_limit_of_calls_in_flight_is_held_gets_a_429(
    client, backend, mcp_entry, regular_user, db_session, monkeypatch
):
    _limit(monkeypatch, user_concurrent=1)
    held = rate_limit.admit(regular_user.id, mcp_entry, "execute_query")

    resp = client.post("/mcp/trino", json=_tool_call())

    assert resp.status_code == 429
    assert resp.headers["Retry-After"] == "1"
    held.release()
    assert client.post("/mcp/trino", json=_tool_call()).status_code == 200


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------


def _new_server(**extra):
    return {
        "service_id": "limited",
        "name": "Limited",
        "mcp_url": "https://limited.example.com/mcp",
        "auth_type": "passthrough",
        **extra,
    }


def test_an_admin_sets_and_clears_a_servers_limits(
    client, as_user, admin_user, db_session
):
    as_user(admin_user)
    limits = {"user_requests": 5, "tools": {"execute_query": {"concurrent": 1}}}

    created = client.post("/api/v1/admin/mcp/", json=_new_server(rate_limits=limits))
    assert created.status_code == 201
    assert created.json()["rate_limits"] == limits

    cleared = client.patch("/api/v1/admin/mcp/limited", json={"rate_limits": None})
    assert cleared.json()["rate_limits"] is None
    assert MCPCatalog.find(db_session, "limited").rate_limits is None


@pytest.mark.parametrize(
    "limits",
    [
        {"user_requests": -1},
        {"unknown": 1},
        {"window_seconds": 5},
        {"tools": {"t": {"requests": "many"}}},
    ],
)
def test_limits_that_make_no_sense_are_refused(client, as_user, admin_user, limits):
    as_user(admin_user)

    resp = client.post("/api/v1/admin/mcp/", json=_new_server(rate_limits=limits))

    assert resp.status_code == 422
