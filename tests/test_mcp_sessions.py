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

"""MCP's Streamable HTTP transport at the gateway: the requests' framing,
initialize, session IDs, notifications, and the GET and DELETE endpoints."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import jwt as pyjwt
import pytest

from mcp_gateway.config import settings
from mcp_gateway.routes import mcp_server

UNKNOWN_SESSION = {"detail": "Unknown or expired session. Please re-initialize."}


def _jsonrpc(method):
    return {"jsonrpc": "2.0", "id": 1, "method": method}


def _session(user_id, service="trino", *, ttl=3600, key=None):
    now = datetime.now(timezone.utc)
    claims = {
        "u": user_id,
        "s": service,
        "iat": now,
        "exp": now + timedelta(seconds=ttl),
    }
    return pyjwt.encode(claims, key or settings.JWT_SECRET_KEY, algorithm="HS256")


def _tampered(token):
    """``token`` with a changed signature.

    The signature's last base64url character carries only 4 bits, so changing
    it may leave the signature as it was; the first carries 6.
    """
    header, payload, signature = token.split(".")
    first = "A" if signature[0] != "A" else "B"
    return f"{header}.{payload}.{first}{signature[1:]}"


@pytest.fixture(name="person")
def fixture_person(as_user, regular_user):
    return as_user(regular_user)


@pytest.mark.parametrize(
    "content_type, content, status",
    [
        # A web page can send a cross-site text/plain POST without a preflight.
        ("text/plain", json.dumps(_jsonrpc("initialize")), 415),
        ("application/json; charset=utf-8", json.dumps(_jsonrpc("initialize")), 200),
        ("application/json", "this is not json", 400),
    ],
)
def test_only_a_body_declared_and_written_as_json_is_read(
    client, person, content_type, content, status
):
    resp = client.post(
        "/mcp/trino", content=content, headers={"Content-Type": content_type}
    )

    assert resp.status_code == status


@pytest.mark.parametrize(
    "body",
    [
        [_jsonrpc("tools/list")],
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": None},
        {"jsonrpc": "2.0", "id": 1, "method": 7},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": 7}},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}},
    ],
)
def test_a_malformed_request_is_refused_before_the_server_is_called(
    client, person, mcp_entry, monkeypatch, body
):
    server = MagicMock()
    monkeypatch.setattr(mcp_server, "_get_mcp_http_client", server)

    resp = client.post("/mcp/trino", json=body)

    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32600
    server.assert_not_called()


def test_initialize_needs_no_server_and_ignores_a_stale_session(client, person):
    """initialize is how a client recovers from a dead session."""
    resp = client.post(
        "/mcp/no-such-service",
        json=_jsonrpc("initialize"),
        headers={"Mcp-Session-Id": "stale-and-invalid"},
    )

    assert resp.json()["result"]["protocolVersion"] == "2025-03-26"
    claims = pyjwt.decode(
        resp.headers["mcp-session-id"], settings.JWT_SECRET_KEY, algorithms=["HS256"]
    )
    # Sessions cannot be revoked, so a bounded lifetime is the only limit.
    assert claims["exp"] - claims["iat"] <= 86400


def test_a_session_from_initialize_is_accepted_on_later_calls(
    client, person, mcp_entry
):
    initialized = client.post("/mcp/trino", json=_jsonrpc("initialize"))

    resp = client.post(
        "/mcp/trino",
        json=_jsonrpc("tools/list"),
        headers={"Mcp-Session-Id": initialized.headers["mcp-session-id"]},
    )

    assert resp.status_code == 200
    assert resp.json() != UNKNOWN_SESSION


NOT_THE_CALLERS = [
    pytest.param(lambda me: _session(me + 1), id="another-persons"),
    pytest.param(lambda me: _session(me, "metastore"), id="another-servers"),
    pytest.param(lambda me: _session(me, ttl=-1), id="expired"),
    pytest.param(lambda me: _session(me, key="another-key" * 4), id="another-key"),
    pytest.param(lambda me: _tampered(_session(me)), id="tampered"),
    pytest.param(lambda me: "not-a-jwt", id="not-a-token"),
]


@pytest.mark.parametrize("session", NOT_THE_CALLERS)
def test_a_session_that_is_not_the_callers_with_this_server_is_unknown(
    client, person, session
):
    resp = client.post(
        "/mcp/trino",
        json=_jsonrpc("tools/list"),
        headers={"Mcp-Session-Id": session(person.id)},
    )

    assert resp.status_code == 404
    assert resp.json() == UNKNOWN_SESSION


@pytest.mark.parametrize(
    "session, status",
    [
        pytest.param(lambda me: None, 400, id="none"),
        pytest.param(lambda me: "not-a-jwt", 404, id="not-a-token"),
        pytest.param(lambda me: _session(me + 1), 403, id="another-persons"),
        pytest.param(lambda me: _session(me, "metastore"), 403, id="another-servers"),
        pytest.param(_session, 200, id="own"),
    ],
)
def test_a_client_can_end_only_its_own_session(client, person, session, status):
    session_id = session(person.id)

    resp = client.delete(
        "/mcp/trino", headers={"Mcp-Session-Id": session_id} if session_id else {}
    )

    assert resp.status_code == status


def test_a_notification_is_accepted_without_a_reply(client, person):
    resp = client.post(
        "/mcp/trino", json={"jsonrpc": "2.0", "method": "notifications/initialized"}
    )

    assert resp.status_code == 202
    assert not resp.content


def test_get_says_the_gateway_pushes_no_messages(client, person, mcp_entry):
    resp = client.get("/mcp/trino")

    assert resp.status_code == 405
    assert resp.headers["allow"] == "POST, DELETE"
