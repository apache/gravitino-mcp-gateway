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

"""The MCP proxy (mcp_gateway.routes.mcp_server): who may call a server, how the
gateway signs in to it, and what the caller gets back.

test_mcp_sessions.py covers the transport: the requests' framing, initialize,
session IDs, GET and DELETE.
"""

import asyncio
import base64
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt as pyjwt
import pytest
from sqlalchemy.exc import IntegrityError

from mcp_gateway.audit import CANCELLED
from mcp_gateway.config import settings
from mcp_gateway.models import (
    AuditLog,
    MCPCatalog,
    MCPUserPermission,
    ServiceAccountCredentials,
)
from mcp_gateway.routes import mcp_server
from mcp_gateway.routes.mcp_tasks import wrap_task_ids
from tests.request_utils import make_starlette_request

# Headers the gateway itself sets on every call to a server.
GATEWAY_HEADERS = {"Authorization", "Content-Type", "Accept"}
SSE = "text/event-stream"


def _jsonrpc(method, params=None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    return body


def _tool_call(name="execute_query"):
    return _jsonrpc("tools/call", {"name": name})


def _reply(payload, *, content_type="application/json", status=200):
    """An MCP server's reply; a string payload is sent as it is."""
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return httpx.Response(
        status,
        headers={"Content-Type": content_type},
        content=text.encode(),
        request=httpx.Request("POST", "http://trino-mcp:8080/mcp"),
    )


def _result(result):
    return _reply({"jsonrpc": "2.0", "id": 1, "result": result})


def _error(message):
    return _reply(
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": message}}
    )


def _message(resp):
    """The JSON-RPC message the gateway answered with: JSON, or SSE for a tool call."""
    if not resp.headers["content-type"].startswith(SSE):
        return resp.json()
    data = [line[6:] for line in resp.text.splitlines() if line.startswith("data: ")]
    return json.loads(data[-1])


def _sent(backend, method):
    """The headers of the call that carried ``method`` to the server, or None."""
    for call in backend.post.await_args_list:
        if call.kwargs["json"].get("method") == method:
            return call.kwargs["headers"]
    return None


def _register(db, service_account, allowed):
    db.add(
        ServiceAccountCredentials(
            service_account_id=service_account.id,
            provider="google",
            service_account_name="svc-test@example.iam.gserviceaccount.com",
            allowed_services=allowed,
            created_by=service_account.id,
        )
    )
    db.commit()


@pytest.fixture(name="upstream")
def fixture_upstream(monkeypatch):
    """Stand in for the MCP server, which answers every POST with ``reply``.

    ``reply`` is a response, or an exception to raise or a function to call instead.
    """

    def _install(reply=None):
        reply = _result({"tools": []}) if reply is None else reply
        backend = MagicMock()
        if isinstance(reply, httpx.Response):
            backend.post = AsyncMock(return_value=reply)
        else:
            backend.post = AsyncMock(side_effect=reply)
        monkeypatch.setattr(mcp_server, "_get_mcp_http_client", lambda: backend)
        return backend

    return _install


@pytest.fixture(name="_connected")
def fixture_connected(monkeypatch):
    """The caller has a token for the server, so OAuth servers can be called."""
    tokens = MagicMock()
    tokens.get_token = AsyncMock(return_value="backend-token")
    monkeypatch.setattr(mcp_server, "TokenManager", lambda db: tokens)


@pytest.fixture(name="person")
def fixture_person(as_user, regular_user, _connected):
    """A person signed in to the gateway and connected to the server."""
    return as_user(regular_user)


# ---------------------------------------------------------------------------
# Who may call a server
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("verb", ["GET", "POST"])
@pytest.mark.parametrize(
    "path, change",
    [
        ("/mcp/no-such-service", {}),
        ("/mcp/trino", {"is_active": False}),
        ("/mcp/trino", {"admin_only": True}),
    ],
    ids=["unknown", "inactive", "admin-only"],
)
def test_a_server_the_caller_may_not_see_is_not_found(
    client, person, mcp_entry, db_session, upstream, verb, path, change
):
    for name, value in change.items():
        setattr(mcp_entry, name, value)
    db_session.commit()
    backend = upstream()

    resp = client.request(verb, path, json=_jsonrpc("tools/list"))

    assert resp.status_code == 404
    backend.post.assert_not_awaited()


def test_an_admin_can_use_an_admin_only_server(
    client, as_user, admin_user, _connected, mcp_entry, db_session, upstream
):
    mcp_entry.admin_only = True
    db_session.commit()
    upstream()
    as_user(admin_user)

    resp = client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    assert resp.json()["result"] == {"tools": []}


def test_a_server_id_in_another_case_is_not_found(
    client, person, mcp_entry, db_session, upstream, monkeypatch
):
    """MySQL matches IDs without regard to case; tool filters and grants don't."""
    real_query = db_session.query
    case_insensitive = MagicMock()
    case_insensitive.filter.return_value = case_insensitive
    case_insensitive.first.return_value = mcp_entry
    monkeypatch.setattr(
        db_session,
        "query",
        lambda model, *args: (
            case_insensitive if model is MCPCatalog else real_query(model, *args)
        ),
    )
    backend = upstream()

    resp = client.post("/mcp/TRINO", json=_tool_call())

    assert resp.status_code == 404
    assert _sent(backend, "tools/call") is None


@pytest.mark.parametrize(
    "allowed", [None, ["metastore"]], ids=["unregistered", "another-server"]
)
def test_a_service_account_is_refused_a_server_it_was_not_granted(
    client, as_user, service_account, mcp_entry, db_session, upstream, allowed
):
    if allowed is not None:
        _register(db_session, service_account, allowed)
    backend = upstream()
    as_user(service_account)

    resp = client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == -32002
    backend.post.assert_not_awaited()


def test_a_service_account_needs_no_approval_for_a_server_it_was_granted(
    client, as_user, service_account, mcp_entry, db_session, upstream
):
    """Its registration is the only gate; the people's permission table is not."""
    mcp_entry.requires_approval = True
    _register(db_session, service_account, ["trino"])
    backend = upstream()
    as_user(service_account)

    resp = client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    assert resp.json()["result"] == {"tools": []}
    assert _sent(backend, "tools/list") is not None


def test_an_open_server_grants_a_person_access_on_first_use(
    client, person, mcp_entry, db_session, upstream
):
    upstream()

    resp = client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    assert resp.json()["result"] == {"tools": []}
    (grant,) = db_session.query(MCPUserPermission).filter_by(user_id=person.id).all()
    # Granted by the system, so an auditor can tell it from an admin's grant.
    assert grant.mcp_id == mcp_entry.id
    assert grant.granted_by is None


def test_a_grant_another_request_recorded_first_is_used(
    client, person, mcp_entry, db_session, upstream, monkeypatch
):
    """Two replicas can race to record the same grant; the loser reads the winner's."""
    real_commit = db_session.commit

    def _commit_after_the_winner():
        monkeypatch.setattr(db_session, "commit", real_commit)
        db_session.rollback()
        db_session.add(MCPUserPermission(user_id=person.id, mcp_id=mcp_entry.id))
        real_commit()
        raise IntegrityError("duplicate", None, Exception("duplicate"))

    monkeypatch.setattr(db_session, "commit", _commit_after_the_winner)
    upstream()

    resp = client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    assert resp.json()["result"] == {"tools": []}


def test_a_person_without_access_to_a_closed_server_is_refused_and_audited(
    client, person, mcp_entry, db_session, upstream
):
    mcp_entry.requires_approval = True
    db_session.commit()
    backend = upstream()

    resp = client.post("/mcp/trino", json=_tool_call())

    # A JSON-RPC error with 200 OK, so clients don't start signing in.
    assert resp.status_code == 200
    assert resp.json()["error"]["code"] == -32002
    backend.post.assert_not_awaited()
    assert db_session.query(MCPUserPermission).count() == 0
    (row,) = db_session.query(AuditLog).all()
    assert (row.status, row.tool_name) == ("unauthorized", "execute_query")
    assert "Access denied" in row.error_message


@pytest.mark.parametrize(
    "requires_approval, is_refused",
    [(True, True), (False, False)],
    ids=["closed", "open"],
)
def test_an_expired_grant_refuses_a_person_only_on_a_closed_server(
    client, person, mcp_entry, db_session, upstream, requires_approval, is_refused
):
    """Open servers take no access requests, so an expired grant could not be renewed."""
    mcp_entry.requires_approval = requires_approval
    db_session.add(
        MCPUserPermission(
            user_id=person.id,
            mcp_id=mcp_entry.id,
            expires_at=datetime.utcnow() - timedelta(days=1),
        )
    )
    db_session.commit()
    upstream()

    resp = client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    assert ("expired" in json.dumps(resp.json())) is is_refused


# ---------------------------------------------------------------------------
# How the gateway signs in to the server
# ---------------------------------------------------------------------------


def test_a_passthrough_server_gets_a_token_the_gateway_signed_for_it_alone(
    client, person, mcp_entry, db_session, upstream
):
    """Audience binding stops a leaked token being replayed against another server."""
    mcp_entry.auth_type = "passthrough"
    db_session.commit()
    backend = upstream()

    client.post(
        "/mcp/trino",
        json=_jsonrpc("tools/list"),
        headers={"Authorization": "Bearer caller-own-token"},
    )

    token = _sent(backend, "tools/list")["Authorization"].removeprefix("Bearer ")
    claims = pyjwt.decode(token, options={"verify_signature": False})
    assert (claims["aud"], claims["sub"]) == ("trino", person.username)


@pytest.mark.parametrize(
    "username, password", [(None, None), ("gravitino-mcp", None), (None, "ciphertext")]
)
def test_a_half_configured_basic_server_is_not_called(
    client, person, mcp_entry, db_session, upstream, username, password
):
    """Half-configured either way must fail closed, not send a blank user."""
    mcp_entry.auth_type = "basic"
    mcp_entry.basic_auth_username = username
    mcp_entry.basic_auth_password_encrypted = password
    db_session.commit()
    backend = upstream()

    resp = client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    assert "Basic auth credentials not configured" in resp.json()["error"]["message"]
    backend.post.assert_not_awaited()


def test_a_basic_server_gets_the_decrypted_password(
    client, person, mcp_entry, db_session, upstream, monkeypatch
):
    mcp_entry.auth_type = "basic"
    mcp_entry.basic_auth_username = "gravitino-mcp"
    mcp_entry.basic_auth_password_encrypted = "ciphertext"
    db_session.commit()
    encryption = MagicMock()
    encryption.decrypt.side_effect = {"ciphertext": "s3cret"}.get
    monkeypatch.setattr(
        mcp_server, "get_token_encryption", AsyncMock(return_value=encryption)
    )
    backend = upstream()

    client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    expected = base64.b64encode(b"gravitino-mcp:s3cret").decode()
    assert _sent(backend, "tools/list")["Authorization"] == f"Basic {expected}"


def test_a_person_cannot_use_credential_forwarding(
    client, person, mcp_entry, db_session, upstream
):
    mcp_entry.auth_type = "credential_forward"
    db_session.commit()
    backend = upstream()

    resp = client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    assert resp.status_code == 403
    assert "only for service accounts" in resp.json()["error"]["message"]
    backend.post.assert_not_awaited()


def test_a_service_account_without_downstream_credentials_is_refused(
    client, as_user, service_account, mcp_entry, db_session, upstream, monkeypatch
):
    mcp_entry.service_auth_type = "credential_forward"
    _register(db_session, service_account, ["trino"])
    monkeypatch.setattr(
        mcp_server, "build_credential_forward_headers", AsyncMock(return_value=None)
    )
    backend = upstream()
    as_user(service_account)

    resp = client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    assert resp.status_code == 403
    assert "No downstream credentials" in resp.json()["error"]["message"]
    backend.post.assert_not_awaited()


def test_a_service_account_forwards_its_downstream_credentials(
    client, as_user, service_account, mcp_entry, db_session, upstream, monkeypatch
):
    mcp_entry.service_auth_type = "credential_forward"
    _register(db_session, service_account, ["trino"])
    monkeypatch.setattr(
        mcp_server,
        "build_credential_forward_headers",
        AsyncMock(return_value={"Authorization": "Bearer downstream-pat"}),
    )
    backend = upstream()
    as_user(service_account)

    client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    assert _sent(backend, "tools/list")["Authorization"] == "Bearer downstream-pat"


def test_a_person_not_connected_to_an_oauth_server_is_told_how_to_connect(
    client, as_user, regular_user, mcp_entry, upstream
):
    backend = upstream()
    as_user(regular_user)

    resp = client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    assert resp.json()["error"] == {
        "code": -32000,
        "message": "Not connected to trino. Please connect first using: "
        "gravitino-mcp connect trino",
    }
    backend.post.assert_not_awaited()


@pytest.mark.parametrize(
    "forward, sent, forwarded",
    [
        ("x-api-key", {"x-api-key": "Bearer sk-1"}, {"x-api-key": "Bearer sk-1"}),
        ("x-api-key", {"X-Api-Key": "  Bearer sk-1  "}, {"x-api-key": "Bearer sk-1"}),
        ("x-api-key", {"x-api-key": "   "}, {}),
        ("x-api-key", {"X-Custom-Secret": "leak", "Cookie": "session=1"}, {}),
        ("", {"x-api-key": "Bearer sk-1"}, {}),
    ],
)
def test_only_the_configured_caller_headers_reach_the_server(
    client, person, mcp_entry, upstream, monkeypatch, forward, sent, forwarded
):
    monkeypatch.setattr(settings, "MCP_FORWARD_HEADERS", forward)
    backend = upstream()

    client.post("/mcp/trino", json=_jsonrpc("tools/list"), headers=sent)

    headers = _sent(backend, "tools/list")
    assert {k: v for k, v in headers.items() if k not in GATEWAY_HEADERS} == forwarded
    # A caller's header never replaces the gateway's own credential.
    assert headers["Authorization"] == "Bearer backend-token"


# ---------------------------------------------------------------------------
# Tool filters
# ---------------------------------------------------------------------------


@pytest.fixture(name="list_tools_only")
def fixture_list_tools_only(monkeypatch):
    monkeypatch.setitem(settings.MCP_TOOL_FILTERS, "trino", ["list_"])


def test_a_tool_outside_the_filter_is_refused_and_audited(
    client, person, mcp_entry, db_session, upstream, list_tools_only
):
    backend = upstream()

    resp = client.post("/mcp/trino", json=_tool_call("drop_table"))

    assert resp.json()["error"]["code"] == -32601
    assert _sent(backend, "tools/call") is None
    (row,) = db_session.query(AuditLog).all()
    assert (row.status, row.tool_name) == ("unauthorized", "drop_table")


@pytest.mark.parametrize(
    "tool, is_called",
    # A prefix that only appears inside the name would let a caller name their way in.
    [("list_catalogs", True), ("evil_list_shim", False)],
)
def test_the_filter_matches_the_start_of_the_tool_name(
    client, person, mcp_entry, upstream, list_tools_only, tool, is_called
):
    backend = upstream()

    client.post("/mcp/trino", json=_tool_call(tool))

    assert (_sent(backend, "tools/call") is not None) is is_called


def test_a_tools_list_holds_only_the_tools_the_filter_allows(
    client, person, mcp_entry, upstream, list_tools_only
):
    tools = [{"name": "list_catalogs"}, {"name": "drop_table"}, "junk", {"name": 7}]
    upstream(_result({"tools": tools}))

    resp = client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    assert resp.json()["result"]["tools"] == [{"name": "list_catalogs"}]


# ---------------------------------------------------------------------------
# The server's reply
# ---------------------------------------------------------------------------

TIMED_OUT = f"Backend MCP timeout after {settings.MCP_TOOL_CALL_TIMEOUT}s"
UNREACHABLE = "Backend MCP connection error: the server could not be reached"
INVALID = "Backend MCP returned an invalid response"
UPSTREAM_FAILURES = [
    (httpx.TimeoutException("slow"), 504, -32000, TIMED_OUT),
    (_reply({}, status=503), 502, -32000, "Backend MCP error: 503"),
    (httpx.ConnectError("no route to mcp.corp.internal"), 502, -32000, UNREACHABLE),
    (_reply("data: still working\n\n", content_type=SSE), 502, -32000, INVALID),
    (RuntimeError("boom"), 500, -32603, "Internal error"),
]


@pytest.mark.parametrize("method", ["tools/list", "tools/call"])
@pytest.mark.parametrize(
    "failure, status, code, message",
    UPSTREAM_FAILURES,
    ids=["timeout", "http-error", "unreachable", "no-message", "unexpected"],
)
def test_a_failed_call_to_the_server_is_a_jsonrpc_error(
    client, person, mcp_entry, upstream, method, failure, status, code, message
):
    """A tool call's stream has begun, so its HTTP status stays 200.

    The error never holds the exception's text, which can name internal hosts.
    """
    upstream(failure)

    resp = client.post("/mcp/trino", json=_jsonrpc(method, {"name": "execute_query"}))

    assert resp.status_code == (200 if method == "tools/call" else status)
    assert _message(resp)["error"] == {"code": code, "message": message}


@pytest.mark.parametrize("method", ["tools/list", "tools/call"])
@pytest.mark.parametrize("field", ["data: ", "data:"])
def test_a_reply_sent_as_a_stream_is_unwrapped(
    client, person, mcp_entry, upstream, method, field
):
    """Servers interleave progress frames; only the JSON-RPC message counts.

    SSE lets a field's value follow the colon with or without a space."""
    upstream(
        _reply(
            f"{field}still working\n\n"
            f'{field}{{"jsonrpc": "2.0", "id": 1, "result": {{"rows": [[7]]}}}}\n\n',
            content_type=SSE,
        )
    )

    resp = client.post("/mcp/trino", json=_jsonrpc(method, {"name": "execute_query"}))

    assert _message(resp)["result"] == {"rows": [[7]]}


@pytest.mark.parametrize("method", ["tools/list", "tools/call"])
def test_an_empty_reply_is_an_error_with_the_requests_id(
    client, person, mcp_entry, upstream, method
):
    upstream(_reply(""))

    resp = client.post("/mcp/trino", json=_jsonrpc(method, {"name": "execute_query"}))

    assert _message(resp) == {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32603, "message": "Empty response from backend"},
    }


@pytest.mark.parametrize(
    "initialize, initializes",
    [(_result({}), 1), (_reply("", status=500), 2)],
    ids=["a server that keeps no session", "initialize failed"],
)
def test_a_server_that_keeps_no_session_is_initialized_once(
    client, person, mcp_entry, upstream, initialize, initializes
):
    """Initializing before every request doubled the calls to such servers."""

    def reply(
        url, json, headers
    ):  # pylint: disable=redefined-outer-name,unused-argument
        return initialize if json["method"] == "initialize" else _result({"tools": []})

    backend = upstream(reply)

    for _ in range(2):
        client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    methods = [call.kwargs["json"]["method"] for call in backend.post.await_args_list]
    assert methods.count("initialize") == initializes


@pytest.mark.parametrize("session_id", ["upstream-sid-1", None])
def test_the_servers_own_session_id_is_sent_when_it_has_one(
    client, person, mcp_entry, upstream, monkeypatch, session_id
):
    """External MCPs refuse calls that don't carry their handshake's session ID."""
    monkeypatch.setattr(
        mcp_server, "ensure_upstream_session", AsyncMock(return_value=session_id)
    )
    backend = upstream()

    client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    assert _sent(backend, "tools/list").get("Mcp-Session-Id") == session_id


# ---------------------------------------------------------------------------
# Audit and metrics
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body, tool_name, method, label",
    [
        (_tool_call("x-1"), "x-1", "tools/call", "tools/call"),
        (
            _jsonrpc("made-up/method-42"),
            "made-up/method-42",
            "made-up/method-42",
            "other",
        ),
    ],
)
def test_a_call_is_audited_by_what_was_called_and_counted_by_mcp_method(
    client, person, mcp_entry, db_session, upstream, body, tool_name, method, label
):
    """Callers choose tool names and methods, so metrics must not label by them."""
    upstream(_result({}))

    with patch("mcp_gateway.audit.record_tool_call") as record:
        client.post("/mcp/trino", json=body)

    (row,) = db_session.query(AuditLog).all()
    assert (row.tool_name, row.method, row.status) == (tool_name, method, "success")
    assert record.call_args.args[1] == label


# A server that refuses a tool call, as Gravitino does when it denies access,
# returns a result with isError set, not a JSON-RPC error.
TOOL_REFUSED = _result(
    {"isError": True, "content": [{"type": "text", "text": "ForbiddenException"}]}
)


@pytest.mark.parametrize(
    "body, reply, error",
    [
        (_tool_call(), TOOL_REFUSED, "ForbiddenException"),
        (_tool_call(), _error("syntax error"), "syntax error"),
        (_jsonrpc("tools/list"), _error("table not found"), "table not found"),
        # MCP servers can send anything; none of it may turn into a 500.
        (_jsonrpc("tools/list"), _reply({"id": 1, "error": "boom"}), "Unknown error"),
    ],
)
def test_a_call_the_server_failed_is_audited_as_an_error(
    client, person, mcp_entry, db_session, upstream, body, reply, error
):
    upstream(reply)

    client.post("/mcp/trino", json=body)

    (row,) = db_session.query(AuditLog).all()
    assert (row.status, row.error_message) == ("error", error)


def test_a_failed_audit_write_does_not_break_the_stream(
    client, person, mcp_entry, upstream
):
    upstream(_result({"rows": []}))

    with patch.object(
        mcp_server.AuditLogger,
        "log_tool_call",
        AsyncMock(side_effect=RuntimeError("audit db down")),
    ):
        resp = client.post("/mcp/trino", json=_tool_call())

    assert _message(resp)["result"] == {"rows": []}


# ---------------------------------------------------------------------------
# Long tool calls
# ---------------------------------------------------------------------------


def test_a_slow_tool_call_is_kept_alive_with_heartbeats(
    client, person, mcp_entry, upstream, monkeypatch
):
    """Load balancers cut idle connections in the middle of a long query."""
    real_wait = asyncio.wait
    timeouts = [None, None]

    async def _wait(tasks, timeout=None):
        if timeouts:
            timeouts.pop()
            return set(), set(tasks)
        return await real_wait(tasks, timeout=timeout)

    monkeypatch.setattr(mcp_server.asyncio, "wait", _wait)
    upstream(_result({"rows": []}))

    resp = client.post("/mcp/trino", json=_tool_call())

    assert resp.headers["content-type"].startswith(SSE)
    assert resp.text.count(": heartbeat") == 2
    assert _message(resp)["result"] == {"rows": []}


async def _never_returns(*args, **kwargs):
    await asyncio.sleep(30)


def test_a_stream_that_fails_cancels_the_call_to_the_server(
    client, person, mcp_entry, upstream, monkeypatch
):
    created = []
    real_create_task = asyncio.create_task

    def _record(coro, **kwargs):
        created.append(real_create_task(coro, **kwargs))
        return created[-1]

    async def _stream_dies(tasks, timeout=None):
        raise RuntimeError("client vanished")

    upstream(_never_returns)
    monkeypatch.setattr(
        mcp_server, "ensure_upstream_session", AsyncMock(return_value=None)
    )
    monkeypatch.setattr(mcp_server.asyncio, "create_task", _record)
    monkeypatch.setattr(mcp_server.asyncio, "wait", _stream_dies)

    with patch.object(mcp_server.AuditLogger, "log_tool_call", AsyncMock()):
        resp = client.post("/mcp/trino", json=_tool_call())

    assert _message(resp)["error"]["message"] == "Internal error"
    assert created[-1].cancelling() or created[-1].cancelled()


async def test_a_stream_the_client_leaves_is_audited_as_cancelled(
    regular_user, mcp_entry, upstream, monkeypatch
):
    """The call may still have run on the server, so the audit log must show it."""

    async def _still_waiting(tasks, timeout=None):
        return set(), set(tasks)

    upstream(_never_returns)
    monkeypatch.setattr(mcp_server.asyncio, "wait", _still_waiting)
    monkeypatch.setattr(mcp_server, "SessionLocal", MagicMock())

    with patch.object(mcp_server.AuditLogger, "log_tool_call", AsyncMock()) as logged:
        response = mcp_server._stream_tool_call(  # pylint: disable=protected-access
            body=_tool_call(),
            request_id=1,
            mcp=mcp_entry,
            auth_headers={},
            current_user=regular_user,
            method="tools/call",
            request=make_starlette_request(method="POST", path="/mcp/trino"),
        )
        stream = response.body_iterator
        assert await anext(stream) == ": heartbeat\n\n"
        await stream.aclose()

    kwargs = logged.await_args.kwargs
    assert (kwargs["status"], kwargs["error_message"]) == ("cancelled", CANCELLED)
    assert kwargs["tool_name"] == "execute_query"


def test_the_database_connection_is_released_while_the_server_works(
    client, person, mcp_entry, db_session, upstream
):
    """Long calls to servers must not hold database connections."""
    in_transaction = []

    async def _reply_later(*args, **kwargs):
        in_transaction.append(db_session.in_transaction())
        return _result({})

    upstream(_reply_later)

    resp = client.post("/mcp/trino", json=_jsonrpc("tools/list"))

    assert resp.status_code == 200
    assert in_transaction and not any(in_transaction)


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------


def _result_message(result):
    return {"jsonrpc": "2.0", "id": 1, "result": result}


def _created_task(client, upstream, task_id="srv-task-1", **task):
    """Run a task-augmented tool call; the task ID the caller is given."""
    upstream(_result({"task": {"taskId": task_id, "status": "working", **task}}))
    resp = client.post(
        "/mcp/trino", json=_jsonrpc("tools/call", {"name": "q", "task": {"ttl": 60000}})
    )
    return _message(resp)["result"]["task"]["taskId"]


def test_initialize_offers_tasks_for_tool_calls_and_cancel_but_not_list(client, person):
    resp = client.post("/mcp/trino", json=_jsonrpc("initialize"))

    tasks = resp.json()["result"]["capabilities"]["tasks"]
    assert tasks == {"requests": {"tools": {"call": {}}}, "cancel": {}}


def test_a_task_the_server_creates_gets_an_id_that_is_not_the_servers(
    client, person, mcp_entry, upstream
):
    backend = upstream(_result({"task": {"taskId": "srv-task-1", "status": "working"}}))

    resp = client.post(
        "/mcp/trino", json=_jsonrpc("tools/call", {"name": "q", "task": {"ttl": 1000}})
    )

    task = _message(resp)["result"]["task"]
    assert task["status"] == "working"
    assert task["taskId"] != "srv-task-1"
    # The server is sent the task request as it was.
    assert _sent(backend, "tools/call") is not None


@pytest.mark.parametrize("method", ["tasks/get", "tasks/cancel", "tasks/result"])
def test_a_task_request_reaches_the_server_under_its_own_id(
    client, person, mcp_entry, upstream, method
):
    backend = upstream(_result({"task": {"taskId": "srv-task-1", "status": "working"}}))
    task_id = _created_task(client, upstream)
    backend = upstream(_result({"taskId": "srv-task-1", "status": "completed"}))

    resp = client.post("/mcp/trino", json=_jsonrpc(method, {"taskId": task_id}))

    sent = [c.kwargs["json"] for c in backend.post.await_args_list]
    assert [m["params"] for m in sent if m["method"] == method] == [
        {"taskId": "srv-task-1"}
    ]
    assert resp.status_code == 200


@pytest.mark.parametrize("method", ["tasks/get", "tasks/cancel"])
def test_a_task_the_server_reports_keeps_the_callers_id(
    client, person, mcp_entry, upstream, method
):
    task_id = _created_task(client, upstream)
    upstream(_result({"taskId": "srv-task-1", "status": "completed"}))

    resp = client.post("/mcp/trino", json=_jsonrpc(method, {"taskId": task_id}))

    result = _message(resp)["result"]
    assert result["status"] == "completed"
    assert result["taskId"] != "srv-task-1"


def test_a_task_result_names_the_task_by_the_callers_id(
    client, person, mcp_entry, upstream
):
    task_id = _created_task(client, upstream)
    related = {"io.modelcontextprotocol/related-task": {"taskId": "srv-task-1"}}
    upstream(_result({"content": [], "_meta": related}))

    resp = client.post("/mcp/trino", json=_jsonrpc("tasks/result", {"taskId": task_id}))

    meta = _message(resp)["result"]["_meta"]
    assert meta["io.modelcontextprotocol/related-task"]["taskId"] != "srv-task-1"


def test_another_person_cannot_use_a_task(
    client, person, regular_user, mcp_entry, upstream
):
    someone_else = wrap_task_ids(
        _result_message({"task": {"taskId": "srv-task-1"}}),
        regular_user.id + 1000,
        "trino",
        "tools/call",
    )["result"]["task"]["taskId"]
    backend = upstream()

    resp = client.post(
        "/mcp/trino", json=_jsonrpc("tasks/get", {"taskId": someone_else})
    )

    assert _message(resp)["error"]["code"] == -32602
    assert _sent(backend, "tasks/get") is None


def test_a_task_cannot_be_used_on_another_server(
    client, person, mcp_entry, db_session, upstream
):
    task_id = _created_task(client, upstream)
    db_session.add(
        MCPCatalog(
            service_id="other",
            name="Other",
            description="Another server",
            mcp_url="http://other:8080/mcp",
            auto_sso_enabled=False,
            is_active=True,
            requires_approval=False,
        )
    )
    db_session.commit()
    backend = upstream()

    resp = client.post("/mcp/other", json=_jsonrpc("tasks/get", {"taskId": task_id}))

    assert _message(resp)["error"]["code"] == -32602
    assert _sent(backend, "tasks/get") is None


@pytest.mark.parametrize(
    "params", [{}, {"taskId": 7}, {"taskId": "srv-task-1"}, {"taskId": "a.b.c"}]
)
def test_an_unknown_task_is_refused_without_calling_the_server(
    client, person, mcp_entry, upstream, params
):
    backend = upstream()

    resp = client.post("/mcp/trino", json=_jsonrpc("tasks/get", params))

    assert _message(resp)["error"] == {"code": -32602, "message": "Unknown task"}
    assert _sent(backend, "tasks/get") is None


def test_a_session_id_is_not_a_task_id_and_a_task_id_is_not_a_session_id(
    client, person, regular_user, mcp_entry, upstream
):
    resp = client.post("/mcp/trino", json=_jsonrpc("initialize"))
    session_id = resp.headers["mcp-session-id"]
    task_id = _created_task(client, upstream)
    backend = upstream()

    as_task = client.post(
        "/mcp/trino", json=_jsonrpc("tasks/get", {"taskId": session_id})
    )
    as_session = client.post(
        "/mcp/trino",
        json=_jsonrpc("tools/list"),
        headers={"Mcp-Session-Id": task_id},
    )

    assert _message(as_task)["error"]["code"] == -32602
    assert as_session.status_code == 404
    assert backend.post.await_count == 0


def test_listing_tasks_is_not_supported(client, person, mcp_entry, upstream):
    backend = upstream()

    resp = client.post("/mcp/trino", json=_jsonrpc("tasks/list"))

    assert _message(resp)["error"]["code"] == -32601
    assert _sent(backend, "tasks/list") is None


def test_a_task_the_server_sends_without_an_id_is_not_passed_on(
    client, person, mcp_entry, upstream
):
    upstream(_result({"task": {"status": "working"}}))

    resp = client.post(
        "/mcp/trino", json=_jsonrpc("tools/call", {"name": "q", "task": {}})
    )

    assert "task" not in _message(resp)["result"]
