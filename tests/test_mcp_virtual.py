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

"""Virtual servers: several catalog servers behind one /mcp/<ID> endpoint."""

import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from mcp_gateway.config import settings
from mcp_gateway.models import AuditLog, MCPCatalog, MCPVirtualMember, MCPVirtualServer
from mcp_gateway.routes import mcp_server

ADMIN = "/api/v1/admin/mcp-virtual"
URLS = {"trino": "http://trino-mcp/mcp", "slack": "http://slack-mcp/mcp"}


def _server(db, service_id, **fields):
    mcp = MCPCatalog(
        service_id=service_id,
        name=service_id.title(),
        mcp_url=URLS.get(service_id, f"http://{service_id}-mcp/mcp"),
        requires_approval=fields.pop("requires_approval", False),
        **fields,
    )
    db.add(mcp)
    db.commit()
    return mcp


def _virtual(db, members, service_id="all", **fields):
    """A virtual server; ``members`` are (catalog server, prefix) pairs."""
    virtual = MCPVirtualServer(service_id=service_id, name="Everything", **fields)
    virtual.members = [
        MCPVirtualMember(mcp_id=mcp.id, tool_prefix=prefix) for mcp, prefix in members
    ]
    db.add(virtual)
    db.commit()
    return virtual


def _rpc(method, params=None, rid=1):
    body = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        body["params"] = params
    return body


def _message(resp):
    if not resp.headers["content-type"].startswith("text/event-stream"):
        return resp.json()
    data = [line[6:] for line in resp.text.splitlines() if line.startswith("data: ")]
    return json.loads(data[-1])


@pytest.fixture(name="servers")
def fixture_servers(db_session):
    return _server(db_session, "trino"), _server(db_session, "slack")


@pytest.fixture(name="upstream")
def fixture_upstream(monkeypatch):
    """The MCP servers: each answers tools/list with its tools, and calls with its URL."""
    tools = {
        URLS["trino"]: ["query", "explain"],
        URLS["slack"]: ["post", "search"],
    }
    backend = MagicMock()

    async def post(
        url, json=None, headers=None
    ):  # pylint: disable=redefined-outer-name
        body = json
        if body["method"] == "tools/list":
            result = {"tools": [{"name": n} for n in tools[url]]}
        else:
            result = {"content": [{"text": f"{url} {body['params']['name']}"}]}
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": body["id"], "result": result},
            request=httpx.Request("POST", url),
        )

    backend.post = AsyncMock(side_effect=post)
    backend.tools = tools
    monkeypatch.setattr(mcp_server, "_get_mcp_http_client", lambda: backend)
    return backend


@pytest.fixture(name="person")
def fixture_person(as_user, regular_user, monkeypatch):
    tokens = MagicMock()
    tokens.get_token = AsyncMock(return_value="backend-token")
    monkeypatch.setattr(mcp_server, "TokenManager", lambda db: tokens)
    return as_user(regular_user)


def _names(resp):
    return [t["name"] for t in resp.json()["result"]["tools"]]


def _calls(backend, method):
    return [
        (c.args[0], c.kwargs["json"])
        for c in backend.post.await_args_list
        if c.kwargs["json"].get("method") == method
    ]


# ---------------------------------------------------------------------------
# The proxy
# ---------------------------------------------------------------------------


def test_tools_list_merges_the_members_tools_under_their_prefixes(
    client, person, servers, db_session, upstream
):
    trino, slack = servers
    _virtual(db_session, [(trino, "trino_"), (slack, "")])

    resp = client.post("/mcp/all", json=_rpc("tools/list"))

    assert resp.status_code == 200
    assert _names(resp) == ["trino_query", "trino_explain", "post", "search"]
    assert upstream is not None


def test_tools_call_goes_to_the_member_with_the_prefix_removed(
    client, person, servers, db_session, upstream
):
    trino, slack = servers
    _virtual(db_session, [(trino, "trino_"), (slack, "slack_")])

    resp = client.post("/mcp/all", json=_rpc("tools/call", {"name": "slack_post"}))

    assert _message(resp)["result"]["content"][0]["text"].endswith("slack-mcp/mcp post")
    ((url, body),) = _calls(upstream, "tools/call")
    assert (url, body["params"]["name"]) == (URLS["slack"], "post")
    # The audit row names the member server and its own tool name.
    row = db_session.query(AuditLog).filter_by(method="tools/call").one()
    assert (row.service, row.tool_name) == ("slack", "post")


def test_the_longest_matching_prefix_routes_a_call(
    client, person, servers, db_session, upstream
):
    trino, slack = servers
    _virtual(db_session, [(trino, "a_"), (slack, "a_b_")])

    client.post("/mcp/all", json=_rpc("tools/call", {"name": "a_b_post"}))

    ((url, body),) = _calls(upstream, "tools/call")
    assert (url, body["params"]["name"]) == (URLS["slack"], "post")


def test_a_call_no_member_claims_is_refused(
    client, person, servers, db_session, upstream
):
    trino, slack = servers
    _virtual(db_session, [(trino, "trino_"), (slack, "slack_")])

    resp = client.post("/mcp/all", json=_rpc("tools/call", {"name": "query"}))

    assert resp.json()["error"]["code"] == -32601
    assert not _calls(upstream, "tools/call")


def test_a_member_the_caller_may_not_use_is_left_out_and_not_callable(
    client, person, servers, db_session, upstream
):
    trino, slack = servers
    slack.requires_approval = True
    db_session.commit()
    _virtual(db_session, [(trino, "trino_"), (slack, "slack_")])

    listed = client.post("/mcp/all", json=_rpc("tools/list"))
    called = client.post("/mcp/all", json=_rpc("tools/call", {"name": "slack_post"}))

    assert _names(listed) == ["trino_query", "trino_explain"]
    assert called.json()["error"]["code"] == -32002
    assert [url for url, _ in _calls(upstream, "tools/call")] == []


@pytest.mark.parametrize(
    "change", [{"admin_only": True}, {"is_active": False}], ids=["hidden", "inactive"]
)
def test_a_hidden_or_inactive_member_is_left_out(
    client, person, servers, db_session, upstream, change
):
    trino, slack = servers
    for name, value in change.items():
        setattr(slack, name, value)
    db_session.commit()
    _virtual(db_session, [(trino, "trino_"), (slack, "slack_")])

    resp = client.post("/mcp/all", json=_rpc("tools/list"))

    assert _names(resp) == ["trino_query", "trino_explain"]
    assert [url for url, _ in _calls(upstream, "tools/list")] == [URLS["trino"]]


def test_a_members_tool_filter_still_applies(
    client, person, servers, db_session, upstream, monkeypatch
):
    trino, slack = servers
    monkeypatch.setattr(settings, "MCP_TOOL_FILTERS", {"trino": ["query"]})
    _virtual(db_session, [(trino, "trino_"), (slack, "slack_")])

    listed = client.post("/mcp/all", json=_rpc("tools/list"))
    called = client.post("/mcp/all", json=_rpc("tools/call", {"name": "trino_explain"}))

    assert _names(listed) == ["trino_query", "slack_post", "slack_search"]
    assert called.json()["error"]["code"] == -32601
    assert not _calls(upstream, "tools/call")


def test_a_member_that_fails_does_not_hide_the_others(
    client, person, servers, db_session, upstream
):
    trino, slack = servers
    _virtual(db_session, [(trino, "trino_"), (slack, "slack_")])
    real = upstream.post.side_effect

    async def flaky(url, **kwargs):
        if url == URLS["slack"]:
            raise httpx.ConnectError("down")
        return await real(url, **kwargs)

    upstream.post.side_effect = flaky

    resp = client.post("/mcp/all", json=_rpc("tools/list"))

    assert _names(resp) == ["trino_query", "trino_explain"]
    rows = {r.service: r.status for r in db_session.query(AuditLog).all()}
    assert rows == {"trino": "success", "slack": "error"}


def test_a_duplicate_tool_name_across_members_is_refused(
    client, person, servers, db_session, upstream
):
    trino, slack = servers
    # Unprefixed trino offers "s_post", which slack's "post" also becomes.
    upstream.tools[URLS["trino"]] = ["s_post"]
    _virtual(db_session, [(trino, ""), (slack, "s_")])

    resp = client.post("/mcp/all", json=_rpc("tools/list"))

    assert resp.json()["error"]["code"] == -32000
    assert "s_post" in resp.json()["error"]["message"]


def test_a_virtual_server_that_is_inactive_or_unknown_is_not_found(
    client, person, servers, db_session, upstream
):
    trino, _ = servers
    _virtual(db_session, [(trino, "")], is_active=False)

    for path in ("/mcp/all", "/mcp/nope"):
        assert client.post(path, json=_rpc("tools/list")).status_code == 404
    assert client.get("/mcp/all").status_code == 404
    assert upstream.post.await_count == 0


def test_initialize_and_ping_are_answered_by_the_gateway(
    client, person, servers, db_session, upstream
):
    trino, _ = servers
    _virtual(db_session, [(trino, "")])

    init = client.post("/mcp/all", json=_rpc("initialize"))
    session = init.headers["mcp-session-id"]
    ping = client.post(
        "/mcp/all", json=_rpc("ping"), headers={"Mcp-Session-Id": session}
    )
    other = client.post(
        "/mcp/all", json=_rpc("resources/list"), headers={"Mcp-Session-Id": session}
    )

    assert init.json()["result"]["capabilities"] == {"tools": {}}
    assert ping.json()["result"] == {}
    assert other.json()["error"]["code"] == -32601
    assert upstream.post.await_count == 0


def test_a_session_of_one_server_is_not_valid_for_the_virtual_server(
    client, person, servers, db_session, upstream
):
    trino, _ = servers
    _virtual(db_session, [(trino, "")])
    session = client.post("/mcp/trino", json=_rpc("initialize")).headers[
        "mcp-session-id"
    ]

    resp = client.post(
        "/mcp/all", json=_rpc("tools/list"), headers={"Mcp-Session-Id": session}
    )

    assert resp.status_code == 404
    assert upstream is not None


def test_each_member_keeps_its_own_upstream_session(
    client, person, servers, db_session, upstream
):
    """Sessions stay per user and member server, shared with direct use."""
    trino, slack = servers
    _virtual(db_session, [(trino, "trino_"), (slack, "slack_")])

    client.post("/mcp/all", json=_rpc("tools/list"))

    inits = _calls(upstream, "initialize")
    assert sorted(url for url, _ in inits) == sorted(URLS.values())


def test_a_server_id_cannot_be_used_by_both_a_server_and_a_virtual_server(
    client, as_user, admin_user, servers, db_session
):
    trino, _ = servers
    _virtual(db_session, [(trino, "")], service_id="shared")
    as_user(admin_user)

    resp = client.post(
        "/api/v1/admin/mcp/",
        json={"service_id": "shared", "name": "Shared", "mcp_url": "http://x/mcp"},
    )

    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# The admin API
# ---------------------------------------------------------------------------


def _create(client, members, service_id="all"):
    return client.post(
        ADMIN + "/",
        json={"service_id": service_id, "name": "Everything", "members": members},
    )


def test_an_admin_creates_lists_updates_and_deletes_a_virtual_server(
    client, as_user, admin_user, servers, db_session
):
    as_user(admin_user)

    created = _create(
        client,
        [
            {"service_id": "trino", "tool_prefix": "trino_"},
            {"service_id": "slack", "tool_prefix": "slack_"},
        ],
    )
    listed = client.get(ADMIN + "/")
    updated = client.patch(
        ADMIN + "/all",
        json={"members": [{"service_id": "slack", "tool_prefix": "s_"}]},
    )
    deleted = client.delete(ADMIN + "/all")

    assert created.status_code == 201
    assert [m["service_id"] for m in created.json()["members"]] == ["trino", "slack"]
    assert [v["service_id"] for v in listed.json()] == ["all"]
    assert updated.json()["members"] == [{"service_id": "slack", "tool_prefix": "s_"}]
    assert deleted.status_code == 204
    assert db_session.query(MCPVirtualServer).count() == 0
    assert db_session.query(MCPVirtualMember).count() == 0
    actions = {
        r.tool_name for r in db_session.query(AuditLog).filter_by(method="admin")
    }
    assert actions == {
        "create_virtual_server",
        "update_virtual_server",
        "delete_virtual_server",
    }


def test_only_admins_manage_virtual_servers(client, person, servers):
    assert _create(client, [{"service_id": "trino"}]).status_code == 403


@pytest.mark.parametrize(
    "members, service_id, status",
    [
        ([], "all", 422),
        ([{"service_id": "nope"}], "all", 422),
        ([{"service_id": "trino"}, {"service_id": "trino"}], "all", 422),
        (
            [
                {"service_id": "trino", "tool_prefix": "a_"},
                {"service_id": "slack", "tool_prefix": "a_"},
            ],
            "all",
            422,
        ),
        (
            [
                {"service_id": "trino", "tool_prefix": ""},
                {"service_id": "slack", "tool_prefix": ""},
            ],
            "all",
            422,
        ),
        ([{"service_id": "trino", "tool_prefix": "bad prefix"}], "all", 422),
        ([{"service_id": "trino"}], "trino", 409),
    ],
    ids=[
        "no-members",
        "unknown-member",
        "member-twice",
        "same-prefix",
        "two-unprefixed",
        "bad-prefix",
        "id-of-a-server",
    ],
)
def test_a_virtual_server_that_would_clash_is_rejected(
    client, as_user, admin_user, servers, members, service_id, status
):
    as_user(admin_user)

    assert _create(client, members, service_id).status_code == status


def test_deleting_a_server_takes_it_out_of_virtual_servers(
    client, as_user, admin_user, servers, db_session
):
    trino, slack = servers
    _virtual(db_session, [(trino, "t_"), (slack, "s_")])
    as_user(admin_user)

    assert client.delete("/api/v1/admin/mcp/slack").status_code == 204

    assert [m.mcp_id for m in db_session.query(MCPVirtualMember)] == [trino.id]
