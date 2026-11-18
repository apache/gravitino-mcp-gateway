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

"""Tests for the CLI's requests to MCP servers, and the commands that use them."""

import importlib
import json
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from click.testing import CliRunner

from mcp_gateway_cli import mcp_client

# The package exports the click group as ``cli``, which hides the module.
cli_module = importlib.import_module("mcp_gateway_cli.cli")


class _Reply:
    """What requests.post returns, for a JSON or a server-sent-events body."""

    def __init__(self, body, *, status=200, sse=False):
        self.status_code = status
        self.headers = {
            "Content-Type": "text/event-stream" if sse else "application/json"
        }
        self._body = body

    def json(self):
        return json.loads(self._body)

    def iter_lines(self, decode_unicode=False):
        yield from self._body.splitlines()

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error")


class _Sent(list):
    """The requests made, and the reply the test sets for them."""

    reply = None


@pytest.fixture(name="posted")
def fixture_posted(monkeypatch):
    sent = _Sent()

    def _post(url, **kwargs):
        sent.append({"url": url, **kwargs})
        return sent.reply

    monkeypatch.setattr(mcp_client.requests, "post", _post)
    return sent


@pytest.fixture(name="signed_in")
def fixture_signed_in(monkeypatch):
    monkeypatch.setattr(cli_module, "get_access_token", lambda: "tok")
    monkeypatch.setattr(cli_module, "get_gateway_url", lambda: "https://gw")


def _run(*args):
    return CliRunner().invoke(cli_module.cli, list(args))


# ------------------------------------------------------------- mcp_client


def test_a_json_reply_gives_its_result(posted):
    posted.reply = _Reply('{"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}')

    result = mcp_client.request("https://gw", "tok", "gravitino", "tools/list")

    assert result == {"tools": []}
    assert posted[0]["url"] == "https://gw/mcp/gravitino"
    assert posted[0]["headers"]["Authorization"] == "Bearer tok"
    assert posted[0]["json"]["method"] == "tools/list"


def test_heartbeats_are_skipped_in_a_streamed_reply(posted):
    posted.reply = _Reply(
        ': heartbeat\n\n: heartbeat\nevent: message\ndata: {"id": 1, "result": 7}\n',
        sse=True,
    )

    assert mcp_client.request("https://gw", "tok", "s", "tools/call") == 7


@pytest.mark.parametrize("status", [200, 404])
def test_a_json_rpc_error_says_what_went_wrong(posted, status):
    """The gateway refuses access with HTTP 200, and unknown servers with 404."""
    posted.reply = _Reply(
        '{"id": 1, "error": {"code": -32002, "message": "Access denied."}}',
        status=status,
    )

    with pytest.raises(mcp_client.McpError, match="Access denied"):
        mcp_client.request("https://gw", "tok", "s", "tools/list")


def test_a_refused_token_raises_the_http_error(posted):
    posted.reply = _Reply('{"detail": "Invalid token"}', status=401)

    with pytest.raises(requests.HTTPError):
        mcp_client.request("https://gw", "tok", "s", "tools/list")


def test_the_server_id_cannot_change_the_path(posted):
    posted.reply = _Reply('{"result": {}}')

    mcp_client.request("https://gw", "tok", "../admin?x=1", "tools/list")

    assert posted[0]["url"] == "https://gw/mcp/..%2Fadmin%3Fx%3D1"


# --------------------------------------------------------------- commands


def test_tools_lists_each_tool_and_its_parameters(posted, signed_in):
    tool = {
        "name": "get_table",
        "description": "Load a table",
        "inputSchema": {"properties": {"name": {}}, "required": ["name"]},
    }
    posted.reply = _Reply(json.dumps({"result": {"tools": [tool]}}))

    result = _run("tools", "gravitino")

    assert result.exit_code == 0
    assert "get_table" in result.output
    assert "Required: name" in result.output


def test_call_sends_the_arguments_and_prints_the_text(posted, signed_in):
    posted.reply = _Reply(
        json.dumps({"result": {"content": [{"type": "text", "text": "catalog_a"}]}})
    )

    result = _run("call", "gravitino", "list", "--params", '{"limit": 1}')

    assert result.exit_code == 0
    assert "catalog_a" in result.output
    assert posted[0]["json"]["params"] == {"name": "list", "arguments": {"limit": 1}}


def test_call_reports_a_refusal_and_fails(posted, signed_in):
    posted.reply = _Reply('{"error": {"message": "Access denied."}}')

    result = _run("call", "gravitino", "list")

    assert result.exit_code == 1
    assert "Access denied." in result.output


def test_services_says_which_servers_need_connecting(monkeypatch, signed_in):
    servers = [
        {
            "service_id": service_id,
            "name": service_id,
            "auth_type": "oauth",
            "auto_sso_enabled": single_sign_on,
            "connected": False,
        }
        for service_id, single_sign_on in [("gravitino", True), ("docs", False)]
    ]
    monkeypatch.setattr(
        cli_module.requests, "get", lambda url, **kwargs: _Reply(json.dumps(servers))
    )

    result = _run("services")

    assert result.exit_code == 0
    assert "gravitino-mcp tools gravitino" in result.output
    assert "gravitino-mcp connect docs" in result.output


@pytest.mark.parametrize(
    "service,continues_at",
    [
        ("docs", "/portal/connect/docs"),
        # A service name cannot change where sign-in continues.
        ("../../admin?x=1", "/portal/connect/..%2F..%2Fadmin%3Fx%3D1"),
    ],
)
def test_connect_signs_in_and_then_connects_the_service(
    monkeypatch, signed_in, service, continues_at
):
    opened = []
    monkeypatch.setattr(
        cli_module.webbrowser, "open", lambda url: opened.append(url) or True
    )

    result = _run("connect", service)

    assert (result.exit_code, len(opened)) == (0, 1)
    parts = urlsplit(opened[0])
    assert (
        f"{parts.scheme}://{parts.netloc}{parts.path}" == "https://gw/auth/oauth/login"
    )
    assert parse_qs(parts.query)["next"] == [continues_at]
