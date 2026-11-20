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

"""Unit tests for mcp_gateway_cli.clients (multi-client config writers)."""

import json
from datetime import datetime, timedelta
from subprocess import CompletedProcess
from types import SimpleNamespace

import pytest
import requests
from click.testing import CliRunner

from mcp_gateway_cli import auth, clients, mcp_client
from mcp_gateway_cli.cli import cli as gravitino_mcp

URL = "http://localhost:8001/mcp/trino"
SERVERS = {"trino": URL}
FILE_CLIENTS = [
    (clients.configure_vscode, "servers", {"url": URL, "type": "http"}),
    (clients.configure_cursor, "mcpServers", {"url": URL}),
    (
        clients.configure_opencode,
        "mcp",
        {"type": "remote", "url": URL, "enabled": True},
    ),
]
CONFIGURE = pytest.mark.parametrize(
    "configure", [c[0] for c in FILE_CLIENTS], ids=["vscode", "cursor", "opencode"]
)


def _config(tmp_path, content):
    path = tmp_path / "client" / "mcp.json"
    path.parent.mkdir(parents=True)
    path.write_text(content)
    return path


def _claude(code_for_add=0):
    calls = []

    def runner(args, **kwargs):
        calls.append(args)
        code = code_for_add if args[2] == "add-json" else 0
        return CompletedProcess(args, code, stdout="", stderr="boom")

    return runner, calls


def test_merging_adds_our_servers_without_touching_the_original():
    existing = {"servers": {"other": {"url": "x"}, "trino": {"url": "old"}}, "x": 1}

    result = clients.merge_servers(existing, "servers", {"trino": {"url": "t"}})

    assert result == {"servers": {"other": {"url": "x"}, "trino": {"url": "t"}}, "x": 1}
    assert existing["servers"]["trino"] == {"url": "old"}


@pytest.mark.parametrize(
    "configure,key,entry", FILE_CLIENTS, ids=["vscode", "cursor", "opencode"]
)
def test_each_client_gets_its_own_entry_format_beside_its_other_servers(
    tmp_path, configure, key, entry
):
    original = json.dumps({key: {"keepme": {"url": "k"}}})
    path = _config(tmp_path, original)

    result = configure(SERVERS, path=path)

    assert result.ok
    assert json.loads(path.read_text())[key] == {"keepme": {"url": "k"}, "trino": entry}
    assert path.with_suffix(".json.bak").read_text() == original


@CONFIGURE
def test_a_client_that_is_not_installed_is_skipped(tmp_path, monkeypatch, configure):
    monkeypatch.setattr(clients.shutil, "which", lambda _: None)
    monkeypatch.setattr(clients, "_home", lambda: tmp_path)

    result = configure(SERVERS, path=tmp_path / "nope" / "mcp.json")

    assert result.status == clients.STATUS_SKIPPED


@CONFIGURE
def test_a_config_that_is_not_json_is_reported_and_left_alone(tmp_path, configure):
    path = _config(tmp_path, "{ not json")

    result = configure(SERVERS, path=path)

    assert result.status == clients.STATUS_ERROR
    assert path.read_text() == "{ not json"


def test_claude_code_is_skipped_when_its_cli_is_missing():
    result = clients.configure_claude_code(SERVERS, which=lambda _: None)

    assert result.status == clients.STATUS_SKIPPED


def test_claude_code_replaces_only_the_user_scope_entry():
    """Project and local scopes belong to whatever repo setup runs in."""
    runner, calls = _claude()

    result = clients.configure_claude_code(
        SERVERS, runner=runner, which=lambda _: "/usr/bin/claude"
    )

    assert result.ok
    assert [c for c in calls if c[2] == "remove"] == [
        ["claude", "mcp", "remove", "trino", "-s", "user"]
    ]
    (add,) = [c for c in calls if c[2] == "add-json"]
    assert add[-1] == "user"
    # headersHelper present so Claude Code skips OAuth discovery
    payload = json.loads(add[4])
    assert (payload["url"], payload["headersHelper"]) == (URL, "echo '{}'")


def test_claude_code_reports_a_failed_add():
    runner, _ = _claude(code_for_add=1)

    result = clients.configure_claude_code(
        SERVERS, runner=runner, which=lambda _: "/usr/bin/claude"
    )

    assert result.status == clients.STATUS_ERROR
    assert "boom" in result.detail


def test_setup_leaves_claude_desktops_config_alone(tmp_path, monkeypatch):
    """Claude Desktop's config holds only local servers; a URL entry can break it."""
    monkeypatch.setattr(clients, "_home", lambda: tmp_path)
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData"))
    original = {"mcpServers": {"local": {"command": "run-me"}}}
    configs = [
        tmp_path / "Library" / "Application Support" / "Claude",  # macOS
        tmp_path / "AppData" / "Claude",  # Windows
        tmp_path / ".config" / "Claude",  # Linux
    ]
    for folder in configs:
        folder.mkdir(parents=True)
        (folder / "claude_desktop_config.json").write_text(json.dumps(original))

    results = clients.configure_all(SERVERS)

    assert "Claude Desktop" not in [result.name for result in results]
    for folder in configs:
        config = folder / "claude_desktop_config.json"
        assert json.loads(config.read_text()) == original


@pytest.mark.parametrize(
    "url, secure",
    [
        ("https://mcp-gateway.example.com", True),
        ("http://localhost:8000", True),
        ("http://127.0.0.1:8000", True),
        ("http://mcp-gateway.example.com", False),
        ("ftp://mcp-gateway.example.com", False),
    ],
)
def test_tokens_go_only_to_an_https_gateway_or_this_machine(url, secure):
    """The device flow hands over the person's tokens, which plain http would expose."""
    assert auth.is_secure_gateway(url) is secure


@pytest.mark.parametrize(
    "configured, token",
    [
        (None, "access"),
        ("https://gw.example.com", "access"),
        ("https://other.example.com", None),
    ],
    ids=["no override", "the same gateway", "another gateway"],
)
def test_the_saved_token_goes_only_to_the_gateway_it_came_from(
    tmp_path, monkeypatch, configured, token
):
    monkeypatch.setattr(auth, "TOKEN_FILE", tmp_path / "tokens")
    auth.save_tokens("access", "refresh", "https://gw.example.com")
    if configured:
        monkeypatch.setenv("MCP_GATEWAY_URL", configured)
    else:
        monkeypatch.delenv("MCP_GATEWAY_URL", raising=False)

    assert auth.get_access_token() == token


def _signed_in(tmp_path, monkeypatch, lifetime, age):
    """A saved sign-in whose token lasts ``lifetime`` seconds and was issued ``age`` seconds ago."""
    token_file = tmp_path / "tokens"
    monkeypatch.setattr(auth, "TOKEN_FILE", token_file)
    monkeypatch.delenv("MCP_GATEWAY_URL", raising=False)
    auth.save_tokens("access", "refresh", "https://gw.example.com", lifetime)
    issued = datetime.utcnow() - timedelta(seconds=age)
    saved = json.loads(token_file.read_text())
    token_file.write_text(json.dumps({**saved, "created_at": issued.isoformat()}))


def _unreachable(*args, **kwargs):
    raise requests.ConnectionError("Connection refused")


@pytest.mark.parametrize(
    "lifetime, age, refreshed",
    [
        # Keycloak's tokens last 5 minutes, so a fresh one isn't refreshed yet.
        (300, 10, False),
        (300, 200, True),
        (3600, 3000, False),
        (3600, 3400, True),
    ],
)
def test_a_token_is_refreshed_only_in_the_last_part_of_its_life(
    tmp_path, monkeypatch, lifetime, age, refreshed
):
    _signed_in(tmp_path, monkeypatch, lifetime, age)
    refreshes = []
    monkeypatch.setattr(auth, "refresh_access_token", lambda: refreshes.append(1))

    auth.get_access_token()

    assert bool(refreshes) is refreshed


def test_an_unreachable_gateway_is_not_taken_for_a_sign_out(tmp_path, monkeypatch):
    monkeypatch.setattr(auth.requests, "post", _unreachable)

    # Due for a refresh, but still good: it's used.
    _signed_in(tmp_path, monkeypatch, 300, 200)
    assert auth.get_access_token() == "access"

    # Expired: the gateway is named, and the sign-in is kept for when it's back.
    _signed_in(tmp_path, monkeypatch, 300, 400)
    with pytest.raises(auth.GatewayUnreachable, match="https://gw.example.com"):
        auth.get_access_token()
    assert (tmp_path / "tokens").exists()


def test_the_cli_says_when_it_cant_reach_the_gateway(tmp_path, monkeypatch):
    monkeypatch.setattr(auth.requests, "post", _unreachable)
    _signed_in(tmp_path, monkeypatch, 300, 400)

    result = CliRunner().invoke(gravitino_mcp, ["services"])

    assert result.exit_code == 1
    assert "Cannot reach https://gw.example.com" in result.output
    assert "login" not in result.output


@pytest.mark.parametrize("opened", [True, False])
def test_login_says_that_the_browser_opened_only_when_it_did(
    tmp_path, monkeypatch, capsys, opened
):
    monkeypatch.setattr(auth, "TOKEN_FILE", tmp_path / "tokens")
    monkeypatch.setattr(
        auth,
        "request_device_code",
        lambda url: SimpleNamespace(
            device_code="device",
            user_code="ABCD-EFGH",
            verification_uri="https://gw.example.com/device",
            expires_in=600,
            interval=5,
        ),
    )
    monkeypatch.setattr(
        auth,
        "poll_device_token_until_done",
        lambda *args, **kwargs: SimpleNamespace(
            status=auth.PollStatus.EXPIRED, token_data=None
        ),
    )
    monkeypatch.setattr(auth.webbrowser, "open", lambda url: opened)

    auth.device_flow_login("https://gw.example.com")

    output = capsys.readouterr().out
    assert ("Browser opened automatically" in output) is opened
    assert ("Open the URL above in a browser" in output) is not opened


def test_a_call_says_when_it_cant_reach_the_gateway(tmp_path, monkeypatch):
    """A token that's still good doesn't need the gateway, until the call itself."""
    monkeypatch.setattr(mcp_client.requests, "post", _unreachable)
    _signed_in(tmp_path, monkeypatch, 300, 10)

    result = CliRunner().invoke(gravitino_mcp, ["call", "gravitino", "list_tools"])

    assert result.exit_code == 1
    assert result.output.strip() == (
        "Cannot reach https://gw.example.com. "
        "Check the URL and that your network can reach it."
    )
