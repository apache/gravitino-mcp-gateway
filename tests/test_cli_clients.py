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
from subprocess import CompletedProcess

import pytest

from mcp_gateway_cli import auth, clients

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
