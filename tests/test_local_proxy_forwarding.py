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

"""The CLI's local proxy: which requests it accepts, and what it forwards to the
gateway with which token.

The proxy adds the user's token to every request it forwards. A web page the
user visits can send requests to localhost, and DNS rebinding can make a page's
own host name point at 127.0.0.1, so the proxy accepts only requests addressed
to a loopback host that no web page sent. MCP clients run outside a browser and
send neither Origin nor Sec-Fetch-Site.
"""

import gzip
import json
import os
import socket
import stat
from datetime import datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from mcp_gateway_cli import auth as cli_auth
from mcp_gateway_cli import proxy as proxy_cli
from mcp_gateway_cli import proxy_daemon
from mcp_gateway_cli.proxy_daemon import AuthProxy, TokenManager, is_local_request
from mcp_gateway_cli.proxy_identity import proof

_MESSAGE = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
_REPLY = {"jsonrpc": "2.0", "id": 1, "result": {}}


def _token_file(path, gateway_url="https://gw.example.com", lifetime=3600, age=0):
    """A sign-in whose token lasts ``lifetime`` seconds and was issued ``age`` seconds ago."""
    issued = datetime.utcnow() - timedelta(seconds=age)
    path.write_text(
        json.dumps(
            {
                "access_token": "token-1",
                "refresh_token": "refresh-1",
                "gateway_url": gateway_url,
                "expires_in": lifetime,
                "created_at": issued.isoformat(),
            }
        )
    )
    return path


def _proxy_client(tmp_path, transport, monkeypatch, **token):
    _through(monkeypatch, transport)
    app = AuthProxy(TokenManager(_token_file(tmp_path / "tokens", **token)))
    return TestClient(app.app, base_url="http://127.0.0.1:8001")


@pytest.fixture(name="gateway")
def fixture_gateway():
    """The gateway, as the proxy's HTTP client sees it; records each request."""
    requests = []
    replies = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/auth/refresh":
            return httpx.Response(
                200, json={"access_token": "token-2", "expires_in": 3600}
            )
        if replies:
            return replies.pop(0)
        return httpx.Response(
            200,
            content=gzip.compress(json.dumps(_REPLY).encode()),
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "Connection": "close",
            },
        )

    return requests, replies, httpx.MockTransport(handler)


def _through(monkeypatch, transport):
    """Send every request the proxy makes, refreshes included, to ``transport``."""
    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        proxy_daemon.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(transport=transport, **kwargs),
    )


@pytest.fixture(name="proxy")
def fixture_proxy(tmp_path, gateway, monkeypatch):
    _through(monkeypatch, gateway[2])
    tokens = TokenManager(_token_file(tmp_path / "tokens"))
    app = AuthProxy(tokens, proxy_id="proxy-id")
    with TestClient(app.app, base_url="http://127.0.0.1:8001") as client:
        yield client


class _NoTokens:
    """A token manager with no token, so an accepted request ends in a 503."""

    gateway_unreachable = False

    def get_gateway_url(self):
        return "http://gateway.example.com"

    async def get_valid_token(self):
        return None


def _unsigned_proxy(host="127.0.0.1:8001"):
    return TestClient(AuthProxy(_NoTokens()).app, base_url=f"http://{host}")


# ------------------------------------------------- requests the proxy accepts


@pytest.mark.parametrize(
    "origin",
    [
        "https://attacker.example",
        "null",
        "http://localhost.attacker.example",
        # A page on another local port, such as some other tool's dev server.
        "http://localhost:6274",
    ],
)
def test_a_request_from_a_web_page_is_refused(origin):
    resp = _unsigned_proxy().post(
        "/mcp/gravitino", json=_MESSAGE, headers={"Origin": origin}
    )

    assert resp.status_code == 403


@pytest.mark.parametrize("site", ["cross-site", "same-site", "same-origin"])
def test_a_request_a_browser_marks_as_from_a_page_is_refused(site):
    """Browsers send Sec-Fetch-Site even on requests that carry no Origin."""
    resp = _unsigned_proxy().get("/mcp/gravitino", headers={"Sec-Fetch-Site": site})

    assert resp.status_code == 403


@pytest.mark.parametrize(
    "host", ["attacker.example:8001", "localhost:8001@attacker.example", "127.0.0.2"]
)
def test_a_request_to_another_host_name_is_refused(host):
    resp = _unsigned_proxy(host=host).post("/mcp/gravitino", json=_MESSAGE)

    assert resp.status_code == 403


@pytest.mark.parametrize(
    "host,is_local",
    [
        ("localhost:8001@attacker.example", False),
        ("attacker.example:80@localhost", False),
        ("[::1", False),
        ("localhost.", False),
        ("", False),
        ("LOCALHOST:8001", True),
    ],
)
def test_host_headers_a_browser_cannot_send_are_parsed_strictly(host, is_local):
    assert is_local_request({"host": host}) is is_local


@pytest.mark.parametrize("host", ["127.0.0.1:8001", "localhost:8001", "[::1]:8001"])
def test_local_mcp_clients_are_proxied(host):
    resp = _unsigned_proxy(host=host).post("/mcp/gravitino", json=_MESSAGE)

    assert resp.status_code == 503


def test_the_status_page_opened_from_the_address_bar_is_served():
    """A typed URL is a navigation the user started: Sec-Fetch-Site is none."""
    resp = _unsigned_proxy().get("/", headers={"Sec-Fetch-Site": "none"})

    assert resp.status_code == 200


# ------------------------------------------------------- what it forwards


def test_only_mcp_calls_reach_the_gateway(proxy, gateway):
    """Anything that can reach the proxy would otherwise use the user's admin API."""
    assert proxy.get("/api/v1/users/me").status_code == 404
    assert proxy.post("/api/v1/admin/mcp/", json={}).status_code == 404
    assert gateway[0] == []


@pytest.mark.parametrize(
    "path",
    [
        "/mcp/../api/v1/admin/mcp/",
        "/mcp/%2e%2e/api/v1/audit/logs",
        "/mcp/gravitino/..%2f..%2fapi%2fusers%2fme",
        "/mcp/gravitino/%2e%2e%2f%2e%2e%2fauth%2frefresh",
        "/mcp/%5c..%5capi",
    ],
)
def test_a_path_that_leaves_mcp_is_not_forwarded(proxy, gateway, path):
    """httpx resolves dot segments, which would reach the gateway's API with the user's token."""
    assert proxy.get(path).status_code == 404
    assert gateway[0] == []


def test_an_mcp_call_carries_the_users_token(proxy, gateway):
    resp = proxy.post(
        "/mcp/gravitino", json=_MESSAGE, headers={"Accept-Encoding": "gzip"}
    )

    assert resp.json() == _REPLY
    [request] = gateway[0]
    assert str(request.url) == "https://gw.example.com/mcp/gravitino"
    assert request.headers["authorization"] == "Bearer token-1"
    # httpx decodes the body, so its encoding headers no longer describe it.
    assert "content-encoding" not in resp.headers
    assert request.headers.get("accept-encoding") != "gzip"


def test_the_gateway_of_the_latest_login_is_used(proxy, gateway, tmp_path):
    _token_file(tmp_path / "tokens", gateway_url="https://other.example.com")

    proxy.post("/mcp/gravitino", json=_MESSAGE)

    assert gateway[0][-1].url.host == "other.example.com"


def test_after_logout_nothing_is_forwarded(proxy, gateway, tmp_path):
    (tmp_path / "tokens").unlink()

    resp = proxy.post("/mcp/gravitino", json=_MESSAGE)

    assert resp.status_code == 503
    assert gateway[0] == []
    assert not (tmp_path / "tokens").exists()


def test_a_refused_token_is_refreshed_even_before_it_expires(proxy, gateway):
    """The identity provider may revoke a token the clock says is still good."""
    gateway[1].append(httpx.Response(401))

    resp = proxy.post("/mcp/gravitino", json=_MESSAGE)

    assert resp.status_code == 200
    paths = [r.url.path for r in gateway[0]]
    assert paths == ["/mcp/gravitino", "/auth/refresh", "/mcp/gravitino"]
    assert gateway[0][-1].headers["authorization"] == "Bearer token-2"


def test_a_short_lived_token_is_not_refreshed_on_every_request(
    tmp_path, gateway, monkeypatch
):
    """Keycloak's tokens last 5 minutes; a fresh one is used as it is."""
    with _proxy_client(tmp_path, gateway[2], monkeypatch, lifetime=300) as client:
        client.post("/mcp/gravitino", json=_MESSAGE)

    assert [r.url.path for r in gateway[0]] == ["/mcp/gravitino"]


def _failing(how):
    """A gateway whose refresh fails ``how``, and that refuses tokens otherwise."""

    def handler(request):
        if how == "unreachable":
            raise httpx.ConnectError("Connection refused", request=request)
        if request.url.path != "/auth/refresh":
            return httpx.Response(401)
        if how == "timed out":
            raise httpx.ReadTimeout("Read timed out", request=request)
        if how == "cut off":
            raise httpx.RemoteProtocolError("Server disconnected", request=request)
        return httpx.Response(503)

    return httpx.MockTransport(handler)


@pytest.mark.parametrize("how", ["unreachable", "timed out", "HTTP 503", "cut off"])
@pytest.mark.parametrize("age", [270, 400], ids=["due", "expired"])
def test_a_gateway_that_isnt_working_is_not_taken_for_a_sign_out(
    tmp_path, monkeypatch, how, age
):
    """Not with a 401, which makes MCP clients ask to sign in, even when a token
    the gateway refused can't be refreshed."""
    with _proxy_client(
        tmp_path, _failing(how), monkeypatch, lifetime=300, age=age
    ) as client:
        resp = client.post("/mcp/gravitino", json=_MESSAGE)

    assert resp.status_code == 503
    assert resp.text == "Could not reach the MCP gateway at https://gw.example.com"
    assert (tmp_path / "tokens").exists()


def test_a_logout_during_an_outage_asks_for_a_login(tmp_path, monkeypatch):
    def unreachable(request):
        raise httpx.ConnectError("Connection refused", request=request)

    with _proxy_client(
        tmp_path, httpx.MockTransport(unreachable), monkeypatch, lifetime=300, age=400
    ) as client:
        assert "Could not reach" in client.post("/mcp/gravitino", json=_MESSAGE).text
        (tmp_path / "tokens").unlink()

        resp = client.post("/mcp/gravitino", json=_MESSAGE)

    assert resp.text == "No valid token available. Please run: gravitino-mcp login"


def test_the_proxy_says_when_another_program_has_its_port(
    tmp_path, monkeypatch, capsys
):
    def started(*args, **kwargs):
        raise AssertionError("a proxy was started")

    monkeypatch.setattr(proxy_cli, "is_proxy_running", lambda: False)
    monkeypatch.setattr(proxy_cli, "TOKEN_FILE", _token_file(tmp_path / "tokens"))
    monkeypatch.setattr(proxy_cli.subprocess, "Popen", started)
    with socket.socket() as other:
        other.bind(("127.0.0.1", 0))
        other.listen()
        port = other.getsockname()[1]
        monkeypatch.setattr(proxy_cli, "PROXY_PORT", port)

        assert proxy_cli.start_proxy() is False

    assert f"Port {port} is in use by another program" in capsys.readouterr().out


def test_a_dropped_connection_is_not_retried(tmp_path, monkeypatch):
    """The gateway may have run the tool call already."""
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.RemoteProtocolError("reset", request=request)

    _through(monkeypatch, httpx.MockTransport(handler))
    app = AuthProxy(TokenManager(_token_file(tmp_path / "tokens")))
    with TestClient(app.app, base_url="http://127.0.0.1:8001") as client:
        assert client.post("/mcp/gravitino", json=_MESSAGE).status_code == 502

    assert len(calls) == 1


# ------------------------------------------------------ proxy identity, tokens


def test_health_proves_the_id_without_sending_it(proxy, gateway):
    """Whoever asks could otherwise answer as this proxy once it stops."""
    body = proxy.get("/health", params={"nonce": "n-1"}).json()

    assert body == {"status": "healthy", "proof": proof("proxy-id", "n-1")}
    assert "proxy-id" not in json.dumps(body)
    assert gateway[0] == []


class _Health:
    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


@pytest.mark.parametrize(
    "answering_id,running",
    [("", False), ("another-id", False), ("this-users-id", True)],
)
def test_another_program_on_the_port_is_not_taken_for_the_proxy(
    tmp_path, monkeypatch, answering_id, running
):
    """Another user could otherwise listen on the port and read the MCP traffic."""
    id_file = tmp_path / "proxy.id"
    id_file.write_text("this-users-id")
    monkeypatch.setattr(proxy_cli, "PROXY_ID_FILE", id_file)
    monkeypatch.setattr(proxy_cli, "get_proxy_pid", lambda: None)
    monkeypatch.setattr(
        proxy_cli.requests,
        "get",
        lambda url, params, timeout: _Health(
            {"status": "healthy", "proof": proof(answering_id, params["nonce"])}
        ),
    )

    assert proxy_cli.is_proxy_running() is running


def test_the_proxy_keeps_saved_tokens_readable_only_by_the_user(tmp_path):
    """mkdir's mode applies only to a directory it creates."""
    directory = tmp_path / ".gravitino-mcp"
    directory.mkdir(mode=0o755)

    TokenManager(directory / "tokens").save_tokens("access", "refresh")

    assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(directory / "tokens").st_mode) == 0o600


def test_the_cli_keeps_its_tokens_private_too(tmp_path, monkeypatch):
    directory = tmp_path / ".gravitino-mcp"
    directory.mkdir(mode=0o755)
    monkeypatch.setattr(cli_auth, "TOKEN_FILE", directory / "tokens")

    cli_auth.save_tokens("access", "refresh", "http://gateway.example.com")

    assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(directory / "tokens").st_mode) == 0o600
