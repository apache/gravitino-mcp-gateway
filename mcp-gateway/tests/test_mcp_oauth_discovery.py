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

# pylint: disable=protected-access

"""Finding the sign-in of an MCP server with its own (RFC 9728 and RFC 8414).

The MCP server names its authorization server, so what the gateway fetches,
and where it sends codes and client secrets, must stay https and its own.
"""

from unittest.mock import patch

import httpx
import pytest

from mcp_gateway.oauth import mcp_oauth_discovery as mod

ORIGIN = "https://mcp.example.com"
MCP_URL = f"{ORIGIN}/v1/mcp"
ORIGIN_OAUTH = f"{ORIGIN}/.well-known/oauth-authorization-server"
ORIGIN_OIDC = f"{ORIGIN}/.well-known/openid-configuration"
ENDPOINTS = {
    "authorization_endpoint": "https://mcp.example.com/auth",
    "token_endpoint": "https://mcp.example.com/token",
}


@pytest.fixture(autouse=True, name="_fresh_cache")
def fixture_fresh_cache():
    mod.clear_discovery_cache()
    yield
    mod.clear_discovery_cache()


def _serve(documents):
    """Answer metadata fetches from ``documents``, keyed by URL; returns the URLs fetched."""
    fetched = []

    async def _fetch(url):
        fetched.append(url)
        document = documents.get(url)
        if isinstance(document, Exception):
            raise document
        return document

    return fetched, patch.object(mod, "_fetch_json", side_effect=_fetch)


@pytest.mark.parametrize(
    "documents",
    [
        pytest.param({ORIGIN_OAUTH: ENDPOINTS}, id="the origin's oauth metadata"),
        pytest.param({ORIGIN_OIDC: ENDPOINTS}, id="the origin's openid configuration"),
        pytest.param(
            {
                ORIGIN_OAUTH: {"issuer": "https://mcp.example.com"},
                ORIGIN_OIDC: ENDPOINTS,
            },
            id="past a document without endpoints",
        ),
        pytest.param(
            {ORIGIN_OAUTH: httpx.ConnectError("refused"), ORIGIN_OIDC: ENDPOINTS},
            id="past an unreachable candidate",
        ),
        pytest.param(
            {
                f"{ORIGIN}/.well-known/oauth-protected-resource/v1/mcp": {
                    "authorization_servers": ["https://auth.example.com"]
                },
                "https://auth.example.com/.well-known/oauth-authorization-server": (
                    ENDPOINTS
                ),
            },
            id="the authorization server the resource names",
        ),
    ],
)
async def test_a_servers_endpoints_are_discovered(documents):
    _fetched, serving = _serve(documents)

    with serving:
        metadata = await mod.resolve_oauth_metadata(MCP_URL, None)

    assert metadata.token_endpoint == ENDPOINTS["token_endpoint"]


async def test_a_configured_metadata_url_is_the_only_one_fetched_and_is_cached():
    metadata_url = "https://auth.example.com/.well-known/oauth-authorization-server"
    fetched, serving = _serve({metadata_url: ENDPOINTS})

    with serving:
        await mod.resolve_oauth_metadata(MCP_URL, metadata_url)
        metadata = await mod.resolve_oauth_metadata(MCP_URL, metadata_url)

    assert metadata.token_endpoint == ENDPOINTS["token_endpoint"]
    assert fetched == [metadata_url]


async def test_an_unreachable_configured_metadata_url_is_an_error():
    _fetched, serving = _serve({})

    with serving, pytest.raises(ValueError, match="could not fetch"):
        await mod.resolve_oauth_metadata(MCP_URL, "https://auth.example.com/x")


@pytest.mark.parametrize(
    "mcp_url, document, refusal",
    [
        # A server's metadata must be its own (RFC 8414 section 3.3).
        pytest.param(
            MCP_URL,
            {**ENDPOINTS, "issuer": "https://other.example.com"},
            "issuer",
            id="another issuer",
        ),
        # Otherwise codes and client secrets would travel in the clear.
        pytest.param(
            MCP_URL,
            {**ENDPOINTS, "token_endpoint": "http://10.0.0.5/token"},
            "https",
            id="an http token endpoint",
        ),
        pytest.param(
            MCP_URL,
            {**ENDPOINTS, "registration_endpoint": "http://10.0.0.5/r"},
            "https",
            id="an http registration endpoint",
        ),
        pytest.param(
            "http://mcp.internal/mcp",
            {
                "authorization_endpoint": "http://mcp.internal/auth",
                "token_endpoint": "http://mcp.internal/token",
            },
            "https",
            id="an http server",
        ),
    ],
)
async def test_metadata_that_isnt_the_servers_own_or_https_is_refused(
    monkeypatch, mcp_url, document, refusal
):
    monkeypatch.setattr(mod.settings, "DEBUG", False)

    with patch.object(mod, "_fetch_json", return_value=document), pytest.raises(
        ValueError, match=refusal
    ):
        await mod.discover_oauth_metadata(mcp_url)


async def test_an_http_authorization_server_named_by_the_mcp_server_is_not_fetched(
    monkeypatch,
):
    monkeypatch.setattr(mod.settings, "DEBUG", False)
    fetched, serving = _serve(
        {
            f"{ORIGIN}/.well-known/oauth-protected-resource/v1/mcp": {
                "authorization_servers": ["http://169.254.169.254"]
            }
        }
    )

    with serving, pytest.raises(ValueError, match="https"):
        await mod.discover_oauth_metadata(MCP_URL)

    assert not any("169.254" in url for url in fetched)


async def test_a_client_secret_needs_a_configured_metadata_url():
    """The MCP server must not choose the token endpoint the secret goes to."""
    fetched, serving = _serve({})

    with serving, pytest.raises(ValueError, match="metadata URL"):
        await mod.resolve_oauth_metadata(MCP_URL, None, has_client_secret=True)

    assert not fetched


async def test_discovery_does_not_follow_redirects():
    """A redirect could send the gateway's request anywhere."""
    requests = []

    def handler(request):
        requests.append(request.url)
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def client(**kwargs):
        return real_client(transport=transport, **kwargs)

    with patch.object(mod.httpx, "AsyncClient", client):
        assert await mod._fetch_json("https://mcp.example.com/.well-known/x") is None

    assert [str(url) for url in requests] == ["https://mcp.example.com/.well-known/x"]


@pytest.mark.parametrize(
    "endpoint, scope",
    [
        ("https://slack.com/oauth", "chat:write,channels:read"),
        ("https://x/oauth", "chat:write channels:read"),
    ],
)
def test_only_slack_gets_comma_separated_scopes(endpoint, scope):
    assert mod.scope_param_for_authorize("chat:write channels:read", endpoint) == scope


@pytest.mark.parametrize(
    "response, parsed",
    [
        (
            {"access_token": "abc", "refresh_token": "r1", "expires_in": 300},
            ("abc", "r1", 300),
        ),
        # Slack's wrapper; without expires_in or a refresh token it lasts until revoked.
        (
            {"ok": True, "access_token": "xoxp"},
            ("xoxp", None, mod._NON_EXPIRING_TTL_SECONDS),
        ),
        (
            {"access_token": "abc", "refresh_token": "r1"},
            ("abc", "r1", mod._DEFAULT_TTL_SECONDS),
        ),
    ],
    ids=["standard", "slack, until revoked", "refreshable, an hour"],
)
def test_a_token_response_gives_the_token_its_refresh_token_and_lifetime(
    response, parsed
):
    assert mod.parse_token_response(response) == parsed


def test_a_slack_error_response_is_an_error():
    with pytest.raises(ValueError):
        mod.parse_token_response({"ok": False, "error": "invalid_code"})
