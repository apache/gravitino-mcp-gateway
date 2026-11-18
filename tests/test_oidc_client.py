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

"""The OIDC client: its provider discovery cache and its timeouts.

TokenManager builds a client for every MCP request, so the discovery document is
fetched once per TTL for the whole process, and every call to the provider has a
timeout. Without either, a slow provider stalls /health past the liveness probe.
"""

import threading
from unittest.mock import MagicMock, patch

import pytest

from mcp_gateway.config import settings
from mcp_gateway.oauth import oidc_client as oidc_module
from mcp_gateway.oauth.oidc_client import (
    OIDCClient,
    get_configured_issuer,
    reset_discovery_cache,
)

DISCOVERY_URL = "https://login.example.com/tenant/v2.0/.well-known/openid-configuration"

DISCOVERY_DOC = {
    "issuer": "https://login.example.com/tenant/v2.0",
    "authorization_endpoint": "https://login.example.com/tenant/oauth2/v2.0/authorize",
    "token_endpoint": "https://login.example.com/tenant/oauth2/v2.0/token",
    "jwks_uri": "https://login.example.com/tenant/discovery/v2.0/keys",
}
DOWN = OSError("provider down")


def _ok_response(payload):
    response = MagicMock(status_code=200)
    response.json.return_value = payload
    return response


@pytest.fixture(autouse=True, name="_clean_discovery_cache")
def fixture_clean_discovery_cache():
    """The discovery cache is process-wide, so isolate it between tests."""
    reset_discovery_cache()
    yield
    reset_discovery_cache()


@pytest.fixture(name="provider_get")
def fixture_provider_get(monkeypatch):
    """The provider's discovery document, served until a test sets side_effect."""
    monkeypatch.setattr(settings, "OIDC_DISCOVERY_URL", DISCOVERY_URL)
    monkeypatch.setattr(settings, "OIDC_DISCOVERY_CACHE_TTL", 3600)
    monkeypatch.setattr(settings, "OIDC_HTTP_TIMEOUT", 10.0)
    with patch.object(
        oidc_module.requests, "get", return_value=_ok_response(DISCOVERY_DOC)
    ) as get:
        yield get


@pytest.fixture(name="clock")
def fixture_clock(monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(oidc_module.time, "monotonic", lambda: clock["now"])
    return clock


# --- discovery -------------------------------------------------------------------


def test_discovery_is_fetched_once_with_a_timeout_across_many_clients(provider_get):
    clients = [OIDCClient() for _ in range(25)]

    assert provider_get.call_count == 1
    assert provider_get.call_args.kwargs["timeout"] == settings.OIDC_HTTP_TIMEOUT
    assert all(c.token_endpoint == DISCOVERY_DOC["token_endpoint"] for c in clients)


def test_discovery_is_fetched_again_once_the_ttl_passes(
    provider_get, clock, monkeypatch
):
    monkeypatch.setattr(settings, "OIDC_DISCOVERY_CACHE_TTL", 60)

    OIDCClient()
    clock["now"] += 30
    OIDCClient()
    assert provider_get.call_count == 1

    clock["now"] += 31
    OIDCClient()
    assert provider_get.call_count == 2


def test_a_ttl_of_zero_disables_caching(provider_get, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_DISCOVERY_CACHE_TTL", 0)

    OIDCClient()
    OIDCClient()

    assert provider_get.call_count == 2


def test_concurrent_clients_collapse_into_one_fetch(provider_get):
    """Threads racing on a cold cache must issue a single request, not N."""
    barrier = threading.Barrier(8)

    def build():
        barrier.wait()
        OIDCClient()

    threads = [threading.Thread(target=build) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert provider_get.call_count == 1


@pytest.mark.parametrize(
    "configured, issuer",
    [
        ("https://manual.example.com/issuer", "https://manual.example.com/issuer"),
        (None, DISCOVERY_DOC["issuer"]),
    ],
)
def test_the_configured_issuer_wins_over_the_discovered_one(
    provider_get, monkeypatch, configured, issuer
):
    monkeypatch.setattr(settings, "OIDC_ISSUER", configured)

    assert get_configured_issuer() == issuer


# --- discovery failures --------------------------------------------------------------


def test_a_failed_discovery_falls_back_to_the_configured_endpoints(
    provider_get, monkeypatch
):
    monkeypatch.setattr(
        settings, "OIDC_TOKEN_ENDPOINT", "https://manual.example.com/token"
    )
    provider_get.side_effect = DOWN

    assert OIDCClient().token_endpoint == "https://manual.example.com/token"


def test_a_failed_discovery_is_not_retried_during_backoff(provider_get):
    """A provider outage must not turn every request into a fresh timeout wait."""
    provider_get.side_effect = DOWN

    for _ in range(10):
        OIDCClient()

    assert provider_get.call_count == 1


def test_a_stale_document_is_served_when_a_refresh_fails(
    provider_get, clock, monkeypatch
):
    monkeypatch.setattr(settings, "OIDC_DISCOVERY_CACHE_TTL", 60)
    OIDCClient()
    clock["now"] += 120
    provider_get.side_effect = DOWN

    assert OIDCClient().token_endpoint == DISCOVERY_DOC["token_endpoint"]


# --- timeouts on every provider call ---------------------------------------------------


@pytest.mark.parametrize(
    "method_name, kwargs",
    [
        (
            "exchange_code_for_token",
            {
                "code": "c",
                "client_id": "id",
                "client_secret": "s",
                "redirect_uri": "u",
                "state": "st",
            },
        ),
        (
            "refresh_access_token",
            {"refresh_token": "rt", "client_id": "id", "client_secret": "s"},
        ),
        (
            "exchange_token_on_behalf_of",
            {
                "user_access_token": "at",
                "client_id": "id",
                "client_secret": "s",
                "target_scope": "api://x/.default",
            },
        ),
        (
            "exchange_token_rfc8693",
            {
                "user_access_token": "at",
                "client_id": "id",
                "client_secret": "s",
                "target_audience": "metastore-mcp",
            },
        ),
    ],
)
def test_provider_calls_send_a_timeout(provider_get, method_name, kwargs):
    client = OIDCClient()

    with patch.object(
        oidc_module.requests, "post", return_value=_ok_response({"access_token": "t"})
    ) as post:
        getattr(client, method_name)(**kwargs)

    assert post.call_args.kwargs["timeout"] == settings.OIDC_HTTP_TIMEOUT
