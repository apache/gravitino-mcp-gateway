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

"""Tests for gateway URL resolution in mcp_gateway_sdk.sa_token."""

import pytest

from mcp_gateway_sdk.sa_token import _resolve_gateway_url


@pytest.mark.parametrize(
    "gateway,expected",
    [
        ("https://mcp-gateway.example.com/", "https://mcp-gateway.example.com"),
        ("local", "http://localhost:8000"),
        # Only a gateway on this machine may use plain http.
        ("http://localhost:8000", "http://localhost:8000"),
        ("http://127.0.0.1:8000", "http://127.0.0.1:8000"),
        ("http://[::1]:8000", "http://[::1]:8000"),
    ],
)
def test_the_gateway_url_is_resolved(gateway, expected):
    assert _resolve_gateway_url(gateway) == expected


@pytest.mark.parametrize(
    "gateway",
    ["prod", "http://mcp-gateway.example.com", "ftp://mcp-gateway.example.com"],
)
def test_a_gateway_that_isnt_https_is_an_error(gateway):
    """The token is a credential, so it goes only over https."""
    with pytest.raises(ValueError, match="https"):
        _resolve_gateway_url(gateway)


def test_none_reads_the_gateway_url_from_the_environment(monkeypatch):
    monkeypatch.setenv("MCP_GATEWAY_URL", "https://mcp-gateway.example.com")

    assert _resolve_gateway_url(None) == "https://mcp-gateway.example.com"


def test_none_without_a_configured_gateway_is_an_error(monkeypatch):
    monkeypatch.delenv("MCP_GATEWAY_URL", raising=False)

    with pytest.raises(ValueError, match="MCP_GATEWAY_URL"):
        _resolve_gateway_url(None)
