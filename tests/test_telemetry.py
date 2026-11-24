#
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

"""OpenTelemetry traces (mcp_gateway.telemetry): spans for MCP requests, token
exchange and refresh, and upstream calls, and trace context passed on."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

pytest.importorskip("opentelemetry.sdk")

# pylint: disable=wrong-import-position
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from mcp_gateway import telemetry
from mcp_gateway.config import settings
from mcp_gateway.oauth.token_encryption import TokenEncryption
from mcp_gateway.routes import mcp_server

CLIENT_TRACE_ID = "0af7651916cd43dd8448eb211c80319c"
TRACEPARENT = f"00-{CLIENT_TRACE_ID}-b7ad6b7169203331-01"


@pytest.fixture(name="spans")
def fixture_spans(monkeypatch):
    """The spans the gateway records, with tracing on."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(settings, "OTEL_ENABLED", True)
    monkeypatch.setattr(telemetry, "_get_tracer", lambda: provider.get_tracer("test"))
    return exporter


def _named(exporter, name):
    return [s for s in exporter.get_finished_spans() if s.name == name]


def _upstream(monkeypatch):
    reply = httpx.Response(
        200,
        json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}},
        request=httpx.Request("POST", "http://trino-mcp:8080/mcp"),
    )
    backend = MagicMock()
    backend.post = AsyncMock(return_value=reply)
    monkeypatch.setattr(mcp_server, "_get_mcp_http_client", lambda: backend)
    return backend


@pytest.fixture(autouse=True, name="_encryption")
def fixture_encryption():
    enc = TokenEncryption(b"k" * 32)
    with patch(
        "mcp_gateway.oauth.token_manager.get_token_encryption",
        new_callable=AsyncMock,
        return_value=enc,
    ):
        yield


@pytest.fixture(name="person")
def fixture_person(as_user, regular_user, monkeypatch, mcp_entry):
    tokens = MagicMock()
    tokens.get_token = AsyncMock(return_value="backend-token")
    monkeypatch.setattr(mcp_server, "TokenManager", lambda db: tokens)
    assert mcp_entry.service_id == "trino"
    return as_user(regular_user)


def _call(client, method, params=None, headers=None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    return client.post("/mcp/trino", json=body, headers=headers or {})


def test_a_request_is_a_span_with_server_method_and_tool(
    client, person, spans, monkeypatch
):
    _upstream(monkeypatch)

    _call(client, "tools/call", {"name": "execute_query", "arguments": {"q": "x"}})

    (span,) = _named(spans, "mcp.request")
    assert dict(span.attributes) == {
        "mcp.server.id": "trino",
        "mcp.method": "tools/call",
        "mcp.tool.name": "execute_query",
    }


def test_no_argument_token_or_email_is_ever_an_attribute(
    client, person, spans, monkeypatch, regular_user
):
    _upstream(monkeypatch)

    _call(
        client,
        "tools/call",
        {"name": "execute_query", "arguments": {"sql": "SELECT secret-sql"}},
        headers={"Authorization": "Bearer caller-secret-token"},
    )

    dump = json.dumps(
        [dict(s.attributes) for s in spans.get_finished_spans()], default=str
    )
    for secret in (
        "secret-sql",
        "caller-secret-token",
        "backend-token",
        regular_user.email,
    ):
        assert secret not in dump


def test_the_upstream_call_is_a_child_span_that_the_server_is_told_of(
    client, person, spans, monkeypatch
):
    backend = _upstream(monkeypatch)

    _call(client, "tools/list")

    (request,) = _named(spans, "mcp.request")
    upstream = _named(spans, "mcp.upstream")[-1]
    assert upstream.parent.span_id == request.context.span_id
    assert upstream.attributes["mcp.server.id"] == "trino"
    sent = backend.post.await_args.kwargs["headers"]["traceparent"]
    assert sent.split("-")[1:3] == [
        f"{upstream.context.trace_id:032x}",
        f"{upstream.context.span_id:016x}",
    ]


def test_a_tool_call_has_its_upstream_span_in_the_requests_trace(
    client, person, spans, monkeypatch
):
    backend = _upstream(monkeypatch)

    _call(client, "tools/call", {"name": "execute_query"})

    (request,) = _named(spans, "mcp.request")
    upstream = _named(spans, "mcp.upstream")[-1]
    assert upstream.context.trace_id == request.context.trace_id
    assert "traceparent" in backend.post.await_args.kwargs["headers"]


def test_a_trace_the_client_started_is_continued(client, person, spans, monkeypatch):
    backend = _upstream(monkeypatch)

    _call(client, "tools/list", headers={"traceparent": TRACEPARENT})

    (request,) = _named(spans, "mcp.request")
    assert f"{request.context.trace_id:032x}" == CLIENT_TRACE_ID
    assert request.parent.span_id == int("b7ad6b7169203331", 16)
    sent = backend.post.await_args.kwargs["headers"]["traceparent"]
    assert sent.split("-")[1] == CLIENT_TRACE_ID


def test_a_failed_upstream_call_marks_its_span_as_an_error(
    client, person, spans, monkeypatch
):
    backend = _upstream(monkeypatch)
    backend.post.side_effect = httpx.ConnectError("down")

    _call(client, "tools/list")

    assert not _named(spans, "mcp.upstream")[-1].status.is_ok


def test_nothing_is_traced_or_sent_when_tracing_is_off(
    client, person, spans, monkeypatch
):
    monkeypatch.setattr(settings, "OTEL_ENABLED", False)
    backend = _upstream(monkeypatch)

    _call(client, "tools/list", headers={"traceparent": TRACEPARENT})

    assert not spans.get_finished_spans()
    assert "traceparent" not in backend.post.await_args.kwargs["headers"]


def test_the_gateway_works_when_opentelemetry_is_not_installed(
    client, person, monkeypatch
):
    monkeypatch.setattr(settings, "OTEL_ENABLED", True)
    monkeypatch.setattr(telemetry, "_trace", None)
    backend = _upstream(monkeypatch)

    resp = _call(client, "tools/list")

    assert resp.json()["result"] == {"tools": []}
    assert "traceparent" not in backend.post.await_args.kwargs["headers"]


def test_setup_without_the_sdk_says_how_to_install_it(monkeypatch):
    monkeypatch.setattr(settings, "OTEL_ENABLED", True)
    monkeypatch.setattr(telemetry, "_sdk_available", lambda: False)

    with pytest.raises(RuntimeError, match=r"\[otel\]"):
        telemetry.setup_telemetry()


def test_setup_installs_a_tracer_provider(monkeypatch):
    installed = []
    monkeypatch.setattr(settings, "OTEL_ENABLED", True)
    monkeypatch.setattr(telemetry, "_install_provider", installed.append)

    telemetry.setup_telemetry()

    assert len(installed) == 1
    assert isinstance(installed[0], TracerProvider)
    installed[0].shutdown()


async def test_a_token_refresh_is_a_span_named_for_the_server(
    spans, db_session, regular_user
):
    # pylint: disable=import-outside-toplevel
    from mcp_gateway.oauth.token_manager import TokenManager

    manager = TokenManager(db_session)
    await manager.store_user_oauth_token(
        regular_user.id, "svc", "stale", refresh_token="renew", expires_in=-60
    )
    manager.oidc_client.refresh_access_token = MagicMock(
        return_value={"access_token": "fresh", "expires_in": 3600}
    )

    await manager.get_user_oauth_token(regular_user.id, "svc")

    (span_,) = _named(spans, "mcp.token_refresh")
    assert dict(span_.attributes) == {"mcp.server.id": "svc"}


async def test_a_token_exchange_is_a_span_named_for_the_server(
    spans, db_session, mcp_entry
):
    # pylint: disable=import-outside-toplevel,protected-access
    from mcp_gateway.oauth.token_manager import TokenManager

    manager = TokenManager(db_session)
    manager.oidc_client.exchange_token_rfc8693 = MagicMock(
        return_value={"access_token": "x"}
    )

    await manager._exchange_token(mcp_entry, "gateway-token", on_behalf_of=False)

    (span_,) = _named(spans, "mcp.token_exchange")
    assert dict(span_.attributes) == {"mcp.server.id": "trino"}
    assert "gateway-token" not in json.dumps(dict(span_.attributes))


@pytest.mark.parametrize(
    "path, excluded",
    [
        ("/mcp/trino", False),
        ("/auth/callback", True),
        ("/health", True),
        ("/metrics", True),
    ],
)
def test_only_the_mcp_endpoint_gets_fastapis_own_spans(path, excluded):
    assert telemetry.exclude_from_native_telemetry({"path": path}) is excluded
