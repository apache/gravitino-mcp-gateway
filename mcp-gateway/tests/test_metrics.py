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

"""The Prometheus metrics (mcp_gateway.metrics) and the /metrics endpoint."""

import pytest
from prometheus_client import REGISTRY

from mcp_gateway.metrics import metric_method, record_token_refresh, record_tool_call


def _value(name, labels):
    return REGISTRY.get_sample_value(name, labels) or 0.0


def test_metrics_are_served_as_prometheus_text(client):
    resp = client.get("/metrics")

    assert resp.headers["content-type"].startswith("text/plain")
    for family in (
        "mcp_gateway_tool_calls_total",
        "mcp_gateway_token_refresh_total",
        "mcp_gateway_build_info",
    ):
        assert family in resp.text
    # Tool calls can take MCP_TOOL_CALL_TIMEOUT (1200s); the library's buckets
    # stop at 60s, which would clamp P95 and P99 for any slower call.
    assert 'http_request_duration_highr_seconds_bucket{le="1200.0"}' in resp.text


def test_a_tool_call_is_counted_and_timed():
    labels = {"service": "trino", "tool": "execute_query"}
    calls = _value("mcp_gateway_tool_calls_total", {**labels, "status": "success"})
    timed = _value("mcp_gateway_tool_call_duration_seconds_count", labels)

    record_tool_call("trino", "execute_query", "success", duration_ms=125)

    assert (
        _value("mcp_gateway_tool_calls_total", {**labels, "status": "success"})
        == calls + 1
    )
    assert _value("mcp_gateway_tool_call_duration_seconds_count", labels) == timed + 1


def test_a_tool_call_without_labels_is_counted_as_unknown():
    labels = {"service": "unknown", "tool": "unknown", "status": "unknown"}
    before = _value("mcp_gateway_tool_calls_total", labels)

    record_tool_call(None, None, None, duration_ms=None)

    assert _value("mcp_gateway_tool_calls_total", labels) == before + 1


@pytest.mark.parametrize("success, result", [(True, "success"), (False, "failure")])
def test_a_token_refresh_is_counted_by_outcome(success, result):
    labels = {"service": "trino", "result": result}
    before = _value("mcp_gateway_token_refresh_total", labels)

    record_token_refresh("trino", success)

    assert _value("mcp_gateway_token_refresh_total", labels) == before + 1


@pytest.mark.parametrize(
    "method, label",
    [
        ("tools/call", "tools/call"),
        ("resources/read", "resources/read"),
        ("notifications/initialized", "notifications/initialized"),
        ("made-up/method-1234", "other"),
        ("", "other"),
        (["tools/call"], "other"),
        ({"a": 1}, "other"),
        (None, "other"),
    ],
)
def test_metrics_label_only_mcp_methods(method, label):
    """Callers choose the method; labelling every value would grow without bound."""
    assert metric_method(method) == label
