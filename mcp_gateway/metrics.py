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

"""
Prometheus metrics for MCP Gateway.

Exposes a ``/metrics`` endpoint plus a small, deliberately-chosen set of
high-signal custom metrics for monitoring gateway health and debugging
outages.  We instrument only code paths that exist today - no dead metrics
for features that aren't built yet (caching, circuit breaker).

HTTP layer (automatic, via prometheus-fastapi-instrumentator):
  - http_request_duration_highr_seconds      → latency P50/P95/P99 (high-res, no route label)
  - http_request_duration_seconds{handler}   → latency per route + request/error rate by status

  Both latency histograms use custom buckets extending to 1200s so quantiles
  stay accurate for long-running proxied calls (matching MCP_TOOL_CALL_TIMEOUT
  and mcp_gateway_tool_call_duration_seconds). With the library defaults the
  highr histogram tops out at le=60, which silently clamps P95/P99 to 60s for
  any request slower than a minute.

MCP proxy (custom):
  - mcp_gateway_tool_calls_total{service,tool,status}
  - mcp_gateway_tool_call_duration_seconds{service,tool}
  - mcp_gateway_rate_limited_total{service,scope}

Auth / tokens (custom):
  - mcp_gateway_token_refresh_total{service,result}

Build / runtime:
  - mcp_gateway_build_info{version,environment}

Cardinality is kept bounded on purpose: labels are limited to finite sets
(service, tool, status, result).  Never label by user id, IP, or any
free-form/unbounded value.
"""

import logging
from typing import Optional

from prometheus_client import Counter, Histogram, Info
from prometheus_fastapi_instrumentator import Instrumentator, metrics

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom metrics
# ---------------------------------------------------------------------------
MCP_TOOL_CALLS = Counter(
    "mcp_gateway_tool_calls_total",
    "Total MCP tool calls proxied through the gateway, by backend and outcome.",
    ["service", "tool", "status"],
)

MCP_TOOL_CALL_DURATION = Histogram(
    "mcp_gateway_tool_call_duration_seconds",
    "End-to-end duration of MCP tool calls proxied through the gateway.",
    ["service", "tool"],
    # Range spans the full call lifetime up to MCP_TOOL_CALL_TIMEOUT (1200s).
    # ~2.5x spacing through 0.1-60s keeps p90/p95/p99 accurate where most
    # traffic sits; coarser tail (120-1200s) flags long-running queries
    # approaching the timeout.
    buckets=(
        0.1,
        0.25,
        0.5,
        1.0,
        2.5,
        5.0,
        10.0,
        30.0,
        60.0,
        120.0,
        300.0,
        600.0,
        1200.0,
    ),
)

MCP_RATE_LIMITED = Counter(
    "mcp_gateway_rate_limited_total",
    "MCP calls refused because a rate limit was reached, by server and scope.",
    ["service", "scope"],
)

TOKEN_REFRESH = Counter(
    "mcp_gateway_token_refresh_total",
    "OAuth token refresh attempts, by backend service and outcome.",
    ["service", "result"],
)

BUILD_INFO = Info(
    "mcp_gateway_build",
    "MCP Gateway build/runtime information (version, environment).",
)


# ---------------------------------------------------------------------------
# Recording helpers — these must NEVER raise into request-handling code.
# ---------------------------------------------------------------------------
# Methods the MCP specification defines. Callers choose the method, so any
# other value is labelled "other" to keep the label set finite.
MCP_METHODS = frozenset(
    {
        "initialize",
        "ping",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
        "resources/templates/list",
        "resources/subscribe",
        "resources/unsubscribe",
        "prompts/list",
        "prompts/get",
        "completion/complete",
        "logging/setLevel",
        "roots/list",
        "sampling/createMessage",
        "elicitation/create",
        "tasks/get",
        "tasks/list",
        "tasks/result",
        "tasks/cancel",
        "notifications/initialized",
        "notifications/cancelled",
        "notifications/progress",
        "notifications/roots/list_changed",
    }
)


def metric_method(method: object) -> str:
    """The metric label for a JSON-RPC method: the method if MCP defines it, else "other"."""
    return method if isinstance(method, str) and method in MCP_METHODS else "other"


def record_tool_call(
    service: Optional[str],
    tool: Optional[str],
    status: Optional[str],
    duration_ms: Optional[int] = None,
) -> None:
    """Record a single proxied MCP tool call. Safe to call from hot paths."""
    try:
        svc = service or "unknown"
        tl = tool or "unknown"
        st = status or "unknown"
        MCP_TOOL_CALLS.labels(service=svc, tool=tl, status=st).inc()
        if duration_ms is not None:
            MCP_TOOL_CALL_DURATION.labels(service=svc, tool=tl).observe(
                duration_ms / 1000.0
            )
    except Exception:  # pylint: disable=broad-exception-caught
        # Metrics must not break requests.
        logger.debug("Failed to record MCP tool-call metric", exc_info=True)


def record_rate_limited(service: Optional[str], scope: str) -> None:
    """Record a call refused by a rate limit; ``scope`` is user, server or tool."""
    try:
        MCP_RATE_LIMITED.labels(service=service or "unknown", scope=scope).inc()
    except Exception:  # pylint: disable=broad-exception-caught
        # Metrics must not break requests.
        logger.debug("Failed to record rate-limit metric", exc_info=True)


def record_token_refresh(service: Optional[str], success: bool) -> None:
    """Record the outcome of an OAuth token refresh attempt."""
    try:
        TOKEN_REFRESH.labels(
            service=service or "unknown",
            result="success" if success else "failure",
        ).inc()
    except Exception:  # pylint: disable=broad-exception-caught
        # Metrics must not break requests.
        logger.debug("Failed to record token-refresh metric", exc_info=True)


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------
def setup_metrics(
    app,
    *,
    version: str = "unknown",
    environment: str = "unknown",
) -> None:
    """Instrument *app* with default HTTP metrics and expose ``GET /metrics``.

    Note: ``/metrics`` is unauthenticated by design (Prometheus scrapes it).
    Restrict access at the network layer (K8s NetworkPolicy / ingress) so it
    is reachable only by the in-cluster Prometheus scraper.
    """
    try:
        BUILD_INFO.info({"version": str(version), "environment": str(environment)})
    except Exception:  # pylint: disable=broad-exception-caught
        logger.debug("Failed to set mcp_gateway_build_info", exc_info=True)

    # HTTP latency buckets reach MCP_TOOL_CALL_TIMEOUT (1200 s), as the tool-call
    # histogram's do: the library's stop at 60 s, which would clamp every
    # quantile of a long call to a minute.
    instrumentator = Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        excluded_handlers=["/metrics", "/health"],
    )
    instrumentator.add(
        metrics.default(
            # High-res histogram is label-less (no handler), so fine granularity
            # is cheap and drives accurate global P50/P95/P99.
            latency_highr_buckets=(
                0.1,
                0.25,
                0.5,
                1,
                2.5,
                5,
                10,
                30,
                60,
                120,
                300,
                600,
                1200,
            ),
            # Low-res histogram carries the per-route `handler` label, so every
            # bucket multiplies across routes — keep it coarse but reaching 1200s
            # so per-route quantiles don't clamp at 60s either.
            latency_lowr_buckets=(0.5, 1, 5, 30, 120, 1200),
        )
    )
    instrumentator.instrument(app).expose(
        app,
        endpoint="/metrics",
        include_in_schema=False,
    )
    logger.info("Prometheus metrics enabled at /metrics")
