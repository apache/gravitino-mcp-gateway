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

"""Optional OpenTelemetry traces, exported over OTLP.

Off unless ``OTEL_ENABLED`` is set, and needs the ``otel`` extra. Without the
extra, or with tracing off, every function here does nothing, so callers need
no checks. Spans carry the server ID, the method and the tool's name, never
arguments, tokens or emails.
"""

import importlib.util
import logging
from contextlib import contextmanager, nullcontext
from typing import Any, Iterator, Mapping, Optional

from .config import settings

try:
    from opentelemetry import propagate, trace
except ImportError:  # the otel extra is not installed
    propagate = None  # pylint: disable=invalid-name
    trace = None  # pylint: disable=invalid-name

# Kept under another name so tests can stand in for "not installed".
_trace = trace

logger = logging.getLogger(__name__)


def _get_tracer():
    return _trace.get_tracer("mcp_gateway")


def enabled() -> bool:
    """Whether spans are recorded and trace context is passed on."""
    return bool(settings.OTEL_ENABLED and _trace is not None)


@contextmanager
def span(
    name: str,
    attributes: Optional[Mapping[str, Any]] = None,
    headers: Optional[Mapping[str, str]] = None,
) -> Iterator[None]:
    """A span named ``name``, current inside the block; an exception in it marks
    the span as an error and propagates.

    ``headers``, a caller's, make the span continue the trace they carry
    (W3C ``traceparent``).
    """
    if not enabled():
        with nullcontext():
            yield
        return
    context = None
    # A current span, such as FastAPI's own server span, already continues the
    # caller's trace.
    if (
        headers is not None
        and not _trace.get_current_span().get_span_context().is_valid
    ):
        context = propagate.extract(dict(headers))
    with _get_tracer().start_as_current_span(
        name, context=context, attributes=dict(attributes or {})
    ):
        yield


def set_attribute(key: str, value: Any) -> None:
    """Set an attribute on the current span."""
    if enabled():
        _trace.get_current_span().set_attribute(key, value)


def with_trace_context(headers: dict) -> dict:
    """``headers`` plus the current span's ``traceparent``, for an upstream call."""
    if not enabled():
        return headers
    out = dict(headers)
    propagate.inject(out)
    return out


def exclude_from_native_telemetry(scope: Mapping[str, Any]) -> bool:
    """Whether FastAPI's own telemetry skips a request: all but the MCP endpoint.

    FastAPI's server spans carry the query string, which on the sign-in routes
    holds authorization codes, and /health and /metrics are only noise.
    """
    return not str(scope.get("path", "")).startswith("/mcp/")


def _sdk_available() -> bool:
    return all(
        importlib.util.find_spec(name) is not None
        for name in (
            "opentelemetry.sdk",
            "opentelemetry.exporter.otlp.proto.http.trace_exporter",
        )
    )


def _install_provider(provider) -> None:
    trace.set_tracer_provider(provider)


def setup_telemetry() -> None:
    """Start exporting traces over OTLP/HTTP when ``OTEL_ENABLED`` is set.

    The endpoint, headers, service name and so on come from the standard
    ``OTEL_EXPORTER_OTLP_*`` and ``OTEL_SERVICE_NAME`` variables.
    """
    if not settings.OTEL_ENABLED:
        return
    if _trace is None or not _sdk_available():
        raise RuntimeError(
            "OTEL_ENABLED needs the OpenTelemetry packages: "
            'pip install "apache-gravitino-mcp-gateway[otel]"'
        )
    # pylint: disable=import-outside-toplevel
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    provider = TracerProvider(resource=Resource.create({"service.name": "mcp-gateway"}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    _install_provider(provider)
    logger.info("OpenTelemetry traces are exported over OTLP")
