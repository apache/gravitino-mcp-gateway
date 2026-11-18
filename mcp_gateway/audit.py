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
Audit logging utilities for tracking MCP tool calls
"""

import asyncio
import hashlib
import logging
import re
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from .config import settings
from .metrics import metric_method, record_tool_call
from .models import AuditLog, User
from .oauth_auth import get_workload_forward_headers

logger = logging.getLogger(__name__)

FAILURE_LENGTH = 500
# Error messages can hold MCP servers' text; MySQL's TEXT holds 64 KB.
ERROR_MESSAGE_LENGTH = 10_000
# Longest tool arguments or response kept whole; longer ones keep a preview.
PAYLOAD_LENGTH = 10_000
_PREVIEW_LENGTH = 1_000
# Arguments with these names hold secrets, which the audit log never keeps.
_SECRET_KEY = re.compile(
    r"pass(word|wd)?|secret|token|authorization|api[_-]?key|credential", re.I
)
CANCELLED = "The client disconnected before the call finished"


def tool_call_failure(response_data: dict) -> Optional[str]:
    """The error message of a failed tool call, or None if it succeeded.

    A JSON-RPC error means the server could not run the call. A result with
    isError set means the tool ran and failed, as when Gravitino denies access.
    The response comes from the MCP server, so any part of it may be malformed.
    """
    if "error" in response_data:
        error = response_data["error"]
        message = error.get("message") if isinstance(error, dict) else None
        return str(message)[:FAILURE_LENGTH] if message else "Unknown error"
    result = response_data.get("result")
    if not isinstance(result, dict) or not result.get("isError"):
        return None
    content = result.get("content")
    texts = [
        str(item["text"])
        for item in (content if isinstance(content, list) else [])
        if isinstance(item, dict)
        and item.get("type") == "text"
        and item.get("text") is not None
    ]
    return " ".join(texts)[:FAILURE_LENGTH] or "The tool reported an error"


def _fit(column: str, value: Any) -> Optional[str]:
    """``value`` as text that fits its AuditLog column.

    Callers and MCP servers choose these values, and MySQL refuses one that
    is longer than its column, losing the row.
    """
    if value is None:
        return None
    length = AuditLog.__table__.c[column].type.length or ERROR_MESSAGE_LENGTH
    return str(value)[:length]


def _redacted(value: Any) -> Any:
    """``value`` with the values of secret-looking keys replaced, at any depth."""
    if isinstance(value, dict):
        return {
            key: (
                "[redacted]"
                if isinstance(key, str) and _SECRET_KEY.search(key)
                else _redacted(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redacted(item) for item in value]
    return value


def _bounded(value: Any) -> Any:
    """``value``, or a preview of it when it is too long to keep whole.

    A long value would bloat the database, and MySQL refuses a row larger than
    max_allowed_packet, losing the record of the call.
    """
    if value is None:
        return None
    text = str(value)
    if len(text) <= PAYLOAD_LENGTH:
        return value
    # The digest shows what the whole value was, though only a preview is kept.
    return {
        "_truncated": True,
        "_original_size": len(text),
        "_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "_preview": text[:_PREVIEW_LENGTH] + "...",
    }


def _exception_summary(error: Exception) -> str:
    """What an audit row records about an exception.

    An HTTPException's detail is what the caller saw. Other exceptions can name
    internal hosts, so only their type is recorded; the log keeps the text.
    """
    if isinstance(error, HTTPException) and isinstance(error.detail, str):
        return error.detail
    return type(error).__name__


class AuditLogger:
    """Service for logging MCP tool calls"""

    @staticmethod
    async def log_tool_call(  # pylint: disable=too-many-locals
        db: Session,
        user: User,
        service: str,
        tool_name: str,
        method: str,
        request_params: Optional[Dict[str, Any]] = None,
        request_headers: Optional[Dict[str, str]] = None,
        response_data: Optional[Dict[str, Any]] = None,
        status: str = "success",
        error_message: Optional[str] = None,
        duration_ms: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metric_name: Optional[str] = None,
    ) -> AuditLog:
        """
        Log a tool call to the audit log.

        Args:
            db: Database session
            user: User making the call
            service: MCP service name (e.g., "metastore", "trino")
            tool_name: Name of the tool being called
            method: MCP method (e.g., "tools/call", "prompts/get")
            request_params: Parameters sent to the tool
            request_headers: SA workload headers only (from get_workload_forward_headers), or None
            response_data: Response from the tool (may be truncated for large responses)
            status: "success", "error", "unauthorized" (the gateway refused
                the call) or "cancelled" (the client left before it finished)
            error_message: Error message if status is "error"
            duration_ms: Request duration in milliseconds
            ip_address: Client IP address
            user_agent: Client user agent
            metric_name: Label for the call in metrics, when the tool name is
                chosen by the caller and would grow the label set without bound

        Returns:
            Created AuditLog entry
        """
        tool_name = _fit("tool_name", tool_name)
        method = _fit("method", method)

        # Emit Prometheus metrics first — independent of DB write success.
        record_tool_call(service, metric_name or tool_name, status, duration_ms)

        audit_log = AuditLog(
            user_id=user.id,
            username=user.username,
            service=_fit("service", service),
            tool_name=tool_name,
            method=method,
            request_params=_bounded(_redacted(request_params)),
            request_headers=request_headers,
            # Responses hold what the server let the caller see, which admins
            # could read here, so they are kept only when a deployment asks.
            response_data=(
                _bounded(response_data) if settings.AUDIT_LOG_RESPONSES else None
            ),
            status=status,
            error_message=_fit("error_message", error_message),
            duration_ms=duration_ms,
            ip_address=_fit("ip_address", ip_address),
            user_agent=_fit("user_agent", user_agent),
        )

        db.add(audit_log)
        db.commit()
        return audit_log

    @staticmethod
    @asynccontextmanager
    async def track_tool_call(  # pylint: disable=too-many-locals
        db: Session,
        user: User,
        service: str,
        tool_name: str,
        method: str = "tools/call",
        request_params: Optional[Dict[str, Any]] = None,
        request: Optional[Request] = None,
        metric_name: Optional[str] = None,
    ):
        """
        Context manager for automatically tracking tool call timing and errors.

        ``metric_name`` labels the call in metrics when the tool name is chosen
        by the caller.

        Usage:
            async with AuditLogger.track_tool_call(db, user, "metastore", "list_databases") as tracker:
                result = await call_mcp_tool(...)
                tracker.set_response(result)
        """
        start_time = time.time()
        tracker = ToolCallTracker()

        # Extract request metadata
        ip_address = None
        user_agent = None
        request_headers = None
        if request:
            ip_address = request.client.host if request.client else None
            user_agent = request.headers.get("user-agent")
            request_headers = get_workload_forward_headers(request)
            # Empty dict means "no workload headers"; store NULL in audit (humans get {} from getter for **kwargs)
            if not request_headers:
                request_headers = None
        fields = {
            "user": user,
            "service": service,
            "tool_name": tool_name,
            "method": method,
            "request_params": request_params,
            "request_headers": request_headers,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "metric_name": metric_name,
        }
        try:
            yield tracker
        except asyncio.CancelledError:
            # The call may still run upstream, so it is recorded all the same.
            await asyncio.shield(
                _record(
                    db,
                    **fields,
                    response_data=None,
                    status="cancelled",
                    error_message=CANCELLED,
                    duration_ms=int((time.time() - start_time) * 1000),
                )
            )
            raise
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.warning("%s %s on %s failed: %s", method, tool_name, service, e)
            await _record(
                db,
                **fields,
                response_data=None,
                status="error",
                error_message=_exception_summary(e),
                duration_ms=duration_ms,
            )
            raise

        # The tracker holds an MCP protocol error, as opposed to an exception.
        await _record(
            db,
            **fields,
            response_data=tracker.response,
            status="error" if tracker.error_message else "success",
            error_message=tracker.error_message,
            duration_ms=int((time.time() - start_time) * 1000),
        )


async def log_refusal(  # pylint: disable=too-many-arguments
    db: Session,
    user: User,
    service: str,
    method: str,
    request_params: Optional[Dict[str, Any]],
    request: Request,
    reason: str,
) -> None:
    """Record a call the gateway refused, such as one without access."""
    tool_name = (request_params or {}).get("name") if method == "tools/call" else None
    await _record(
        db,
        user=user,
        service=service,
        tool_name=tool_name or method,
        method=method,
        metric_name=metric_method(method),
        request_params=request_params,
        request_headers=get_workload_forward_headers(request) or None,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        response_data=None,
        status="unauthorized",
        error_message=reason,
        duration_ms=0,
    )


def record_admin_change(  # pylint: disable=too-many-arguments
    db: Session,
    admin: User,
    request: Request,
    *,
    service: str,
    action: str,
    changes: Optional[Dict[str, Any]] = None,
) -> None:
    """Add to ``db`` a record of an admin's change, committed with the change.

    ``changes`` are the fields the admin set; secrets among them are redacted.
    """
    db.add(
        AuditLog(
            user_id=admin.id,
            username=admin.username,
            service=_fit("service", service),
            tool_name=_fit("tool_name", action),
            method="admin",
            request_params=_bounded(_redacted(changes)),
            status="success",
            duration_ms=0,
            ip_address=_fit(
                "ip_address", request.client.host if request.client else None
            ),
            user_agent=_fit("user_agent", request.headers.get("user-agent")),
        )
    )


async def _record(db: Session, **fields) -> None:
    """Write an audit row, logging rather than raising if the write fails.

    The call has run by then, so its result or error must reach the caller.
    """
    try:
        await AuditLogger.log_tool_call(db=db, **fields)
    except Exception:  # pylint: disable=broad-exception-caught
        db.rollback()
        logger.exception(
            "Failed to write the audit log for %s %s on %s",
            fields["method"],
            fields["tool_name"],
            fields["service"],
        )


class ToolCallTracker:
    """Helper class for tracking tool call responses"""

    def __init__(self):
        self.response = None
        self.error_message = None

    def set_response(self, response: Any):
        """Set the response data from the tool call"""
        self.response = response

    def set_error(self, error_message: str):
        """Set error message for MCP protocol errors (not Python exceptions)"""
        self.error_message = error_message
