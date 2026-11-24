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

"""The MCP endpoint, /mcp/<server ID>: MCP's Streamable HTTP transport, in front
of the servers in the catalog.

The gateway answers ``initialize`` itself, offering tools, and forwards
requests to the server once the caller's access is checked, signed in as the
server accepts. Notifications are acknowledged but not passed on, and GET,
for messages a server starts, is not offered.
"""

import asyncio
import base64
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
import jwt as pyjwt
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import VERSION
from ..audit import CANCELLED, AuditLogger, log_refusal, tool_call_failure
from ..config import settings
from ..database import SessionLocal, get_db
from ..gateway_keys import mint_gateway_jwt
from ..metrics import metric_method
from ..models import MCPCatalog, MCPUserPermission, ServiceAccountCredentials, User
from ..oauth.mcp_service_auth import (
    build_credential_forward_headers,
    effective_auth_type,
)
from ..oauth.token_encryption import get_token_encryption
from ..oauth.token_manager import TokenManager
from ..oauth_auth import (
    get_passthrough_forward_headers,
    get_user_from_bearer_token,
    get_workload_forward_headers,
)
from ..telemetry import span
from .mcp_upstream import (
    MCP_PROTOCOL_VERSION,
    ensure_upstream_session,
    filter_tools,
    post_to_upstream,
    read_jsonrpc_message,
    tool_allowed,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/mcp", tags=["mcp-proxy"])

# An MCP session ID (Streamable HTTP) is not a credential: the bearer token is.
# It says that this person called initialize for this server recently, so an
# unknown or expired one tells the client to initialize again. It is a signed
# token, so the gateway keeps no session state, and any replica can check it.
_SESSION_TTL = 86400  # 24 hours


def _create_session(user_id: int, service: str) -> str:
    """A session ID for ``user_id``'s session with ``service``."""
    now = datetime.now(timezone.utc)
    payload = {
        "u": user_id,
        "s": service,
        "iat": now,
        "exp": now + timedelta(seconds=_SESSION_TTL),
    }
    return pyjwt.encode(
        payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )


def _session_claims(session_id: str) -> Optional[dict]:
    """The claims of an unexpired session ID the gateway issued, or None."""
    try:
        return pyjwt.decode(
            session_id, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
    except pyjwt.InvalidTokenError:
        return None


def _invalid_request(body: Any) -> Optional[str]:
    """Why ``body`` is not a JSON-RPC message the gateway can proxy, or None.

    MCP's Streamable HTTP takes one message per POST, with params an object.
    """
    if not isinstance(body, dict):
        return "the body must be one JSON-RPC message"
    if "method" in body and not isinstance(body["method"], str):
        return "method must be a string"
    params = body.get("params", {})
    if not isinstance(params, dict):
        return "params must be an object"
    if body.get("method") == "tools/call" and not isinstance(params.get("name"), str):
        return "tools/call needs the tool's name"
    return None


def _validate_session(session_id: str, service: str, user_id: int) -> bool:
    """Whether ``session_id`` is an unexpired session of ``user_id`` with ``service``."""
    claims = _session_claims(session_id)
    return claims is not None and (claims.get("u"), claims.get("s")) == (
        user_id,
        service,
    )


# Shared httpx client for proxying requests to backend MCPs.
# Created lazily on first use; reuses TCP connections across requests.
_mcp_http_client: Optional[httpx.AsyncClient] = None  # pylint: disable=invalid-name


def _get_mcp_http_client() -> httpx.AsyncClient:
    """Return (and lazily create) the shared httpx client for backend MCP calls."""
    global _mcp_http_client  # pylint: disable=global-statement
    if _mcp_http_client is None:
        _mcp_http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=30.0,
                read=float(settings.MCP_TOOL_CALL_TIMEOUT),
                write=30.0,
                pool=30.0,
            ),
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
                keepalive_expiry=30.0,
            ),
            verify=settings.upstream_tls_verify,
        )
    return _mcp_http_client


# Upstream MCP session management lives in mcp_upstream.py.


def _rpc_message(request_id, code: int, message: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _rpc_error(
    request_id, code: int, message: str, status_code: int = 200
) -> JSONResponse:
    """A JSON-RPC error reply."""
    return JSONResponse(
        _rpc_message(request_id, code, message), status_code=status_code
    )


def _timed_out() -> str:
    return f"Backend MCP timeout after {settings.MCP_TOOL_CALL_TIMEOUT}s"


def _tool_call_outcome(backend_task: asyncio.Task, request_id, service: str):
    """What a finished upstream tool call sends the client: (message, status, error)."""

    def failed(code: int, message: str):
        return _rpc_message(request_id, code, message), "error", message

    try:
        backend_response = backend_task.result()
        backend_response.raise_for_status()
        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            **read_jsonrpc_message(backend_response),
        }
    except httpx.TimeoutException:
        return failed(-32000, _timed_out())
    except httpx.HTTPStatusError as e:
        return failed(-32000, f"Backend MCP error: {e.response.status_code}")
    except ValueError as e:
        # Includes JSON that does not parse; the server's text stays in the log.
        logger.warning("Invalid response from %s: %s", service, e)
        return failed(-32000, "Backend MCP returned an invalid response")
    except httpx.RequestError as e:
        # httpx's text can name the server's host, which is for admins.
        logger.warning("Could not reach %s: %s", service, e)
        return failed(
            -32000, "Backend MCP connection error: the server could not be reached"
        )
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("Streaming tool call error for %s", service)
        return failed(-32603, "Internal error")
    failure = tool_call_failure(message)
    return message, "error" if failure is not None else "success", failure


def _stream_tool_call(  # pylint: disable=too-many-arguments
    body: dict,
    request_id,
    mcp,
    auth_headers: dict,
    current_user: User,
    method: str,
    request: Request,
) -> StreamingResponse:
    """
    Stream an MCP tool call response using SSE with periodic heartbeats.

    Prevents idle-connection timeouts (from load balancers or MCP clients)
    during long-running backend operations like Trino queries.  Heartbeat
    comments (`: heartbeat`) keep the TCP connection alive while the backend
    processes the request.

    The request's DB session is not held while streaming: the audit row is
    written with a short-lived session once the call ends, or the client
    leaves, so many long tool calls can't exhaust the connection pool.
    """
    service = mcp.service_id
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    request_params = body.get("params", {})
    workload_headers = get_workload_forward_headers(request)

    # Fire backend request concurrently so we can yield heartbeats while waiting.
    backend_task = asyncio.create_task(
        post_to_upstream(
            _get_mcp_http_client(),
            mcp.mcp_url,
            body,
            {
                **workload_headers,
                **get_passthrough_forward_headers(request),
                **auth_headers,
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            current_user.id,
            service,
        )
    )

    async def _log_audit(response_data, status, error_message, duration_ms):
        """Write audit log using a fresh short-lived DB session."""
        audit_db = SessionLocal()
        try:
            await AuditLogger.log_tool_call(
                db=audit_db,
                user=current_user,
                service=service,
                tool_name=request_params.get("name") or method,
                method=method,
                metric_name=metric_method(method),
                request_params=request_params,
                request_headers=workload_headers,
                response_data=response_data,
                status=status,
                error_message=error_message,
                duration_ms=duration_ms,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("Failed to write streaming audit log")
        finally:
            audit_db.close()

    async def sse_generator():
        start_time = time.time()
        audited = False
        try:
            try:
                # Send heartbeats while waiting for the backend response.
                while True:
                    done, _ = await asyncio.wait({backend_task}, timeout=15.0)
                    if done:
                        break
                    yield ": heartbeat\n\n"
                message, status, error = _tool_call_outcome(
                    backend_task, request_id, service
                )
            except Exception:  # pylint: disable=broad-exception-caught
                logger.exception("Streaming tool call error for %s", service)
                message = _rpc_message(request_id, -32603, "Internal error")
                status, error = "error", "Internal error"
            await _log_audit(message, status, error, _elapsed_ms(start_time))
            audited = True
            yield f"event: message\ndata: {json.dumps(message)}\n\n"
        finally:
            if not backend_task.done():
                backend_task.cancel()
            if not audited:
                # The client left first; the call may still have run upstream.
                await asyncio.shield(
                    _log_audit(None, "cancelled", CANCELLED, _elapsed_ms(start_time))
                )

    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


def _elapsed_ms(start_time: float) -> int:
    return int((time.time() - start_time) * 1000)


@router.get("/{service}")
async def mcp_endpoint_info(
    service: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_user_from_bearer_token),
):
    """405: the stream for messages a server starts is not offered (Streamable HTTP).

    It still needs a token, so that a client without one gets a 401 that
    starts its sign-in (RFC 9728).
    """
    mcp = MCPCatalog.find_active(db, service)

    if not mcp or mcp.is_hidden_from(current_user):
        return JSONResponse(
            {"detail": f"Service '{service}' not found or inactive"}, status_code=404
        )

    # Auth passed — server-initiated SSE not supported, tell client to use POST
    return JSONResponse(
        status_code=405,
        content={
            "detail": "Server-initiated SSE stream not supported. Use POST for JSON-RPC requests.",
            "service": service,
            "transport": "streamable-http",
        },
        headers={"Allow": "POST, DELETE"},
    )


@router.delete("/{service}")
async def mcp_session_terminate(
    service: str,
    request: Request,
    current_user: User = Depends(get_user_from_bearer_token),
):
    """End an MCP session (Streamable HTTP), as a client that is done sends.

    A session ID expires by itself, so there is nothing to delete; the reply
    says whether the session was the caller's.
    """
    session_id = request.headers.get("mcp-session-id")
    if not session_id:
        return Response(status_code=400)
    claims = _session_claims(session_id)
    if claims is None:
        return Response(status_code=404)
    if (claims.get("u"), claims.get("s")) != (current_user.id, service):
        return Response(status_code=403)

    logger.info(
        "MCP session terminated by user %s for %s", current_user.username, service
    )
    return Response(status_code=200)


class _Refusal(Exception):
    """A call the gateway refuses, answering with a JSON-RPC error itself."""

    def __init__(self, code: int, message: str, status_code: int = 200):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _check_access(db: Session, user: User, mcp: MCPCatalog) -> None:
    """Raise _Refusal unless ``user`` may call ``mcp``.

    An open server grants a person access on first use; service accounts reach
    only the servers their registration lists.
    """
    service = mcp.service_id
    if user.is_service_account:
        sa_creds = (
            db.query(ServiceAccountCredentials)
            .filter(ServiceAccountCredentials.service_account_id == user.id)
            .first()
        )
        if not sa_creds or service not in sa_creds.allowed_services:
            raise _Refusal(
                -32002, f"Service account not authorized to access {service}", 403
            )
        return

    permission = _permission(db, user, mcp)
    if permission is None:
        if not mcp.is_open_access:
            # A JSON-RPC error with 200 OK, so clients don't start signing in.
            raise _Refusal(
                -32002,
                f"Access denied. You don't have permission to access {service}. "
                "Please request access.",
            )
        permission = _grant_open_access(db, user, mcp)
    if permission is not None and permission.has_expired(mcp):
        raise _Refusal(
            -32002,
            f"Your permission to access {service} has expired. "
            "Please request renewed access.",
        )


def _permission(
    db: Session, user: User, mcp: MCPCatalog
) -> Optional[MCPUserPermission]:
    return (
        db.query(MCPUserPermission)
        .filter(
            MCPUserPermission.user_id == user.id,
            MCPUserPermission.mcp_id == mcp.id,
        )
        .first()
    )


def _grant_open_access(
    db: Session, user: User, mcp: MCPCatalog
) -> Optional[MCPUserPermission]:
    """Record that ``user`` uses an open server; lasts only while it stays open."""
    permission = MCPUserPermission(user_id=user.id, mcp_id=mcp.id, granted_by=None)
    db.add(permission)
    try:
        db.commit()
    except IntegrityError:
        # A concurrent request recorded it first.
        db.rollback()
        return _permission(db, user, mcp)
    logger.info("Granted %s open access to %s", user.username, mcp.service_id)
    return permission


async def _upstream_auth_headers(
    db: Session, request: Request, user: User, mcp: MCPCatalog
) -> dict:
    """How the gateway signs in to ``mcp`` for ``user``; raises _Refusal if it can't."""
    service = mcp.service_id
    auth_mode = effective_auth_type(mcp, user)

    if auth_mode == "passthrough":
        # A token the gateway signs for this server alone.
        return {"Authorization": f"Bearer {mint_gateway_jwt(user, audience=service)}"}

    if auth_mode == "basic":
        if not mcp.basic_auth_username or not mcp.basic_auth_password_encrypted:
            raise _Refusal(
                -32000,
                f"Basic auth credentials not configured for {service}. Contact your admin.",
            )
        encryption = await get_token_encryption()
        password = encryption.decrypt(mcp.basic_auth_password_encrypted)
        if password is None:
            raise _Refusal(
                -32000,
                f"The basic auth password for {service} can't be read. Contact your admin.",
            )
        credentials = base64.b64encode(
            f"{mcp.basic_auth_username}:{password}".encode()
        ).decode()
        return {"Authorization": f"Basic {credentials}"}

    if auth_mode == "credential_forward":
        if not user.is_service_account:
            raise _Refusal(
                -32002,
                "credential_forward authentication is only for service accounts.",
                403,
            )
        headers = await build_credential_forward_headers(db, user, service)
        if not headers:
            raise _Refusal(
                -32000,
                "No downstream credentials configured for service account "
                f"on {service}. Contact your admin.",
                403,
            )
        return headers

    # OAuth: the person's own, exchanged or connected token. An exchanged token
    # is stored, so later calls, whatever their method, reuse it.
    token = await TokenManager(db).get_token(
        user.id, service, bearer_token=getattr(request.state, "bearer_token", None)
    )
    if not token:
        raise _Refusal(
            -32000,
            f"Not connected to {service}. Please connect first using: "
            f"gravitino-mcp connect {service}",
        )
    return {"Authorization": f"Bearer {token}"}


@router.post("/{service}")
async def mcp_proxy(  # pylint: disable=too-many-return-statements
    service: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_user_from_bearer_token),
):
    """Answer one JSON-RPC message: initialize here, requests by the server,
    once the caller's access is checked; and write requests to the audit log."""
    # A web page can send a cross-site text/plain POST without a CORS preflight;
    # MCP clients always declare JSON.
    media_type = request.headers.get("content-type", "").split(";")[0].strip()
    if media_type.lower() != "application/json":
        return _rpc_error(None, -32700, "Content-Type must be application/json", 415)

    try:
        body = await request.json()
    except Exception:  # pylint: disable=broad-exception-caught
        return _rpc_error(None, -32700, "Parse error", 400)

    invalid = _invalid_request(body)
    if invalid:
        request_id = body.get("id") if isinstance(body, dict) else None
        return _rpc_error(request_id, -32600, f"Invalid Request: {invalid}", 400)

    method = body.get("method", "unknown")
    attributes = {"mcp.server.id": service, "mcp.method": method}
    if method == "tools/call":
        attributes["mcp.tool.name"] = body["params"]["name"]
    # Continues the caller's trace, if its request carries one. A streamed tool
    # call's reply outlives this span; the "mcp.upstream" span times the call.
    with span("mcp.request", attributes, headers=request.headers):
        return await _proxy_message(service, request, db, current_user, body)


async def _proxy_message(  # pylint: disable=too-many-return-statements
    service: str, request: Request, db: Session, current_user: User, body: dict
):
    """Answer a valid JSON-RPC message, as ``mcp_proxy`` describes."""
    method = body.get("method", "unknown")
    request_id = body.get("id")

    # A notification (no id) gets no JSON-RPC reply, per MCP's Streamable HTTP
    # transport, only 202 Accepted.
    if "id" not in body:
        return Response(status_code=202)

    if method == "initialize":
        return _initialize_reply(request_id, current_user, service)

    # An unknown or expired Mcp-Session-Id tells the client to initialize again;
    # requests without one are allowed for older clients.
    session_id = request.headers.get("mcp-session-id")
    if session_id and not _validate_session(session_id, service, current_user.id):
        return JSONResponse(
            {"detail": "Unknown or expired session. Please re-initialize."},
            status_code=404,
        )

    mcp = MCPCatalog.find_active(db, service)
    if not mcp or mcp.is_hidden_from(current_user):
        return _rpc_error(
            request_id, -32001, f"Service '{service}' not found or inactive", 404
        )

    params = body.get("params", {})
    try:
        _check_access(db, current_user, mcp)
        auth_headers = await _upstream_auth_headers(db, request, current_user, mcp)
        if method == "tools/call" and not tool_allowed(service, params.get("name", "")):
            raise _Refusal(
                -32601,
                f"Tool '{params.get('name', '')}' is not available on {service}.",
            )
    except _Refusal as refusal:
        await log_refusal(
            db, current_user, service, method, params, request, refusal.message
        )
        return _rpc_error(
            request_id, refusal.code, refusal.message, refusal.status_code
        )

    # Nothing more is read from the database until the audit row, so the
    # connection goes back to the pool for the upstream calls, however long.
    _release(db, mcp, current_user)

    # Some servers need an initialize handshake first, and then their session id.
    upstream_sid = await ensure_upstream_session(
        _get_mcp_http_client(),
        mcp.mcp_url,
        auth_headers,
        {
            **get_workload_forward_headers(request),
            **get_passthrough_forward_headers(request),
        },
        current_user.id,
        service,
    )
    if upstream_sid:
        auth_headers["Mcp-Session-Id"] = upstream_sid

    # Tool calls stream, with heartbeats, so long ones aren't cut off as idle.
    if method == "tools/call":
        return _stream_tool_call(
            body=body,
            request_id=request_id,
            mcp=mcp,
            auth_headers=auth_headers,
            current_user=current_user,
            method=method,
            request=request,
        )
    return await _forward(db, request, current_user, mcp, body, auth_headers)


def _initialize_reply(request_id, user: User, service: str) -> JSONResponse:
    """The gateway's own answer to initialize, with a new session for ``user``."""
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": f"MCP Gateway {service}", "version": VERSION},
            },
        },
        headers={"Mcp-Session-Id": _create_session(user.id, service)},
    )


def _release(db: Session, *instances) -> None:
    """Close ``db``, keeping ``instances`` readable once they're detached."""
    for instance in instances:
        if inspect(instance).expired_attributes:
            db.refresh(instance)
    db.close()


async def _forward(  # pylint: disable=too-many-arguments,too-many-return-statements
    db: Session,
    request: Request,
    current_user: User,
    mcp: MCPCatalog,
    body: dict,
    auth_headers: dict,
) -> JSONResponse:
    """Send any other method to the server and return its reply, audited."""
    service = mcp.service_id
    method = body.get("method")
    request_id = body.get("id")
    try:
        async with AuditLogger.track_tool_call(
            db=db,
            user=current_user,
            service=service,
            tool_name=method,
            method=method,
            metric_name=metric_method(method),
            request_params=body.get("params", {}),
            request=request,
        ) as tracker:
            backend_response = await post_to_upstream(
                _get_mcp_http_client(),
                mcp.mcp_url,
                body,
                {
                    **get_workload_forward_headers(request),
                    **get_passthrough_forward_headers(request),
                    **auth_headers,
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
                current_user.id,
                service,
            )
            backend_response.raise_for_status()

            # The reply may be JSON or an SSE stream. An empty reply gets the
            # request's id, so clients can match it.
            response_data = {
                "jsonrpc": "2.0",
                "id": request_id,
                **read_jsonrpc_message(backend_response),
            }

            # Hide the tools that the server's filter removes.
            result = response_data.get("result")
            if method == "tools/list" and isinstance(result, dict):
                tools = result.get("tools")
                if isinstance(tools, list):
                    result["tools"] = filter_tools(service, tools)

            tracker.set_response(response_data)
            if "error" in response_data:
                tracker.set_error(tool_call_failure(response_data))
            return JSONResponse(response_data)

    except httpx.TimeoutException:
        return _rpc_error(request_id, -32000, _timed_out(), 504)
    except httpx.HTTPStatusError as e:
        return _rpc_error(
            request_id, -32000, f"Backend MCP error: {e.response.status_code}", 502
        )
    except ValueError as e:
        # Includes JSON that does not parse; the server's text stays in the log.
        logger.warning("Invalid response from %s: %s", service, e)
        return _rpc_error(
            request_id, -32000, "Backend MCP returned an invalid response", 502
        )
    except httpx.RequestError as e:
        logger.warning("Could not reach %s: %s", service, e)
        return _rpc_error(
            request_id,
            -32000,
            "Backend MCP connection error: the server could not be reached",
            502,
        )
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("MCP proxy error for %s", service)
        return _rpc_error(request_id, -32603, "Internal error", 500)
