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

"""Talking to upstream MCP servers: their sessions, their replies, and tool filters."""

import json
import logging
import time
from typing import Optional

import httpx

from .. import VERSION
from ..config import settings
from ..telemetry import set_attribute, span, with_trace_context

logger = logging.getLogger(__name__)


def read_jsonrpc_message(response: httpx.Response) -> dict:
    """The JSON-RPC message in an MCP server's reply, sent as JSON or as SSE.

    An empty reply reads as an error. The server can send anything, so a
    reply that holds no JSON-RPC message raises ValueError.
    """
    if "text/event-stream" in response.headers.get("Content-Type", ""):
        message = None
        for line in response.text.splitlines():
            # A field's value follows the colon, after one optional space.
            if not line.startswith("data:"):
                continue
            try:
                message = json.loads(line[len("data:") :])
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict) and (
                message.get("done") or "result" in message or "error" in message
            ):
                break
    elif response.content:
        message = json.loads(response.content)
    else:
        message = {"error": {"code": -32603, "message": "Empty response from backend"}}
    if not isinstance(message, dict):
        raise ValueError("The response holds no JSON-RPC message")
    return message


def tool_allowed(service: str, tool_name: str) -> bool:
    """Whether MCP_TOOL_FILTERS lets callers list and call *tool_name* on *service*.

    Prefix matching is intentional: new tools that start with an allowed prefix
    are included without a configuration change.
    """
    prefixes = settings.MCP_TOOL_FILTERS.get(service)
    if prefixes is None:
        return True
    # A server listed with no prefixes exposes no tools.
    return any(tool_name.startswith(p) for p in prefixes)


def filter_tools(service: str, tools: list[dict]) -> list[dict]:
    """Return only the tools of *service* that MCP_TOOL_FILTERS allows.

    The list comes from the MCP server, so entries without a name are dropped.
    """
    return [
        t
        for t in tools
        if isinstance(t, dict)
        and isinstance(t.get("name"), str)
        and tool_allowed(service, t["name"])
    ]


# The MCP session each person holds with each server, and when to start a new
# one: (user ID, server ID) -> (session ID, expiry). Some servers need an
# initialize before any other request; an empty ID is a server that keeps no
# session, which needs no initialize again until the entry expires.
_upstream_sessions: dict[tuple[int, str], tuple[str, float]] = {}
_UPSTREAM_SESSION_TTL = 3600  # 1 hour
MCP_PROTOCOL_VERSION = "2025-03-26"


def forget_sessions(service: str) -> None:
    """Drop every session with ``service``, such as when it moves to another URL."""
    for key in [key for key in _upstream_sessions if key[1] == service]:
        del _upstream_sessions[key]


async def ensure_upstream_session(
    client: httpx.AsyncClient,
    mcp_url: str,
    auth_headers: dict,
    extra_headers: dict,
    user_id: int,
    service: str,
) -> Optional[str]:
    """The person's session with the server, initializing one when there is none.

    None when the server keeps no session, or when initialize failed, which is
    tried again on the next request.
    """
    cache_key = (user_id, service)
    cached = _upstream_sessions.get(cache_key)
    if cached and time.time() < cached[1]:
        return cached[0] or None

    session_id = await _mcp_initialize(client, mcp_url, auth_headers, extra_headers)
    if session_id is not None:
        _upstream_sessions[cache_key] = (
            session_id,
            time.time() + _UPSTREAM_SESSION_TTL,
        )
    return session_id or None


async def post_to_upstream(
    client: httpx.AsyncClient,
    mcp_url: str,
    body: dict,
    headers: dict,
    user_id: int,
    service: str,
) -> httpx.Response:
    """POST a message to an MCP server, starting a new session if it forgot ours.

    An MCP server answers 404 for a session it does not know, for example after a
    restart, and the client must then initialize a new one (Streamable HTTP).
    """
    with span("mcp.upstream", {"mcp.server.id": service}):
        resp = await client.post(
            mcp_url, json=body, headers=with_trace_context(headers)
        )
        set_attribute("http.response.status_code", resp.status_code)
        if resp.status_code != 404 or "Mcp-Session-Id" not in headers:
            return resp

        logger.info("%s no longer knows the MCP session; starting a new one", service)
        _upstream_sessions.pop((user_id, service), None)
        headers = {k: v for k, v in headers.items() if k != "Mcp-Session-Id"}
        session_id = await ensure_upstream_session(
            client, mcp_url, headers, {}, user_id, service
        )
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        return await client.post(
            mcp_url, json=body, headers=with_trace_context(headers)
        )


async def _mcp_initialize(
    client: httpx.AsyncClient,
    mcp_url: str,
    auth_headers: dict,
    extra_headers: dict,
) -> Optional[str]:
    """Initialize with the server: its session ID, "" for a server that keeps no
    session, or None if initialize failed."""
    try:
        resp = await client.post(
            mcp_url,
            json={
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "MCP Gateway", "version": VERSION},
                },
                "id": 0,
            },
            headers=with_trace_context(
                {
                    **extra_headers,
                    **auth_headers,
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                }
            ),
        )
        if resp.status_code >= 400:
            logger.warning(
                "MCP initialize returned %s for %s", resp.status_code, mcp_url
            )
            return None
        session_id = resp.headers.get("mcp-session-id", "")
        if session_id:
            # Send initialized notification
            notif_resp = await client.post(
                mcp_url,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers={
                    **extra_headers,
                    **auth_headers,
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Session-Id": session_id,
                },
            )
            if notif_resp.status_code >= 400:
                logger.warning(
                    "MCP notifications/initialized returned %s for %s: %s",
                    notif_resp.status_code,
                    mcp_url,
                    notif_resp.text[:300],
                )
        return session_id
    except Exception:  # pylint: disable=broad-exception-caught
        logger.debug("MCP initialize handshake skipped/failed for %s", mcp_url)
        return None
