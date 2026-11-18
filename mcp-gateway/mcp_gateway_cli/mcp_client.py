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

"""Requests to MCP servers through the gateway, as any MCP client makes them."""

import json
from typing import Any, Optional
from urllib.parse import quote

import requests

from .constants import PROXY_REQUEST_TIMEOUT

# How long to wait for the gateway to answer; a tool may then run for up to
# PROXY_REQUEST_TIMEOUT while the gateway sends heartbeats.
CONNECT_TIMEOUT_SECONDS = 30


class McpError(Exception):
    """A JSON-RPC error from the gateway or the MCP server, such as access denied."""


def request(
    gateway_url: str,
    access_token: str,
    service: str,
    method: str,
    params: Optional[dict] = None,
) -> Any:
    """The result of one JSON-RPC request to ``service``.

    Raises McpError for a JSON-RPC error, and requests' exceptions when the
    gateway can't be reached or refuses the token.
    """
    response = requests.post(
        f"{gateway_url}/mcp/{quote(service, safe='')}",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json, text/event-stream",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        stream=True,
        timeout=(CONNECT_TIMEOUT_SECONDS, PROXY_REQUEST_TIMEOUT),
    )
    message = _read_message(response)
    if isinstance(message, dict) and "error" in message:
        raise McpError(message["error"].get("message", "The server returned an error"))
    response.raise_for_status()
    if not isinstance(message, dict) or "result" not in message:
        raise McpError("The gateway sent no response")
    return message["result"]


def _read_message(response: requests.Response) -> Optional[dict]:
    """The JSON-RPC message in a reply sent as JSON or as server-sent events."""
    if "text/event-stream" not in response.headers.get("Content-Type", ""):
        try:
            return response.json()
        except ValueError:
            return None
    for line in response.iter_lines(decode_unicode=True):
        # Heartbeats are comments (":"); the message is a data line.
        if not line or not line.startswith("data:"):
            continue
        try:
            message = json.loads(line[len("data:") :])
        except json.JSONDecodeError:
            continue
        if isinstance(message, dict) and ("result" in message or "error" in message):
            return message
    return None
