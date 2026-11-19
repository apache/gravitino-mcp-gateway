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
OAuth 2.0 device authorization grant client (RFC 8628).

Shared HTTP client used by mcp_gateway_cli login and the Slack /gravitino-mcp bot.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_CLIENT_ID = "gravitino-mcp-cli"
DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


class PollStatus(str, Enum):
    PENDING = "pending"
    SUCCESS = "success"
    ERROR = "error"
    EXPIRED = "expired"


@dataclass(frozen=True)
class DeviceCodeData:
    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int


@dataclass(frozen=True)
class PollResult:
    status: PollStatus
    token_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    error_description: Optional[str] = None


def request_device_code(
    gateway_url: str,
    *,
    client_id: str = DEFAULT_CLIENT_ID,
    timeout: int = 10,
) -> DeviceCodeData:
    """POST /api/device/code — same request body as gravitino-mcp login."""
    logger.info("Requesting device code from %s", gateway_url)
    base = gateway_url.rstrip("/")
    response = requests.post(
        f"{base}/api/device/code",
        json={"client_id": client_id},
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()
    return DeviceCodeData(
        device_code=data["device_code"],
        user_code=data["user_code"],
        verification_uri=data["verification_uri"],
        expires_in=int(data["expires_in"]),
        interval=int(data["interval"]),
    )


async def request_device_code_async(
    gateway_url: str,
    *,
    client_id: str = DEFAULT_CLIENT_ID,
    timeout: int = 10,
) -> DeviceCodeData:
    """Non-blocking wrapper for use from async handlers (e.g. Slack Bolt)."""
    return await asyncio.to_thread(
        request_device_code,
        gateway_url,
        client_id=client_id,
        timeout=timeout,
    )


def poll_device_token_once(
    gateway_url: str,
    device_code: str,
    *,
    timeout: int = 10,
) -> PollResult:
    """POST /api/device/token — one poll attempt."""
    base = gateway_url.rstrip("/")
    try:
        response = requests.post(
            f"{base}/api/device/token",
            json={
                "device_code": device_code,
                "grant_type": DEVICE_GRANT_TYPE,
            },
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return PollResult(
            status=PollStatus.ERROR,
            error="request_failed",
            error_description=str(exc),
        )

    if response.status_code == 200:
        return PollResult(status=PollStatus.SUCCESS, token_data=response.json())

    if response.status_code == 400:
        try:
            error_data = response.json()
        except ValueError:
            return PollResult(
                status=PollStatus.ERROR,
                error="invalid_response",
                error_description=response.text,
            )
        if error_data.get("error") == "authorization_pending":
            return PollResult(status=PollStatus.PENDING)
        return PollResult(
            status=PollStatus.ERROR,
            error=error_data.get("error"),
            error_description=error_data.get("error_description"),
        )

    return PollResult(
        status=PollStatus.ERROR,
        error="unexpected_status",
        error_description=f"HTTP {response.status_code}: {response.text}",
    )


def poll_device_token_until_done(
    gateway_url: str,
    device_code: str,
    *,
    expires_in: int,
    interval: int,
    sleep: Callable[[float], None] = time.sleep,
    on_pending: Optional[Callable[[], None]] = None,
) -> PollResult:
    """Poll until success, terminal error, or TTL — same loop as gravitino-mcp login."""
    deadline = time.time() + expires_in
    while time.time() < deadline:
        result = poll_device_token_once(gateway_url, device_code)
        if result.status != PollStatus.PENDING:
            return result
        if on_pending:
            on_pending()
        sleep(interval)
    return PollResult(
        status=PollStatus.EXPIRED,
        error="expired",
        error_description="Device code expired before authorization completed",
    )


async def poll_device_token_until_done_async(
    gateway_url: str,
    device_code: str,
    *,
    expires_in: int,
    interval: int,
) -> PollResult:
    """Async variant for Slack Bolt (uses asyncio.sleep)."""
    deadline = time.time() + expires_in
    while time.time() < deadline:
        result = await asyncio.to_thread(
            poll_device_token_once, gateway_url, device_code
        )
        if result.status != PollStatus.PENDING:
            return result
        await asyncio.sleep(interval)
    return PollResult(
        status=PollStatus.EXPIRED,
        error="expired",
        error_description="Device code expired before authorization completed",
    )
