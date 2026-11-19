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
HMAC request signing and client helpers for MCP Gateway user-token retrieval.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass

import httpx

from .sa_token import _resolve_gateway_url

logger = logging.getLogger(__name__)

_SLACK_SIG_VERSION = "v0"
_USER_TOKENS_PATH = "/api/sa/user-tokens"
_DEFAULT_POLL_INTERVAL = 3.0
_DEFAULT_POLL_TIMEOUT = 600.0
_DEFAULT_REQUEST_TIMEOUT = 30.0


class SlackUserTokenError(Exception):
    """Failed to retrieve a Slack user's MCP Gateway token."""


class SlackUserTokenTimeoutError(SlackUserTokenError):
    """User did not approve within the polling timeout."""


@dataclass(frozen=True)
class SlackUserToken:
    """OAuth token for a Slack user retrieved via ``POST /api/sa/user-tokens``."""

    email: str
    access_token: str


def _unsigned_user_tokens_payload(event: dict, app_name: str) -> str:
    return json.dumps(
        {"app_name": app_name, "event": event},
        sort_keys=True,
        separators=(",", ":"),
    )


def _compute_signature_hex(signing_secret: str, event: dict, app_name: str) -> str:
    payload = _unsigned_user_tokens_payload(event, app_name)
    basestring = f"{_SLACK_SIG_VERSION}:{payload}"
    digest = hmac.new(
        signing_secret.encode("utf-8"),
        basestring.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{_SLACK_SIG_VERSION}={digest}"


def _require_user_tokens_fields(body: dict, *, require_signature: bool = False) -> None:
    """Validate ``event``, ``app_name``, and optionally ``slack_signature`` on a body dict."""
    if not isinstance(body, dict):
        raise ValueError("body must be a dict")

    event = body.get("event")
    if not isinstance(event, dict):
        raise ValueError("body must include event")

    app_name = body.get("app_name")
    if not isinstance(app_name, str) or not app_name.strip():
        raise ValueError("body must include app_name")

    if require_signature:
        signature = body.get("slack_signature")
        if signature is None or not str(signature).strip():
            raise ValueError("body must include slack_signature")


def _sign_user_tokens_body(signing_secret: str, body: dict) -> dict:
    _require_user_tokens_fields(body)
    event = body["event"]
    app_name = body["app_name"].strip()

    signed = {
        "event": event,
        "app_name": app_name,
        "slack_signature": _compute_signature_hex(signing_secret, event, app_name),
    }
    _require_user_tokens_fields(signed, require_signature=True)
    return signed


def verify_user_tokens_body(body: dict, signing_secret: str) -> None:
    """Verify ``slack_signature`` on a parsed user-tokens request body."""
    _require_user_tokens_fields(body, require_signature=True)
    event = body["event"]
    app_name = body["app_name"]

    if not signing_secret:
        raise ValueError("slack_signing_secret is not configured")

    signature = body["slack_signature"]
    expected = _compute_signature_hex(signing_secret, event, app_name)
    if not hmac.compare_digest(expected, signature):
        raise ValueError("Invalid Slack signature")


def fetch_slack_user_token(  # pylint: disable=too-many-branches,too-many-locals
    *,
    headers: dict[str, str],
    body: dict,
    secret: str,
    env: str | None = None,
    poll_interval: float = _DEFAULT_POLL_INTERVAL,
    poll_timeout: float = _DEFAULT_POLL_TIMEOUT,
    request_timeout: float = _DEFAULT_REQUEST_TIMEOUT,
) -> SlackUserToken:
    """
    Poll ``POST /api/sa/user-tokens`` until the user approves or *poll_timeout* elapses.

    *headers* must include ``Authorization``, plus the workload headers the
    gateway requires of service accounts (``SERVICE_ACCOUNT_REQUIRED_HEADERS``).
    *body* must contain ``event`` and ``app_name``. *env* is the gateway URL,
    ``"local"``, or ``None`` to read ``MCP_GATEWAY_URL``.
    """
    if not headers:
        raise ValueError("headers are required")

    if not secret or not str(secret).strip():
        raise ValueError("secret is required")

    _require_user_tokens_fields(body)
    if "slack_signature" in body:
        signature = body.get("slack_signature")
        if signature is None or not str(signature).strip():
            raise ValueError("slack_signature must not be empty")

    lower = {key.lower(): value for key, value in headers.items()}
    if not lower.get("authorization", "").strip():
        raise ValueError("headers must include authorization")

    request_headers = {**headers, "Content-Type": "application/json"}
    url = f"{_resolve_gateway_url(env).rstrip('/')}{_USER_TOKENS_PATH}"
    deadline = time.monotonic() + poll_timeout

    while time.monotonic() < deadline:
        try:
            response = httpx.post(
                url,
                json=_sign_user_tokens_body(secret, body),
                headers=request_headers,
                timeout=request_timeout,
            )
        except (TimeoutError, httpx.TimeoutException):
            logger.exception("Timed out waiting for MCP Gateway user token approval")
            raise
        except httpx.TransportError:
            logger.exception("MCP Gateway service is unreachable")
            raise
        except Exception:
            logger.exception("Failed to fetch MCP Gateway user token")
            raise

        if response.status_code == 200:
            data = response.json()
            try:
                token = data["token"]
                return SlackUserToken(
                    email=data["email"],
                    access_token=token["access_token"],
                )
            except (KeyError, TypeError) as exc:
                raise SlackUserTokenError(
                    f"Unexpected token response shape: {data!r}"
                ) from exc

        if response.status_code == 202:
            time.sleep(poll_interval)
            continue

        logger.exception("MCP Gateway user token API returned an error")
        detail = response.text
        try:
            payload = response.json()
            if isinstance(payload, dict) and "detail" in payload:
                detail = payload["detail"]
        except ValueError:
            pass
        raise SlackUserTokenError(
            f"MCP Gateway returned HTTP {response.status_code}: {detail}"
        )

    logger.exception("Timed out waiting for MCP Gateway user token approval")
    raise SlackUserTokenTimeoutError(
        f"User did not approve within {poll_timeout:.0f} seconds"
    )


async def fetch_slack_user_token_async(
    *,
    headers: dict[str, str],
    body: dict,
    secret: str,
    env: str | None = None,
    poll_interval: float = _DEFAULT_POLL_INTERVAL,
    poll_timeout: float = _DEFAULT_POLL_TIMEOUT,
    request_timeout: float = _DEFAULT_REQUEST_TIMEOUT,
) -> SlackUserToken:
    """Async wrapper around :func:`fetch_slack_user_token`."""
    return await asyncio.to_thread(
        fetch_slack_user_token,
        headers=headers,
        body=body,
        secret=secret,
        env=env,
        poll_interval=poll_interval,
        poll_timeout=poll_timeout,
        request_timeout=request_timeout,
    )
