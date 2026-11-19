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
Slack Bolt slash command /gravitino-mcp.

Thin adapter over mcp_gateway_cli.device_flow — same HTTP path as gravitino-mcp login.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Awaitable, Callable, Optional

from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler
from slack_bolt.async_app import AsyncApp
from sqlalchemy.orm import Session

from mcp_gateway.config import settings
from mcp_gateway.models import OAuthToken, SlackTokenApproval, User
from mcp_gateway.oauth.token_manager import SLACK_TOKEN_SERVICE, TokenManager
from mcp_gateway.routes.user_tokens import _APPROVAL_TTL
from mcp_gateway.slack_service import lookup_slack_user_email
from mcp_gateway_cli.device_flow import (
    DeviceCodeData,
    PollStatus,
    poll_device_token_until_done_async,
    request_device_code_async,
)

logger = logging.getLogger(__name__)

GATEWAY_URL = settings.GATEWAY_BASE_URL.rstrip("/")
_BACKGROUND_TASKS: set[asyncio.Task] = set()
_session_factory: Optional[Callable[[], Session]] = None


async def handle_gateway_command(ack, command, client, respond) -> None:  # type: ignore[no-untyped-def]
    """Top-level handler for the /gravitino-mcp slash command (testable without Bolt)."""
    await ack()
    user_id = command["user_id"]
    channel = command["channel_id"]
    args = command.get("text", "").split()
    logger.info(
        "handle_gateway_command: user_id=%s, channel=%s, args=%s",
        user_id,
        channel,
        args,
    )

    if not args:
        await respond(text=_gateway_help(), response_type="ephemeral")
        return

    subcommand = args[0].lower()

    if subcommand == "login":
        await _cmd_login(respond, user_id)
    elif subcommand == "logout":
        await _cmd_logout(respond, user_id)
    else:
        await respond(
            text=f"Unknown subcommand `{subcommand}`.\n{_gateway_help()}",
            response_type="ephemeral",
        )


async def handle_token_approval(ack, body, client) -> None:  # type: ignore[no-untyped-def]
    """Handle Approve/Deny clicks on ephemeral token approval messages."""
    await ack()

    if not _session_factory:
        logger.error("Token approval handler: database not configured")
        return

    actions = body.get("actions") or []
    if not actions:
        return

    approval_id = actions[0].get("value")
    action_id = actions[0].get("action_id")
    acting_user = (body.get("user") or {}).get("id")
    channel_id = (body.get("channel") or {}).get("id")

    db = _session_factory()
    try:
        approval = (
            db.query(SlackTokenApproval)
            .filter(SlackTokenApproval.id == approval_id)
            .first()
        )

        async def _ephemeral(text: str) -> None:
            if channel_id and acting_user:
                await client.chat_postEphemeral(
                    channel=channel_id,
                    user=acting_user,
                    text=text,
                )

        if not approval or approval.expires_at < datetime.utcnow():
            await _ephemeral("This request has expired or does not exist")
            return

        if acting_user != approval.slack_user_id:
            await _ephemeral("You are not authorized to respond to this request")
            return

        if approval.status != "pending":
            await _ephemeral("You have already responded to this request")
            return

        approval.status = (
            "approved" if action_id == "approve_token_request" else "denied"
        )
        if approval.status == "approved":
            approval.expires_at = datetime.utcnow() + _APPROVAL_TTL
        db.commit()

        if approval.status == "approved":
            await _ephemeral(f"✅ You approved access for *{approval.app_name}*")
        else:
            await _ephemeral(f"❌ You denied access for *{approval.app_name}*")
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("handle_token_approval failed for approval_id=%s", approval_id)
    finally:
        db.close()


def create_app() -> AsyncApp:
    # Socket Mode only — events arrive over the app token WebSocket, not HTTP.
    # Disable HTTP-only middleware so SLACK_SIGNING_SECRET is not required.
    _app = AsyncApp(
        token=settings.SLACK_BOT_TOKEN,
        logger=logger,
        request_verification_enabled=False,
        ssl_check_enabled=False,
        url_verification_enabled=False,
    )
    _app.command("/gravitino-mcp")(handle_gateway_command)
    _app.action("approve_token_request")(handle_token_approval)
    _app.action("deny_token_request")(handle_token_approval)
    return _app


Respond = Callable[..., Awaitable[Any]]


def _gateway_help() -> str:
    return (
        "Usage:\n"
        "  `/gravitino-mcp login` — authenticate via browser (same as `gravitino-mcp login`)\n"
        "  `/gravitino-mcp logout` — log out of MCP Gateway"
    )


def login_start_message(device_data: DeviceCodeData) -> str:
    # Not the device code: whoever polls with it first gets the person's tokens.
    logger.info("Slack login started with user code %s", device_data.user_code)
    return (
        "*MCP Gateway login*\n"
        f"1. Open: {device_data.verification_uri}\n"
        f"2. Enter the code `{device_data.user_code}`, and approve it\n"
        f"_Expires in {device_data.expires_in} seconds._"
    )


def login_result_message(result) -> str:
    if result.status == PollStatus.SUCCESS:
        user = (result.token_data or {}).get("user", {})
        email = user.get("email") or user.get("username") or "your account"
        return f"MCP Gateway login complete for {email}."
    if result.status == PollStatus.EXPIRED:
        return "MCP Gateway login timed out. Run `/gravitino-mcp login` again."
    desc = result.error_description or result.error or "Unknown error"
    return f"MCP Gateway login failed: {desc}"


async def _store_slack_token(token_data: dict, slack_user_id: str) -> bool:
    """Keep the gateway token a person signed in with from Slack; False if it failed."""
    user_id = (token_data.get("user") or {}).get("id")
    db = _session_factory()
    try:
        await TokenManager(db).store_user_oauth_token(
            user_id,
            SLACK_TOKEN_SERVICE,
            token_data["access_token"],
            token_data.get("refresh_token"),
            token_data.get("expires_in", 3600),
        )
        logger.info("Stored %s token for user id=%s", SLACK_TOKEN_SERVICE, user_id)
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception(
            "Failed to store %s token for Slack user %s",
            SLACK_TOKEN_SERVICE,
            slack_user_id,
        )
        return False
    finally:
        db.close()


async def poll_and_notify(
    respond: Respond,
    *,
    user_id: str,
    gateway_url: str,
    device_data: DeviceCodeData,
) -> None:
    """Wait for the person to approve the sign-in, keep their token, and tell them."""
    result = await poll_device_token_until_done_async(
        gateway_url,
        device_data.device_code,
        expires_in=device_data.expires_in,
        interval=device_data.interval,
    )
    text = login_result_message(result)
    if result.status == PollStatus.SUCCESS and result.token_data and _session_factory:
        if not await _store_slack_token(result.token_data, user_id):
            text = (
                "MCP Gateway could not keep your login. "
                "Run `/gravitino-mcp login` again."
            )

    # respond() uses the response_url webhook — no bot membership required,
    # and the message lands exactly where the user ran the command.
    try:
        await respond(text=text, response_type="ephemeral")
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("Failed to send login result to user_id=%s", user_id)


async def _cmd_login(
    respond: Respond,
    user_id: str,
) -> None:
    try:
        logger.info("_cmd_login: calling request_device_code (gateway=%s)", GATEWAY_URL)
        device_data = await request_device_code_async(
            GATEWAY_URL, client_id="gravitino-mcp-slack"
        )
        await respond(text=login_start_message(device_data), response_type="ephemeral")
        task = asyncio.create_task(
            poll_and_notify(
                respond,
                user_id=user_id,
                gateway_url=GATEWAY_URL,
                device_data=device_data,
            )
        )
        _BACKGROUND_TASKS.add(task)
        task.add_done_callback(_BACKGROUND_TASKS.discard)
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("Slack /gravitino-mcp login failed")
        await respond(
            text="MCP Gateway could not start the login. Try again later.",
            response_type="ephemeral",
        )


async def _cmd_logout(respond: Respond, slack_user_id: str) -> None:
    if not _session_factory:
        await respond(
            text="MCP Gateway logout is unavailable (database not configured).",
            response_type="ephemeral",
        )
        return

    lookup = await lookup_slack_user_email(slack_user_id)
    if not lookup.email:
        await respond(
            text="Could not resolve your Slack account to an email address.",
            response_type="ephemeral",
        )
        return

    email_norm = lookup.email.strip().lower()
    db = _session_factory()
    try:
        user = User.find_person(db, email_norm)
        if not user:
            await respond(
                text=f"No active MCP Gateway user found for {lookup.email}.",
                response_type="ephemeral",
            )
            return

        oauth_token = (
            db.query(OAuthToken)
            .filter(
                OAuthToken.user_id == user.id,
                OAuthToken.service == SLACK_TOKEN_SERVICE,
            )
            .first()
        )
        if not oauth_token:
            await respond(
                text="No MCP Gateway Slack session found. Run `/gravitino-mcp login` first.",
                response_type="ephemeral",
            )
            return

        await TokenManager(db).disconnect_user_service_async(
            user.id, SLACK_TOKEN_SERVICE
        )
        logger.info(
            "Deleted %s token for user id=%s (slack_user_id=%s)",
            SLACK_TOKEN_SERVICE,
            user.id,
            slack_user_id,
        )
        await respond(
            text=f"MCP Gateway logout complete for {lookup.email}.",
            response_type="ephemeral",
        )
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception(
            "Slack /gravitino-mcp logout failed for slack_user_id=%s",
            slack_user_id,
        )
        await respond(
            text="Failed to log out of MCP Gateway. Please try again.",
            response_type="ephemeral",
        )
    finally:
        db.close()


async def main() -> None:
    app = create_app()
    logger.info(
        "Starting MCP Gateway Slack bot (gateway=%s)",
        settings.GATEWAY_BASE_URL.rstrip("/"),
    )
    handler = AsyncSocketModeHandler(app, settings.SLACK_APP_TOKEN)
    try:
        await handler.start_async()
    finally:
        await handler.close_async()
    logger.info("MCP Gateway Slack bot stopped")


async def start_slack_bot(
    session_factory: Optional[Callable[[], Session]] = None,
) -> asyncio.Task:
    global _session_factory  # pylint: disable=global-statement
    _session_factory = session_factory

    def _log_task_failure(task: asyncio.Task) -> None:
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("Slack bot task exited with an error")

    task = asyncio.create_task(main(), name="slack_bot")
    task.add_done_callback(_log_task_failure)
    return task
