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
Slack notification service using Incoming Webhooks.

Setup:
  1. Go to https://api.slack.com/apps → Create New App → From scratch
  2. Features → Incoming Webhooks → toggle ON
  3. "Add New Webhook to Workspace" → pick your channel for notifications
  4. Copy the Webhook URL
  5. Set SLACK_WEBHOOK_URL=<url> in .env
"""

import logging
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from .config import settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SlackUserEmailLookup:
    """Result of resolving a Slack user ID to a workspace email."""

    email: Optional[str] = None
    user_not_found: bool = False
    email_missing: bool = False


async def lookup_slack_user_email(slack_user_id: str) -> SlackUserEmailLookup:
    """
    Resolve a Slack user ID to their workspace email via users.info.

    Requires bot scope: users:read.email
    """
    if not settings.SLACK_BOT_TOKEN:
        logger.warning("Slack user lookup skipped — SLACK_BOT_TOKEN not set")
        return SlackUserEmailLookup()

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://slack.com/api/users.info",
                params={"user": slack_user_id},
                headers={"Authorization": f"Bearer {settings.SLACK_BOT_TOKEN}"},
            )
        data = resp.json()
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("Slack users.info request failed for %s: %s", slack_user_id, exc)
        return SlackUserEmailLookup(user_not_found=True)

    if not data.get("ok"):
        logger.warning(
            "Slack users.info error for %s: %s",
            slack_user_id,
            data.get("error"),
        )
        return SlackUserEmailLookup(user_not_found=True)

    email = (data.get("user", {}) or {}).get("profile", {}).get("email")
    if not email:
        return SlackUserEmailLookup(email_missing=True)

    return SlackUserEmailLookup(email=email.strip())


def _enabled() -> bool:
    if not settings.SLACK_WEBHOOK_URL:
        logger.debug("Slack notifications disabled — SLACK_WEBHOOK_URL not set")
        return False
    return True


async def _post(payload: dict) -> None:
    """POST a Block Kit payload to the Slack webhook. Never raises."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(settings.SLACK_WEBHOOK_URL, json=payload)
        if resp.status_code != 200 or resp.text != "ok":
            logger.error("Slack webhook returned %s: %s", resp.status_code, resp.text)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("Slack notification failed: %s", exc)


# Longest user-written text, such as a justification, put in a message.
_USER_TEXT_LENGTH = 500


def _mrkdwn(text: str) -> str:
    """``text`` escaped for Slack mrkdwn, so that it cannot ping or link.

    Slack reads <!channel>, <@user> and <url|label> as markup; escaping the
    three characters Slack documents makes them plain text.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ── Public helpers ────────────────────────────────────────────────────────────


async def notify_new_access_request(
    *,
    user_name: str,
    user_email: str,
    mcp_name: str,
    mcp_icon: Optional[str],
    justification: Optional[str],
    request_id: int,
) -> None:
    """Notify the channel when a user submits a new MCP access request."""
    if not _enabled():
        return

    icon = _mrkdwn(mcp_icon or "🔌")

    text = (
        f"🔔 *{icon} {_mrkdwn(mcp_name)}* access request from "
        f"*{_mrkdwn(user_name)}* ({_mrkdwn(user_email)})"
    )
    if justification:
        text += f"\n>{_mrkdwn(justification[:_USER_TEXT_LENGTH])}"
    text += "\nReview it in Gravitino's web UI, under MCP > Access Requests."

    await _post(
        {"blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]}
    )
    logger.info(
        "Slack: new access request #%s by %s for %s", request_id, user_name, mcp_name
    )


async def notify_request_reviewed(
    *,
    user_name: str,
    mcp_name: str,
    mcp_icon: Optional[str],
    status: str,  # "approved" or "denied"
    admin_notes: Optional[str],
    reviewer_name: str,
) -> None:
    """Notify the channel when a request is approved or denied."""
    if not _enabled():
        return

    icon = _mrkdwn(mcp_icon or "🔌")
    status_emoji = "✅" if status == "approved" else "❌"

    outcome = "approved" if status == "approved" else "denied"
    text = (
        f"{status_emoji} *{icon} {_mrkdwn(mcp_name)}* — {outcome} "
        f"for *{_mrkdwn(user_name)}* by {_mrkdwn(reviewer_name)}"
    )
    if admin_notes:
        text += f"\n>{_mrkdwn(admin_notes[:_USER_TEXT_LENGTH])}"

    await _post(
        {"blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]}
    )
    logger.info("Slack: %s/%s %s by %s", user_name, mcp_name, status, reviewer_name)


# ── Channel invite helpers ────────────────────────────────────────────────────


def _invite_enabled() -> bool:
    if not settings.SLACK_BOT_TOKEN or not settings.SLACK_CHANNEL_ID:
        logger.debug(
            "Slack channel invite disabled — SLACK_BOT_TOKEN or SLACK_CHANNEL_ID not set"
        )
        return False
    return True


async def _slack_api(method: str, payload: dict) -> Optional[dict]:
    """Call a Slack Web API method with the bot token. Returns the JSON response or None on error."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"https://slack.com/api/{method}",
                data=payload,
                headers={"Authorization": f"Bearer {settings.SLACK_BOT_TOKEN}"},
            )
        data = resp.json()
        if not data.get("ok"):
            # "already_in_channel" is fine — not an error
            if data.get("error") == "already_in_channel":
                logger.debug("Slack: user already in channel")
                return data
            logger.error("Slack API %s error: %s", method, data.get("error"))
            return None
        return data
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("Slack API %s failed: %s", method, exc)
        return None


async def invite_user_to_channel(email: str) -> None:
    """
    Look up a Slack user by email and invite them to the notifications channel.

    Requires bot scopes:
      users:read, users:read.email, channels:write.invites
    Silently succeeds if the user is already in the channel.
    """
    if not _invite_enabled() or not email:
        return

    # Step 1: Resolve email → Slack user ID
    lookup = await _slack_api("users.lookupByEmail", {"email": email})
    if not lookup or not lookup.get("user"):
        logger.warning("Slack: could not find user for email %s", email)
        return

    slack_user_id = lookup["user"]["id"]

    # Step 2: Invite to channel
    result = await _slack_api(
        "conversations.invite",
        {
            "channel": settings.SLACK_CHANNEL_ID,
            "users": slack_user_id,
        },
    )
    if result:
        if result.get("ok"):
            logger.info(
                "Slack: invited %s (%s) to channel %s",
                email,
                slack_user_id,
                settings.SLACK_CHANNEL_ID,
            )
        else:
            logger.info(
                "Slack: %s (%s) already in channel %s (no-op)",
                email,
                slack_user_id,
                settings.SLACK_CHANNEL_ID,
            )


# ── Token approval helpers ───────────────────────────────────────────────────


def _approval_blocks(app_name: str, approval_id: str) -> list[dict[str, Any]]:
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{_mrkdwn(app_name)}* is requesting access to your MCP Gateway token. "
                    "Do you approve?"
                ),
            },
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "action_id": "approve_token_request",
                    "value": approval_id,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Deny"},
                    "style": "danger",
                    "action_id": "deny_token_request",
                    "value": approval_id,
                },
            ],
        },
    ]


async def send_token_approval_message(
    client: Any,
    *,
    channel: str,
    slack_user_id: str,
    app_name: str,
    approval_id: str,
) -> bool:
    """
    Post an ephemeral approval request in the channel (not in a thread).

    Only the requesting user sees the message. Buttons fire block_actions via Socket Mode.

    Returns True when Slack accepts the message, False otherwise.
    """
    if client is None:
        logger.warning("Cannot send token approval — Slack client not provided")
        return False

    logger.info(
        "Sending token approval message for %s to channel=%s user=%s approval_id=%s",
        app_name,
        channel,
        slack_user_id,
        approval_id,
    )

    text = f"{_mrkdwn(app_name)} is requesting access to your MCP Gateway token. Do you approve?"
    try:
        response = await client.chat_postEphemeral(
            channel=channel,
            user=slack_user_id,
            text=text,
            blocks=_approval_blocks(app_name, approval_id),
        )
        if not response.get("ok", False):
            logger.error(
                "Slack chat_postEphemeral failed for approval_id=%s: %s",
                approval_id,
                response.get("error"),
            )
            return False
        logger.info(
            "Token approval ephemeral sent for approval_id=%s channel=%s",
            approval_id,
            channel,
        )
        return True
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error(
            "Failed to send token approval message for approval_id=%s: %s",
            approval_id,
            exc,
        )
        return False


async def get_slack_web_client() -> Any:
    """Return an AsyncWebClient for Slack Web API calls from FastAPI routes."""
    from slack_sdk.web.async_client import (  # pylint: disable=import-outside-toplevel
        AsyncWebClient,
    )

    if not settings.SLACK_BOT_TOKEN:
        raise RuntimeError("SLACK_BOT_TOKEN is not configured")
    return AsyncWebClient(token=settings.SLACK_BOT_TOKEN)
