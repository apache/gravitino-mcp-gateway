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

"""Tests for the Slack bot's /gravitino-mcp command."""

import logging
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.orm import sessionmaker

from mcp_gateway.models import OAuthToken, SlackTokenApproval
from mcp_gateway.oauth.token_encryption import TokenEncryption
from mcp_gateway.slack.app import (
    _gateway_help,
    handle_gateway_command,
    handle_token_approval,
    login_result_message,
    login_start_message,
    poll_and_notify,
)
from mcp_gateway.slack_service import SlackUserEmailLookup
from mcp_gateway_cli.auth import device_flow_login
from mcp_gateway_cli.device_flow import DeviceCodeData, PollResult, PollStatus

SESSIONS = "mcp_gateway.slack.app._session_factory"
POLL = "mcp_gateway.slack.app.poll_device_token_until_done_async"
ENCRYPTION = TokenEncryption(b"k" * 32)


def _completed(user_id, email="a@example.com"):
    return PollResult(
        status=PollStatus.SUCCESS,
        token_data={
            "access_token": "at",
            "refresh_token": "rt",
            "expires_in": 3600,
            "user": {"id": user_id, "email": email},
        },
    )


async def _run(text, respond):
    """Run /gravitino-mcp ``text``; returns the ack Slack waits for."""
    ack = AsyncMock()
    command = {"user_id": "U1", "channel_id": "C1", "text": text}
    await handle_gateway_command(
        ack, command=command, client=AsyncMock(), respond=respond
    )
    return ack


async def _poll_and_notify(respond, device_data):
    await poll_and_notify(
        respond,
        user_id="U1",
        gateway_url="https://gw.example.com",
        device_data=device_data,
    )


@pytest.fixture(name="device_data")
def fixture_device_data():
    return DeviceCodeData(
        device_code="dev-secret",
        user_code="WXYZ-9999",
        verification_uri="http://gw/device",
        expires_in=600,
        interval=5,
    )


@pytest.fixture(name="bot_db")
def fixture_bot_db(db_engine):
    """The bot's own database sessions, on the test's database."""
    with (
        patch(SESSIONS, sessionmaker(bind=db_engine)),
        patch(
            "mcp_gateway.oauth.token_manager.get_token_encryption",
            new_callable=AsyncMock,
            return_value=ENCRYPTION,
        ),
    ):
        yield


@pytest.fixture(name="slack_email")
def fixture_slack_email():
    """Slack resolves the person running the command to this email; tests may change it."""
    with patch(
        "mcp_gateway.slack.app.lookup_slack_user_email",
        new_callable=AsyncMock,
        return_value=SlackUserEmailLookup(email="testuser@example.com"),
    ) as lookup:
        yield lookup


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text, start", [("", "Usage"), ("help", "Unknown subcommand `help`")]
)
async def test_anything_but_login_or_logout_gets_the_usage(text, start):
    respond = AsyncMock()

    ack = await _run(text, respond)

    ack.assert_awaited_once()
    reply = respond.await_args.kwargs["text"]
    assert reply.startswith(start)
    assert _gateway_help() in reply
    assert respond.await_args.kwargs["response_type"] == "ephemeral"


@patch("mcp_gateway.slack.app.request_device_code_async", new_callable=AsyncMock)
async def test_login_shows_the_code_to_enter_and_waits_for_approval(
    request_device_code, device_data
):
    request_device_code.return_value = device_data
    respond = AsyncMock()

    with patch("mcp_gateway.slack.app.asyncio.create_task") as create_task:
        await _run("login", respond)

    reply = respond.await_args.kwargs["text"]
    assert device_data.user_code in reply
    assert device_data.verification_uri in reply
    assert respond.await_args.kwargs["response_type"] == "ephemeral"
    create_task.assert_called_once()
    create_task.call_args.args[0].close()


def test_the_device_code_stays_out_of_the_logs(device_data, caplog):
    """Whoever polls with it first gets the person's tokens."""
    caplog.set_level(logging.DEBUG)

    login_start_message(device_data)

    assert "dev-secret" not in caplog.text


@pytest.mark.parametrize(
    "result, expected",
    [
        (_completed(42), "login complete for a@example.com"),
        (PollResult(status=PollStatus.EXPIRED), "timed out"),
        (
            PollResult(status=PollStatus.ERROR, error_description="denied"),
            "login failed: denied",
        ),
    ],
    ids=["completed", "expired", "failed"],
)
def test_the_login_result_is_explained(result, expected):
    assert expected in login_result_message(result)


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


async def test_logout_deletes_only_the_persons_slack_token(
    db_session, regular_user, bot_db, slack_email
):
    for service in ("slack_gateway", "gateway"):
        db_session.add(
            OAuthToken(
                user_id=regular_user.id, service=service, access_token_encrypted="x"
            )
        )
    db_session.commit()
    respond = AsyncMock()

    await _run("logout", respond)

    assert "logout complete" in respond.await_args.kwargs["text"]
    assert {token.service for token in db_session.query(OAuthToken)} == {"gateway"}


@pytest.mark.parametrize(
    "email, reply",
    [
        (None, "Could not resolve your Slack account"),
        ("nobody@example.com", "No active MCP Gateway user"),
        ("testuser@example.com", "No MCP Gateway Slack session"),
    ],
    ids=["no-email", "no-such-person", "not-signed-in"],
)
async def test_logout_without_a_slack_session_says_why(
    regular_user, bot_db, slack_email, email, reply
):
    slack_email.return_value = SlackUserEmailLookup(email=email)
    respond = AsyncMock()

    await _run("logout", respond)

    assert reply in respond.await_args.kwargs["text"]


async def test_logout_without_a_database_says_so():
    respond = AsyncMock()

    with patch(SESSIONS, None):
        await _run("logout", respond)

    assert "unavailable" in respond.await_args.kwargs["text"]


# ---------------------------------------------------------------------------
# After the person approves the login
# ---------------------------------------------------------------------------


@patch(POLL, new_callable=AsyncMock)
async def test_a_completed_login_stores_the_persons_slack_token(
    poll, device_data, db_session, regular_user, bot_db
):
    poll.return_value = _completed(regular_user.id)
    respond = AsyncMock()

    await _poll_and_notify(respond, device_data)

    row = db_session.query(OAuthToken).filter_by(service="slack_gateway").one()
    assert row.user_id == regular_user.id
    assert ENCRYPTION.decrypt(row.access_token_encrypted) == "at"
    assert ENCRYPTION.decrypt(row.refresh_token_encrypted) == "rt"
    assert "a@example.com" in respond.await_args.kwargs["text"]


@pytest.mark.parametrize(
    "has_database, result, reply",
    [
        (False, _completed(42), "login complete"),
        (True, PollResult(status=PollStatus.EXPIRED), "timed out"),
    ],
    ids=["no-database", "expired"],
)
@patch(POLL, new_callable=AsyncMock)
async def test_nothing_is_stored_without_a_database_or_a_completed_login(
    poll, device_data, db_engine, db_session, has_database, result, reply
):
    poll.return_value = result
    respond = AsyncMock()

    with patch(SESSIONS, sessionmaker(bind=db_engine) if has_database else None):
        await _poll_and_notify(respond, device_data)

    assert db_session.query(OAuthToken).count() == 0
    assert reply in respond.await_args.kwargs["text"]


@pytest.mark.parametrize(
    "store_error, reply_error",
    [(RuntimeError("db down"), None), (None, RuntimeError("webhook expired"))],
    ids=["store-fails", "reply-fails"],
)
@patch(POLL, new_callable=AsyncMock)
async def test_a_failure_after_login_does_not_escape_the_background_task(
    poll, device_data, store_error, reply_error
):
    poll.return_value = _completed(42)
    respond = AsyncMock(side_effect=reply_error)
    db = MagicMock()

    with (
        patch(SESSIONS, lambda: db),
        patch("mcp_gateway.slack.app.TokenManager") as token_manager,
    ):
        token_manager.return_value.store_user_oauth_token = AsyncMock(
            side_effect=store_error
        )
        await _poll_and_notify(respond, device_data)

    respond.assert_awaited_once()
    db.close.assert_called_once()
    if store_error:
        assert "could not keep your login" in respond.await_args.kwargs["text"]


# ---------------------------------------------------------------------------
# The CLI's login, which the Slack command mirrors
# ---------------------------------------------------------------------------


@patch("mcp_gateway_cli.auth.request_device_code")
@patch("mcp_gateway_cli.auth.poll_device_token_until_done")
@patch("mcp_gateway_cli.auth.webbrowser.open")
def test_the_cli_login_saves_the_tokens_the_device_flow_returns(
    browser, poll, request_device_code, capsys
):
    request_device_code.return_value = DeviceCodeData(
        device_code="d",
        user_code="U-1",
        verification_uri="http://x/device",
        expires_in=60,
        interval=1,
    )
    poll.return_value = PollResult(
        status=PollStatus.SUCCESS,
        token_data={"access_token": "at", "refresh_token": "rt", "expires_in": 3600},
    )

    with (
        patch("mcp_gateway_cli.auth.save_tokens") as save_tokens,
        patch("mcp_gateway_cli.auth.requests.get", side_effect=Exception("no network")),
    ):
        assert device_flow_login("https://gw.example.com") is True

    request_device_code.assert_called_once_with("https://gw.example.com")
    save_tokens.assert_called_once()
    assert "Successfully authenticated" in capsys.readouterr().out


# --- Approve / Deny on a service account's request for a person's token ------


def _approval(db, service_account, **overrides):
    values = {
        "id": "approval-1",
        "requesting_sa_id": service_account.id,
        "slack_user_id": "U1",
        "app_name": "Report bot",
        "status": "pending",
        "expires_at": datetime.utcnow() + timedelta(minutes=5),
        **overrides,
    }
    db.add(SlackTokenApproval(**values))
    db.commit()


async def _click(action_id, clicked_by="U1"):
    """Click ``action_id`` on approval-1 as ``clicked_by``; returns what Slack showed."""
    client = AsyncMock()
    body = {
        "actions": [{"action_id": action_id, "value": "approval-1"}],
        "user": {"id": clicked_by},
        "channel": {"id": "C1"},
    }
    await handle_token_approval(AsyncMock(), body=body, client=client)
    return client.chat_postEphemeral.await_args.kwargs


def _status(db):
    db.expire_all()
    return db.query(SlackTokenApproval).one().status


@pytest.mark.parametrize(
    "action_id, status",
    [("approve_token_request", "approved"), ("deny_token_request", "denied")],
)
async def test_the_person_whose_token_it_is_approves_or_denies(
    db_session, service_account, bot_db, action_id, status
):
    _approval(db_session, service_account)

    shown = await _click(action_id)

    assert _status(db_session) == status
    assert shown["user"] == "U1"
    assert "Report bot" in shown["text"]


async def test_nobody_else_can_approve_sharing_a_persons_token(
    db_session, service_account, bot_db
):
    _approval(db_session, service_account)

    shown = await _click("approve_token_request", clicked_by="U2")

    assert _status(db_session) == "pending"
    assert "not authorized" in shown["text"]


@pytest.mark.parametrize(
    "overrides, reply",
    [
        ({"expires_at": datetime.utcnow() - timedelta(seconds=1)}, "expired"),
        ({"status": "denied"}, "already responded"),
    ],
)
async def test_an_expired_or_answered_request_cannot_be_approved(
    db_session, service_account, bot_db, overrides, reply
):
    _approval(db_session, service_account, **overrides)

    shown = await _click("approve_token_request")

    assert _status(db_session) == overrides.get("status", "pending")
    assert reply in shown["text"]
