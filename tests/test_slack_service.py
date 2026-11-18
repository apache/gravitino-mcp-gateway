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

# pylint: disable=protected-access

"""Tests for mcp_gateway.slack_service, with Slack's HTTP API faked."""

from unittest.mock import AsyncMock

import pytest

import mcp_gateway.slack_service as slack
from mcp_gateway.config import settings
from mcp_gateway.slack_service import (
    SlackUserEmailLookup,
    get_slack_web_client,
    invite_user_to_channel,
    lookup_slack_user_email,
    notify_new_access_request,
    notify_request_reviewed,
    send_token_approval_message,
)


class _FakeResp:
    def __init__(self, json_data=None, status_code=200, text="ok"):
        self._json = json_data or {}
        self.status_code = status_code
        self.text = text

    def json(self):
        return self._json


class _FakeClient:
    """Stands in for ``httpx.AsyncClient``: answers with ``answers`` in turn, or raises."""

    def __init__(self, answers, calls):
        self._answers = answers
        self._calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def _answer(self, args, kwargs):
        self._calls.append((args, kwargs))
        answer = self._answers.pop(0) if len(self._answers) > 1 else self._answers[0]
        if isinstance(answer, Exception):
            raise answer
        return answer

    async def get(self, *args, **kwargs):
        return await self._answer(args, kwargs)

    async def post(self, *args, **kwargs):
        return await self._answer(args, kwargs)


@pytest.fixture(name="slack_api")
def fixture_slack_api(monkeypatch):
    """Fake Slack's HTTP API; returns the (args, kwargs) of each call it got."""
    monkeypatch.setattr(settings, "SLACK_BOT_TOKEN", "xoxb-x")
    monkeypatch.setattr(settings, "SLACK_CHANNEL_ID", "C1")
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hook")
    calls = []

    def _install(*answers):
        answers = list(answers)
        monkeypatch.setattr(
            slack.httpx, "AsyncClient", lambda *a, **k: _FakeClient(answers, calls)
        )
        return calls

    return _install


@pytest.fixture(name="posted")
def fixture_posted(monkeypatch):
    """The webhook messages posted, with the webhook configured."""
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hook")
    post = AsyncMock()
    monkeypatch.setattr(slack, "_post", post)
    return post


def _text(posted):
    return posted.await_args.args[0]["blocks"][0]["text"]["text"]


# ---------------------------------------------------------------------------
# lookup_slack_user_email
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "answer, expected",
    [
        (RuntimeError("network"), SlackUserEmailLookup(user_not_found=True)),
        (
            _FakeResp({"ok": False, "error": "user_not_found"}),
            SlackUserEmailLookup(user_not_found=True),
        ),
        (
            _FakeResp({"ok": True, "user": {"profile": {}}}),
            SlackUserEmailLookup(email_missing=True),
        ),
        (
            _FakeResp({"ok": True, "user": {"profile": {"email": " a@example.com "}}}),
            SlackUserEmailLookup(email="a@example.com"),
        ),
    ],
    ids=["unreachable", "slack-error", "no-email", "found"],
)
async def test_a_slack_user_is_resolved_to_their_email(slack_api, answer, expected):
    slack_api(answer)

    assert await lookup_slack_user_email("U1") == expected


async def test_without_a_bot_token_no_lookup_is_made(slack_api, monkeypatch):
    calls = slack_api(_FakeResp({"ok": True}))
    monkeypatch.setattr(settings, "SLACK_BOT_TOKEN", "")

    assert await lookup_slack_user_email("U1") == SlackUserEmailLookup()
    assert not calls


# ---------------------------------------------------------------------------
# Webhook notifications
# ---------------------------------------------------------------------------


async def test_a_message_is_posted_to_the_webhook(slack_api):
    calls = slack_api(_FakeResp())

    await slack._post({"blocks": []})

    args, kwargs = calls[0]
    assert args[0] == "https://hook"
    assert kwargs["json"] == {"blocks": []}


@pytest.mark.parametrize(
    "answer",
    [_FakeResp(status_code=500, text="err"), RuntimeError("down")],
    ids=["refused", "unreachable"],
)
async def test_a_webhook_that_fails_does_not_raise(slack_api, answer):
    slack_api(answer)

    await slack._post({"blocks": []})


async def _new_request(**overrides):
    await notify_new_access_request(
        **{
            "user_name": "Alice",
            "user_email": "alice@example.com",
            "mcp_name": "Trino",
            "mcp_icon": None,
            "justification": "need it",
            "request_id": 1,
            **overrides,
        }
    )


async def _reviewed(**overrides):
    await notify_request_reviewed(
        **{
            "user_name": "Alice",
            "mcp_name": "Trino",
            "mcp_icon": None,
            "status": "approved",
            "admin_notes": None,
            "reviewer_name": "admin",
            **overrides,
        }
    )


@pytest.mark.parametrize("notify", [_new_request, _reviewed])
async def test_no_notification_is_sent_without_a_webhook(posted, monkeypatch, notify):
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "")

    await notify()

    posted.assert_not_awaited()


async def test_a_new_access_request_says_who_wants_what_and_where_to_review_it(
    posted,
):
    await _new_request(mcp_icon="🔥")

    text = _text(posted)
    for part in ("Trino", "alice@example.com", "need it", "MCP > Access Requests"):
        assert part in text


@pytest.mark.parametrize(
    "notify, field",
    [(_new_request, "justification"), (_reviewed, "admin_notes")],
    ids=["justification", "admin-notes"],
)
async def test_user_text_cannot_ping_the_channel_or_add_links(posted, notify, field):
    """Any signed-in user writes the justification an admin channel reads."""
    hostile = "<!channel> <https://evil.example/login|Review Request →> & co"

    await notify(user_name="<!here>", **{field: hostile})

    text = _text(posted)
    assert "<!channel>" not in text and "<!here>" not in text
    assert "<https://evil.example" not in text
    assert "&lt;!channel&gt;" in text and "&amp; co" in text


@pytest.mark.parametrize(
    "status, notes, expected",
    [
        ("approved", "looks good", ["✅", "approved", "looks good"]),
        ("denied", None, ["❌", "denied"]),
    ],
)
async def test_a_reviewed_request_says_how_it_was_decided(
    posted, status, notes, expected
):
    await _reviewed(status=status, admin_notes=notes)

    text = _text(posted)
    for part in expected:
        assert part in text


# ---------------------------------------------------------------------------
# Channel invites
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "invite_answer",
    [{"ok": True}, {"ok": False, "error": "already_in_channel"}],
    ids=["invited", "already-in-channel"],
)
async def test_a_person_is_looked_up_by_email_and_invited_to_the_channel(
    slack_api, invite_answer
):
    calls = slack_api(
        _FakeResp({"ok": True, "user": {"id": "U1"}}), _FakeResp(invite_answer)
    )

    await invite_user_to_channel("a@example.com")

    (lookup_args, lookup), (invite_args, invite) = calls
    assert lookup_args[0].endswith("/users.lookupByEmail")
    assert lookup["data"] == {"email": "a@example.com"}
    assert invite_args[0].endswith("/conversations.invite")
    assert invite["data"] == {"channel": "C1", "users": "U1"}


@pytest.mark.parametrize(
    "answer",
    [_FakeResp({"ok": False, "error": "users_not_found"}), RuntimeError("down")],
    ids=["not-found", "unreachable"],
)
async def test_no_invite_is_sent_for_a_person_slack_cannot_find(slack_api, answer):
    calls = slack_api(answer)

    await invite_user_to_channel("a@example.com")

    assert len(calls) == 1


@pytest.mark.parametrize(
    "setting, email",
    [
        ("SLACK_BOT_TOKEN", "a@example.com"),
        ("SLACK_CHANNEL_ID", "a@example.com"),
        (None, ""),
    ],
    ids=["no-bot-token", "no-channel", "no-email"],
)
async def test_no_invite_is_attempted_without_what_it_needs(
    slack_api, monkeypatch, setting, email
):
    calls = slack_api(_FakeResp({"ok": True}))
    if setting:
        monkeypatch.setattr(settings, setting, "")

    await invite_user_to_channel(email)

    assert not calls


# ---------------------------------------------------------------------------
# Token approval messages
# ---------------------------------------------------------------------------


def _client(**chat_post_ephemeral):
    client = AsyncMock()
    client.chat_postEphemeral = AsyncMock(**chat_post_ephemeral)
    return client


@pytest.mark.parametrize(
    "client, sent",
    [
        (None, False),
        (_client(return_value={"ok": True}), True),
        (_client(return_value={"ok": False, "error": "bad"}), False),
        (_client(side_effect=RuntimeError("boom")), False),
    ],
    ids=["no-client", "accepted", "refused", "unreachable"],
)
async def test_an_approval_message_reports_whether_slack_took_it(client, sent):
    result = await send_token_approval_message(
        client, channel="C1", slack_user_id="U1", app_name="App", approval_id="a1"
    )

    assert result is sent
    if sent:
        # Only the person whose token it is sees the message.
        assert client.chat_postEphemeral.await_args.kwargs["user"] == "U1"


async def test_the_web_client_needs_the_bot_token(monkeypatch):
    monkeypatch.setattr(settings, "SLACK_BOT_TOKEN", "")

    with pytest.raises(RuntimeError, match="SLACK_BOT_TOKEN"):
        await get_slack_web_client()


async def test_the_web_client_uses_the_bot_token(monkeypatch):
    monkeypatch.setattr(settings, "SLACK_BOT_TOKEN", "xoxb-x")

    assert (await get_slack_web_client()).token == "xoxb-x"
