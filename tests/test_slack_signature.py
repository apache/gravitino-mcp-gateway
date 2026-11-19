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

"""Tests for mcp_gateway_sdk.slack_signature: signing, and polling for a person's token.

The gateway's side, refusing a body the signature does not match, is in test_user_tokens.py.
"""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from mcp_gateway_sdk.slack_signature import (
    SlackUserToken,
    SlackUserTokenError,
    SlackUserTokenTimeoutError,
    _sign_user_tokens_body,
    fetch_slack_user_token,
    verify_user_tokens_body,
)

SECRET = "test-signing-secret"
EVENT = {"type": "app_mention", "user": "U123", "channel": "C1"}
BODY = {"event": EVENT, "app_name": "Test Agent"}
GATEWAY_URL = "https://mcp-gateway.example.com"
HEADERS = {"Authorization": "Bearer sa-jwt", "team": "team-b", "namespace": "agent"}
APPROVED = {
    "email": "user@example.com",
    "token": {"service": "slack_gateway", "access_token": "tok"},
}
PENDING = {"status": "pending"}


@pytest.fixture(autouse=True, name="_gateway_url")
def fixture_gateway_url(monkeypatch):
    monkeypatch.setenv("MCP_GATEWAY_URL", GATEWAY_URL)


@pytest.fixture(autouse=True, name="sleep")
def fixture_sleep():
    with patch("mcp_gateway_sdk.slack_signature.time.sleep") as sleep:
        yield sleep


@pytest.fixture(name="gateway")
def fixture_gateway():
    """The gateway's answers, as (status, json) pairs; returns the mocked httpx.post."""
    with patch("mcp_gateway_sdk.slack_signature.httpx.post") as post:

        def _answer(*answers):
            post.side_effect = [
                httpx.Response(status, json=data, request=httpx.Request("POST", "x"))
                for status, data in answers
            ]
            return post

        yield _answer


def _fetch(**kwargs):
    return fetch_slack_user_token(
        **{"headers": HEADERS, "body": BODY, "secret": SECRET, **kwargs}
    )


def test_a_signed_body_verifies_and_signing_is_deterministic():
    signed = _sign_user_tokens_body(SECRET, BODY)

    assert signed == {**BODY, "slack_signature": signed["slack_signature"]}
    assert signed["slack_signature"].startswith("v0=")
    assert _sign_user_tokens_body(SECRET, BODY) == signed
    verify_user_tokens_body(signed, SECRET)


def test_signing_replaces_an_existing_signature():
    signed = _sign_user_tokens_body(SECRET, {**BODY, "slack_signature": "v0=old"})

    assert signed["slack_signature"] != "v0=old"
    verify_user_tokens_body(signed, SECRET)


def test_fetching_polls_until_the_person_approves(gateway, sleep):
    post = gateway((202, PENDING), (200, APPROVED))

    result = _fetch(poll_interval=0.01)

    assert result == SlackUserToken(email="user@example.com", access_token="tok")
    assert post.call_count == 2
    assert post.call_args.args[0] == f"{GATEWAY_URL}/api/v1/sa/user-tokens"
    verify_user_tokens_body(post.call_args.kwargs["json"], SECRET)
    sleep.assert_called_once_with(0.01)


def test_fetching_uses_an_explicit_gateway(gateway):
    post = gateway((200, APPROVED))

    _fetch(env="https://other-gateway.example.com/")

    assert (
        post.call_args.args[0]
        == "https://other-gateway.example.com/api/v1/sa/user-tokens"
    )


def test_a_refusal_from_the_gateway_is_raised_with_its_detail(gateway):
    gateway((403, {"detail": "Invalid Slack signature"}))

    with pytest.raises(SlackUserTokenError, match="HTTP 403: Invalid Slack signature"):
        _fetch()


@pytest.mark.parametrize(
    "kwargs, match",
    [
        ({"headers": {"namespace": "agent"}}, "authorization"),
        ({"body": {"app_name": "Test Agent"}}, "event"),
        ({"body": {"event": EVENT}}, "app_name"),
        ({"secret": ""}, "secret is required"),
        (
            {"body": {**BODY, "slack_signature": ""}},
            "slack_signature must not be empty",
        ),
    ],
    ids=["no-authorization", "no-event", "no-app-name", "no-secret", "empty-signature"],
)
def test_fetching_refuses_an_incomplete_request(kwargs, match):
    with pytest.raises(ValueError, match=match):
        _fetch(**kwargs)


@patch("mcp_gateway_sdk.slack_signature.time.monotonic")
def test_fetching_gives_up_when_the_person_does_not_approve_in_time(monotonic, gateway):
    monotonic.side_effect = [0.0, 0.0, 601.0]
    gateway((202, PENDING))

    with pytest.raises(SlackUserTokenTimeoutError, match="did not approve"):
        _fetch(poll_timeout=600, poll_interval=0.01)


@pytest.mark.parametrize(
    "error",
    [httpx.ConnectError("connection refused"), httpx.ReadTimeout("read timed out")],
    ids=["unreachable", "timed-out"],
)
def test_a_transport_error_is_raised_to_the_caller(error):
    with patch("mcp_gateway_sdk.slack_signature.httpx.post", side_effect=error):
        with pytest.raises(type(error)):
            _fetch()
