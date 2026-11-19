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

"""Tests for POST /api/sa/user-tokens: a bot gets a person's Slack token once they approve."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from mcp_gateway.config import settings
from mcp_gateway.main import app
from mcp_gateway.models import (
    AuditLog,
    OAuthToken,
    ServiceAccountCredentials,
    SlackTokenApproval,
)
from mcp_gateway.oauth.token_encryption import TokenEncryption
from mcp_gateway.routes.user_tokens import _require_service_account
from mcp_gateway.slack_service import SlackUserEmailLookup
from mcp_gateway_sdk.slack_signature import _sign_user_tokens_body
from tests.request_utils import make_starlette_request

SLACK_USER = "U_TEST_USER"
APP_NAME = "Test Agent"
SIGNING_SECRET = "test-slack-signing-secret"
GRANTED = {
    "token_retrieval_services": "slack_gateway",
    "slack_signing_secret": SIGNING_SECRET,
}
ENCRYPTION = TokenEncryption(b"k" * 32)


def _event(**overrides) -> dict:
    return {
        "type": "app_mention",
        "user": SLACK_USER,
        "channel": "C_TEST_CHANNEL",
        "ts": "1234567890.123456",
        **overrides,
    }


def _signed(event: dict | None = None) -> dict:
    body = {"event": event or _event(), "app_name": APP_NAME}
    return _sign_user_tokens_body(SIGNING_SECRET, body)


def _post(client, body: dict | bytes | None = None):
    if not isinstance(body, bytes):
        body = json.dumps(body or _signed()).encode()
    return client.post(
        "/api/sa/user-tokens",
        content=body,
        headers={"Content-Type": "application/json"},
    )


def _store_token(db, user, token="slack-token", service="slack_gateway"):
    """As if ``user`` signed in, through Slack's /gravitino-mcp login by default."""
    db.add(
        OAuthToken(
            user_id=user.id,
            service=service,
            access_token_encrypted=ENCRYPTION.encrypt(token),
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
    )
    db.commit()


def _approval(db, sa, status, *, approval_id="approval-1", expires_in=None):
    db.add(
        SlackTokenApproval(
            id=approval_id,
            requesting_sa_id=sa.id,
            slack_user_id=SLACK_USER,
            app_name=APP_NAME,
            status=status,
            expires_at=datetime.utcnow() + (expires_in or timedelta(minutes=30)),
        )
    )
    db.commit()


def _approvals(db, sa) -> list[SlackTokenApproval]:
    return db.query(SlackTokenApproval).filter_by(requesting_sa_id=sa.id).all()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True, name="enabled")
def fixture_enabled(monkeypatch):
    """The route answers only when a deployment turns it on."""
    monkeypatch.setattr(settings, "SLACK_USER_TOKENS_ENABLED", True)


@pytest.fixture(autouse=True, name="_encryption")
def fixture_encryption():
    with patch(
        "mcp_gateway.oauth.token_manager.get_token_encryption",
        new_callable=AsyncMock,
        return_value=ENCRYPTION,
    ):
        yield


@pytest.fixture(autouse=True, name="lookup")
def fixture_lookup(regular_user):
    """Slack resolves the event's user to ``regular_user``; tests may change the answer."""
    with patch(
        "mcp_gateway.routes.user_tokens.lookup_slack_user_email",
        new_callable=AsyncMock,
        return_value=SlackUserEmailLookup(email=regular_user.email),
    ) as mock:
        yield mock


@pytest.fixture(autouse=True, name="send")
def fixture_send():
    """Slack accepts the approval message; tests may change the answer."""
    with (
        patch(
            "mcp_gateway.routes.user_tokens.send_token_approval_message",
            new_callable=AsyncMock,
            return_value=True,
        ) as mock,
        patch(
            "mcp_gateway.routes.user_tokens.get_slack_web_client",
            new_callable=AsyncMock,
        ),
    ):
        yield mock


@pytest.fixture(name="as_service_account")
def fixture_as_service_account(db_session, service_account):
    """Call the route as the service account, with ``config`` (None: no credentials row)."""

    def _as(config):
        if config is not None:
            db_session.add(
                ServiceAccountCredentials(
                    service_account_id=service_account.id,
                    provider="google",
                    service_account_name="svc@test.iam.gserviceaccount.com",
                    allowed_services=[],
                    additional_config=config,
                    created_by=service_account.id,
                )
            )
            db_session.commit()
        app.dependency_overrides[_require_service_account] = lambda: service_account
        return service_account

    yield _as
    app.dependency_overrides.pop(_require_service_account, None)


@pytest.fixture(name="caller")
def fixture_caller(as_service_account):
    """A service account granted the people's Slack tokens."""
    return as_service_account(GRANTED)


# ---------------------------------------------------------------------------
# Who may call
# ---------------------------------------------------------------------------


class TestCaller:
    def test_a_person_cannot_call_the_route(self, regular_user):
        """Else anyone signed in could ask for anyone else's token."""
        with pytest.raises(HTTPException) as exc:
            _require_service_account(
                request=make_starlette_request(), current_user=regular_user
            )

        assert exc.value.status_code == 403

    def test_a_service_account_may_call_the_route(self, service_account):
        request = make_starlette_request()
        request.state.is_service_account = True

        caller = _require_service_account(request=request, current_user=service_account)

        assert caller is service_account

    @pytest.mark.parametrize(
        "config, detail",
        [
            pytest.param(None, "no credentials configured", id="no-credentials"),
            pytest.param({}, "token_retrieval_services", id="not-granted"),
            pytest.param(
                {**GRANTED, "token_retrieval_services": "trino"},
                "slack_gateway",
                id="granted-another-service",
            ),
            pytest.param(
                {"token_retrieval_services": "slack_gateway"},
                "slack_signing_secret",
                id="no-signing-secret",
            ),
        ],
    )
    def test_a_service_account_not_granted_slack_tokens_is_refused(
        self, client, as_service_account, config, detail
    ):
        as_service_account(config)

        resp = _post(client)

        assert resp.status_code == 403
        assert detail in resp.json()["detail"]

    def test_the_granted_service_may_be_written_with_surrounding_spaces(
        self, client, db_session, as_service_account, regular_user
    ):
        as_service_account({**GRANTED, "token_retrieval_services": " slack_gateway "})
        _store_token(db_session, regular_user)

        assert _post(client).status_code == 202

    def test_the_route_does_not_exist_unless_turned_on(self, client, monkeypatch):
        monkeypatch.setattr(settings, "SLACK_USER_TOKENS_ENABLED", False)

        assert client.post("/api/sa/user-tokens", json={}).status_code == 404


# ---------------------------------------------------------------------------
# The request
# ---------------------------------------------------------------------------


class TestRequest:
    @pytest.mark.parametrize(
        "body",
        [
            pytest.param(b"not-json", id="not-json"),
            pytest.param(
                {"app_name": APP_NAME, "slack_signature": "v0=deadbeef"}, id="no-event"
            ),
            pytest.param({"event": _event(), "app_name": APP_NAME}, id="no-signature"),
        ],
    )
    def test_a_malformed_body_is_refused(self, client, caller, body):
        assert _post(client, body).status_code == 422

    @pytest.mark.parametrize(
        "event, detail",
        [
            (_event(type="reaction_added"), "Unsupported Slack event type"),
            (_event(user=None), "Missing user"),
            (_event(channel=None), "Missing channel"),
        ],
        ids=["unsupported-type", "no-user", "no-channel"],
    )
    def test_an_event_without_a_user_and_channel_is_refused(
        self, client, caller, event, detail
    ):
        resp = _post(client, _signed(event))

        assert resp.status_code == 400
        assert detail in resp.json()["detail"]

    @pytest.mark.parametrize(
        "change",
        [
            pytest.param({"slack_signature": "v0=deadbeef"}, id="forged-signature"),
            # Else a bot could ask for anyone's token by changing the event's user.
            pytest.param({"event": _event(user="U_SOMEONE_ELSE")}, id="changed-event"),
        ],
    )
    def test_a_body_the_signature_does_not_match_is_refused(
        self, client, caller, change
    ):
        resp = _post(client, {**_signed(), **change})

        assert resp.status_code == 403
        assert "Invalid Slack signature" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------


class TestApproval:
    def test_a_first_request_asks_the_person_to_approve(
        self, client, db_session, caller, regular_user, send
    ):
        _store_token(db_session, regular_user)

        resp = _post(client)

        assert resp.status_code == 202
        assert resp.json() == {"status": "pending"}
        [approval] = _approvals(db_session, caller)
        assert (approval.status, approval.app_name) == ("pending", APP_NAME)
        send.assert_awaited_once()
        assert send.await_args.kwargs["approval_id"] == approval.id
        # The person sees which registered account asks, not only its chosen name.
        assert (
            send.await_args.kwargs["app_name"]
            == f"{APP_NAME} (service account {caller.username})"
        )

    def test_a_pending_request_is_not_asked_again(
        self, client, db_session, caller, send
    ):
        _approval(db_session, caller, "pending")

        resp = _post(client)

        assert resp.status_code == 202
        assert resp.json() == {"status": "pending"}
        send.assert_not_awaited()

    @pytest.mark.parametrize(
        "status, expires_in",
        [
            pytest.param("denied", None, id="denied"),
            pytest.param("failed", None, id="message-failed"),
            pytest.param("approved", timedelta(minutes=-1), id="approval-expired"),
        ],
    )
    def test_a_request_no_longer_active_is_asked_again(
        self, client, db_session, caller, regular_user, send, status, expires_in
    ):
        _store_token(db_session, regular_user)
        _approval(db_session, caller, status, approval_id="old", expires_in=expires_in)

        resp = _post(client)

        assert resp.status_code == 202
        send.assert_awaited_once()
        pending = [
            a.id for a in _approvals(db_session, caller) if a.status == "pending"
        ]
        assert len(pending) == 1
        assert pending[0] != "old"

    def test_an_approval_message_slack_wont_deliver_fails_the_request(
        self, client, db_session, caller, regular_user, send
    ):
        _store_token(db_session, regular_user)
        send.return_value = False

        with patch(
            "mcp_gateway.routes.user_tokens.asyncio.sleep", new_callable=AsyncMock
        ):
            resp = _post(client)

        assert resp.status_code == 503
        assert "Could not deliver approval message" in resp.json()["detail"]
        assert send.await_count == 3
        [approval] = _approvals(db_session, caller)
        assert approval.status == "failed"

    def test_an_approved_request_returns_the_persons_slack_token(
        self, client, db_session, caller, regular_user
    ):
        _store_token(db_session, regular_user, "slack-token")
        _approval(db_session, caller, "approved")

        resp = _post(client)

        assert resp.status_code == 200
        assert resp.json() == {
            "email": regular_user.email,
            "token": {"service": "slack_gateway", "access_token": "slack-token"},
        }
        audit = db_session.query(AuditLog).filter_by(tool_name="get_user_tokens").one()
        assert audit.user_id == caller.id
        assert "slack-token" not in json.dumps(
            [audit.request_params, audit.response_data]
        )

    def test_the_persons_email_is_matched_whatever_its_case(
        self, client, db_session, caller, regular_user, lookup
    ):
        _store_token(db_session, regular_user)
        _approval(db_session, caller, "approved")
        lookup.return_value = SlackUserEmailLookup(email=regular_user.email.upper())

        resp = _post(client)

        assert resp.status_code == 200
        assert resp.json()["email"] == regular_user.email


# ---------------------------------------------------------------------------
# Whose token
# ---------------------------------------------------------------------------


class TestWhoseToken:
    @pytest.mark.parametrize(
        "answer",
        [
            SlackUserEmailLookup(user_not_found=True),
            SlackUserEmailLookup(email_missing=True),
        ],
        ids=["no-such-slack-user", "no-email"],
    )
    def test_a_slack_user_slack_cannot_resolve_is_not_found(
        self, client, db_session, caller, lookup, answer
    ):
        _approval(db_session, caller, "approved")
        lookup.return_value = answer

        resp = _post(client)

        assert resp.status_code == 404
        assert SLACK_USER in resp.json()["detail"]

    @pytest.mark.parametrize(
        "email", ["nobody@example.com", "svc-test@example.com"], ids=["unknown", "sa"]
    )
    def test_an_email_of_no_active_person_is_not_found(
        self, client, db_session, caller, lookup, email
    ):
        """A service account's email must never yield a token."""
        _store_token(db_session, caller)
        _approval(db_session, caller, "approved")
        lookup.return_value = SlackUserEmailLookup(email=email)

        resp = _post(client)

        assert resp.status_code == 404
        assert "No active human user" in resp.json()["detail"]

    @pytest.mark.parametrize("approved", [False, True], ids=["before", "after"])
    def test_a_person_not_signed_in_through_slack_is_told_to_sign_in(
        self, client, db_session, caller, regular_user, send, approved
    ):
        # Signed in to the gateway, but not with /gravitino-mcp login.
        _store_token(db_session, regular_user, service="gateway")
        if approved:
            _approval(db_session, caller, "approved")

        resp = _post(client)

        assert resp.status_code == 404
        assert "No user token exists" in resp.json()["detail"]
        # No one is asked to approve a request that can't succeed.
        send.assert_not_awaited()
        assert len(_approvals(db_session, caller)) == int(approved)
