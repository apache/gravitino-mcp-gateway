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

"""The gateway's side of the device flow (RFC 8628).

With it the CLI gets a person's gateway token, so what matters is that only a
person who typed the code and approved it hands their tokens over; that a
link, another person or a stale review can't approve for them; and that one
poll, by whoever holds the device code, gets the tokens once.
"""

import re
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest

from mcp_gateway.config import settings
from mcp_gateway.models import DeviceCode, OAuthToken
from mcp_gateway.routes import device_flow
from mcp_gateway.sessions import SESSION_TYPE, session_cookie_name

CODE_URL = "/api/v1/device/code"
TOKEN_URL = "/api/v1/device/token"
USER_CODE = "WXYZ-1234"


class _StubEncryptor:
    def decrypt(self, value):
        return value.removeprefix("enc::")


@pytest.fixture(autouse=True, name="stub_encryption")
def fixture_stub_encryption(monkeypatch):
    async def _get():
        return _StubEncryptor()

    monkeypatch.setattr(device_flow, "get_token_encryption", _get)


@pytest.fixture(name="sign_in")
def fixture_sign_in(client):
    """Authenticate the way a browser does, through the real session cookie."""

    def _sign_in(user_id, secret=None, claims=None):
        payload = (
            {"user_id": user_id, "type": SESSION_TYPE} if claims is None else claims
        )
        token = jwt.encode(
            payload, secret or settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
        )
        client.cookies.set(session_cookie_name(), token)

    return _sign_in


@pytest.fixture(name="signed_in")
def fixture_signed_in(sign_in, db_session, regular_user):
    """The regular user, signed in with a stored gateway token."""
    _gateway_token(db_session, regular_user)
    sign_in(regular_user.id)
    return regular_user


def _device_code(db, code="dev-code", user_code=USER_CODE, **extra):
    entry = DeviceCode(
        device_code=code,
        user_code=user_code,
        client_id=extra.pop("client_id", "gravitino-mcp-cli"),
        requested_from=extra.pop("requested_from", "203.0.113.7"),
        requested_by_agent=extra.pop("requested_by_agent", "python-requests/2.32"),
        expires_at=extra.pop("expires_at", datetime.utcnow() + timedelta(minutes=10)),
        **extra,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def _gateway_token(db, user, **extra):
    """Store the user's gateway token, replacing any before it."""
    service = extra.pop("service", "gateway")
    db.query(OAuthToken).filter(
        OAuthToken.user_id == user.id, OAuthToken.service == service
    ).delete()
    db.add(
        OAuthToken(
            user_id=user.id,
            service=service,
            access_token_encrypted=extra.pop("access", "enc::access"),
            expires_at=extra.pop("expires_at", datetime.utcnow() + timedelta(hours=1)),
            **extra,
        )
    )
    db.commit()


def _login_next(resp):
    """Where the sign-in a response redirects to continues afterwards."""
    location = urlsplit(resp.headers["location"])
    assert location.path == "/auth/oauth/login"
    return parse_qs(location.query)["next"][0]


def _review(client, user_code=USER_CODE):
    return client.post("/device", data={"user_code": user_code}, follow_redirects=False)


def _csrf(resp):
    match = re.search(r'name="approval_csrf" value="([^"]+)"', resp.text)
    assert match, resp.text
    return match.group(1)


def _decide(client, csrf, action="approve", user_code=USER_CODE):
    data = {"user_code": user_code, "approval_csrf": csrf}
    if action is not None:
        data["action"] = action
    return client.post("/device/approve", data=data, follow_redirects=False)


def _poll(client, code="dev-code", **extra):
    return client.post(TOKEN_URL, json={"device_code": code, **extra})


# --- requesting a code --------------------------------------------------------


def test_a_requested_code_is_stored_unapproved_with_where_it_came_from(
    client, db_session
):
    body = client.post(
        CODE_URL,
        json={"client_id": "gravitino-mcp-cli"},
        headers={"User-Agent": "gravitino-mcp/1.0"},
    ).json()

    entry = db_session.query(DeviceCode).one()
    assert entry.device_code == body["device_code"]
    assert entry.user_code == body["user_code"]
    assert not entry.approved and not entry.denied and entry.user_id is None
    assert entry.requested_from == "testclient"
    assert entry.requested_by_agent == "gravitino-mcp/1.0"


def test_the_user_code_is_typeable_and_no_link_fills_it_in(client):
    """A link that fills in the code makes it easy to phish."""
    body = client.post(CODE_URL, json={}).json()

    assert re.fullmatch(r"[A-Z0-9]{4}-[A-Z0-9]{4}", body["user_code"])
    assert body["user_code"] not in body["device_code"]
    assert body != client.post(CODE_URL, json={}).json()
    assert body["verification_uri"] == f"{settings.GATEWAY_BASE_URL}/device"
    assert "verification_uri_complete" not in body


@pytest.mark.parametrize(
    "client_id, error",
    [("gravitino-mcp-slack", None), ("evil-client", "invalid_client")],
)
def test_only_a_registered_client_can_start(client, db_session, client_id, error):
    resp = client.post(CODE_URL, json={"client_id": client_id})

    assert resp.json().get("error") == error
    assert db_session.query(DeviceCode).count() == (0 if error else 1)


# --- the page -------------------------------------------------------------------


@pytest.mark.parametrize(
    "send",
    [
        lambda client: client.get(
            f"/device?user_code={USER_CODE}", follow_redirects=False
        ),
        _review,
        lambda client: _decide(client, "csrf"),
    ],
    ids=["the page, which drops the code", "reviewing", "deciding"],
)
def test_without_a_session_each_step_sends_the_browser_to_sign_in_and_back(
    client, db_session, send
):
    _device_code(db_session)

    assert _login_next(send(client)) == "/device"


@pytest.mark.parametrize(
    "secret, claims",
    [
        ("not-the-gateway-secret" * 2, None),
        (None, {"user_id": 4242, "type": SESSION_TYPE}),
        (None, {"type": SESSION_TYPE}),
    ],
    ids=["another key", "a deleted user", "no user"],
)
def test_a_session_that_names_no_one_is_sent_to_sign_in(
    client, sign_in, regular_user, secret, claims
):
    sign_in(regular_user.id, secret=secret, claims=claims)

    assert _login_next(client.get("/device", follow_redirects=False)) == "/device"


def test_a_person_without_a_gateway_token_is_sent_to_sign_in(
    client, sign_in, db_session, regular_user, admin_user
):
    """Signing in stores the token that approving hands over."""
    _gateway_token(db_session, admin_user)
    _gateway_token(db_session, regular_user, service="trino")
    sign_in(regular_user.id)

    assert _login_next(client.get("/device", follow_redirects=False)) == "/device"


def test_a_link_with_the_code_does_not_fill_it_in(client, db_session, signed_in):
    _device_code(db_session)

    resp = client.get(f"/device?user_code={USER_CODE}")

    assert resp.status_code == 200
    assert USER_CODE not in resp.text
    assert "approval_csrf" not in resp.text


# --- reviewing a code -----------------------------------------------------------


def test_a_typed_code_shows_who_asked_from_where_and_when(
    client, db_session, signed_in
):
    entry = _device_code(db_session)

    resp = _review(client)

    assert "the gravitino-mcp CLI" in resp.text
    assert "203.0.113.7" in resp.text
    assert "python-requests/2.32" in resp.text
    assert entry.created_at.strftime("%Y-%m-%d %H:%M") in resp.text
    assert _csrf(resp)


def test_a_code_typed_in_lower_case_without_the_hyphen_is_found(
    client, db_session, signed_in
):
    _device_code(db_session)

    assert _csrf(_review(client, "wxyz1234"))


@pytest.mark.parametrize(
    "entry, message",
    [
        (None, "No such code"),
        ({"expires_at": datetime.utcnow() - timedelta(seconds=1)}, "expired"),
        ({"approved": True}, "already been used"),
        ({"denied": True}, "already been used"),
        ({"client_id": "unregistered"}, "No such code"),
    ],
    ids=["unknown", "expired", "approved", "denied", "unregistered client"],
)
def test_a_code_that_cant_be_approved_says_why(
    client, db_session, signed_in, entry, message
):
    if entry is not None:
        _device_code(db_session, **entry)

    resp = _review(client)

    assert message in resp.text
    assert "approval_csrf" not in resp.text


def test_a_code_someone_else_is_reviewing_cannot_be_taken_over(
    client, sign_in, db_session, signed_in, admin_user
):
    """Otherwise anyone who saw the code could cancel the owner's review."""
    _device_code(db_session)
    owners_csrf = _csrf(_review(client))
    _gateway_token(db_session, admin_user)
    sign_in(admin_user.id)

    assert "Someone else" in _review(client).text

    sign_in(signed_in.id)
    assert "Approved" in _decide(client, owners_csrf).text


# --- deciding ---------------------------------------------------------------------


def test_a_decision_must_be_chosen(client, db_session, signed_in):
    entry = _device_code(db_session)

    resp = _decide(client, _csrf(_review(client)), action=None)

    assert resp.status_code == 400
    db_session.refresh(entry)
    assert not entry.approved


def test_a_review_token_from_elsewhere_cannot_approve(
    client, sign_in, db_session, signed_in, admin_user
):
    entry = _device_code(db_session)
    _csrf(_review(client))

    for csrf in ("", "forged"):
        assert _decide(client, csrf).status_code == 403
    _gateway_token(db_session, admin_user)
    sign_in(admin_user.id)
    db_session.refresh(entry)
    assert _decide(client, entry.approval_csrf).status_code == 403

    db_session.refresh(entry)
    assert not entry.approved


def test_a_code_that_expires_during_the_review_cannot_be_approved(
    client, db_session, signed_in
):
    entry = _device_code(db_session)
    csrf = _csrf(_review(client))
    entry.expires_at = datetime.utcnow() - timedelta(seconds=1)
    db_session.commit()

    assert "expired" in _decide(client, csrf).text
    db_session.refresh(entry)
    assert not entry.approved


def test_a_denied_code_is_refused_to_the_cli(client, db_session, signed_in):
    _device_code(db_session)

    assert "Denied" in _decide(client, _csrf(_review(client)), "deny").text

    assert _poll(client).json()["error"] == "access_denied"
    assert db_session.query(DeviceCode).count() == 0


# --- polling ----------------------------------------------------------------------


def test_an_unknown_device_code_is_an_invalid_grant(client):
    assert _poll(client, "nope").json()["error"] == "invalid_grant"


def test_only_the_device_code_grant_is_accepted(client, db_session, regular_user):
    _device_code(db_session, approved=True, user_id=regular_user.id)

    resp = _poll(client, grant_type="password")

    assert resp.json()["error"] == "unsupported_grant_type"


@pytest.mark.parametrize(
    "state",
    [{}, {"approved": True}, {"user_id": None, "approved": False}],
    ids=["new", "approved without a person", "unapproved"],
)
def test_a_code_stays_pending_until_a_person_approves_it(client, db_session, state):
    _device_code(db_session, **state)

    assert _poll(client).json()["error"] == "authorization_pending"


def test_approving_binds_the_code_to_the_approver_whose_token_the_cli_then_gets(
    client, db_session, signed_in
):
    entry = _device_code(db_session)
    csrf = _csrf(_review(client))
    assert _poll(client).json()["error"] == "authorization_pending"

    resp = _decide(client, csrf)

    assert "Approved" in resp.text
    db_session.refresh(entry)
    assert entry.approved and entry.user_id == signed_in.id
    assert entry.approval_csrf is None
    assert _poll(client).json()["access_token"] == "access"


def test_an_expired_code_is_deleted(client, db_session, regular_user):
    _device_code(
        db_session,
        approved=True,
        user_id=regular_user.id,
        expires_at=datetime.utcnow() - timedelta(seconds=1),
    )

    assert _poll(client).json()["error"] == "expired_token"
    assert db_session.query(DeviceCode).count() == 0


def test_a_poll_returns_the_approvers_tokens_once(
    client, db_session, regular_user, admin_user
):
    """A leaked device code must not be replayable after the CLI has used it."""
    _gateway_token(db_session, admin_user, access="enc::admin-token")
    _gateway_token(
        db_session,
        regular_user,
        access="enc::user-token",
        refresh_token_encrypted="enc::user-refresh",
        expires_at=datetime.utcnow() + timedelta(hours=2),
    )
    _device_code(db_session, approved=True, user_id=regular_user.id)

    body = _poll(client).json()

    assert body["access_token"] == "user-token"
    assert body["refresh_token"] == "user-refresh"
    assert body["token_type"] == "Bearer"
    assert 7100 < body["expires_in"] <= 7200
    assert body["user"]["id"] == regular_user.id
    assert _poll(client).json()["error"] == "invalid_grant"


def test_a_poll_that_loses_the_race_to_another_gets_nothing(
    client, db_session, regular_user, monkeypatch
):
    _gateway_token(db_session, regular_user)
    _device_code(db_session, approved=True, user_id=regular_user.id)
    real_tokens = device_flow._gateway_tokens  # pylint: disable=protected-access

    async def _other_poll_wins(db, user):
        tokens = await real_tokens(db, user)
        db.query(DeviceCode).delete()
        db.commit()
        return tokens

    monkeypatch.setattr(device_flow, "_gateway_tokens", _other_poll_wins)

    resp = _poll(client)

    assert resp.json()["error"] == "invalid_grant"
    assert "access_token" not in resp.json()


@pytest.mark.parametrize(
    "token",
    [None, {"expires_at": datetime.utcnow() - timedelta(hours=1)}],
    ids=["none", "expired"],
)
def test_the_lifetime_is_never_negative_and_a_missing_refresh_token_is_none(
    client, db_session, regular_user, token
):
    _gateway_token(db_session, regular_user, **(token or {}))
    _device_code(db_session, approved=True, user_id=regular_user.id)

    body = _poll(client).json()

    assert body["refresh_token"] is None
    assert body["expires_in"] >= 0


def test_no_tokens_go_to_a_deactivated_person(client, db_session, regular_user):
    _gateway_token(db_session, regular_user)
    _device_code(db_session, approved=True, user_id=regular_user.id)
    regular_user.is_active = False
    db_session.commit()

    assert _poll(client).json()["error"] == "invalid_grant"
    assert db_session.query(DeviceCode).count() == 0


def test_a_person_without_a_gateway_token_gets_an_error(
    client, db_session, regular_user
):
    _gateway_token(db_session, regular_user, service="trino")
    _device_code(db_session, approved=True, user_id=regular_user.id)

    assert _poll(client).json()["error"] == "invalid_grant"


def test_a_token_that_cannot_be_decrypted_is_not_handed_back(
    client, db_session, regular_user, monkeypatch
):
    class _WrongKey:
        def decrypt(self, value):
            return None

    async def _get():
        return _WrongKey()

    monkeypatch.setattr(device_flow, "get_token_encryption", _get)
    _gateway_token(db_session, regular_user)
    _device_code(db_session, approved=True, user_id=regular_user.id)

    resp = _poll(client)

    assert resp.json()["error"] == "invalid_grant"
    assert "enc::" not in resp.text
