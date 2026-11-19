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

"""Tests for the MCP catalog admin API (mcp_gateway/routes/mcp_admin.py)."""

from datetime import datetime

import jwt
import pytest

from mcp_gateway.config import settings
from mcp_gateway.models import (
    AuditLog,
    MCPAccessRequest,
    MCPCatalog,
    MCPUserPermission,
    OAuthToken,
    ServiceAccountCredentials,
    User,
)
from mcp_gateway.routes import mcp_admin
from mcp_gateway.sessions import SESSION_TYPE, session_cookie_name

METADATA_URL = "https://auth.example.com/.well-known/oauth-authorization-server"
AUDIENCE = "11111111-2222-3333-4444-666666666666"
BASE = "/api/admin/mcp"
SINGLE_SIGN_ON = {"auth_type": "oauth", "auto_sso_enabled": True, "audience": AUDIENCE}
# A server with its own sign-in, whose client secret the gateway holds.
OWN_SIGN_IN = {
    "auth_type": "oauth",
    "auto_sso_enabled": False,
    "oauth_client_secret_encrypted": "enc::keep",
    "oauth_metadata_url": METADATA_URL,
}


class _StubEncryptor:
    def encrypt(self, value):
        return f"enc::{value}"


@pytest.fixture(name="stub_encryption")
def fixture_stub_encryption(monkeypatch):
    async def _get():
        return _StubEncryptor()

    monkeypatch.setattr(mcp_admin, "get_token_encryption", _get)


@pytest.fixture(name="as_admin")
def fixture_as_admin(as_user, admin_user):
    return as_user(admin_user)


def _payload(service_id="newmcp", **extra):
    return {
        "service_id": service_id,
        "name": "New MCP",
        "mcp_url": "https://mcp.example.com",
        **extra,
    }


def _entry(db, service_id, **extra):
    fields = {
        "service_id": service_id,
        "name": "Existing MCP",
        "mcp_url": "https://existing.example.com",
        "is_active": True,
        "requires_approval": False,
        **extra,
    }
    mcp = MCPCatalog(**fields)
    db.add(mcp)
    db.commit()
    db.refresh(mcp)
    return mcp


def _stored(db):
    return db.query(MCPCatalog).filter(MCPCatalog.service_id == "newmcp").one()


def _call(client, method, path):
    """GET and DELETE reject a JSON body, so only send one where it is allowed."""
    if method in ("get", "delete"):
        return getattr(client, method)(path)
    return getattr(client, method)(path, json={})


# ------------------------------------------------------------ admin gate, auth


@pytest.mark.parametrize(
    "method,path",
    [
        ("post", f"{BASE}/"),
        ("get", f"{BASE}/"),
        ("get", f"{BASE}/trino"),
        ("patch", f"{BASE}/trino"),
        ("delete", f"{BASE}/trino"),
    ],
)
def test_every_catalog_route_refuses_a_non_admin(
    client, as_user, regular_user, method, path
):
    as_user(regular_user)

    resp = _call(client, method, path)

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin privileges required"


def test_a_session_cookie_does_not_authenticate_the_api(client, admin_user):
    """Only bearer tokens do, so another site can't use a browser's sign-in."""
    token = jwt.encode(
        {"user_id": admin_user.id, "type": SESSION_TYPE},
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    client.cookies.set(session_cookie_name(), token)

    assert client.get(f"{BASE}/").status_code == 401


@pytest.mark.parametrize("method", ["get", "patch", "delete"])
def test_an_unknown_mcp_is_a_404(client, as_admin, method):
    resp = _call(client, method, f"{BASE}/ghost")

    assert resp.status_code == 404
    assert "ghost" in resp.json()["detail"]


# ------------------------------------------------------------------- creation


def test_registering_an_mcp_records_its_creator_and_access_control_flags(
    client, as_admin, db_session
):
    client.post(
        f"{BASE}/",
        json=_payload(
            name="Trino MCP",
            requires_approval=False,
            admin_only=True,
            auto_sso_enabled=True,
            audience=AUDIENCE,
            is_active=False,
            service_auth_type="credential_forward",
        ),
    )

    stored = _stored(db_session)
    assert (stored.created_by, stored.name) == (as_admin.id, "Trino MCP")
    assert stored.admin_only and stored.auto_sso_enabled
    assert stored.requires_approval is stored.is_active is False
    assert stored.service_auth_type == "credential_forward"


def test_a_server_registered_through_the_api_requires_approval_by_default(
    client, as_admin, db_session
):
    client.post(f"{BASE}/", json=_payload())

    assert _stored(db_session).is_open_access is False


def test_registering_a_duplicate_service_id_is_rejected(client, as_admin, db_session):
    _entry(db_session, "taken")

    resp = client.post(f"{BASE}/", json=_payload("taken"))

    assert resp.status_code == 409
    assert "taken" in resp.json()["detail"]
    assert db_session.query(MCPCatalog).count() == 1


@pytest.mark.parametrize(
    "fields",
    [
        {"service_id": "ab"},
        {"service_id": "x" * 101},
        {"name": "ab"},
        # MySQL matches IDs without regard to case, and they become URL paths.
        {"service_id": "Trino"},
        {"service_id": "trino/x"},
        {"service_id": "trino?x"},
        {"service_id": "-trino"},
        # The gateway keeps its own tokens under this ID.
        {"service_id": "gateway"},
        {"mcp_url": "ftp://mcp.example.com/mcp"},
        {"mcp_url": "file:///etc/passwd"},
        {"mcp_url": "mcp.example.com/mcp"},
        {"mcp_url": "https://user:secret@mcp.example.com/mcp"},
        {"mcp_url": "https://mcp.example.com/" + "x" * 500},
        # An unknown type used to fall through to OAuth and fail as "Not connected".
        {"auth_type": "none"},
        {"auth_type": "OAuth"},
        {"service_auth_type": "oauth"},
        {"auth_type": "oauth", "auto_sso_enabled": True},
        # Otherwise the MCP server could point the gateway's secret anywhere.
        {"auth_type": "oauth", "oauth_client_secret": "topsecret"},
        {**SINGLE_SIGN_ON, "oauth_client_secret": "topsecret"},
    ],
)
def test_creation_refuses_a_server_the_gateway_could_not_safely_use(
    client, as_admin, db_session, stub_encryption, fields
):
    resp = client.post(f"{BASE}/", json=_payload(**fields))

    assert resp.status_code == 422
    assert db_session.query(MCPCatalog).count() == 0


@pytest.mark.parametrize(
    "auth,stored",
    [
        ({"auth_type": "basic"}, "enc::s3cret"),
        # People may sign in with OAuth while service accounts use basic auth.
        ({"auth_type": "passthrough", "service_auth_type": "basic"}, "enc::s3cret"),
        ({"auth_type": "oauth"}, None),
    ],
)
def test_a_password_is_stored_encrypted_only_for_basic_auth_and_never_returned(
    client, as_admin, db_session, stub_encryption, auth, stored
):
    body = client.post(
        f"{BASE}/",
        json=_payload(basic_auth_username="svc", basic_auth_password="s3cret", **auth),
    ).json()

    assert _stored(db_session).basic_auth_password_encrypted == stored
    assert body["basic_auth_username"] == "svc"
    assert "s3cret" not in str(body)
    assert not any("password" in key for key in body)


def test_an_oauth_client_secret_is_stored_encrypted_and_never_returned(
    client, as_admin, db_session, stub_encryption
):
    body = client.post(
        f"{BASE}/",
        json=_payload(
            auth_type="oauth",
            oauth_client_secret="topsecret",
            oauth_metadata_url=METADATA_URL,
        ),
    ).json()

    stored = _stored(db_session)
    assert stored.oauth_client_secret_encrypted == "enc::topsecret"
    assert stored.oauth_metadata_url == body["oauth_metadata_url"] == METADATA_URL
    assert body["oauth_client_secret_configured"] is True
    assert "topsecret" not in str(body)


def test_a_server_with_its_own_sign_in_needs_no_audience_or_metadata_url(
    client, as_admin
):
    resp = client.post(f"{BASE}/", json=_payload(auth_type="oauth"))

    assert resp.status_code == 201
    assert resp.json()["audience"] is None
    assert resp.json()["oauth_metadata_url"] is None


# -------------------------------------------------------------- listing, lookup


@pytest.mark.parametrize(
    "params,expected",
    [
        ({}, {"live", "stealth"}),
        ({"include_inactive": True}, {"live", "stealth", "retired"}),
    ],
)
def test_the_listing_shows_admin_only_servers_and_disabled_ones_on_request(
    client, as_admin, db_session, params, expected
):
    """admin_only hides an MCP from the user catalog, not from its administrators."""
    _entry(db_session, "live")
    _entry(db_session, "retired", is_active=False)
    _entry(db_session, "stealth", admin_only=True)

    ids = {m["service_id"] for m in client.get(f"{BASE}/", params=params).json()}

    assert ids == expected


def test_fetching_an_mcp_returns_its_configuration(client, as_admin, db_session):
    _entry(db_session, "trino", auth_type="basic", basic_auth_username="svc")

    body = client.get(f"{BASE}/trino").json()

    assert (body["service_id"], body["auth_type"]) == ("trino", "basic")
    assert body["basic_auth_username"] == "svc"


# -------------------------------------------------------------------- updates


def test_updating_changes_only_the_fields_that_were_sent(client, as_admin, db_session):
    mcp = _entry(db_session, "trino", name="Old", category="data")

    body = client.patch(f"{BASE}/trino", json={"mcp_url": "https://new.example"}).json()

    assert (body["mcp_url"], body["name"]) == ("https://new.example", "Old")
    db_session.refresh(mcp)
    assert mcp.category == "data"


def test_an_update_that_changes_nothing_still_records_the_touch(
    client, as_admin, db_session
):
    """An empty body sets no field, so only the explicit stamp moves the clock."""
    mcp = _entry(db_session, "trino", updated_at=datetime(2020, 1, 1))

    resp = client.patch(f"{BASE}/trino", json={})

    assert resp.status_code == 200
    db_session.refresh(mcp)
    assert mcp.updated_at > datetime(2020, 1, 1)


@pytest.mark.parametrize(
    "change,keeps_automatic_grant",
    [({"requires_approval": True}, False), ({"name": "Renamed"}, True)],
)
def test_only_closing_a_server_drops_the_access_it_gave_itself_while_open(
    client,
    as_admin,
    db_session,
    admin_user,
    regular_user,
    change,
    keeps_automatic_grant,
):
    """Access an admin approved stays; access granted automatically does not."""
    mcp = _entry(db_session, "trino")
    other = User(username="other", email="other@example.com")
    db_session.add(other)
    db_session.commit()
    db_session.add(MCPUserPermission(user_id=regular_user.id, mcp_id=mcp.id))
    db_session.add(
        MCPUserPermission(user_id=other.id, mcp_id=mcp.id, granted_by=admin_user.id)
    )
    db_session.commit()

    assert client.patch(f"{BASE}/trino", json=change).status_code == 200

    grants = sorted(
        p.granted_by or 0
        for p in db_session.query(MCPUserPermission).filter_by(mcp_id=mcp.id)
    )
    assert grants == [0] * keeps_automatic_grant + [admin_user.id]


@pytest.mark.parametrize(
    "change,stored",
    [
        ({"basic_auth_password": "rotated"}, "enc::rotated"),
        ({"name": "Renamed"}, "enc::old"),
    ],
)
def test_an_update_replaces_the_password_only_when_one_is_sent(
    client, as_admin, db_session, stub_encryption, change, stored
):
    mcp = _entry(db_session, "trino", basic_auth_password_encrypted="enc::old")

    body = client.patch(f"{BASE}/trino", json=change).json()

    db_session.refresh(mcp)
    assert mcp.basic_auth_password_encrypted == stored
    assert "rotated" not in str(body)


@pytest.mark.parametrize(
    "secret,stored",
    [("rotated", "enc::rotated"), (None, "enc::keep"), ("", None)],
    ids=["replaced", "null-keeps-it", "empty-clears-it"],
)
def test_an_update_replaces_keeps_or_clears_the_oauth_client_secret(
    client, as_admin, db_session, stub_encryption, secret, stored
):
    mcp = _entry(db_session, "trino", **OWN_SIGN_IN)

    resp = client.patch(f"{BASE}/trino", json={"oauth_client_secret": secret})

    assert resp.status_code == 200
    db_session.refresh(mcp)
    assert mcp.oauth_client_secret_encrypted == stored
    assert resp.json()["oauth_client_secret_configured"] is (stored is not None)
    assert "rotated" not in resp.text


@pytest.mark.parametrize(
    "existing,change,code,problem",
    [
        ({}, {"mcp_url": "http://u:p@host/mcp"}, 422, "mcp_url"),
        ({}, {"auth_type": "none"}, 422, "auth_type"),
        ({}, {"service_auth_type": "oauth"}, 422, "service_auth_type"),
        # A null requires_approval used to make the server open to everyone.
        ({}, {"requires_approval": None}, 422, "requires_approval"),
        ({}, {"is_active": None}, 422, "is_active"),
        ({}, {"mcp_url": None}, 422, "mcp_url"),
        ({}, {"name": None}, 422, "name"),
        (OWN_SIGN_IN, {"oauth_metadata_url": None}, 400, "oauth_metadata_url"),
        (SINGLE_SIGN_ON, {"oauth_client_secret": "s"}, 400, "its own sign-in"),
        ({"auth_type": "oauth"}, {"auto_sso_enabled": True}, 400, "audience"),
    ],
)
def test_an_update_that_would_break_the_server_is_refused(
    client, as_admin, db_session, stub_encryption, existing, change, code, problem
):
    _entry(db_session, "trino", **existing)

    resp = client.patch(f"{BASE}/trino", json=change)

    assert resp.status_code == code
    assert problem in resp.text


def _tokens_for(db, *services):
    for service in services:
        db.add(OAuthToken(user_id=1, service=service, access_token_encrypted="enc::t"))
    db.commit()


@pytest.mark.parametrize(
    "existing, change",
    [
        ({}, {"mcp_url": "https://elsewhere.example.com/mcp"}),
        (SINGLE_SIGN_ON, {"audience": "another-audience"}),
        (OWN_SIGN_IN, {"oauth_client_id": "another-client"}),
        ({}, {"auth_type": "passthrough"}),
    ],
)
def test_changing_where_tokens_go_deletes_the_tokens_people_hold_for_it(
    client, as_admin, db_session, existing, change
):
    """A token for one address or audience must not go to another."""
    _entry(db_session, "trino", **existing)
    _entry(db_session, "hive")
    _tokens_for(db_session, "trino", "hive")

    resp = client.patch(f"{BASE}/trino", json=change)

    assert resp.status_code == 200
    assert [t.service for t in db_session.query(OAuthToken)] == ["hive"]


def test_other_changes_keep_the_tokens(client, as_admin, db_session):
    _entry(db_session, "trino")
    _tokens_for(db_session, "trino")

    client.patch(
        f"{BASE}/trino",
        json={"name": "Renamed", "mcp_url": "https://existing.example.com"},
    )

    assert db_session.query(OAuthToken).count() == 1


def test_moving_a_server_drops_the_client_it_registered_with_its_old_sign_in(
    client, as_admin, db_session
):
    mcp = _entry(db_session, "trino", auth_type="oauth", oauth_client_id="registered")

    client.patch(f"{BASE}/trino", json={"mcp_url": "https://elsewhere.example.com/mcp"})

    db_session.refresh(mcp)
    assert mcp.oauth_client_id is None


@pytest.mark.parametrize(
    "existing, change, needed",
    [
        (
            OWN_SIGN_IN,
            {"oauth_metadata_url": "https://evil.example.com/.well-known/x"},
            "oauth_client_secret",
        ),
        (
            {"auth_type": "basic", "basic_auth_password_encrypted": "enc::pw"},
            {"mcp_url": "https://evil.example.com/mcp"},
            "basic_auth_password",
        ),
    ],
)
def test_a_stored_credential_does_not_follow_a_server_to_another_address(
    client, as_admin, db_session, stub_encryption, existing, change, needed
):
    """Otherwise whoever can edit a server could point it at their own host and
    collect the secret an admin stored for the real one."""
    _entry(db_session, "trino", **existing)

    refused = client.patch(f"{BASE}/trino", json=change)
    given_again = client.patch(f"{BASE}/trino", json={**change, needed: "again"})

    assert refused.status_code == 400
    assert needed in refused.json()["detail"]
    assert given_again.status_code == 200


def test_admin_changes_are_in_the_audit_log_without_secrets(
    client, as_admin, admin_user, db_session, stub_encryption
):
    client.post(
        f"{BASE}/", json=_payload(auth_type="basic", basic_auth_password="hunter2")
    )
    client.patch(f"{BASE}/newmcp", json={"name": "Renamed MCP"})
    client.delete(f"{BASE}/newmcp")

    rows = db_session.query(AuditLog).order_by(AuditLog.id).all()
    assert [(r.username, r.service, r.tool_name, r.method) for r in rows] == [
        (admin_user.username, "newmcp", action, "admin")
        for action in ("create_server", "update_server", "delete_server")
    ]
    assert rows[0].request_params["basic_auth_password"] == "[redacted]"
    assert rows[1].request_params == {"name": "Renamed MCP"}


# ------------------------------------------------------------------- deletion


def test_deleting_removes_the_mcp_with_everyones_access_and_tokens_for_it_only(
    client, as_admin, db_session, regular_user
):
    """Access requests refer to the server; MySQL refuses to delete it while they exist."""
    doomed = _entry(db_session, "trino")
    keeper = _entry(db_session, "hive")
    for mcp in (doomed, keeper):
        db_session.add_all(
            [
                MCPUserPermission(user_id=regular_user.id, mcp_id=mcp.id),
                MCPAccessRequest(user_id=regular_user.id, mcp_id=mcp.id),
                OAuthToken(
                    user_id=regular_user.id,
                    service=mcp.service_id,
                    access_token_encrypted="enc::tok",
                ),
            ]
        )
    db_session.commit()

    resp = client.delete(f"{BASE}/trino")

    assert resp.status_code == 204
    assert [m.service_id for m in db_session.query(MCPCatalog)] == ["hive"]
    assert [p.mcp_id for p in db_session.query(MCPUserPermission)] == [keeper.id]
    assert [r.mcp_id for r in db_session.query(MCPAccessRequest)] == [keeper.id]
    assert [t.service for t in db_session.query(OAuthToken)] == ["hive"]


def test_deleting_takes_the_mcp_from_service_accounts(
    client, as_admin, db_session, service_account
):
    """A new server registered with the same id must not inherit their access."""
    _entry(db_session, "trino")
    creds = ServiceAccountCredentials(
        service_account_id=service_account.id,
        provider="google",
        service_account_name="svc@proj.iam.gserviceaccount.com",
        allowed_services=["trino", "hive"],
        created_by=service_account.id,
    )
    db_session.add(creds)
    db_session.commit()

    client.delete(f"{BASE}/trino")

    db_session.refresh(creds)
    assert creds.allowed_services == ["hive"]
