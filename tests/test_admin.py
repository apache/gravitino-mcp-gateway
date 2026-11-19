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

"""Tests for the service account administration routes (routes/admin.py)."""

import pytest

from mcp_gateway.models import (
    AuditLog,
    MCPAccessRequest,
    MCPUserPermission,
    ServiceAccountCredentials,
    User,
)

API = "/api/v1/admin/service-accounts"
SHARED = "shared@proj.iam.gserviceaccount.com"


def _payload(name="svc-new", identity="svc-new@proj.iam.gserviceaccount.com", **extra):
    return {
        "name": name,
        "oauth_credentials": {"service_account_name": identity},
        **extra,
    }


@pytest.fixture(name="as_admin")
def fixture_as_admin(as_user, admin_user):
    return as_user(admin_user)


def _call(client, method, path):
    """GET and DELETE reject a JSON body, so only send one where it is allowed."""
    if method in ("get", "delete"):
        return getattr(client, method)(path)
    return getattr(client, method)(path, json={})


def _creds(db, sa, *, identity=None, provider="google", services=None, config=None):
    row = ServiceAccountCredentials(
        service_account_id=sa.id,
        provider=provider,
        service_account_name=identity or f"{sa.username}@proj.iam.gserviceaccount.com",
        allowed_services=services if services is not None else ["trino"],
        additional_config=config,
        created_by=sa.id,
    )
    db.add(row)
    db.commit()
    return row


def _user_row(db, user_id):
    db.expire_all()
    return db.query(User).filter(User.id == user_id).one()


# --- admin gate -----------------------------------------------------------


@pytest.mark.parametrize(
    "method,path",
    [
        ("post", API),
        ("get", API),
        ("patch", f"{API}/1"),
        ("delete", f"{API}/1"),
    ],
)
def test_the_routes_refuse_a_non_admin(client, as_user, regular_user, method, path):
    as_user(regular_user)

    resp = _call(client, method, path)

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin privileges required"


@pytest.mark.parametrize("method", ["patch", "delete"])
def test_a_person_is_not_a_service_account_to_these_routes(
    client, as_admin, db_session, regular_user, method
):
    resp = _call(client, method, f"{API}/{regular_user.id}")

    assert resp.status_code == 404
    assert resp.json()["detail"] == "Service account not found"
    assert _user_row(db_session, regular_user.id).is_active


# --- creation -------------------------------------------------------------


def test_creating_a_service_account_records_the_oidc_identity(
    client, as_admin, db_session
):
    body = client.post(
        API,
        json=_payload(team="data-eng", provider="google", allowed_services=["trino"]),
    ).json()

    assert body["username"] == "svc-new"
    assert (body["team"], body["provider"]) == ("data-eng", "google")
    assert body["service_account_name"] == "svc-new@proj.iam.gserviceaccount.com"
    assert body["allowed_services"] == ["trino"]
    created = db_session.query(User).filter(User.username == "svc-new").one()
    assert created.is_service_account is True
    assert created.email == "svc-new@proj.iam.gserviceaccount.com"


def test_a_created_service_account_is_never_an_admin(client, as_admin, db_session):
    """The request body has no admin field, so creation must not be an escalation API."""
    client.post(API, json=_payload(is_admin=True))

    created = db_session.query(User).filter(User.username == "svc-new").one()
    assert created.is_admin is False


def test_creation_rejects_a_username_already_in_use(
    client, as_admin, db_session, regular_user
):
    resp = client.post(API, json=_payload(name=regular_user.username))

    assert resp.status_code == 409
    assert "already exists" in resp.json()["detail"]
    assert db_session.query(ServiceAccountCredentials).count() == 0


@pytest.mark.parametrize("claimed", [SHARED, "Shared@Proj.Iam.Gserviceaccount.Com"])
def test_creation_rejects_an_identity_already_claimed_by_another_account(
    client, as_admin, db_session, service_account, claimed
):
    """The identity is matched against the JWT email claim, so it must stay unique."""
    _creds(db_session, service_account, identity=claimed)

    resp = client.post(API, json=_payload(name="svc-other", identity=SHARED))

    assert resp.status_code == 409
    assert service_account.username in resp.json()["detail"]
    assert db_session.query(User).filter(User.username == "svc-other").count() == 0


def test_a_claimed_identity_is_reported_by_id_when_its_owner_is_gone(
    client, as_admin, db_session, service_account
):
    creds = _creds(db_session, service_account, identity=SHARED)
    creds.service_account_id = 999999
    db_session.commit()

    resp = client.post(API, json=_payload(name="svc-other", identity=SHARED))

    assert resp.status_code == 409
    assert "id=999999" in resp.json()["detail"]


@pytest.mark.parametrize(
    "fields",
    [
        {"name": "ab"},
        {"name": "x" * 101},
        {"name": "  ab  "},
        # No workload signs in as a blank identity, and it would block the next one.
        {"identity": ""},
        {"identity": "   "},
    ],
)
def test_creation_rejects_an_out_of_range_name_or_a_blank_identity(
    client, as_admin, fields
):
    assert client.post(API, json=_payload(**fields)).status_code == 422


def test_creation_trims_the_name_and_identity(client, as_admin):
    body = client.post(
        API,
        json=_payload(
            name="  svc-new ",
            identity=" svc-new@proj.iam.gserviceaccount.com\n",
            team=" data-eng ",
        ),
    ).json()

    assert body["username"] == "svc-new"
    assert body["service_account_name"] == "svc-new@proj.iam.gserviceaccount.com"
    assert body["team"] == "data-eng"


# --- listing and lookup ---------------------------------------------------


def test_listing_returns_active_service_accounts_with_their_credentials(
    client, as_admin, db_session, service_account, regular_user
):
    _creds(db_session, service_account, provider="aws", services=["trino", "hive"])
    retired = User(
        username="svc-old", email="o@x.com", is_service_account=True, is_active=False
    )
    db_session.add(retired)
    db_session.commit()

    body = client.get(API).json()

    assert [sa["username"] for sa in body] == [service_account.username]
    assert (body[0]["provider"], body[0]["allowed_services"]) == (
        "aws",
        ["trino", "hive"],
    )


def test_a_service_account_without_credentials_is_still_listed(
    client, as_admin, service_account
):
    """A missing credentials row must not break the admin UI."""
    (body,) = client.get(API).json()

    assert (body["provider"], body["service_account_name"]) == ("unknown", "N/A")
    assert body["allowed_services"] == []


# --- updates --------------------------------------------------------------


@pytest.mark.parametrize(
    "change,services,config",
    [
        ({"allowed_services": ["hive"]}, ["hive"], {"a": 1}),
        ({"additional_config": {"b": 2}}, ["trino"], {"b": 2}),
        ({"clear_additional_config": True}, ["trino"], None),
        ({}, ["trino"], {"a": 1}),
    ],
)
def test_an_update_changes_only_what_it_names(
    client, as_admin, db_session, service_account, change, services, config
):
    creds = _creds(db_session, service_account, services=["trino"], config={"a": 1})

    body = client.patch(f"{API}/{service_account.id}", json=change).json()

    assert (body["allowed_services"], body["additional_config"]) == (services, config)
    db_session.refresh(creds)
    assert (creds.allowed_services, creds.additional_config) == (services, config)


def test_setting_and_clearing_the_config_at_once_is_rejected(
    client, as_admin, db_session, service_account
):
    _creds(db_session, service_account, config={"a": 1})

    resp = client.patch(
        f"{API}/{service_account.id}",
        json={"clear_additional_config": True, "additional_config": {"b": 2}},
    )

    assert resp.status_code == 400
    assert "Cannot send additional_config together" in resp.json()["detail"]


def test_updating_a_service_account_without_credentials_is_a_404(
    client, as_admin, service_account
):
    resp = client.patch(f"{API}/{service_account.id}", json={"allowed_services": []})

    assert resp.status_code == 404
    assert resp.json()["detail"] == "Service account credentials not found"


_KEY_FORWARDING = {
    "downstream_credentials": {
        "trino": {
            "secret_ref": "mcp-gateway-encryption-key",
            "auth_header_type": "bearer",
        }
    }
}


def test_a_service_account_cannot_be_given_the_gateways_own_secrets(
    client, as_admin, db_session, service_account
):
    """An admin could otherwise read any secret the gateway can, by forwarding it."""
    _creds(db_session, service_account)

    created = client.post(API, json=_payload(additional_config=_KEY_FORWARDING))
    updated = client.patch(
        f"{API}/{service_account.id}", json={"additional_config": _KEY_FORWARDING}
    )

    assert created.status_code == 422
    assert updated.status_code == 422
    assert "SERVICE_ACCOUNT_SECRET_PREFIX" in updated.text


def test_a_slack_signing_secret_is_hidden_and_kept(client, as_admin, db_session):
    """Responses must not show it, and saving a shown config must keep it."""
    created = client.post(
        API,
        json=_payload(
            additional_config={"slack_signing_secret": "s3cret", "team": "data"}
        ),
    ).json()
    assert created["additional_config"]["slack_signing_secret"] == "<hidden>"

    updated = client.patch(
        f"{API}/{created['id']}",
        json={"additional_config": {**created["additional_config"], "team": "ml"}},
    ).json()

    assert updated["additional_config"] == {
        "slack_signing_secret": "<hidden>",
        "team": "ml",
    }
    creds = db_session.query(ServiceAccountCredentials).one()
    assert creds.additional_config["slack_signing_secret"] == "s3cret"


# --- deletion -------------------------------------------------------------


def test_deleting_retires_the_account_and_its_access_but_keeps_its_audit_history(
    client, as_admin, db_session, service_account, mcp_entry
):
    """Audit rows refer to the user row, and its pending requests could never be used."""
    sa_id = service_account.id
    name = service_account.username
    _creds(db_session, service_account)
    db_session.add_all(
        [
            MCPAccessRequest(user_id=sa_id, mcp_id=mcp_entry.id, status="pending"),
            MCPUserPermission(user_id=sa_id, mcp_id=mcp_entry.id),
            AuditLog(
                user_id=sa_id,
                username=name,
                service="trino",
                tool_name="query",
                method="tools/call",
                status="success",
            ),
        ]
    )
    db_session.commit()

    body = client.delete(f"{API}/{sa_id}").json()

    assert name in body["message"]
    assert _user_row(db_session, sa_id).is_active is False
    calls = db_session.query(AuditLog).filter(AuditLog.method != "admin")
    assert calls.one().user_id == sa_id
    for model in (ServiceAccountCredentials, MCPAccessRequest, MCPUserPermission):
        assert db_session.query(model).count() == 0, model.__name__


@pytest.mark.parametrize("method", ["patch", "delete"])
def test_a_deleted_service_account_is_gone_from_every_route(
    client, as_admin, service_account, method
):
    """It has no credentials, which must not stop it being deleted."""
    deleted = client.delete(f"{API}/{service_account.id}")

    resp = _call(client, method, f"{API}/{service_account.id}")

    assert (deleted.status_code, resp.status_code) == (200, 404)


def test_a_deleted_service_account_can_be_registered_again(client, as_admin):
    created = client.post(API, json=_payload()).json()

    client.delete(f"{API}/{created['id']}")
    again = client.post(API, json=_payload())

    assert again.status_code == 200, again.text
    assert again.json()["id"] != created["id"]


def test_admin_changes_to_service_accounts_are_in_the_audit_log(
    client, as_admin, admin_user, db_session
):
    account = client.post(API, json=_payload()).json()
    client.patch(f"{API}/{account['id']}", json={"allowed_services": ["trino"]})
    client.delete(f"{API}/{account['id']}")

    rows = db_session.query(AuditLog).order_by(AuditLog.id).all()
    assert [(r.username, r.tool_name, r.method) for r in rows] == [
        (admin_user.username, action, "admin")
        for action in (
            "create_service_account",
            "update_service_account",
            "delete_service_account",
        )
    ]
