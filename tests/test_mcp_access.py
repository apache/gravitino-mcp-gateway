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

"""Tests for mcp_gateway.routes.mcp_access: access requests and admin approvals."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

import pytest
from sqlalchemy.orm import sessionmaker

from mcp_gateway.models import MCPAccessRequest, MCPCatalog, MCPUserPermission, User
from mcp_gateway.routes import mcp_access

REQUEST = "/api/v1/mcp-access/request"
REVIEW = "/api/v1/mcp-access/admin/review"
PERMISSIONS = "/api/v1/mcp-access/admin/permissions"

# Captured before the autouse fixture below replaces the module attribute.
_real_fire_and_forget = mcp_access._fire_and_forget


@pytest.fixture(autouse=True, name="_no_background_slack")
def fixture_no_background_slack(monkeypatch):
    """Drop fire-and-forget Slack notifications so tests stay hermetic."""
    monkeypatch.setattr(mcp_access, "_fire_and_forget", lambda coro: coro.close())


def _add(db, row):
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _mcp(db, service_id="gated", **overrides):
    fields = {
        "service_id": service_id,
        "name": service_id.title(),
        "mcp_url": f"http://{service_id}-mcp:8080/mcp",
        "is_active": True,
        "admin_only": False,
        "requires_approval": True,
        **overrides,
    }
    return _add(db, MCPCatalog(**fields))


def _user(db, username):
    return _add(db, User(username=username, email=f"{username}@example.com"))


def _request_row(db, user, mcp, status="pending", **overrides):
    fields = {"justification": "need it", "status": status, **overrides}
    return _add(db, MCPAccessRequest(user_id=user.id, mcp_id=mcp.id, **fields))


def _permission(db, user, mcp, **overrides):
    return _add(db, MCPUserPermission(user_id=user.id, mcp_id=mcp.id, **overrides))


# ---------------------------------------------------------------------------
# Asking for access
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "server,existing,status,detail",
    [
        ({"is_active": False}, None, 404, "not found"),
        # To anyone but an admin it does not exist.
        ({"admin_only": True}, None, 404, "not found"),
        ({"requires_approval": False}, None, 400, "open access"),
        ({}, _permission, 400, "already have access"),
        ({}, _request_row, 400, "pending request"),
    ],
    ids=["inactive", "admin-only", "open", "has-access", "pending"],
)
def test_access_cannot_be_requested_when_it_is_not_offered_or_not_needed(
    client, db_session, regular_user, as_user, server, existing, status, detail
):
    mcp = _mcp(db_session, **server)
    if existing:
        existing(db_session, regular_user, mcp)
    as_user(regular_user)

    resp = client.post(REQUEST, json={"mcp_id": mcp.id})

    assert resp.status_code == status
    assert detail in resp.json()["detail"].lower()


def test_a_request_after_a_denial_creates_a_new_pending_one(
    client, db_session, regular_user, as_user
):
    mcp = _mcp(db_session)
    _request_row(db_session, regular_user, mcp, status="denied")
    as_user(regular_user)

    body = client.post(
        REQUEST, json={"mcp_id": mcp.id, "justification": "nightly reports"}
    ).json()

    assert (body["status"], body["mcp_service_id"]) == ("pending", "gated")
    assert body["reviewed_at"] is None
    row = db_session.query(MCPAccessRequest).filter_by(status="pending").one()
    assert (row.id, row.user_id) == (body["id"], regular_user.id)
    assert row.justification == "nightly reports"


def test_expired_access_can_be_asked_for_again_and_its_approval_renews_it(
    client, db_session, regular_user, admin_user, as_user
):
    mcp = _mcp(db_session)
    expired = datetime.utcnow() - timedelta(days=1)
    _permission(db_session, regular_user, mcp, expires_at=expired)
    as_user(regular_user)
    request_id = client.post(REQUEST, json={"mcp_id": mcp.id}).json()["id"]
    as_user(admin_user)

    resp = client.post(
        f"{REVIEW}/{request_id}", json={"status": "approved", "expires_in_days": 30}
    )

    assert resp.status_code == 200
    perm = db_session.query(MCPUserPermission).one()
    db_session.refresh(perm)
    assert perm.granted_by == admin_user.id
    lasts = perm.expires_at - datetime.utcnow()
    assert timedelta(days=29) < lasts < timedelta(days=31)


# ---------------------------------------------------------------------------
# A person's own requests and permissions
# ---------------------------------------------------------------------------


def test_my_requests_shows_only_mine_with_their_reviewer(
    client, db_session, regular_user, admin_user, as_user
):
    mcp = _mcp(db_session)
    _request_row(
        db_session,
        regular_user,
        mcp,
        status="approved",
        justification="mine",
        reviewed_by=admin_user.id,
    )
    _request_row(db_session, _user(db_session, "someone-else"), mcp)
    as_user(regular_user)

    body = client.get("/api/v1/mcp-access/my-requests").json()

    assert [(r["justification"], r["reviewer_username"]) for r in body] == [
        ("mine", admin_user.username)
    ]


def test_my_permissions_shows_only_mine_for_servers_that_still_exist(
    client, db_session, regular_user, as_user
):
    live = _mcp(db_session, "live")
    gone = _mcp(db_session, "gone")
    _permission(db_session, regular_user, live)
    _permission(db_session, regular_user, gone)
    _permission(db_session, _user(db_session, "someone-else"), live)
    db_session.delete(gone)
    db_session.commit()
    as_user(regular_user)

    body = client.get("/api/v1/mcp-access/my-permissions").json()

    assert [(p["mcp_service_id"], p["user_id"]) for p in body] == [
        ("live", regular_user.id)
    ]


# ---------------------------------------------------------------------------
# Admin lists
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/api/v1/mcp-access/admin/pending"),
        ("get", "/api/v1/mcp-access/admin/all"),
        ("get", PERMISSIONS),
        ("delete", f"{PERMISSIONS}/1"),
    ],
)
def test_the_admin_routes_refuse_a_person_who_is_not_an_admin(
    client, regular_user, as_user, method, path
):
    as_user(regular_user)

    assert getattr(client, method)(path).status_code == 403


def test_a_person_cannot_approve_their_own_request(
    client, db_session, regular_user, as_user
):
    row = _request_row(db_session, regular_user, _mcp(db_session))
    as_user(regular_user)

    resp = client.post(f"{REVIEW}/{row.id}", json={"status": "approved"})

    assert resp.status_code == 403
    assert db_session.query(MCPUserPermission).count() == 0


def test_admin_all_filters_by_server_and_status(
    client, db_session, regular_user, admin_user, as_user
):
    wanted = _mcp(db_session, "wanted")
    _request_row(db_session, regular_user, wanted, justification="this one")
    _request_row(db_session, regular_user, wanted, status="denied")
    _request_row(db_session, regular_user, _mcp(db_session, "other"))
    as_user(admin_user)

    body = client.get(
        "/api/v1/mcp-access/admin/all",
        params={"mcp_id": wanted.id, "status_filter": "pending"},
    ).json()

    assert [item["justification"] for item in body["items"]] == ["this one"]


def test_admin_all_reports_unknown_user_for_orphaned_request(
    client, db_session, regular_user, admin_user, as_user
):
    row = _request_row(db_session, regular_user, _mcp(db_session))
    row.user_id = 4242
    db_session.commit()
    as_user(admin_user)

    body = client.get("/api/v1/mcp-access/admin/all").json()

    assert body["items"][0]["username"] == "Unknown"


def test_admin_permissions_lists_granter_and_expiry_and_filters_by_server(
    client, db_session, regular_user, admin_user, as_user
):
    wanted = _mcp(db_session, "wanted")
    expires = datetime.utcnow() + timedelta(days=7)
    _permission(
        db_session, regular_user, wanted, granted_by=admin_user.id, expires_at=expires
    )
    _permission(db_session, regular_user, _mcp(db_session, "other"))
    as_user(admin_user)

    body = client.get(PERMISSIONS, params={"mcp_id": wanted.id}).json()

    assert body["total"] == 1
    (item,) = body["items"]
    assert (item["mcp_service_id"], item["username"]) == (
        "wanted",
        regular_user.username,
    )
    assert item["granted_by"] == admin_user.username
    assert item["expires_at"] == expires.isoformat()


@pytest.mark.parametrize(
    "path",
    ["/api/v1/mcp-access/admin/pending", "/api/v1/mcp-access/admin/all", PERMISSIONS],
)
@pytest.mark.parametrize("params", [{"page_size": 101}, {"page": 0}])
def test_an_admin_list_pages_within_bounds(client, admin_user, as_user, path, params):
    as_user(admin_user)

    assert client.get(path, params=params).status_code == 422


def test_an_admin_list_counts_every_row_not_just_the_page(
    client, db_session, regular_user, admin_user, as_user
):
    for service_id in ("one", "two", "three"):
        _request_row(db_session, regular_user, _mcp(db_session, service_id))
    as_user(admin_user)

    body = client.get(
        "/api/v1/mcp-access/admin/pending", params={"page_size": 2}
    ).json()

    assert (len(body["items"]), body["total"]) == (2, 3)


# ---------------------------------------------------------------------------
# Reviews and revocation
# ---------------------------------------------------------------------------


def test_approving_a_request_grants_access_that_never_expires(
    client, db_session, regular_user, admin_user, as_user
):
    mcp = _mcp(db_session)
    row = _request_row(db_session, regular_user, mcp)
    as_user(admin_user)

    resp = client.post(
        f"{REVIEW}/{row.id}", json={"status": "approved", "admin_notes": "ok"}
    )

    assert resp.status_code == 200
    perm = db_session.query(MCPUserPermission).one()
    assert (perm.user_id, perm.mcp_id) == (regular_user.id, mcp.id)
    assert (perm.granted_by, perm.expires_at) == (admin_user.id, None)
    db_session.refresh(row)
    assert (row.status, row.admin_notes) == ("approved", "ok")
    assert (row.reviewed_by, row.reviewed_at is not None) == (admin_user.id, True)


@pytest.mark.parametrize(
    "row_status,review,code",
    [
        (None, {"status": "approved"}, 404),
        ("approved", {"status": "denied"}, 400),
        ("pending", {"status": "maybe"}, 422),
    ],
    ids=["unknown", "already-reviewed", "bad-status"],
)
def test_a_review_that_cannot_apply_grants_nothing(
    client, db_session, regular_user, admin_user, as_user, row_status, review, code
):
    request_id = 9999
    if row_status:
        row = _request_row(db_session, regular_user, _mcp(db_session), row_status)
        request_id = row.id
    as_user(admin_user)

    resp = client.post(f"{REVIEW}/{request_id}", json=review)

    assert resp.status_code == code
    assert db_session.query(MCPUserPermission).count() == 0


def test_a_request_another_admin_reviewed_first_is_not_reviewed_again(
    db_session, db_engine, regular_user, admin_user
):
    """Otherwise a denied request could leave access granted, or the reverse."""
    row = _request_row(db_session, regular_user, _mcp(db_session))
    other = sessionmaker(bind=db_engine)()
    other.query(MCPAccessRequest).filter_by(id=row.id).update({"status": "denied"})
    other.commit()
    other.close()
    review = mcp_access.ReviewAccessRequest(status="approved")

    claimed = mcp_access._claim_for_review(db_session, row, review, admin_user)

    assert claimed is False
    assert row.status == "denied"
    assert db_session.query(MCPUserPermission).count() == 0


def test_a_review_another_admin_made_first_is_a_conflict(
    client, db_session, regular_user, admin_user, as_user, monkeypatch
):
    row = _request_row(db_session, regular_user, _mcp(db_session))
    monkeypatch.setattr(mcp_access, "_claim_for_review", lambda *args: False)
    as_user(admin_user)

    resp = client.post(f"{REVIEW}/{row.id}", json={"status": "approved"})

    assert resp.status_code == 409
    assert db_session.query(MCPUserPermission).count() == 0


def test_revoking_a_permission_deletes_it_once(
    client, db_session, regular_user, admin_user, as_user
):
    perm = _permission(db_session, regular_user, _mcp(db_session))
    as_user(admin_user)

    first = client.delete(f"{PERMISSIONS}/{perm.id}")
    again = client.delete(f"{PERMISSIONS}/{perm.id}")

    assert (first.status_code, again.status_code) == (200, 404)
    assert db_session.query(MCPUserPermission).count() == 0


async def test_a_background_notification_is_held_until_it_finishes():
    started = asyncio.Event()

    async def _work():
        started.set()

    _real_fire_and_forget(_work())

    assert len(mcp_access._background_tasks) == 1
    await started.wait()
    await asyncio.sleep(0)
    assert mcp_access._background_tasks == set()
