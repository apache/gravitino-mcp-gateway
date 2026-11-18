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

"""Expired device codes, sign-in states and approvals, and old audit rows, are deleted."""

from datetime import datetime, timedelta

import pytest

from mcp_gateway.config import settings
from mcp_gateway.models import AuditLog, DeviceCode, OAuthState, SlackTokenApproval
from mcp_gateway.purge import purge_expired_rows

PAST = datetime.utcnow() - timedelta(minutes=1)
FUTURE = datetime.utcnow() + timedelta(minutes=10)


def _device_code(code, expires_at):
    return DeviceCode(
        device_code=code,
        user_code=code[-8:],
        client_id="gravitino-mcp-cli",
        expires_at=expires_at,
    )


def test_expired_rows_of_every_kind_are_deleted(
    db_session, regular_user, service_account
):
    db_session.add_all(
        [
            _device_code("device-old", PAST),
            _device_code("device-new", FUTURE),
            OAuthState(
                state="s-old", user_id=regular_user.id, service="x", expires_at=PAST
            ),
            OAuthState(
                state="s-new", user_id=regular_user.id, service="x", expires_at=FUTURE
            ),
            SlackTokenApproval(
                id="approval-old",
                requesting_sa_id=service_account.id,
                slack_user_id="U1",
                app_name="app",
                expires_at=PAST,
            ),
        ]
    )
    db_session.commit()

    deleted = purge_expired_rows(db_session)

    assert deleted == 3
    assert [d.device_code for d in db_session.query(DeviceCode).all()] == ["device-new"]
    assert [s.state for s in db_session.query(OAuthState).all()] == ["s-new"]
    assert db_session.query(SlackTokenApproval).count() == 0


def _call(db, user, days_ago):
    db.add(
        AuditLog(
            user_id=user.id,
            username=user.username,
            service="gravitino",
            tool_name="list_catalogs",
            method="tools/call",
            status="success",
            created_at=datetime.utcnow() - timedelta(days=days_ago),
        )
    )
    db.commit()


@pytest.mark.parametrize("retention_days, kept", [(90, 1), (0, 2)])
def test_calls_older_than_the_retention_are_deleted(
    db_session, regular_user, monkeypatch, retention_days, kept
):
    """A retention of 0 keeps every call."""
    monkeypatch.setattr(settings, "AUDIT_RETENTION_DAYS", retention_days)
    _call(db_session, regular_user, days_ago=3650)
    _call(db_session, regular_user, days_ago=1)

    assert purge_expired_rows(db_session) == 2 - kept
    assert db_session.query(AuditLog).count() == kept
