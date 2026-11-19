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

"""Who the caller is, for the CLI's whoami (GET /api/v1/users/me)."""

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from mcp_gateway.models import User

ME = "/api/v1/users/me"


def test_who_am_i_needs_a_bearer_token(client):
    resp = client.get(ME)

    assert resp.status_code == 401
    assert resp.json()["detail"] == "Authorization header required"


@pytest.mark.parametrize(
    "created_at, shown",
    [(datetime(2024, 3, 1, 12, 30), "2024-03-01T12:30:00"), (None, None)],
)
def test_who_am_i_reports_the_callers_identity(
    client, as_user, admin_user, created_at, shown
):
    admin_user.team = "data-eng"
    admin_user.created_at = created_at
    as_user(admin_user)

    body = client.get(ME).json()

    assert body == {
        "id": admin_user.id,
        "username": admin_user.username,
        "email": admin_user.email,
        "is_admin": True,
        "is_service_account": False,
        "team": "data-eng",
        "created_at": shown,
    }


def test_a_person_is_found_by_email_whatever_its_case(db_session, regular_user):
    assert User.find_person(db_session, regular_user.email.upper()) == regular_user


def test_a_person_whose_email_the_database_only_resembles_is_not_found(regular_user):
    """MySQL's collation matches "ádmin@" to "admin@"; another account must never
    be taken for the person."""
    query = MagicMock()
    query.filter.return_value.first.return_value = regular_user
    db = MagicMock(query=MagicMock(return_value=query))

    assert User.find_person(db, "tèstuser@example.com") is None
