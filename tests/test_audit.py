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

"""The audit API (mcp_gateway.routes.audit): the log list, one log, the CSV
export and the summary, and whose calls each lets the caller read."""

import csv
import io
from datetime import datetime, timedelta

import pytest

from mcp_gateway.models import AuditLog, User

LOGS = "/api/v1/audit/logs"
CSV_EXPORT = "/api/v1/audit/logs/export/csv"
SUMMARY = "/api/v1/audit/analytics/summary"


def _user(db, username):
    user = User(username=username, email=f"{username}@example.com")
    db.add(user)
    db.commit()
    return user


def _log(db, user, **fields):
    entry = AuditLog(
        user_id=user.id,
        username=user.username,
        **{
            "service": "trino",
            "tool_name": "execute_query",
            "method": "tools/call",
            "status": "success",
            "created_at": datetime.utcnow(),
            **fields,
        },
    )
    db.add(entry)
    db.commit()
    return entry


def _listed_services(client, params=None):
    resp = client.get(LOGS, params=params)
    assert resp.status_code == 200, resp.text
    return sorted(log["service"] for log in resp.json()["logs"])


def _csv_rows(client, params=None):
    resp = client.get(CSV_EXPORT, params=params)
    assert resp.status_code == 200, resp.text
    return list(csv.reader(io.StringIO(resp.text)))


def _exported_services(client, params=None):
    return sorted(row[2] for row in _csv_rows(client, params)[1:])


def _summarised_services(client, params=None):
    resp = client.get(SUMMARY, params=params)
    assert resp.status_code == 200, resp.text
    return sorted(item["service"] for item in resp.json()["top_services"])


# The services of the calls each endpoint reports, so that one test can check
# that all three agree.
SERVICES_FROM = {
    "logs": _listed_services,
    "csv": _exported_services,
    "summary": _summarised_services,
}


# --------------------------------------------------------------------------
# Whose calls the caller reads
# --------------------------------------------------------------------------


@pytest.mark.parametrize("asked_for_victim", [False, True])
@pytest.mark.parametrize("endpoint", SERVICES_FROM)
def test_a_person_reads_only_their_own_calls(
    client, db_session, regular_user, as_user, endpoint, asked_for_victim
):
    victim = _user(db_session, "victim")
    _log(db_session, regular_user, service="mine")
    _log(db_session, victim, service="theirs")
    as_user(regular_user)

    services = SERVICES_FROM[endpoint](
        client, {"user_id": victim.id} if asked_for_victim else None
    )

    assert services == ["mine"]


@pytest.mark.parametrize(
    "narrowed_to, expected",
    # No account has id 0, so it must not read as "no filter".
    [(None, ["admin-data", "other-data"]), ("other", ["other-data"]), (0, [])],
)
@pytest.mark.parametrize("endpoint", SERVICES_FROM)
def test_an_admin_reads_every_account_or_narrows_to_one(
    client, db_session, admin_user, as_user, endpoint, narrowed_to, expected
):
    other = _user(db_session, "other")
    _log(db_session, admin_user, service="admin-data")
    _log(db_session, other, service="other-data")
    as_user(admin_user)
    user_id = other.id if narrowed_to == "other" else narrowed_to

    services = SERVICES_FROM[endpoint](
        client, None if user_id is None else {"user_id": user_id}
    )

    assert services == expected


def test_a_person_is_counted_only_their_own_calls(
    client, db_session, regular_user, as_user
):
    victim = _user(db_session, "victim")
    _log(db_session, regular_user)
    _log(db_session, victim)
    as_user(regular_user)

    assert client.get(LOGS).json()["total"] == 1


def test_every_aggregate_of_the_summary_is_the_callers_own(
    client, db_session, regular_user, as_user
):
    """Each aggregate carries its own owner filter, so each one could leak."""
    victim = _user(db_session, "victim")
    _log(db_session, regular_user, service="mine", tool_name="my_tool", duration_ms=10)
    _log(db_session, victim, service="theirs", tool_name="their_tool", duration_ms=999)
    _log(db_session, victim, service="theirs", status="error")
    as_user(regular_user)

    body = client.get(SUMMARY).json()

    assert body["total_calls"] == 1
    assert body["average_response_time_ms"] == 10.0
    assert body["top_services"] == [{"service": "mine", "calls": 1}]
    assert body["top_tools"] == [{"tool": "my_tool", "service": "mine", "calls": 1}]
    assert body["errors_by_service"] == []
    assert body["active_users"] is None


def test_the_summary_tells_an_admin_who_made_the_calls(
    client, db_session, admin_user, as_user
):
    _log(db_session, admin_user)
    as_user(admin_user)

    assert client.get(SUMMARY).json()["active_users"] == [
        {"username": admin_user.username, "calls": 1}
    ]


def test_an_unknown_log_is_not_found(client, regular_user, as_user):
    as_user(regular_user)

    resp = client.get(f"{LOGS}/999")

    assert resp.status_code == 404


@pytest.mark.parametrize("caller, status", [("regular_user", 403), ("admin_user", 200)])
def test_only_an_admin_reads_another_accounts_log(
    client, db_session, as_user, request, caller, status
):
    entry = _log(db_session, _user(db_session, "other"))
    as_user(request.getfixturevalue(caller))

    resp = client.get(f"{LOGS}/{entry.id}")

    assert resp.status_code == status


def test_a_log_shows_its_owner_the_whole_call(
    client, db_session, regular_user, as_user
):
    entry = _log(
        db_session,
        regular_user,
        response_data={"rows": 3},
        user_agent="pytest-agent",
        duration_ms=42,
    )
    as_user(regular_user)

    body = client.get(f"{LOGS}/{entry.id}").json()

    assert body["username"] == regular_user.username
    assert body["response_data"] == {"rows": 3}
    assert (body["user_agent"], body["duration_ms"]) == ("pytest-agent", 42)


# --------------------------------------------------------------------------
# Filters, periods and pages
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "params", [{"service": "hive"}, {"tool_name": "list_tables"}, {"status": "error"}]
)
@pytest.mark.parametrize("endpoint", ["logs", "csv"])
def test_the_list_and_the_export_apply_the_same_filters(
    client, db_session, regular_user, as_user, endpoint, params
):
    """The file holds the calls the web UI shows, not every call in the period."""
    _log(
        db_session,
        regular_user,
        service="hive",
        tool_name="list_tables",
        status="error",
    )
    _log(db_session, regular_user)
    as_user(regular_user)

    assert SERVICES_FROM[endpoint](client, params) == ["hive"]


@pytest.mark.parametrize("params", [{"service": "kept"}, {"tool_name": "list_tables"}])
def test_the_summary_counts_the_calls_the_list_shows(
    client, db_session, regular_user, as_user, params
):
    _log(db_session, regular_user, service="kept", tool_name="list_tables")
    _log(db_session, regular_user, service="dropped", duration_ms=500)
    _log(db_session, regular_user, service="dropped", status="error")
    as_user(regular_user)

    body = client.get(SUMMARY, params=params).json()

    assert body["total_calls"] == 1
    assert body["success_rate"] == 100
    assert body["average_response_time_ms"] == 0
    assert body["errors_by_service"] == []


@pytest.mark.parametrize("endpoint", SERVICES_FROM)
def test_every_endpoint_keeps_to_a_date_range(
    client, db_session, regular_user, as_user, endpoint
):
    """The web UI sends one range to all three, so their figures agree."""
    now = datetime.utcnow()
    for service, minutes_ago in (("before", 180), ("within", 30), ("after", 0)):
        _log(
            db_session,
            regular_user,
            service=service,
            created_at=now - timedelta(minutes=minutes_ago),
        )
    as_user(regular_user)
    window = {
        "start_date": (now - timedelta(hours=1)).isoformat(),
        "end_date": (now - timedelta(minutes=10)).isoformat(),
    }

    assert SERVICES_FROM[endpoint](client, window) == ["within"]


@pytest.mark.parametrize(
    "window, stale_age",
    [
        ({"minutes": 30}, timedelta(hours=2)),
        ({"hours": 2}, timedelta(days=1)),
        ({"days": 1}, timedelta(days=5)),
    ],
)
@pytest.mark.parametrize("endpoint", ["csv", "summary"])
def test_a_period_drops_older_calls(
    client, db_session, regular_user, as_user, endpoint, window, stale_age
):
    now = datetime.utcnow()
    _log(db_session, regular_user, service="stale", created_at=now - stale_age)
    _log(db_session, regular_user, service="fresh", created_at=now)
    as_user(regular_user)

    assert SERVICES_FROM[endpoint](client, window) == ["fresh"]


@pytest.mark.parametrize(
    "window", [{"days": 91}, {"hours": 169}, {"minutes": 10081}, {"days": -1}]
)
@pytest.mark.parametrize("endpoint", [CSV_EXPORT, SUMMARY])
def test_a_period_out_of_range_is_refused(
    client, regular_user, as_user, endpoint, window
):
    """An unbounded period used to overflow datetime and fail with a 500."""
    as_user(regular_user)

    assert client.get(endpoint, params=window).status_code == 422


def test_the_list_is_paged_newest_first_with_the_whole_total(
    client, db_session, regular_user, as_user
):
    now = datetime.utcnow()
    for index in range(5):
        _log(
            db_session,
            regular_user,
            service=f"svc{index}",
            created_at=now - timedelta(minutes=index),
        )
    as_user(regular_user)

    body = client.get(LOGS, params={"limit": 2, "offset": 1}).json()

    assert (body["total"], body["limit"], body["offset"]) == (5, 2, 1)
    assert [log["service"] for log in body["logs"]] == ["svc1", "svc2"]


@pytest.mark.parametrize("limit", [1001, 0, -1])
def test_a_page_size_out_of_bounds_is_refused(client, regular_user, as_user, limit):
    """SQLite reads a negative LIMIT as no limit at all."""
    as_user(regular_user)

    assert client.get(LOGS, params={"limit": limit}).status_code == 422


# --------------------------------------------------------------------------
# The CSV export
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "request_headers, error_message, cells",
    [
        ({"x-trace": "abc"}, "boom", ['{"x-trace": "abc"}', "boom"]),
        (None, None, ["", ""]),
    ],
)
def test_the_export_is_a_csv_file_with_a_row_per_call(
    client, db_session, regular_user, as_user, request_headers, error_message, cells
):
    _log(
        db_session,
        regular_user,
        duration_ms=12,
        ip_address="10.0.0.1",
        request_headers=request_headers,
        error_message=error_message,
    )
    as_user(regular_user)

    resp = client.get(CSV_EXPORT)

    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.headers["content-disposition"].startswith(
        "attachment; filename=audit_logs_"
    )
    header, row = csv.reader(io.StringIO(resp.text))
    assert header == [
        "Timestamp (UTC)",
        "User",
        "Service",
        "Tool",
        "Method",
        "Status",
        "Duration (ms)",
        "IP Address",
        "Request Headers",
        "Error",
    ]
    assert row[1:] == [
        regular_user.username,
        "trino",
        "execute_query",
        "tools/call",
        "success",
        "12",
        "10.0.0.1",
        *cells,
    ]


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r"])
def test_the_export_keeps_spreadsheets_from_running_logged_text(
    client, db_session, regular_user, as_user, prefix
):
    """Callers choose tool names, upstream servers write error messages, and a
    proxy that trusts X-Forwarded-For writes the caller's address."""
    _log(
        db_session,
        regular_user,
        tool_name=f'{prefix}HYPERLINK("https://attacker.example")',
        ip_address=f"{prefix}2+2",
        error_message=f"{prefix}1+1",
    )
    as_user(regular_user)

    row = _csv_rows(client)[1]

    assert row[3] == f'\'{prefix}HYPERLINK("https://attacker.example")'
    assert row[7] == f"'{prefix}2+2"
    assert row[9] == f"'{prefix}1+1"


# --------------------------------------------------------------------------
# The summary
# --------------------------------------------------------------------------


def test_the_summary_counts_calls_and_successes(
    client, db_session, regular_user, as_user
):
    _log(db_session, regular_user, service="trino")
    _log(db_session, regular_user, service="trino", duration_ms=50)
    _log(db_session, regular_user, service="trino")
    _log(
        db_session,
        regular_user,
        service="hive",
        tool_name="list_tables",
        status="error",
        duration_ms=100,
    )
    as_user(regular_user)

    body = client.get(SUMMARY).json()

    assert (body["total_calls"], body["successful_calls"]) == (4, 3)
    assert body["success_rate"] == 75.0
    assert body["average_response_time_ms"] == 75.0
    # Only successful calls count towards the most used.
    assert body["top_services"] == [{"service": "trino", "calls": 3}]
    assert body["top_tools"] == [
        {"tool": "execute_query", "service": "trino", "calls": 3}
    ]
    assert body["errors_by_service"] == [{"service": "hive", "errors": 1}]


def test_a_summary_without_calls_reports_zeroes(client, regular_user, as_user):
    as_user(regular_user)

    body = client.get(SUMMARY).json()

    assert body["total_calls"] == 0
    assert body["success_rate"] == 0
    assert body["average_response_time_ms"] == 0


@pytest.mark.parametrize(
    "params, label",
    [
        ({}, "7 days"),
        ({"days": 3}, "3 days"),
        ({"hours": 6}, "6 hours"),
        ({"minutes": 15}, "15 minutes"),
        (
            {"days": 3, "start_date": "2026-01-01T00:00:00"},
            "from 2026-01-01T00:00:00",
        ),
        (
            {"start_date": "2026-01-01T00:00:00", "end_date": "2026-01-02T00:00:00"},
            "from 2026-01-01T00:00:00 to 2026-01-02T00:00:00",
        ),
    ],
)
def test_the_summary_names_its_period(client, regular_user, as_user, params, label):
    as_user(regular_user)

    assert client.get(SUMMARY, params=params).json()["period"] == label
