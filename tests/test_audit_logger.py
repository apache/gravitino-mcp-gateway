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

"""What an audit row records about a call (mcp_gateway.audit)."""

from unittest.mock import patch

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError

from mcp_gateway.audit import PAYLOAD_LENGTH, AuditLogger, tool_call_failure
from mcp_gateway.config import settings
from mcp_gateway.models import AuditLog
from tests.request_utils import make_starlette_request


async def _log(db_session, user, **fields):
    return await AuditLogger.log_tool_call(
        db=db_session,
        user=user,
        **{"service": "logs", "tool_name": "query", "method": "tools/call", **fields},
    )


@pytest.mark.parametrize(
    "error, recorded",
    [
        # Exception text can name internal hosts, and callers read their audit rows.
        (httpx.ConnectError("hostname 'secret-host.corp.internal'"), "ConnectError"),
        # An HTTP error's detail is what the caller saw anyway.
        (HTTPException(status_code=403, detail="Access expired"), "Access expired"),
    ],
)
async def test_an_exception_is_recorded_without_its_internal_text(
    db_session, regular_user, error, recorded
):
    with pytest.raises(type(error)):
        async with AuditLogger.track_tool_call(
            db=db_session, user=regular_user, service="logs", tool_name="tools/list"
        ):
            raise error

    row = db_session.query(AuditLog).one()
    assert (row.status, row.error_message) == ("error", recorded)


async def test_caller_and_server_text_is_cut_to_fit_the_audit_columns(
    db_session, regular_user
):
    """MySQL refuses a value longer than its column, and the row is lost."""
    row = await _log(
        db_session,
        regular_user,
        tool_name=["x"] * 200,
        method="m" * 80,
        status="error",
        error_message="e" * 70_000,
        ip_address="1" * 80,
        user_agent="u" * 600,
    )

    assert isinstance(row.tool_name, str)
    assert [len(row.tool_name), len(row.method), len(row.error_message)] == [
        255,
        50,
        10_000,
    ]
    assert [len(row.ip_address), len(row.user_agent)] == [50, 500]


async def test_a_failed_audit_write_does_not_fail_the_call(db_session, regular_user):
    """The tool already ran; the caller must still get its result."""
    with patch.object(
        AuditLogger, "log_tool_call", side_effect=SQLAlchemyError("data too long")
    ):
        async with AuditLogger.track_tool_call(
            db=db_session, user=regular_user, service="logs", tool_name="t"
        ) as tracker:
            tracker.set_response({"ok": True})

    assert db_session.query(AuditLog).count() == 0


async def test_a_failed_audit_write_keeps_the_tools_own_error(db_session, regular_user):
    with (
        patch.object(
            AuditLogger, "log_tool_call", side_effect=SQLAlchemyError("data too long")
        ),
        pytest.raises(HTTPException),
    ):
        async with AuditLogger.track_tool_call(
            db=db_session, user=regular_user, service="logs", tool_name="t"
        ):
            raise HTTPException(status_code=502, detail="upstream failed")


@pytest.mark.parametrize(
    "is_service_account, recorded",
    [
        (True, {"team": "BA99", "namespace": "flink-ns", "pipeline": "daily"}),
        # A person could write any team in these headers.
        (False, None),
    ],
)
async def test_only_a_service_accounts_workload_headers_are_recorded(
    db_session, regular_user, service_account, is_service_account, recorded
):
    request = make_starlette_request(
        {
            "authorization": "Bearer eyJ.fake",
            "team": "BA99",
            "namespace": "flink-ns",
            "pipeline": "daily",
        },
        method="POST",
    )
    request.state.is_service_account = is_service_account

    async with AuditLogger.track_tool_call(
        db=db_session,
        user=service_account if is_service_account else regular_user,
        service="logs",
        tool_name="tools/list",
        request=request,
    ) as tracker:
        tracker.set_response({})

    assert db_session.query(AuditLog).one().request_headers == recorded


@pytest.mark.parametrize(
    "response, failure",
    [
        ({"result": {"content": []}}, None),
        ({"error": {"message": "Unknown tool"}}, "Unknown tool"),
        ({"error": "a string error"}, "Unknown error"),
        ({"error": {"message": 42}}, "42"),
        (
            {"result": {"isError": True, "content": [{"type": "text", "text": None}]}},
            "The tool reported an error",
        ),
        (
            {"result": {"isError": True, "content": [{"type": "text", "text": 7}]}},
            "7",
        ),
        (
            {"result": {"isError": True, "content": "not a list"}},
            "The tool reported an error",
        ),
        ({"result": {"isError": True}}, "The tool reported an error"),
        (
            {
                "result": {
                    "isError": True,
                    "content": [{"type": "text", "text": "x" * 2000}],
                }
            },
            "x" * 500,
        ),
    ],
)
def test_tool_call_failure_tolerates_odd_responses(response, failure):
    """Every proxied response is read; a malformed one must not raise."""
    assert tool_call_failure(response) == failure


async def test_secret_arguments_never_reach_the_audit_row(db_session, regular_user):
    row = await _log(
        db_session,
        regular_user,
        request_params={
            "name": "login",
            "arguments": {
                "user": "alice",
                "Password": "hunter2",
                "nested": [{"api_key": "k"}],
            },
        },
    )

    assert row.request_params["arguments"] == {
        "user": "alice",
        "Password": "[redacted]",
        "nested": [{"api_key": "[redacted]"}],
    }


async def test_an_oversized_payload_keeps_a_preview(
    db_session, regular_user, monkeypatch
):
    """MySQL refuses a row larger than max_allowed_packet, losing the call's record."""
    monkeypatch.setattr(settings, "AUDIT_LOG_RESPONSES", True)

    row = await _log(
        db_session,
        regular_user,
        request_params={"arguments": {"sql": "x" * (PAYLOAD_LENGTH + 1)}},
        response_data={"result": "small"},
    )

    assert row.request_params["_truncated"] is True
    assert row.request_params["_original_size"] > PAYLOAD_LENGTH
    assert len(row.request_params["_sha256"]) == 64
    assert len(row.request_params["_preview"]) < PAYLOAD_LENGTH
    assert row.response_data == {"result": "small"}


async def test_responses_are_not_kept_unless_a_deployment_asks(
    db_session, regular_user
):
    """Admins can read the audit log, but not what a server showed someone else."""
    row = await _log(
        db_session,
        regular_user,
        response_data={"result": {"content": [{"type": "text", "text": "salaries"}]}},
    )

    assert row.response_data is None
