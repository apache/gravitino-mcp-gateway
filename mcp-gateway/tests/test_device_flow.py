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

"""The CLI's side of the device flow (RFC 8628), which the Slack bot shares."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from mcp_gateway_cli.device_flow import (
    DEVICE_GRANT_TYPE,
    PollStatus,
    poll_device_token_once,
    poll_device_token_until_done,
    request_device_code,
)


@patch("mcp_gateway_cli.device_flow.requests.post")
def test_a_device_code_is_requested_for_the_cli(post):
    post.return_value.json.return_value = {
        "device_code": "dev-secret",
        "user_code": "ABCD-1234",
        "verification_uri": "http://gw/device",
        "expires_in": 600,
        "interval": 5,
    }

    data = request_device_code("http://gw")

    assert (data.device_code, data.user_code) == ("dev-secret", "ABCD-1234")
    post.assert_called_once_with(
        "http://gw/api/device/code", json={"client_id": "gravitino-mcp-cli"}, timeout=10
    )


@patch("mcp_gateway_cli.device_flow.requests.post")
def test_a_refused_device_code_request_raises(post):
    post.return_value.raise_for_status.side_effect = requests.HTTPError("boom")

    with pytest.raises(requests.HTTPError):
        request_device_code("http://gw")


@pytest.mark.parametrize(
    "status_code, body, status, error",
    [
        (400, {"error": "authorization_pending"}, PollStatus.PENDING, None),
        (200, {"access_token": "at"}, PollStatus.SUCCESS, None),
        (400, {"error": "access_denied"}, PollStatus.ERROR, "access_denied"),
    ],
)
@patch("mcp_gateway_cli.device_flow.requests.post")
def test_one_poll_reports_the_gateways_answer(post, status_code, body, status, error):
    post.return_value = MagicMock(status_code=status_code)
    post.return_value.json.return_value = body

    result = poll_device_token_once("http://gw", "dev-secret")

    assert (result.status, result.error) == (status, error)
    assert result.token_data == (body if status is PollStatus.SUCCESS else None)
    post.assert_called_once_with(
        "http://gw/api/device/token",
        json={"device_code": "dev-secret", "grant_type": DEVICE_GRANT_TYPE},
        timeout=10,
    )


@patch("mcp_gateway_cli.device_flow.poll_device_token_once")
def test_polling_waits_the_interval_between_pending_answers(poll_once):
    poll_once.side_effect = [
        MagicMock(status=PollStatus.PENDING),
        MagicMock(status=PollStatus.SUCCESS),
    ]
    sleeps = []

    result = poll_device_token_until_done(
        "http://gw", "dev-secret", expires_in=60, interval=1, sleep=sleeps.append
    )

    assert result.status == PollStatus.SUCCESS
    assert sleeps == [1]


@patch("mcp_gateway_cli.device_flow.poll_device_token_once")
def test_polling_stops_when_the_code_expires(poll_once):
    poll_once.return_value = MagicMock(status=PollStatus.PENDING)

    result = poll_device_token_until_done(
        "http://gw", "dev-secret", expires_in=0, interval=1, sleep=lambda _: None
    )

    assert result.status == PollStatus.EXPIRED
