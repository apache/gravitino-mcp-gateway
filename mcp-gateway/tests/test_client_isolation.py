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

"""The ordinary API test client must not contact Slack."""

import asyncio
from unittest.mock import AsyncMock

from mcp_gateway import slack_service
from mcp_gateway.config import settings


def test_api_client_disables_slack_connections(monkeypatch, request):
    # Mirror developer environments with all Slack settings present.
    monkeypatch.setattr(settings, "SLACK_BOT_TOKEN", "xoxb-synthetic-test-token")
    monkeypatch.setattr(settings, "SLACK_APP_TOKEN", "xapp-synthetic-test-token")
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://example.test/slack")

    async def fake_start(**kwargs):
        return asyncio.create_task(asyncio.sleep(3600))

    start = AsyncMock(side_effect=fake_start)
    monkeypatch.setattr("mcp_gateway.slack.app.start_slack_bot", start)
    http_client = AsyncMock()
    monkeypatch.setattr(slack_service.httpx, "AsyncClient", http_client)

    # Resolve the fixture only after installing the spy, including its startup.
    client = request.getfixturevalue("client")
    assert client.get("/health").status_code == 200
    assert (
        asyncio.run(slack_service.lookup_slack_user_email("synthetic-user")).email
        is None
    )
    asyncio.run(
        slack_service.notify_new_access_request(
            user_name="Test User",
            user_email="user@example.test",
            mcp_name="Test MCP",
            mcp_icon=None,
            justification="Test",
            request_id=1,
        )
    )
    start.assert_not_awaited()
    http_client.assert_not_called()
