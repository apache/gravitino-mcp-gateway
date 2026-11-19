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

"""Tool filters and reading MCP servers' replies (mcp_gateway.routes.mcp_upstream)."""

import httpx
import pytest

from mcp_gateway.config import settings
from mcp_gateway.routes.mcp_upstream import (
    filter_tools,
    read_jsonrpc_message,
    tool_allowed,
)

# Gravitino's MCP server's tools; the gateway's default filter must keep only the reads.
GRAVITINO_READ_TOOLS = """
    get_list_of_catalogs get_list_of_schemas get_list_of_tables
    get_table_metadata_details get_list_of_policies get_policy_detail_information
    get_policy_for_metadata get_job_by_id get_job_template_by_name get_tag_by_name
    list_files_in_fileset list_metadata_by_policy list_metadata_by_tag
    list_model_versions list_of_filesets list_of_job_templates list_of_jobs
    list_of_models list_of_tags list_of_topics list_policies_for_metadata
    list_statistics_for_metadata list_statistics_for_partition list_tags_for_metadata
    load_fileset load_model load_model_version load_model_version_by_alias load_topic
    metadata_type_to_fullname_formats
""".split()
GRAVITINO_WRITE_TOOLS = """
    create_catalog alter_catalog drop_catalog set_catalog_in_use create_schema
    alter_schema drop_schema create_table alter_table drop_table create_topic
    alter_topic delete_topic create_fileset alter_fileset drop_fileset delete_model
    create_tag alter_tag delete_tag associate_policy_with_metadata
    disassociate_policy_from_metadata associate_tag_with_metadata
    disassociate_tag_from_metadata run_job cancel_job
""".split()


@pytest.fixture(autouse=True, name="_atlassian_filter")
def fixture_atlassian_filter(monkeypatch):
    monkeypatch.setitem(
        settings.MCP_TOOL_FILTERS,
        "atlassian",
        ["getJira", "getConfluence", "searchJiraIssues"],
    )


@pytest.mark.parametrize(
    "tool, is_allowed",
    [
        ("getJiraIssue", True),
        ("getConfluencePage", True),
        ("searchJiraIssuesUsingJql", True),
        # New tools that start with an allowed prefix need no change to the filter.
        ("getJiraIssueChangelog", True),
        ("getCompassComponent", False),
        ("searchCompassComponents", False),
        ("search", False),
        ("fetch", False),
    ],
)
def test_a_filtered_server_allows_only_tools_with_its_prefixes(tool, is_allowed):
    assert tool_allowed("atlassian", tool) is is_allowed
    assert filter_tools("atlassian", [{"name": tool}]) == (
        [{"name": tool}] if is_allowed else []
    )


def test_a_server_without_a_filter_allows_every_tool():
    tools = [{"name": "anything"}, {"name": "other"}]

    assert filter_tools("trino", tools) == tools


@pytest.mark.parametrize("service", ["atlassian", "unfiltered"])
def test_tools_without_a_name_are_dropped(service):
    """The list comes from the MCP server; a malformed entry must not raise."""
    tools = [{"name": "getJiraIssue"}, "junk", {"name": 7}, {"description": "x"}]

    assert filter_tools(service, tools) == [{"name": "getJiraIssue"}]


def test_gravitino_exposes_only_its_read_tools():
    tools = [{"name": name} for name in GRAVITINO_READ_TOOLS + GRAVITINO_WRITE_TOOLS]

    assert [t["name"] for t in filter_tools("gravitino", tools)] == GRAVITINO_READ_TOOLS


def _reply(body, content_type="application/json"):
    return httpx.Response(
        200, headers={"Content-Type": content_type}, content=body.encode()
    )


@pytest.mark.parametrize(
    "reply, message",
    [
        (
            _reply('{"jsonrpc": "2.0", "id": 1, "result": {}}'),
            {"jsonrpc": "2.0", "id": 1, "result": {}},
        ),
        (
            _reply(
                'data: {"jsonrpc": "2.0", "method": "notifications/progress"}\n\n'
                'data: not json\n\ndata: {"id": 1, "result": {"ok": true}}\n\n',
                "text/event-stream",
            ),
            {"id": 1, "result": {"ok": True}},
        ),
        (
            _reply(""),
            {"error": {"code": -32603, "message": "Empty response from backend"}},
        ),
    ],
)
def test_the_jsonrpc_message_is_read_from_json_or_a_stream(reply, message):
    assert read_jsonrpc_message(reply) == message


@pytest.mark.parametrize(
    "reply",
    [
        _reply("[1, 2]"),
        _reply("not json"),
        _reply("data: [1]\n\n", "text/event-stream"),
        _reply(": keep-alive\n\n", "text/event-stream"),
    ],
)
def test_a_reply_without_a_jsonrpc_message_is_refused(reply):
    with pytest.raises(ValueError):
        read_jsonrpc_message(reply)
