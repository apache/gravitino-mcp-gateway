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

"""Declaring the MCP catalog in a file."""

import json

import pytest

from mcp_gateway.catalog_defaults import register_gravitino_mcp
from mcp_gateway.catalog_file import CatalogFileError, load_catalog_file
from mcp_gateway.config import settings
from mcp_gateway.models import MCPCatalog, OAuthToken, User


def _write(tmp_path, servers):
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps({"servers": servers}))
    return str(path)


def _server(**fields):
    return {
        "service_id": "trino",
        "name": "Trino",
        "mcp_url": "http://trino-mcp:8000/mcp",
        **fields,
    }


def _find(db, service_id="trino"):
    return MCPCatalog.find(db, service_id, active=False)


def test_a_declared_server_is_added(db_session, tmp_path):
    load_catalog_file(db_session, _write(tmp_path, [_server(category="sql")]))

    mcp = _find(db_session)
    assert (mcp.name, mcp.mcp_url, mcp.category) == (
        "Trino",
        "http://trino-mcp:8000/mcp",
        "sql",
    )


def test_the_file_wins_over_an_admins_change(db_session, tmp_path):
    path = _write(tmp_path, [_server(requires_approval=False)])
    load_catalog_file(db_session, path)
    mcp = _find(db_session)
    mcp.requires_approval = True
    mcp.name = "Renamed in the web UI"
    db_session.commit()

    load_catalog_file(db_session, path)

    mcp = _find(db_session)
    assert (mcp.name, mcp.requires_approval) == ("Trino", False)


def test_the_file_wins_over_the_gravitino_default(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "GRAVITINO_MCP_URL", "http://default:8000/mcp")
    register_gravitino_mcp(db_session)

    load_catalog_file(
        db_session,
        _write(
            tmp_path,
            [_server(service_id="gravitino", mcp_url="http://declared:8000/mcp")],
        ),
    )

    assert _find(db_session, "gravitino").mcp_url == "http://declared:8000/mcp"


def test_servers_missing_from_the_file_are_left_alone(db_session, tmp_path):
    db_session.add(MCPCatalog(service_id="other", name="Other", mcp_url="http://o/mcp"))
    db_session.commit()

    load_catalog_file(db_session, _write(tmp_path, [_server()]))

    assert _find(db_session, "other") is not None


def test_secrets_the_file_cannot_hold_are_kept(db_session, tmp_path):
    path = _write(tmp_path, [_server(auth_type="basic", basic_auth_username="u")])
    load_catalog_file(db_session, path)
    mcp = _find(db_session)
    mcp.basic_auth_password_encrypted = "sealed"
    db_session.commit()

    load_catalog_file(db_session, path)

    assert _find(db_session).basic_auth_password_encrypted == "sealed"


def test_moving_a_server_deletes_the_tokens_held_for_it(db_session, tmp_path):
    load_catalog_file(db_session, _write(tmp_path, [_server()]))
    user = User(email="a@example.com", username="a")
    db_session.add(user)
    db_session.flush()
    db_session.add(
        OAuthToken(user_id=user.id, service="trino", access_token_encrypted="x")
    )
    db_session.commit()

    load_catalog_file(
        db_session, _write(tmp_path, [_server(mcp_url="http://elsewhere:8000/mcp")])
    )

    assert db_session.query(OAuthToken).count() == 0


def test_an_unchanged_file_keeps_the_tokens(db_session, tmp_path):
    path = _write(tmp_path, [_server()])
    load_catalog_file(db_session, path)
    user = User(email="a@example.com", username="a")
    db_session.add(user)
    db_session.flush()
    db_session.add(
        OAuthToken(user_id=user.id, service="trino", access_token_encrypted="x")
    )
    db_session.commit()

    load_catalog_file(db_session, path)

    assert db_session.query(OAuthToken).count() == 1


@pytest.mark.parametrize(
    "servers",
    [
        [_server(mcp_url="ftp://nope")],
        [_server(service_id="Bad Id")],
        [_server(), _server()],
        [_server(basic_auth_password="inline")],
        [_server(unknown_field=1)],
    ],
)
def test_a_bad_file_is_refused_whole(db_session, tmp_path, servers):
    with pytest.raises(CatalogFileError):
        load_catalog_file(db_session, _write(tmp_path, servers))

    assert db_session.query(MCPCatalog).count() == 0


def test_an_unreadable_file_is_refused(db_session, tmp_path):
    with pytest.raises(CatalogFileError):
        load_catalog_file(db_session, str(tmp_path / "missing.json"))
