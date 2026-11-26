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

"""MCP servers declared in a file, such as a mounted Kubernetes ConfigMap.

The file is JSON, ``{"servers": [{...}, ...]}``, and each entry has the fields of
``POST /api/v1/admin/mcp/`` except the two secrets. Every start, each replica
makes the listed servers match the file: it adds the missing ones and sets every
declared field on the others, so the file wins over the admin API and over
GRAVITINO_MCP_URL. Servers the file doesn't list are left alone, and so are the
secrets stored for the listed ones; set those through the admin API.
"""

import json
import logging

from pydantic import ConfigDict, model_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import MCPCatalog, OAuthToken
from .routes.mcp_admin import _TOKEN_FIELDS, CreateMCPRequest
from .routes.mcp_upstream import forget_sessions

logger = logging.getLogger(__name__)

_SECRETS = ("basic_auth_password", "oauth_client_secret")


class CatalogFileError(ValueError):
    """The catalog file can't be read or holds a bad entry."""


class _DeclaredServer(CreateMCPRequest):
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def _no_secrets(cls, data):
        held = [name for name in _SECRETS if isinstance(data, dict) and name in data]
        if held:
            raise ValueError(f"{', '.join(held)} can't be set in the file")
        return data


def _read(path: str) -> list[_DeclaredServer]:
    try:
        with open(path, encoding="utf-8") as handle:
            entries = json.load(handle)["servers"]
        servers = [_DeclaredServer.model_validate(entry) for entry in entries]
    except (OSError, ValueError, KeyError, TypeError) as error:
        # ValidationError is a ValueError, and its text names the entry.
        raise CatalogFileError(f"MCP_CATALOG_FILE {path}: {error}") from error
    ids = [server.service_id for server in servers]
    if len(set(ids)) != len(ids):
        raise CatalogFileError(f"MCP_CATALOG_FILE {path}: a service_id is listed twice")
    return servers


def _apply(db: Session, server: _DeclaredServer) -> None:
    fields = server.model_dump(exclude=set(_SECRETS))
    mcp = MCPCatalog.find(db, server.service_id, active=False)
    if mcp is None:
        db.add(MCPCatalog(**fields))
        return
    changed = {name for name, value in fields.items() if getattr(mcp, name) != value}
    if _TOKEN_FIELDS & changed:
        db.query(OAuthToken).filter(OAuthToken.service == mcp.service_id).delete()
        forget_sessions(mcp.service_id)
    if "mcp_url" in changed or "oauth_metadata_url" in changed:
        # A secret stored for one address must not follow the server to another.
        mcp.basic_auth_password_encrypted = None
        mcp.oauth_client_secret_encrypted = None
        mcp.oauth_client_id = None
    for name in changed:
        setattr(mcp, name, fields[name])


def load_catalog_file(db: Session, path: str) -> None:
    """Make the servers in the file at ``path`` match it; see the module docstring.

    Raises CatalogFileError, changing nothing, when the file is bad.
    """
    servers = _read(path)
    for _ in range(2):
        for server in servers:
            _apply(db, server)
        try:
            db.commit()
            break
        except IntegrityError:
            # Another replica added the same server first; apply again as updates.
            db.rollback()
    else:
        raise CatalogFileError(f"MCP_CATALOG_FILE {path}: could not be applied")
    logger.info("Loaded %d MCP servers from %s", len(servers), path)
