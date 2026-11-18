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

"""MCP servers the gateway registers by itself."""

import logging

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import settings
from .models import MCPCatalog

logger = logging.getLogger(__name__)

GRAVITINO_SERVICE_ID = "gravitino"


def register_gravitino_mcp(db: Session) -> None:
    """Add the Gravitino MCP server to the catalog when GRAVITINO_MCP_URL is set.

    An existing entry is left as it is, so admins can change it in the web UI.
    """
    if not settings.GRAVITINO_MCP_URL:
        return
    exists = (
        db.query(MCPCatalog.id)
        .filter(MCPCatalog.service_id == GRAVITINO_SERVICE_ID)
        .first()
    )
    if exists:
        return

    db.add(
        MCPCatalog(
            service_id=GRAVITINO_SERVICE_ID,
            name="Gravitino",
            description="Apache Gravitino metadata: catalogs, schemas, tables, "
            "filesets, models, topics, tags, policies and jobs",
            icon="🗂️",
            category="data",
            mcp_url=settings.GRAVITINO_MCP_URL,
            # Gravitino checks the token's audience; the gateway's own tokens are
            # forwarded when it is the gateway's audience, otherwise exchanged.
            audience=settings.GRAVITINO_MCP_AUDIENCE or settings.JWT_AUDIENCE,
            auth_type="oauth",
            auto_sso_enabled=True,
            # Gravitino authorizes each call itself, as the calling user.
            requires_approval=False,
            is_active=True,
        )
    )
    try:
        db.commit()
    except IntegrityError:
        # Another gateway instance registered it first.
        db.rollback()
        return
    logger.info("Registered the Gravitino MCP server at %s", settings.GRAVITINO_MCP_URL)
