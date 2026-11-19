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

"""The MCP servers a caller can see, and whether they are connected to each.

Admins manage servers through /api/v1/admin/mcp (mcp_admin.py); this list says
nothing about how the gateway reaches or signs in to a server.
"""

from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy import false, true
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import MCPCatalog, OAuthToken, ServiceAccountCredentials, User
from ..oauth.token_manager import token_expired
from ..oauth_auth import get_user_from_bearer_token

router = APIRouter(prefix="/api/v1/catalog", tags=["mcp-catalog"])


class MCPCatalogResponse(BaseModel):
    """A server in the catalog, and the caller's connection to it."""

    id: int
    service_id: str
    name: str
    description: Optional[str]
    icon: Optional[str]
    category: Optional[str]
    auth_type: str
    auto_sso_enabled: bool
    requires_approval: bool
    admin_only: bool
    connected: bool = False
    token_expires_at: Optional[datetime] = None
    token_expired: bool = False

    model_config = ConfigDict(from_attributes=True)


def _connections(db: Session, user: User) -> Dict[str, dict]:
    """The caller's connection to each server they hold a token or credentials for."""
    # A token that can be refreshed is still a connection; the gateway
    # refreshes it on the next call.
    connections = {
        token.service: {
            "connected": True,
            "token_expires_at": token.expires_at,
            "token_expired": token_expired(token.expires_at)
            and not token.refresh_token_encrypted,
        }
        for token in db.query(OAuthToken).filter(OAuthToken.user_id == user.id)
    }
    if user.is_service_account:
        credentials = db.query(ServiceAccountCredentials).filter(
            ServiceAccountCredentials.service_account_id == user.id
        )
        for credential in credentials:
            for service in credential.allowed_services or []:
                connections.setdefault(service, {"connected": True})
    return connections


@router.get("/mcps", response_model=List[MCPCatalogResponse])
async def list_available_mcps(
    category: Optional[str] = None,
    current_user: User = Depends(get_user_from_bearer_token),
    db: Session = Depends(get_db),
):
    """The active servers the caller can see, with whether they are connected."""
    connections = _connections(db, current_user)
    query = db.query(MCPCatalog).filter(MCPCatalog.is_active == true())
    if current_user.is_service_account:
        # A service account reaches only the servers its registration lists.
        query = query.filter(MCPCatalog.service_id.in_(list(connections)))
    elif not current_user.is_admin:
        # The same rule as MCPCatalog.is_hidden_from, in SQL.
        query = query.filter(MCPCatalog.admin_only == false())
    if category:
        query = query.filter(MCPCatalog.category == category)

    return [
        MCPCatalogResponse.model_validate(mcp).model_copy(
            update=connections.get(mcp.service_id, {})
        )
        for mcp in query.order_by(MCPCatalog.name)
    ]
