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

"""Virtual servers: a named group of catalog servers behind one /mcp/<ID>.

This module holds what the proxy (mcp_server.py) does not need to know about
requests: the admin API, routing a tool name to a member, and merging the
members' tool lists. A virtual server grants nothing: access, upstream
sign-in, tool filters and audit are each member's, checked by the proxy.
"""

import logging
from datetime import datetime
from typing import List, Optional, Tuple

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session

from ..audit import record_admin_change, tool_call_failure
from ..database import get_db
from ..models import MCPCatalog, MCPVirtualMember, MCPVirtualServer, User
from ..oauth_auth import require_admin
from .mcp_admin import SERVICE_ID_PATTERN
from .mcp_upstream import filter_tools, read_jsonrpc_message

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/admin/mcp-virtual", tags=["admin-mcp-virtual"])

# What an MCP tool name may hold, so a prefix keeps the names valid.
PREFIX_PATTERN = r"^[A-Za-z0-9_.-]{0,50}$"


class MemberRequest(BaseModel):
    """A catalog server in a virtual server."""

    service_id: str = Field(..., pattern=SERVICE_ID_PATTERN)
    tool_prefix: str = Field(
        "",
        pattern=PREFIX_PATTERN,
        description="Put before the server's tool names, such as 'trino_'",
    )


def _unique_members(members: Optional[List[MemberRequest]]):
    """Reject members that would make a tool name's server ambiguous."""
    if members is None:
        return members
    if not members:
        raise ValueError("a virtual server needs at least one member")
    for field in ("service_id", "tool_prefix"):
        values = [getattr(m, field) for m in members]
        if len(set(values)) != len(values):
            raise ValueError(f"each member needs its own {field}")
    return members


class CreateVirtualRequest(BaseModel):
    """A virtual server to add."""

    service_id: str = Field(
        ...,
        pattern=SERVICE_ID_PATTERN,
        description="Its URL is /mcp/<service_id>; no server may have the same ID",
    )
    name: str = Field(..., min_length=3, max_length=255)
    description: Optional[str] = None
    is_active: bool = True
    members: List[MemberRequest]

    @model_validator(mode="after")
    def _check_members(self):
        _unique_members(self.members)
        return self


class UpdateVirtualRequest(BaseModel):
    """Changes to a virtual server; members, when given, replace the old ones."""

    name: Optional[str] = Field(None, min_length=3, max_length=255)
    description: Optional[str] = None
    is_active: Optional[bool] = None
    members: Optional[List[MemberRequest]] = None

    @model_validator(mode="after")
    def _check_members(self):
        _unique_members(self.members)
        return self


def _view(virtual: MCPVirtualServer) -> dict:
    return {
        "id": virtual.id,
        "service_id": virtual.service_id,
        "name": virtual.name,
        "description": virtual.description,
        "is_active": virtual.is_active,
        "members": [
            {"service_id": m.mcp.service_id, "tool_prefix": m.tool_prefix}
            for m in virtual.members
        ],
    }


def _member_rows(db: Session, members: List[MemberRequest]):
    rows = []
    for member in members:
        mcp = MCPCatalog.find(db, member.service_id, active=False)
        if mcp is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"MCP '{member.service_id}' not found",
            )
        rows.append(MCPVirtualMember(mcp_id=mcp.id, tool_prefix=member.tool_prefix))
    return rows


def _virtual(db: Session, service_id: str) -> MCPVirtualServer:
    virtual = find_virtual(db, service_id, active=False)
    if virtual is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, f"Virtual server '{service_id}' not found"
        )
    return virtual


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_virtual(
    request: CreateVirtualRequest,
    http_request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Add a virtual server."""
    if MCPCatalog.find(db, request.service_id, active=False) or find_virtual(
        db, request.service_id, active=False
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"'{request.service_id}' is already the ID of a server",
        )
    virtual = MCPVirtualServer(
        **request.model_dump(exclude={"members"}),
        created_by=admin.id,
        created_at=datetime.utcnow(),
    )
    virtual.members = _member_rows(db, request.members)
    db.add(virtual)
    record_admin_change(
        db,
        admin,
        http_request,
        service=request.service_id,
        action="create_virtual_server",
        changes=request.model_dump(exclude_none=True),
    )
    db.commit()
    db.refresh(virtual)
    return _view(virtual)


@router.get("/")
async def list_virtual(
    admin: User = Depends(require_admin),  # pylint: disable=unused-argument
    db: Session = Depends(get_db),
):
    """Every virtual server, active or not."""
    return [
        _view(v) for v in db.query(MCPVirtualServer).order_by(MCPVirtualServer.name)
    ]


@router.patch("/{service_id}")
async def update_virtual(
    service_id: str,
    request: UpdateVirtualRequest,
    http_request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Change a virtual server."""
    virtual = _virtual(db, service_id)
    changes = request.model_dump(exclude_unset=True)
    for field in ("name", "description", "is_active"):
        if field in changes:
            setattr(virtual, field, changes[field])
    if request.members is not None:
        rows = _member_rows(db, request.members)
        # The old rows go first: a member may stay, under another prefix.
        virtual.members = []
        db.flush()
        virtual.members = rows
    record_admin_change(
        db,
        admin,
        http_request,
        service=virtual.service_id,
        action="update_virtual_server",
        changes=changes,
    )
    db.commit()
    db.refresh(virtual)
    return _view(virtual)


@router.delete("/{service_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_virtual(
    service_id: str,
    http_request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Delete a virtual server; its members stay in the catalog."""
    virtual = _virtual(db, service_id)
    db.delete(virtual)
    record_admin_change(
        db,
        admin,
        http_request,
        service=service_id,
        action="delete_virtual_server",
    )
    db.commit()


# ---------------------------------------------------------------------------
# What the proxy needs
# ---------------------------------------------------------------------------


def find_virtual(
    db: Session, service_id: str, *, active: bool = True
) -> Optional[MCPVirtualServer]:
    """The virtual server whose ID is exactly ``service_id``, or None."""
    query = db.query(MCPVirtualServer).filter(MCPVirtualServer.service_id == service_id)
    if active:
        query = query.filter(MCPVirtualServer.is_active.is_(True))
    virtual = query.first()
    return virtual if virtual is not None and virtual.service_id == service_id else None


def visible_members(virtual: MCPVirtualServer, user: User) -> List[MCPVirtualMember]:
    """The members that are active and not hidden from ``user``."""
    return [
        m for m in virtual.members if m.mcp.is_active and not m.mcp.is_hidden_from(user)
    ]


def route_tool(
    members: List[MCPVirtualMember], name: str
) -> Optional[Tuple[MCPVirtualMember, str]]:
    """The member a tool name belongs to, and the name it has there.

    The longest matching prefix wins, so a member's prefix may begin with
    another's.
    """
    matches = [
        m for m in members if name.startswith(m.tool_prefix) and name != m.tool_prefix
    ]
    if not matches:
        return None
    member = max(matches, key=lambda m: len(m.tool_prefix))
    return member, name[len(member.tool_prefix) :]


def merge_tools(listings: List[Tuple[MCPVirtualMember, list]]) -> list:
    """The members' tools, named as callers see them; ValueError on a clash.

    A clash is a name two members offer, or a name that would route to another
    member than the one that offers it.
    """
    merged, owner = [], {}
    members = [member for member, _ in listings]
    for member, tools in listings:
        for tool in tools:
            name = member.tool_prefix + tool["name"]
            routed = route_tool(members, name)
            if name in owner or routed is None or routed[0] is not member:
                raise ValueError(
                    f"Tool name '{name}' of {member.mcp.service_id} clashes with "
                    f"{owner.get(name, 'another member')}; give the members "
                    "different tool prefixes."
                )
            owner[name] = member.mcp.service_id
            merged.append({**tool, "name": name})
    return merged


async def member_tools(
    post, mcp_url: str, service: str, request_id, headers: dict
) -> Tuple[list, Optional[dict], Optional[str]]:
    """One member's tools/list: (tools, reply, error); no tools when it failed.

    ``post`` sends a message to the server, as ``post_to_upstream`` does with
    the caller's identity filled in.
    """
    try:
        response = await post(
            mcp_url,
            {"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": {}},
            headers,
        )
        response.raise_for_status()
        reply = {"jsonrpc": "2.0", "id": request_id, **read_jsonrpc_message(response)}
    except (httpx.HTTPError, ValueError) as error:
        # The text can name the server's host, which is for admins.
        logger.warning("Could not list the tools of %s: %s", service, error)
        return [], None, "The server could not be reached or sent a bad reply"
    failure = tool_call_failure(reply)
    result = reply.get("result")
    tools = result.get("tools") if isinstance(result, dict) else None
    if failure is not None or not isinstance(tools, list):
        return [], reply, failure or "The reply holds no tools"
    return filter_tools(service, tools), reply, None
