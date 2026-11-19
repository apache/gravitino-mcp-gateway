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

"""People ask for access to MCP servers, and admins approve or deny it."""

import asyncio
from datetime import datetime, timedelta
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import true
from sqlalchemy.orm import Query as OrmQuery
from sqlalchemy.orm import Session, joinedload

from ..database import get_db
from ..models import MCPAccessRequest, MCPCatalog, MCPUserPermission, User
from ..oauth_auth import get_user_from_bearer_token, require_admin
from ..slack_service import (
    invite_user_to_channel,
    notify_new_access_request,
    notify_request_reviewed,
)

router = APIRouter(prefix="/api/v1/mcp-access", tags=["mcp-access"])

_MAX_PAGE_SIZE = 100

# Strong references to fire-and-forget tasks to prevent GC before completion
_background_tasks: set[asyncio.Task] = set()


def _fire_and_forget(coro) -> None:
    """Schedule a coroutine as a background task, keeping a strong reference until done."""
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


class RequestAccessRequest(BaseModel):
    """A person's request for access to a server."""

    mcp_id: int = Field(..., description="The server's catalog ID")
    justification: Optional[str] = Field(None, description="Why they need access")


class AccessRequestResponse(BaseModel):
    """An access request, with who made and reviewed it."""

    id: int
    user_id: int
    username: str
    mcp_id: int
    mcp_name: str
    mcp_service_id: str
    mcp_icon: Optional[str] = None
    justification: Optional[str]
    status: str
    admin_notes: Optional[str]
    requested_at: datetime
    reviewed_at: Optional[datetime]
    reviewed_by: Optional[int]
    reviewer_username: Optional[str]


class ReviewAccessRequest(BaseModel):
    """An admin's decision on an access request."""

    status: Literal["approved", "denied"]
    admin_notes: Optional[str] = Field(None, description="Why, shown to the person")
    expires_in_days: Optional[int] = Field(
        None, ge=1, le=3650, description="When the access ends; never when unset"
    )


class MCPPermissionResponse(BaseModel):
    """A person's access to a server."""

    id: int
    user_id: int
    mcp_id: int
    mcp_name: str
    mcp_service_id: str
    granted_at: datetime
    expires_at: Optional[datetime]
    granted_by: Optional[int]


_UNKNOWN = "Unknown"


def _request_response(req: MCPAccessRequest) -> AccessRequestResponse:
    # Without foreign keys enforced, as on SQLite, a row can outlive its user
    # or server.
    mcp = req.mcp
    return AccessRequestResponse(
        id=req.id,
        user_id=req.user_id,
        username=req.user.username if req.user else _UNKNOWN,
        mcp_id=req.mcp_id,
        mcp_name=mcp.name if mcp else _UNKNOWN,
        mcp_service_id=mcp.service_id if mcp else "unknown",
        mcp_icon=mcp.icon if mcp else None,
        justification=req.justification,
        status=req.status,
        admin_notes=req.admin_notes,
        requested_at=req.requested_at,
        reviewed_at=req.reviewed_at,
        reviewed_by=req.reviewed_by,
        reviewer_username=req.reviewer.username if req.reviewer else None,
    )


def _requests(db: Session) -> OrmQuery:
    return db.query(MCPAccessRequest).options(
        joinedload(MCPAccessRequest.user),
        joinedload(MCPAccessRequest.mcp),
        joinedload(MCPAccessRequest.reviewer),
    )


def _page(query: OrmQuery, page: int, page_size: int, item) -> dict:
    """One page of ``query``'s rows, each made into an item by ``item``."""
    rows = query.offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [item(row) for row in rows],
        "total": query.order_by(None).count(),
        "page": page,
        "page_size": page_size,
    }


_PAGE = Query(1, ge=1)
_PAGE_SIZE = Query(25, ge=1, le=_MAX_PAGE_SIZE)


def _claim_for_review(
    db: Session,
    access_request: MCPAccessRequest,
    review: ReviewAccessRequest,
    admin: User,
) -> bool:
    """Record the review if the request is still pending, and say whether it was.

    Two admins can review one request at once; only the first may grant or
    deny it, or a denied request could leave access granted.
    """
    claimed = (
        db.query(MCPAccessRequest)
        .filter(
            MCPAccessRequest.id == access_request.id,
            MCPAccessRequest.status == "pending",
        )
        .update(
            {
                MCPAccessRequest.status: review.status,
                MCPAccessRequest.admin_notes: review.admin_notes,
                MCPAccessRequest.reviewed_at: datetime.utcnow(),
                MCPAccessRequest.reviewed_by: admin.id,
            },
            synchronize_session=False,
        )
    )
    db.refresh(access_request)
    return claimed == 1


def _grant_access(
    db: Session,
    access_request: MCPAccessRequest,
    admin: User,
    expires_in_days: Optional[int],
) -> None:
    """Give the requester access, renewing their expired permission if they have one.

    A user has at most one permission per server, so a renewal updates it.
    """
    expires_at = None
    if expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
    permission = (
        db.query(MCPUserPermission)
        .filter(
            MCPUserPermission.user_id == access_request.user_id,
            MCPUserPermission.mcp_id == access_request.mcp_id,
        )
        .first()
    )
    if permission is None:
        db.add(
            MCPUserPermission(
                user_id=access_request.user_id,
                mcp_id=access_request.mcp_id,
                granted_by=admin.id,
                expires_at=expires_at,
            )
        )
        return
    permission.granted_by = admin.id
    permission.granted_at = datetime.utcnow()
    permission.expires_at = expires_at


def _refused(detail: str, code: int = status.HTTP_400_BAD_REQUEST) -> HTTPException:
    return HTTPException(status_code=code, detail=detail)


@router.post("/request", response_model=AccessRequestResponse)
async def request_mcp_access(
    request: RequestAccessRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_user_from_bearer_token),
):
    """Ask for access to a server; admins are told in Slack when it is set up."""
    mcp = (
        db.query(MCPCatalog)
        .filter(MCPCatalog.id == request.mcp_id, MCPCatalog.is_active == true())
        .first()
    )
    if not mcp or mcp.is_hidden_from(current_user):
        raise _refused("MCP not found or inactive", status.HTTP_404_NOT_FOUND)

    permission = (
        db.query(MCPUserPermission)
        .filter(
            MCPUserPermission.user_id == current_user.id,
            MCPUserPermission.mcp_id == mcp.id,
        )
        .first()
    )
    # An expired approval can be asked for again.
    if permission and not permission.has_expired(mcp):
        raise _refused("You already have access to this MCP")
    if mcp.is_open_access:
        raise _refused(
            "This MCP is open access — no request needed. Connect or use it directly."
        )
    pending = (
        db.query(MCPAccessRequest.id)
        .filter(
            MCPAccessRequest.user_id == current_user.id,
            MCPAccessRequest.mcp_id == mcp.id,
            MCPAccessRequest.status == "pending",
        )
        .first()
    )
    if pending:
        raise _refused("You already have a pending request for this MCP")

    access_request = MCPAccessRequest(
        user_id=current_user.id,
        mcp_id=mcp.id,
        justification=request.justification,
        status="pending",
    )
    db.add(access_request)
    db.commit()
    db.refresh(access_request)
    response = _request_response(access_request)

    _fire_and_forget(
        notify_new_access_request(
            user_name=response.username,
            user_email=current_user.email or "",
            mcp_name=response.mcp_name,
            mcp_icon=response.mcp_icon,
            justification=request.justification,
            request_id=response.id,
        )
    )
    return response


@router.get("/my-requests", response_model=List[AccessRequestResponse])
async def list_my_access_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_user_from_bearer_token),
):
    """The caller's access requests, newest first."""
    requests = (
        _requests(db)
        .filter(MCPAccessRequest.user_id == current_user.id)
        .order_by(MCPAccessRequest.requested_at.desc())
    )
    return [_request_response(req) for req in requests]


@router.get("/my-permissions", response_model=List[MCPPermissionResponse])
async def list_my_permissions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_user_from_bearer_token),
):
    """The servers the caller was given access to."""
    permissions = (
        db.query(MCPUserPermission)
        .options(joinedload(MCPUserPermission.mcp))
        .filter(MCPUserPermission.user_id == current_user.id)
    )
    return [
        MCPPermissionResponse(
            id=perm.id,
            user_id=perm.user_id,
            mcp_id=perm.mcp_id,
            mcp_name=perm.mcp.name,
            mcp_service_id=perm.mcp.service_id,
            granted_at=perm.granted_at,
            expires_at=perm.expires_at,
            granted_by=perm.granted_by,
        )
        for perm in permissions
        if perm.mcp is not None
    ]


@router.get("/admin/pending")
def list_pending_requests(
    page: int = _PAGE,
    page_size: int = _PAGE_SIZE,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Requests waiting for review, oldest first."""
    query = (
        _requests(db)
        .filter(MCPAccessRequest.status == "pending")
        .order_by(MCPAccessRequest.requested_at)
    )
    return _page(query, page, page_size, _request_response)


@router.get("/admin/all")
def list_all_requests(
    status_filter: Optional[str] = None,
    mcp_id: Optional[int] = None,
    page: int = _PAGE,
    page_size: int = _PAGE_SIZE,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Every request, newest first, optionally with one status or for one server."""
    query = _requests(db)
    if status_filter:
        query = query.filter(MCPAccessRequest.status == status_filter)
    if mcp_id is not None:
        query = query.filter(MCPAccessRequest.mcp_id == mcp_id)
    query = query.order_by(MCPAccessRequest.requested_at.desc())
    return _page(query, page, page_size, _request_response)


@router.post("/admin/review/{request_id}")
async def review_access_request(
    request_id: int,
    review: ReviewAccessRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Approve or deny a pending request; approving gives the person access."""
    access_request = _requests(db).filter(MCPAccessRequest.id == request_id).first()
    if not access_request:
        raise _refused("Access request not found", status.HTTP_404_NOT_FOUND)
    if access_request.status != "pending":
        raise _refused(f"Request already {access_request.status}")
    if not _claim_for_review(db, access_request, review, admin):
        raise _refused(
            "Another admin reviewed this request first", status.HTTP_409_CONFLICT
        )
    if review.status == "approved":
        _grant_access(db, access_request, admin, review.expires_in_days)
    db.commit()

    reviewed = _request_response(access_request)
    requester = access_request.user
    _fire_and_forget(
        notify_request_reviewed(
            user_name=reviewed.username,
            mcp_name=reviewed.mcp_name,
            mcp_icon=reviewed.mcp_icon,
            status=review.status,
            admin_notes=review.admin_notes,
            reviewer_name=admin.username,
        )
    )
    if review.status == "approved" and requester and requester.email:
        _fire_and_forget(invite_user_to_channel(requester.email))

    return {
        "message": f"Access request {review.status}",
        "request_id": request_id,
        "status": review.status,
    }


def _permission_item(perm: MCPUserPermission) -> dict:
    user, mcp = perm.user, perm.mcp
    return {
        "id": perm.id,
        "user_id": perm.user_id,
        "username": user.username if user else _UNKNOWN,
        "email": user.email if user else None,
        "mcp_id": perm.mcp_id,
        "mcp_name": mcp.name if mcp else _UNKNOWN,
        "mcp_service_id": mcp.service_id if mcp else "unknown",
        "mcp_icon": mcp.icon if mcp else None,
        "granted_at": perm.granted_at.isoformat() if perm.granted_at else None,
        "expires_at": perm.expires_at.isoformat() if perm.expires_at else None,
        "granted_by": perm.granter.username if perm.granter else None,
    }


@router.get("/admin/permissions")
def list_all_permissions(
    mcp_id: Optional[int] = None,
    page: int = _PAGE,
    page_size: int = _PAGE_SIZE,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Everyone's access, newest first, optionally to one server."""
    query = db.query(MCPUserPermission).options(
        joinedload(MCPUserPermission.user),
        joinedload(MCPUserPermission.mcp),
        joinedload(MCPUserPermission.granter),
    )
    if mcp_id is not None:
        query = query.filter(MCPUserPermission.mcp_id == mcp_id)
    query = query.order_by(MCPUserPermission.granted_at.desc())
    return _page(query, page, page_size, _permission_item)


@router.delete("/admin/permissions/{permission_id}")
def revoke_permission(
    permission_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Take away a person's access to a server."""
    deleted = (
        db.query(MCPUserPermission)
        .filter(MCPUserPermission.id == permission_id)
        .delete()
    )
    if not deleted:
        raise _refused("Permission not found", status.HTTP_404_NOT_FOUND)
    db.commit()
    return {"message": "Permission revoked successfully"}
