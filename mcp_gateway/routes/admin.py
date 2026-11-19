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

"""
Admin API Routes - Service Account Management
Requires admin privileges (is_admin=True)
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, true
from sqlalchemy.orm import Session

from ..audit import record_admin_change
from ..database import get_db
from ..models import (
    MCPAccessRequest,
    MCPUserPermission,
    ServiceAccountCredentials,
    User,
)
from ..oauth.mcp_service_auth import refused_secret_refs
from ..oauth_auth import require_admin

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])
logger = logging.getLogger(__name__)


# ========== Pydantic Models ==========


# Secrets in a registration's additional_config that responses don't show.
_HIDDEN_FIELDS = ("slack_signing_secret",)
HIDDEN = "<hidden>"


def _hide_secrets(config: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not config:
        return config
    return {
        key: HIDDEN if key in _HIDDEN_FIELDS and value else value
        for key, value in config.items()
    }


def _keep_hidden_secrets(
    config: Dict[str, Any], stored: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """``config``, with the stored secrets that a response showed as hidden."""
    return {
        key: (stored or {}).get(key) if value == HIDDEN else value
        for key, value in config.items()
    }


def _forwardable(config: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """``config``, if every secret it forwards is one a service account may forward."""
    refused = refused_secret_refs(config)
    if refused:
        raise ValueError(
            "Secrets that service accounts forward must be named with "
            f"SERVICE_ACCOUNT_SECRET_PREFIX; refused: {', '.join(refused)}"
        )
    return config


class OAuthCredentials(BaseModel):
    """OIDC identity for service account registration (e.g. GCP SA email)"""

    model_config = ConfigDict(str_strip_whitespace=True)

    service_account_name: str = Field(
        ...,
        min_length=1,
        description="Service account identity (e.g. name@project.iam.gserviceaccount.com)",
    )


class CreateServiceAccountRequest(BaseModel):
    """Request to create a new service account"""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(
        ...,
        min_length=3,
        max_length=100,
        description="Service account username (e.g., 'svc-data-platform')",
    )
    team: Optional[str] = Field(
        None, description="Team or department owning this account"
    )
    provider: Literal["google", "aws", "other"] = Field(
        default="other", description="Where the workload runs, shown to admins"
    )
    oauth_credentials: OAuthCredentials
    additional_config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Provider-specific JSON (e.g. downstream_credentials for MCP proxy)",
    )
    allowed_services: List[str] = Field(
        default=[],
        description="List of MCP service IDs this account can access (e.g., ['metastore', 'trino'])",
    )

    @field_validator("additional_config")
    @classmethod
    def _check_secrets(cls, config: Optional[Dict[str, Any]]):
        """Refuse secrets that service accounts may not forward."""
        return _forwardable(config)


class ServiceAccountResponse(BaseModel):
    """Service account details"""

    id: int
    username: str
    team: Optional[str]
    is_service_account: bool
    provider: str
    service_account_name: str
    allowed_services: List[str]
    additional_config: Optional[Dict[str, Any]] = None
    created_at: datetime


class UpdateServiceAccountRequest(BaseModel):
    """Partial update for service account credentials (allowed MCPs + optional JSON config)."""

    allowed_services: Optional[List[str]] = None
    additional_config: Optional[Dict[str, Any]] = None
    clear_additional_config: bool = Field(
        default=False,
        description="When true, clears stored additional_config (mutually exclusive with additional_config)",
    )

    @field_validator("additional_config")
    @classmethod
    def _check_secrets(cls, config: Optional[Dict[str, Any]]):
        """Refuse secrets that service accounts may not forward."""
        return _forwardable(config)


def _service_account_response(
    sa: User, sa_creds: Optional[ServiceAccountCredentials]
) -> ServiceAccountResponse:
    """Build ServiceAccountResponse from User + optional credentials row."""
    return ServiceAccountResponse(
        id=sa.id,
        username=sa.username,
        team=sa.team,
        is_service_account=True,
        provider=sa_creds.provider if sa_creds else "unknown",
        service_account_name=sa_creds.service_account_name if sa_creds else "N/A",
        allowed_services=list(sa_creds.allowed_services or []) if sa_creds else [],
        additional_config=_hide_secrets(
            sa_creds.additional_config if sa_creds else None
        ),
        created_at=sa.created_at,
    )


def _apply_service_account_update(
    db: Session,
    service_account_id: int,
    update: UpdateServiceAccountRequest,
) -> ServiceAccountResponse:
    """Apply partial updates to SA credentials; 404 if the SA or its credentials row is missing."""
    if update.clear_additional_config and update.additional_config is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot send additional_config together with clear_additional_config=true",
        )

    sa = _active_service_account(db, service_account_id)

    if not sa:
        raise HTTPException(status_code=404, detail="Service account not found")

    sa_creds = (
        db.query(ServiceAccountCredentials)
        .filter(ServiceAccountCredentials.service_account_id == service_account_id)
        .first()
    )

    if not sa_creds:
        raise HTTPException(
            status_code=404, detail="Service account credentials not found"
        )
    if update.allowed_services is not None:
        sa_creds.allowed_services = update.allowed_services
    if update.clear_additional_config:
        sa_creds.additional_config = None
    elif update.additional_config is not None:
        sa_creds.additional_config = _keep_hidden_secrets(
            update.additional_config, sa_creds.additional_config
        )

    db.commit()
    db.refresh(sa)
    db.refresh(sa_creds)

    return _service_account_response(sa, sa_creds)


def _check_service_account_name_not_taken(
    db: Session, service_account_name: str
) -> None:
    """Refuse an identity another service account has, naming that account.

    The database refuses it too, but with an IntegrityError that says less.
    """
    existing_creds = (
        db.query(ServiceAccountCredentials).filter(
            func.lower(ServiceAccountCredentials.service_account_name)
            == service_account_name.lower()
        )
    ).first()
    if existing_creds:
        owner = (
            db.query(User).filter(User.id == existing_creds.service_account_id).first()
        )
        owner_desc = (
            f"'{owner.username}'"
            if owner
            else f"id={existing_creds.service_account_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Service account '{service_account_name}' is already registered "
                f"to service account {owner_desc}"
            ),
        )


# ========== API Endpoints ==========


@router.post("/service-accounts", response_model=ServiceAccountResponse)
async def create_service_account(
    request: CreateServiceAccountRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Register a workload's identity as a service account, with the servers it may call."""
    existing = db.query(User).filter(User.username == request.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{request.name}' already exists",
        )

    _check_service_account_name_not_taken(
        db, request.oauth_credentials.service_account_name
    )

    # Create user
    user = User(
        username=request.name,
        email=request.oauth_credentials.service_account_name,
        is_service_account=True,
        is_admin=False,
        team=request.team,
    )
    db.add(user)
    db.flush()  # Get user.id

    sa_creds = ServiceAccountCredentials(
        service_account_id=user.id,
        provider=request.provider,
        service_account_name=request.oauth_credentials.service_account_name,
        additional_config=request.additional_config,
        allowed_services=request.allowed_services,
        created_by=admin.id,
    )
    db.add(sa_creds)
    record_admin_change(
        db,
        admin,
        http_request,
        service="service-accounts",
        action="create_service_account",
        changes=request.model_dump(),
    )
    db.commit()
    db.refresh(user)

    return _service_account_response(user, sa_creds)


@router.get("/service-accounts", response_model=List[ServiceAccountResponse])
async def list_service_accounts(
    db: Session = Depends(get_db), admin: User = Depends(require_admin)
):
    """Every service account, with its identity and servers."""
    rows = (
        db.query(User, ServiceAccountCredentials)
        .outerjoin(
            ServiceAccountCredentials,
            ServiceAccountCredentials.service_account_id == User.id,
        )
        .filter(User.is_service_account == true(), User.is_active == true())
    )
    return [_service_account_response(sa, sa_creds) for sa, sa_creds in rows]


@router.patch(
    "/service-accounts/{service_account_id}", response_model=ServiceAccountResponse
)
async def update_service_account_permissions(
    service_account_id: int,
    update: UpdateServiceAccountRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Change the servers a service account may call, or its other configuration."""
    record_admin_change(
        db,
        admin,
        http_request,
        service="service-accounts",
        action="update_service_account",
        changes={"id": service_account_id, **update.model_dump(exclude_unset=True)},
    )
    return _apply_service_account_update(db, service_account_id, update)


def _active_service_account(db: Session, service_account_id: int) -> Optional[User]:
    """The service account with this id, or None if there is none or it was deleted."""
    return (
        db.query(User)
        .filter(
            User.id == service_account_id,
            User.is_service_account == true(),
            User.is_active == true(),
        )
        .first()
    )


def _retire_service_account(db: Session, sa: User) -> str:
    """Delete a service account but keep its user row, and return its name.

    Audit log rows refer to the user row, so it stays, deactivated. Its name and
    identity are freed so the same workload can be registered again, and its
    credentials, access requests and grants go.
    """
    name = sa.username
    db.query(ServiceAccountCredentials).filter(
        ServiceAccountCredentials.service_account_id == sa.id
    ).delete()
    db.query(MCPAccessRequest).filter(MCPAccessRequest.user_id == sa.id).delete()
    db.query(MCPUserPermission).filter(MCPUserPermission.user_id == sa.id).delete()
    sa.is_active = False
    sa.username = f"deleted-{sa.id}-{name}"
    sa.email = f"deleted-{sa.id}-{sa.email}"
    db.commit()
    return name


@router.delete("/service-accounts/{service_account_id}")
async def delete_service_account(
    service_account_id: int,
    http_request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Delete a service account: it stops working at once; its audit history is kept."""
    sa = _active_service_account(db, service_account_id)

    if not sa:
        raise HTTPException(status_code=404, detail="Service account not found")

    record_admin_change(
        db,
        admin,
        http_request,
        service="service-accounts",
        action="delete_service_account",
        changes={"id": sa.id, "name": sa.username},
    )
    name = _retire_service_account(db, sa)

    return {"message": f"Service account '{name}' deleted successfully"}
