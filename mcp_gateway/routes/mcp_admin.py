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

"""Admins add, change and delete the MCP servers in the catalog."""

from datetime import datetime
from typing import List, Literal, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import true
from sqlalchemy.orm import Session

from ..audit import record_admin_change
from ..database import get_db
from ..models import (
    MCPAccessRequest,
    MCPCatalog,
    MCPUserPermission,
    OAuthToken,
    ServiceAccountCredentials,
    User,
)
from ..oauth.token_encryption import get_token_encryption
from ..oauth.token_manager import RESERVED_SERVICE_IDS
from ..oauth_auth import require_admin
from .mcp_upstream import forget_sessions

# How the gateway reaches a server for people, and for service accounts. Any
# other value would fall through to OAuth and fail as "Not connected".
AuthType = Literal["oauth", "basic", "passthrough"]
ServiceAuthType = Literal["passthrough", "basic", "credential_forward"]

# A server ID is part of URLs, token audiences and metric labels. Only lower
# case, because MySQL compares IDs without regard to case.
SERVICE_ID_PATTERN = r"^[a-z0-9][a-z0-9_.-]{2,99}$"

# Fields an update may change but not empty.
_REQUIRED_FIELDS = frozenset(
    {
        "name",
        "mcp_url",
        "auto_sso_enabled",
        "requires_approval",
        "is_active",
        "admin_only",
        "auth_type",
        "service_auth_type",
    }
)

_URL_MAX_LENGTH = 500


def _upstream_url(value: Optional[str]) -> Optional[str]:
    """An http(s) URL with a host and no user name or password in it."""
    if value is None:
        return value
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("must be an http or https URL")
    if parts.username or parts.password:
        raise ValueError("must not hold a user name or password")
    if len(value) > _URL_MAX_LENGTH:
        raise ValueError(f"must be at most {_URL_MAX_LENGTH} characters")
    return value


router = APIRouter(prefix="/api/v1/admin/mcp", tags=["admin-mcp"])


def _sign_in_problem(  # pylint: disable=too-many-arguments
    *,
    auth_type: str,
    auto_sso_enabled: bool,
    audience: Optional[str],
    sets_client_secret: bool,
    has_client_secret: bool,
    oauth_metadata_url: Optional[str],
) -> Optional[str]:
    """What is wrong with how a server's users sign in, or None."""
    if auth_type == "oauth" and auto_sso_enabled and not (audience or "").strip():
        return "audience is required with single sign-on (auto_sso_enabled)"
    if sets_client_secret and (auth_type != "oauth" or auto_sso_enabled):
        return (
            "An OAuth client secret is only for a server with its own sign-in "
            "(auth_type 'oauth' without auto_sso_enabled)"
        )
    # The MCP server names its authorization server, so a server that a client
    # secret goes to must be one an admin named.
    if has_client_secret and not oauth_metadata_url:
        return (
            "An OAuth client secret needs oauth_metadata_url, the authorization "
            "server the secret is sent to"
        )
    return None


class CreateMCPRequest(BaseModel):
    """A server to add to the catalog."""

    service_id: str = Field(
        ...,
        pattern=SERVICE_ID_PATTERN,
        description="The server's ID, in its gateway URL /mcp/<service_id>",
    )
    name: str = Field(..., min_length=3, max_length=255)
    description: Optional[str] = None
    icon: Optional[str] = Field("🔌", description="An emoji shown with the name")
    mcp_url: str = Field(..., description="The MCP server's URL")
    audience: Optional[str] = Field(
        None,
        description=(
            "With single sign-on, the audience of the tokens the server accepts "
            "(with Entra, its app's ID)"
        ),
    )
    oauth_scopes: Optional[str] = Field(
        None, description="Space-separated scopes to ask for"
    )
    auto_sso_enabled: bool = Field(
        False,
        description="Single sign-on: forward or exchange each person's own token",
    )
    category: Optional[str] = Field("data", description="A label to group servers by")
    requires_approval: bool = Field(
        True,
        description="Whether people need an admin's approval; otherwise anyone signed in may use it",
    )
    is_active: bool = Field(True, description="Whether the server can be used")
    admin_only: bool = Field(False, description="Only admins may see and use it")
    auth_type: AuthType = Field(
        "oauth", description="How the gateway signs in to the server for people"
    )
    service_auth_type: ServiceAuthType = Field(
        "passthrough",
        description="How the gateway signs in to the server for service accounts",
    )
    basic_auth_username: Optional[str] = None
    basic_auth_password: Optional[str] = Field(None, description="Stored encrypted")
    oauth_client_id: Optional[str] = Field(
        None,
        description=(
            "For a server with its own sign-in, the gateway's client ID at its "
            "authorization server; registered on the first connect when not set"
        ),
    )
    oauth_client_secret: Optional[str] = Field(
        None, description="That client's secret, stored encrypted"
    )
    oauth_metadata_url: Optional[str] = Field(
        None,
        max_length=500,
        description=(
            "The authorization server's RFC 8414 metadata URL; found from mcp_url "
            "when not set"
        ),
    )

    _check_urls = field_validator("mcp_url", "oauth_metadata_url")(_upstream_url)

    @field_validator("service_id")
    @classmethod
    def _not_reserved(cls, value: str) -> str:
        if value in RESERVED_SERVICE_IDS:
            raise ValueError(f"{value} is reserved for the gateway's own tokens")
        return value

    @model_validator(mode="after")
    def _check_sign_in(self):
        problem = _sign_in_problem(
            auth_type=self.auth_type,
            auto_sso_enabled=self.auto_sso_enabled,
            audience=self.audience,
            sets_client_secret=bool(self.oauth_client_secret),
            has_client_secret=bool(self.oauth_client_secret),
            oauth_metadata_url=self.oauth_metadata_url,
        )
        if problem:
            raise ValueError(problem)
        return self


class UpdateMCPRequest(BaseModel):
    """Changes to a server; fields left out stay as they are."""

    name: Optional[str] = Field(None, min_length=3, max_length=255)
    description: Optional[str] = None
    icon: Optional[str] = None
    mcp_url: Optional[str] = None
    audience: Optional[str] = None
    oauth_scopes: Optional[str] = None
    auto_sso_enabled: Optional[bool] = None
    category: Optional[str] = None
    requires_approval: Optional[bool] = None
    is_active: Optional[bool] = None
    admin_only: Optional[bool] = None
    auth_type: Optional[AuthType] = None
    service_auth_type: Optional[ServiceAuthType] = None
    basic_auth_username: Optional[str] = None
    basic_auth_password: Optional[str] = None
    oauth_client_id: Optional[str] = None
    oauth_client_secret: Optional[str] = Field(
        None, description="An empty string removes the secret"
    )
    oauth_metadata_url: Optional[str] = Field(None, max_length=500)

    _check_urls = field_validator("mcp_url", "oauth_metadata_url")(_upstream_url)

    @model_validator(mode="after")
    def refuse_nulls(self):
        """A field sent as null would be stored as null, and an open or broken server."""
        nulls = sorted(
            name
            for name in self.model_fields_set & _REQUIRED_FIELDS
            if getattr(self, name) is None
        )
        if nulls:
            raise ValueError(f"These fields cannot be null: {', '.join(nulls)}")
        return self


class MCPResponse(BaseModel):
    """A server in the catalog, as admins manage it."""

    id: int
    service_id: str
    name: str
    description: Optional[str]
    icon: Optional[str]
    mcp_url: str
    audience: Optional[str]
    oauth_scopes: Optional[str]
    auto_sso_enabled: bool
    category: Optional[str]
    is_active: bool
    admin_only: bool = False
    requires_approval: bool
    auth_type: str = "oauth"
    service_auth_type: str = "passthrough"
    basic_auth_username: Optional[str] = None
    oauth_client_id: Optional[str] = None
    oauth_client_secret_configured: bool = False
    oauth_metadata_url: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)


async def _encrypted(value: str) -> str:
    return (await get_token_encryption()).encrypt(value)


# Fields that decide where the gateway sends people's tokens for a server, or
# which tokens those are: changing one deletes the tokens people hold for it.
_TOKEN_FIELDS = frozenset(
    {
        "mcp_url",
        "oauth_metadata_url",
        "auth_type",
        "auto_sso_enabled",
        "audience",
        "oauth_client_id",
    }
)


def _moves_sign_in(mcp: MCPCatalog, changed: dict) -> bool:
    """Whether ``changed`` may change the authorization server people sign in at."""
    if "oauth_metadata_url" in changed:
        return True
    pinned = changed.get("oauth_metadata_url", mcp.oauth_metadata_url)
    return "mcp_url" in changed and not pinned


def _repointing_problem(
    mcp: MCPCatalog, changed: dict, password: Optional[str], secret: Optional[str]
) -> Optional[str]:
    """Why a change that moves a server can't keep its stored credentials, or None.

    A credential an admin stored for one address must not follow the server
    to another without being given again: whoever can edit a server could
    otherwise point it at their own host and collect it.
    """
    if _moves_sign_in(mcp, changed) and mcp.oauth_client_secret_encrypted:
        if secret is None:
            return (
                "Moving the server's sign-in needs oauth_client_secret again, or an "
                "empty string to remove it"
            )
    if "mcp_url" in changed and mcp.basic_auth_password_encrypted and password is None:
        return "Moving the server needs basic_auth_password again"
    return None


@router.post("/", response_model=MCPResponse, status_code=status.HTTP_201_CREATED)
async def create_mcp(
    request: CreateMCPRequest,
    http_request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Add a server to the catalog."""
    existing = (
        db.query(MCPCatalog).filter(MCPCatalog.service_id == request.service_id).first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"MCP with service_id '{request.service_id}' already exists",
        )

    fields = request.model_dump(exclude={"basic_auth_password", "oauth_client_secret"})
    uses_basic = "basic" in (request.auth_type, request.service_auth_type)
    if uses_basic and request.basic_auth_password is not None:
        fields["basic_auth_password_encrypted"] = await _encrypted(
            request.basic_auth_password
        )
    if request.oauth_client_secret:
        fields["oauth_client_secret_encrypted"] = await _encrypted(
            request.oauth_client_secret
        )

    mcp = MCPCatalog(**fields, created_by=admin.id, created_at=datetime.utcnow())
    db.add(mcp)
    record_admin_change(
        db,
        admin,
        http_request,
        service=request.service_id,
        action="create_server",
        changes=request.model_dump(exclude_none=True),
    )
    db.commit()
    db.refresh(mcp)
    return mcp


@router.get("/", response_model=List[MCPResponse])
async def list_mcps(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
    include_inactive: bool = False,
):
    """Every server, newest first; inactive ones only with include_inactive."""
    query = db.query(MCPCatalog)
    if not include_inactive:
        query = query.filter(MCPCatalog.is_active == true())
    return query.order_by(MCPCatalog.created_at.desc()).all()


def _server(db: Session, service_id: str) -> MCPCatalog:
    """The server with exactly this ID, active or not, or a 404."""
    mcp = MCPCatalog.find(db, service_id, active=False)
    if not mcp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP '{service_id}' not found",
        )
    return mcp


@router.get("/{service_id}", response_model=MCPResponse)
async def get_mcp(
    service_id: str, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    """A server, active or not."""
    return _server(db, service_id)


@router.patch("/{service_id}", response_model=MCPResponse)
async def update_mcp(
    service_id: str,
    request: UpdateMCPRequest,
    http_request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Change a server. Setting is_active to false takes it out of use.

    Moving it, or changing how people sign in to it, deletes the tokens people
    hold for it, and the client the gateway registered with its old sign-in.
    """
    mcp = _server(db, service_id)
    changes = request.model_dump(exclude_unset=True)
    password = changes.pop("basic_auth_password", None)
    # None leaves the secret as it is, and an empty string removes it.
    secret = changes.pop("oauth_client_secret", None)
    changed = {
        field: value for field, value in changes.items() if getattr(mcp, field) != value
    }

    keeps_secret = bool(mcp.oauth_client_secret_encrypted) and secret != ""
    problem = _sign_in_problem(
        auth_type=changes.get("auth_type", mcp.auth_type),
        auto_sso_enabled=changes.get("auto_sso_enabled", mcp.auto_sso_enabled),
        audience=changes.get("audience", mcp.audience),
        sets_client_secret=bool(secret),
        has_client_secret=bool(secret) or keeps_secret,
        oauth_metadata_url=changes.get("oauth_metadata_url", mcp.oauth_metadata_url),
    ) or _repointing_problem(mcp, changed, password, secret)
    if problem:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=problem)

    if password is not None:
        mcp.basic_auth_password_encrypted = await _encrypted(password)
    if secret == "":
        mcp.oauth_client_secret_encrypted = None
    elif secret:
        mcp.oauth_client_secret_encrypted = await _encrypted(secret)

    if _TOKEN_FIELDS & changed.keys():
        if _moves_sign_in(mcp, changed):
            # A client the gateway registered belongs to the old sign-in.
            mcp.oauth_client_id = changes.get("oauth_client_id")
        db.query(OAuthToken).filter(OAuthToken.service == mcp.service_id).delete()
        forget_sessions(mcp.service_id)

    was_open = mcp.is_open_access
    for field, value in changes.items():
        setattr(mcp, field, value)

    if was_open and not mcp.is_open_access:
        # Access the gateway granted itself while the server was open lasts only
        # while it is open; grants an admin approved stay.
        db.query(MCPUserPermission).filter(
            MCPUserPermission.mcp_id == mcp.id,
            MCPUserPermission.granted_by.is_(None),
        ).delete(synchronize_session=False)

    mcp.updated_at = datetime.utcnow()
    record_admin_change(
        db,
        admin,
        http_request,
        service=mcp.service_id,
        action="update_server",
        changes={
            **changed,
            **({"basic_auth_password": password} if password is not None else {}),
            **({"oauth_client_secret": secret} if secret is not None else {}),
        },
    )
    db.commit()
    db.refresh(mcp)
    return mcp


@router.delete("/{service_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mcp(
    service_id: str,
    http_request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Delete an MCP server from the catalog, with everyone's access to it and
    their stored tokens for it. To take it out of use for a while, set
    is_active to false instead.
    """
    mcp = _server(db, service_id)
    service_id = mcp.service_id
    db.query(OAuthToken).filter(OAuthToken.service == service_id).delete()
    db.query(MCPUserPermission).filter(MCPUserPermission.mcp_id == mcp.id).delete()
    db.query(MCPAccessRequest).filter(MCPAccessRequest.mcp_id == mcp.id).delete()

    # Service accounts name their servers by id; a new server registered with
    # this id must not inherit them.
    for creds in db.query(ServiceAccountCredentials).all():
        if service_id in (creds.allowed_services or []):
            creds.allowed_services = [
                s for s in creds.allowed_services if s != service_id
            ]

    db.delete(mcp)
    forget_sessions(service_id)
    record_admin_change(
        db, admin, http_request, service=service_id, action="delete_server"
    )
    db.commit()

    return None
