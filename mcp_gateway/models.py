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
SQLAlchemy models for the Gravitino MCP Gateway
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import relationship

from .database import MYSQL_TABLE_OPTIONS, Base


class User(Base):
    """User model"""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    full_name = Column(String(255), nullable=True)  # Display name from OIDC token
    is_active = Column(Boolean, default=True)  # Soft-disable accounts
    is_admin = Column(Boolean, default=False)
    is_service_account = Column(Boolean, default=False)
    team = Column(String(100), nullable=True)  # For service accounts
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    oauth_tokens = relationship("OAuthToken", back_populates="user")
    oauth_creds = relationship(
        "ServiceAccountCredentials",
        back_populates="service_account",
        foreign_keys="[ServiceAccountCredentials.service_account_id]",
    )

    @classmethod
    def find_person(cls, db, email: str) -> Optional["User"]:
        """The active person whose email is ``email``, apart from case, or None.

        MySQL also matches emails that differ only in accents, so the match is
        checked again here: another account must never be found instead.
        """
        email = email.strip().lower()
        user = (
            db.query(cls)
            .filter(
                func.lower(cls.email) == email,
                cls.is_service_account.is_(False),
                cls.is_active.is_(True),
            )
            .first()
        )
        return user if user is not None and user.email.lower() == email else None


class OAuthToken(Base):
    """A person's token for one MCP server, or their gateway token, encrypted."""

    __tablename__ = "oauth_tokens"
    __table_args__ = (
        UniqueConstraint("user_id", "service", name="unique_user_service_token"),
        MYSQL_TABLE_OPTIONS,
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    # A server ID, or one of token_manager.RESERVED_SERVICE_IDS.
    service = Column(String(100), nullable=False)

    # AES-256-GCM, with the key from the secret store (TOKEN_ENCRYPTION_KEY).
    access_token_encrypted = Column(Text, nullable=False)
    refresh_token_encrypted = Column(Text, nullable=True)

    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="oauth_tokens")


class ServiceAccountCredentials(Base):
    """OAuth credentials for service accounts (generic OIDC)"""

    __tablename__ = "service_account_credentials"

    id = Column(Integer, primary_key=True, index=True)
    service_account_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    # Where the workload runs: "google", "aws" or "other", shown to admins.
    provider = Column(String(100), nullable=False)
    service_account_name = Column(
        String(255), unique=True, index=True, nullable=False
    )  # GCP SA email or OIDC identity
    additional_config = Column(JSON, nullable=True)  # Provider-specific config
    allowed_services = Column(JSON, nullable=False)  # ["trino", "metastore", "slack"]
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relationships
    service_account = relationship(
        "User", foreign_keys=[service_account_id], back_populates="oauth_creds"
    )
    creator = relationship("User", foreign_keys=[created_by])


class DeviceCode(Base):
    """One run of the device flow, with which the CLI gets a person's token."""

    __tablename__ = "device_codes"

    id = Column(Integer, primary_key=True, index=True)
    device_code = Column(String(255), nullable=False, unique=True, index=True)
    user_code = Column(String(20), nullable=False, unique=True, index=True)
    client_id = Column(String(255), nullable=False, default="gravitino-mcp-cli")
    # Shown to the person who reviews the code.
    requested_from = Column(String(45), nullable=True)
    requested_by_agent = Column(String(255), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # who approved
    expires_at = Column(DateTime, nullable=False)
    approved = Column(Boolean, default=False)
    denied = Column(Boolean, default=False)
    # Issued to the one person reviewing the code.
    approval_csrf = Column(String(255), nullable=True)
    approval_csrf_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    """Comprehensive audit log for MCP tool calls"""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    username = Column(
        String(255), nullable=False, index=True
    )  # Denormalized for easier querying
    service = Column(
        String(100), nullable=False, index=True
    )  # "metastore", "trino", etc.
    tool_name = Column(
        String(255), nullable=False, index=True
    )  # "list_databases", "execute_query"
    method = Column(String(50), nullable=False)  # "tools/call", "prompts/get"
    request_params = Column(JSON, nullable=True)  # Tool parameters
    request_headers = Column(JSON, nullable=True)  # Tool request headers
    response_data = Column(JSON, nullable=True)  # Tool response
    status = Column(
        String(50), nullable=False, index=True
    )  # "success", "error", "unauthorized", "cancelled"
    error_message = Column(Text, nullable=True)
    duration_ms = Column(Integer, nullable=True)  # Request duration in milliseconds
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationships
    user = relationship("User")


class MCPCatalog(Base):
    """MCP Catalog - Admin-managed registry of available MCP servers"""

    __tablename__ = "mcp_catalog"

    id = Column(Integer, primary_key=True, index=True)
    service_id = Column(
        String(100), unique=True, nullable=False, index=True
    )  # "metastore", "trino", "slack"
    name = Column(String(255), nullable=False)  # Display name
    description = Column(Text, nullable=True)
    icon = Column(String(50), nullable=True)  # Emoji or icon identifier
    mcp_url = Column(String(500), nullable=False)  # MCP server URL
    # With single sign-on, the audience of the tokens the server accepts; with
    # Entra, the ID of the server's app.
    audience = Column(String(255), nullable=True)
    # For a server with its own sign-in, the gateway's client ID at its
    # authorization server, and that client's encrypted secret if it has one.
    # The gateway registers a client on the first connect when no ID is set.
    oauth_client_id = Column(String(255), nullable=True)
    oauth_client_secret_encrypted = Column(Text, nullable=True)
    # Optional RFC 8414 authorization-server metadata URL. When set, MCP Gateway
    # fetches it directly instead of probing well-known paths under mcp_url.
    oauth_metadata_url = Column(String(500), nullable=True)
    oauth_scopes = Column(String(500), nullable=True)  # OAuth scopes if applicable
    # Single sign-on: the gateway forwards or exchanges the person's own token.
    auto_sso_enabled = Column(Boolean, default=False)
    category = Column(
        String(100), nullable=True
    )  # "data", "communication", "analytics", etc.
    is_active = Column(Boolean, default=True)  # Admin can disable MCPs
    admin_only = Column(Boolean, default=False)  # Only admins may see and use it
    # Whether people need an admin's approval; otherwise the server is open.
    requires_approval = Column(Boolean, nullable=False, default=True)
    auth_type = Column(
        String(20), default="oauth"
    )  # "oauth", "basic", or "passthrough" — how MCP Gateway authenticates to this MCP
    service_auth_type = Column(
        String(30), default="passthrough"
    )  # "passthrough" "basic" or "credential_forward" - how MCP Gateway authenticates to this MCP for service accounts
    basic_auth_username = Column(
        String(255), nullable=True
    )  # Username for basic auth to backend MCP
    basic_auth_password_encrypted = Column(
        Text, nullable=True
    )  # Encrypted password for basic auth
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def is_open_access(self) -> bool:
        """Whether anyone signed in may use this server, without an admin's approval."""
        return not self.requires_approval

    @classmethod
    def find(
        cls, db, service_id: str, *, active: bool = True
    ) -> Optional["MCPCatalog"]:
        """The server whose ID is exactly ``service_id``, or None; only an
        active one unless ``active`` is false.

        MySQL compares IDs without regard to case, but tool filters, service
        accounts' servers and tokens are keyed on the exact ID.
        """
        query = db.query(cls).filter(cls.service_id == service_id)
        if active:
            query = query.filter(cls.is_active.is_(True))
        mcp = query.first()
        return mcp if mcp is not None and mcp.service_id == service_id else None

    @classmethod
    def find_active(cls, db, service_id: str) -> Optional["MCPCatalog"]:
        """The active server whose ID is exactly ``service_id``, or None."""
        return cls.find(db, service_id)

    def is_hidden_from(self, user: "User") -> bool:
        """Whether this server is admin-only and ``user``, a person, is not an admin.

        A hidden server answers as if it did not exist. Service accounts reach
        only the servers an admin listed for them, so the flag is for people.
        """
        return (
            bool(self.admin_only) and not user.is_admin and not user.is_service_account
        )

    @property
    def oauth_client_secret_configured(self) -> bool:
        """Whether an OAuth client secret is stored (never expose the secret itself)."""
        return bool(self.oauth_client_secret_encrypted)

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])


class MCPAccessRequest(Base):
    """User requests to access an MCP server"""

    __tablename__ = "mcp_access_requests"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    mcp_id = Column(Integer, ForeignKey("mcp_catalog.id"), nullable=False, index=True)
    justification = Column(Text, nullable=True)  # Why user needs access
    status = Column(
        String(20), default="pending", index=True
    )  # pending, approved, denied
    admin_notes = Column(Text, nullable=True)  # Admin's reason for approval/denial
    requested_at = Column(DateTime, default=datetime.utcnow, index=True)
    reviewed_at = Column(DateTime, nullable=True)
    reviewed_by = Column(
        Integer, ForeignKey("users.id"), nullable=True
    )  # Admin who reviewed

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    mcp = relationship("MCPCatalog")
    reviewer = relationship("User", foreign_keys=[reviewed_by])


class OAuthState(Base):
    """OAuth state tokens for CSRF protection - Stored in database to survive pod restarts"""

    __tablename__ = "oauth_states"

    id = Column(Integer, primary_key=True, index=True)
    state = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    service = Column(String(100), nullable=False)  # "metastore", "trino", etc.
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)  # Auto-expire after 10 minutes

    # Relationships
    user = relationship("User")


class SlackTokenApproval(Base):
    """User consent record for service accounts retrieving Slack user tokens."""

    __tablename__ = "slack_token_approvals"

    id = Column(String(36), primary_key=True)
    requesting_sa_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    slack_user_id = Column(String(100), nullable=False)
    app_name = Column(String(255), nullable=False)
    status = Column(String(20), default="pending")  # pending/approved/denied/failed
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    requesting_sa = relationship("User", foreign_keys=[requesting_sa_id])


class MCPUserPermission(Base):
    """Approved permissions for human users to access MCPs"""

    __tablename__ = "mcp_user_permissions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    mcp_id = Column(Integer, ForeignKey("mcp_catalog.id"), nullable=False, index=True)
    granted_by = Column(
        Integer, ForeignKey("users.id"), nullable=True
    )  # Admin who granted
    granted_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)  # Optional expiration

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    mcp = relationship("MCPCatalog")
    granter = relationship("User", foreign_keys=[granted_by])

    # Unique constraint: one permission per user per MCP
    __table_args__ = (
        UniqueConstraint("user_id", "mcp_id", name="unique_user_mcp_permission"),
        MYSQL_TABLE_OPTIONS,
    )

    def has_expired(self, mcp: Optional["MCPCatalog"] = None) -> bool:
        """Whether this grant has expired.

        Open servers take no access requests, so a grant for one, which could
        not be renewed, never expires. Expiry times are naive UTC.
        """
        if mcp is not None and mcp.is_open_access:
            return False
        return self.expires_at is not None and self.expires_at < datetime.utcnow()


class MCPVirtualServer(Base):
    """A named group of catalog servers served at one URL, /mcp/<service_id>."""

    __tablename__ = "mcp_virtual_servers"

    id = Column(Integer, primary_key=True, index=True)
    # Shares the URL space of MCPCatalog.service_id; the admin API keeps them apart.
    service_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    members = relationship(
        "MCPVirtualMember",
        cascade="all, delete-orphan",
        order_by="MCPVirtualMember.id",
        lazy="selectin",
    )

    __table_args__ = (MYSQL_TABLE_OPTIONS,)


class MCPVirtualMember(Base):
    """A catalog server in a virtual server, and the prefix of its tool names."""

    __tablename__ = "mcp_virtual_members"

    id = Column(Integer, primary_key=True, index=True)
    virtual_id = Column(
        Integer, ForeignKey("mcp_virtual_servers.id"), nullable=False, index=True
    )
    mcp_id = Column(Integer, ForeignKey("mcp_catalog.id"), nullable=False, index=True)
    # Put before the server's tool names; empty leaves them as they are.
    tool_prefix = Column(String(50), nullable=False, default="")

    mcp = relationship("MCPCatalog", lazy="joined")

    __table_args__ = (
        UniqueConstraint("virtual_id", "mcp_id", name="unique_virtual_member"),
        MYSQL_TABLE_OPTIONS,
    )
