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
Shared pytest fixtures for MCP Gateway test suite.
Uses an in-memory SQLite database so tests are fully isolated.
"""

import asyncio
import atexit
import os
import secrets
import shutil
import tempfile

import pytest

# ---------------------------------------------------------------------------
# The CLI keeps its tokens and settings, and writes MCP clients' configuration,
# under the home directory. The suite's home is its own, so that no test can
# touch the developer's, and no test opens a browser.
# ---------------------------------------------------------------------------
_HOME = tempfile.mkdtemp(prefix="mcp-gateway-tests-")
atexit.register(shutil.rmtree, _HOME, ignore_errors=True)
os.environ.update({"HOME": _HOME, "USERPROFILE": _HOME, "BROWSER": "true"})

# ---------------------------------------------------------------------------
# The settings, read when the app is imported: the suite's own, whatever the
# developer's environment or .env file holds.
# ---------------------------------------------------------------------------
os.environ.update(
    {
        "MCP_GATEWAY_ENV_FILE": "",
        "ENVIRONMENT": "test",
        "DEBUG": "false",
        "JWT_SECRET_KEY": secrets.token_hex(32),
        "JWT_AUDIENCE": "test-audience",
        "DATABASE_URL": "sqlite:///:memory:",
        "OIDC_PROVIDER": "generic",
        "GATEWAY_OAUTH_CLIENT_ID": "test-gateway-client-id",
        "OIDC_ISSUER": "https://login.example.com/tenant/v2.0",
        "OIDC_AUTHORIZATION_ENDPOINT": "https://login.example.com/tenant/oauth2/authorize",
        "OIDC_TOKEN_ENDPOINT": "https://login.example.com/tenant/oauth2/token",
        "TRUSTED_ISSUERS": "https://login.example.com/tenant/v2.0,"
        "https://accounts.google.com,"
        "https://oidc.eks.us-west-2.amazonaws.com/id/ABC123",
        "SLACK_BOT_TOKEN": "",
        "SLACK_APP_TOKEN": "",
        "SLACK_WEBHOOK_URL": "",
        # The suite runs against a deployment with workload and forwarded headers.
        "SERVICE_ACCOUNT_REQUIRED_HEADERS": "team,namespace",
        "SERVICE_ACCOUNT_OPTIONAL_HEADERS": "pipeline,cost-center",
        "MCP_FORWARD_HEADERS": "x-api-key",
    }
)
for _name in (
    "OIDC_DISCOVERY_URL",
    "OIDC_JWKS_URI",
    "GRAVITINO_URI",
    "GRAVITINO_MCP_URL",
    "ADMIN_EMAILS",
    "TOKEN_ENCRYPTION_KEY",
    "TOKEN_ENCRYPTION_KEY_FILE",
):
    os.environ.pop(_name, None)

# The app reads its settings at import time, so these imports follow the env setup.
# pylint: disable=wrong-import-position
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mcp_gateway import main
from mcp_gateway.config import settings
from mcp_gateway.database import Base, SessionLocal, engine, get_db
from mcp_gateway.main import app
from mcp_gateway.models import MCPCatalog, MCPUserPermission, User
from mcp_gateway.oauth_auth import get_user_from_bearer_token

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True, name="_no_real_claude_cli")
def fixture_no_real_claude_cli(monkeypatch):
    """Tests never run the developer's claude CLI, which would change its config."""
    # Imported here: the module reads no settings, but keep conftest's imports lean.
    from mcp_gateway_cli import clients  # pylint: disable=import-outside-toplevel

    monkeypatch.setattr(clients, "_which", lambda name: None)


@pytest.fixture(autouse=True, name="_no_upstream_sessions")
def fixture_no_upstream_sessions(monkeypatch):
    """Each test starts with no MCP sessions held open with upstream servers.

    They are keyed by user ID, which every test's fresh database reuses.
    """
    # pylint: disable=import-outside-toplevel
    from mcp_gateway.routes import mcp_upstream

    monkeypatch.setattr(mcp_upstream, "_upstream_sessions", {})


@pytest.fixture(scope="function", name="db_engine")
def fixture_db_engine():
    """
    Create a fresh in-memory SQLite engine for each test.

    StaticPool is required for sqlite:///:memory: so that
    *all* connection checkouts from the pool reuse the same
    underlying connection.  Without it, commit() releases the
    connection back to the pool; on the next checkout SQLAlchemy
    might open a brand-new :memory: DB that has no tables at all.
    """
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    # The app's own sessions, such as its background tasks', use it too.
    SessionLocal.configure(bind=test_engine)
    yield test_engine
    SessionLocal.configure(bind=engine)
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function", name="db_session")
def fixture_db_session(db_engine):
    """Return a database session bound to the in-memory engine."""
    make_session = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)
    session = make_session()
    try:
        yield session
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Application client
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function", name="client")
def fixture_client(db_session, monkeypatch):
    """TestClient with the in-memory database injected."""

    # API tests must not contact Slack; dedicated Slack tests opt in with mocks.
    for name in ("SLACK_APP_TOKEN", "SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL"):
        monkeypatch.setattr(settings, name, None)
    # The purge runs in a thread, on the test's one SQLite connection, and its
    # rollback would undo the test's rows; test_purge.py tests it.
    monkeypatch.setattr(
        main, "start_purge_task", lambda: asyncio.ensure_future(asyncio.sleep(0))
    )

    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db
    # Use raise_server_exceptions=True so server-side errors surface as pytest failures
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Identity provider
# ---------------------------------------------------------------------------

PROVIDER_DISCOVERY_URL = (
    "https://idp.example.com/realms/test/.well-known/openid-configuration"
)


@pytest.fixture(name="as_user")
def fixture_as_user():
    """Call the API as a given user, standing in for the bearer-token check.

    Admin endpoints depend on the same check, so their is_admin gate still runs.
    """

    def _as(user):
        app.dependency_overrides[get_user_from_bearer_token] = lambda: user
        return user

    yield _as
    app.dependency_overrides.pop(get_user_from_bearer_token, None)


@pytest.fixture(name="oidc_provider")
def fixture_oidc_provider(monkeypatch) -> dict:
    """A provider configured through discovery; tests may edit the returned document."""
    base = "https://idp.example.com/realms/test"
    document = {
        "issuer": base,
        "authorization_endpoint": f"{base}/protocol/openid-connect/auth",
        "token_endpoint": f"{base}/protocol/openid-connect/token",
        "jwks_uri": f"{base}/protocol/openid-connect/certs",
        "end_session_endpoint": f"{base}/protocol/openid-connect/logout",
        "device_authorization_endpoint": f"{base}/protocol/openid-connect/auth/device",
        "registration_endpoint": f"{base}/clients-registrations/openid-connect",
    }
    monkeypatch.setattr(settings, "OIDC_DISCOVERY_URL", PROVIDER_DISCOVERY_URL)
    monkeypatch.setattr(
        "mcp_gateway.oauth.oidc_client._get_discovery_document",
        lambda url: document if url == PROVIDER_DISCOVERY_URL else None,
    )
    return document


# ---------------------------------------------------------------------------
# Common model factories
# ---------------------------------------------------------------------------


@pytest.fixture(name="regular_user")
def fixture_regular_user(db_session) -> User:
    user = User(
        username="testuser",
        email="testuser@example.com",
        full_name="Test User",
        is_active=True,
        is_admin=False,
        is_service_account=False,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(name="admin_user")
def fixture_admin_user(db_session) -> User:
    user = User(
        username="adminuser",
        email="admin@example.com",
        full_name="Admin User",
        is_active=True,
        is_admin=True,
        is_service_account=False,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(name="service_account")
def fixture_service_account(db_session) -> User:
    user = User(
        username="svc-test",
        email="svc-test@example.com",
        is_active=True,
        is_admin=False,
        is_service_account=True,
        team="data-eng",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(name="mcp_entry")
def fixture_mcp_entry(db_session) -> MCPCatalog:
    mcp = MCPCatalog(
        service_id="trino",
        name="Trino",
        description="Trino SQL engine",
        mcp_url="http://trino-mcp:8080/mcp",
        auto_sso_enabled=False,
        is_active=True,
        requires_approval=False,
    )
    db_session.add(mcp)
    db_session.commit()
    db_session.refresh(mcp)
    return mcp


@pytest.fixture(name="user_with_mcp_permission")
def fixture_user_with_mcp_permission(db_session, regular_user, mcp_entry) -> User:
    perm = MCPUserPermission(
        user_id=regular_user.id,
        mcp_id=mcp_entry.id,
    )
    db_session.add(perm)
    db_session.commit()
    return regular_user
