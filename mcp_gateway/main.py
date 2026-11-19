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
Gravitino MCP Gateway - main FastAPI application
"""

import asyncio
import logging
from contextlib import asynccontextmanager, suppress

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from . import VERSION
from .body_limit import BodySizeLimitMiddleware
from .catalog_defaults import register_gravitino_mcp
from .config import settings
from .database import Base, SessionLocal, engine
from .gateway_keys import get_jwks
from .log_filter import install_sensitive_data_filter
from .metrics import setup_metrics
from .oauth.oidc_client import OIDCClient
from .pages import HOME
from .purge import start_purge_task
from .routes import (
    admin,
    audit,
    auth,
    connect,
    device_flow,
    mcp_access,
    mcp_admin,
    mcp_catalog,
    mcp_oauth,
    mcp_server,
    user_tokens,
    users,
)
from .security_headers import SecurityHeadersMiddleware

# Configure logging to show INFO level messages
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
# Redact JWTs, Bearer tokens, and secrets from all log output (including uvicorn.access)
install_sensitive_data_filter()
logger = logging.getLogger(__name__)

# Suppress verbose SQLAlchemy logs, and httpx's request lines, whose URLs can
# hold secrets such as a Slack webhook's
for _name in (
    "sqlalchemy.engine",
    "sqlalchemy.pool",
    "sqlalchemy.dialects",
    "httpx",
    "httpcore",
):
    logging.getLogger(_name).setLevel(logging.WARNING)

# Create database tables
Base.metadata.create_all(bind=engine)

# Log startup
logger.info(
    "MCP Gateway starting up - Environment: %s, Debug: %s",
    settings.ENVIRONMENT,
    settings.DEBUG,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Application lifespan handler (replaces deprecated @app.on_event)."""
    logger.info("MCP Gateway server ready - http://%s:%s", settings.HOST, settings.PORT)
    with SessionLocal() as db:
        register_gravitino_mcp(db)
    slack_task: asyncio.Task | None = None
    purge_task = start_purge_task()
    if settings.SLACK_BOT_TOKEN and settings.SLACK_APP_TOKEN:
        from mcp_gateway.slack.app import (  # pylint: disable=import-outside-toplevel
            start_slack_bot,
        )

        logger.info("Starting Slack bot (Socket Mode)")
        slack_task = await start_slack_bot(session_factory=SessionLocal)
    elif settings.SLACK_BOT_TOKEN or settings.SLACK_APP_TOKEN:
        logger.warning(
            "Slack bot not started — both SLACK_BOT_TOKEN and SLACK_APP_TOKEN "
            "are required for /gravitino-mcp (have_bot=%s have_app=%s)",
            bool(settings.SLACK_BOT_TOKEN),
            bool(settings.SLACK_APP_TOKEN),
        )
    try:
        yield
    finally:
        purge_task.cancel()
        with suppress(asyncio.CancelledError):
            await purge_task
        if slack_task is not None:
            slack_task.cancel()
            with suppress(asyncio.CancelledError):
                await slack_task


# The API's interactive docs are for development; production doesn't serve them.
_DOCS = settings.ENVIRONMENT != "production"

app = FastAPI(
    title="Gravitino MCP Gateway",
    description="Sign-in, access control and audit for MCP servers",
    version=VERSION,
    swagger_ui_parameters={"persistAuthorization": True},
    docs_url="/docs" if _DOCS else None,
    redoc_url="/redoc" if _DOCS else None,
    openapi_url="/openapi.json" if _DOCS else None,
    lifespan=lifespan,
)


def cors_options(allowed_origins: str) -> dict:
    """CORSMiddleware options for CORS_ALLOWED_ORIGINS.

    The API takes bearer tokens, so no origin, listed or not, may send the
    gateway's session cookie with its requests.
    """
    if allowed_origins.strip() == "*":
        origins = ["*"]
    else:
        origins = [o.strip() for o in allowed_origins.split(",") if o.strip()]
    return {
        "allow_origins": origins,
        "allow_credentials": False,
        "allow_methods": ["*"],
        "allow_headers": ["*"],
    }


app.add_middleware(CORSMiddleware, **cors_options(settings.CORS_ALLOWED_ORIGINS))
app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.MAX_REQUEST_BYTES)
app.add_middleware(
    SecurityHeadersMiddleware,
    # Browsers only honour HSTS over https, where it keeps them there.
    extra_headers=(
        {"Strict-Transport-Security": "max-age=31536000"}
        if settings.GATEWAY_BASE_URL.startswith("https://")
        else None
    ),
)

# Prometheus metrics — instrument HTTP layer and expose GET /metrics
if settings.METRICS_ENABLED:
    setup_metrics(app, version=app.version, environment=settings.ENVIRONMENT)


app.include_router(auth.router, prefix="/auth", tags=["auth"])
for router in (
    auth.pages_router,
    device_flow.router,
    users.router,
    connect.router,
    mcp_server.router,
    audit.router,
    mcp_catalog.router,
    admin.router,
    mcp_admin.router,
    mcp_access.router,
    mcp_oauth.router,
    user_tokens.router,
):
    app.include_router(router)


def _www_authenticate() -> dict:
    """Where an MCP client finds out how to sign in (RFC 9728 section 5.1)."""
    metadata = f"{settings.GATEWAY_BASE_URL}/.well-known/oauth-protected-resource"
    return {
        "WWW-Authenticate": f'Bearer realm="MCP Gateway", resource_metadata="{metadata}"'
    }


@app.exception_handler(HTTPException)
async def mcp_http_exception_handler(request: Request, exc: HTTPException):
    """HTTP errors, as each kind of MCP client needs them.

    Streamable HTTP clients, which accept text/event-stream, get a real 401
    with WWW-Authenticate, which starts their sign-in (RFC 9728). Older
    JSON-RPC clients get errors on a POST as a JSON-RPC error with status 200,
    so that they don't open a sign-in window of their own.
    """
    body = {"detail": exc.detail}
    if not request.url.path.startswith("/mcp/"):
        return JSONResponse(status_code=exc.status_code, content=body)
    streamable = "text/event-stream" in request.headers.get("accept", "")
    if request.method == "POST" and not (exc.status_code == 401 and streamable):
        return JSONResponse(
            status_code=200,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32000, "message": exc.detail},
            },
        )
    headers = _www_authenticate() if exc.status_code == 401 else {}
    return JSONResponse(status_code=exc.status_code, headers=headers, content=body)


@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource_metadata():
    """RFC 9728 — OAuth 2.0 Protected Resource Metadata.

    Tells MCP clients (and any OAuth-aware client) which authorization server
    issues tokens accepted by this gateway.  Clients fetch this URL after
    receiving a 401 + WWW-Authenticate header from any /mcp/* endpoint.
    """
    provider = await run_in_threadpool(OIDCClient)
    return JSONResponse(
        {
            "resource": settings.oauth_resource,
            "authorization_servers": [provider.issuer] if provider.issuer else [],
            "bearer_methods_supported": ["header"],
            **(
                {"resource_documentation": f"{settings.GATEWAY_BASE_URL}/docs"}
                if _DOCS
                else {}
            ),
            "scopes_supported": settings.gateway_api_scopes,
            "resource_name": "Gravitino MCP Gateway",
        }
    )


@app.get("/.well-known/jwks.json")
async def jwks_endpoint():
    """JWKS endpoint — public keys for verifying MCP Gateway gateway JWTs.

    Downstream MCP servers fetch this to verify RS256
    gateway tokens without needing access to the private signing key.
    Uses aggressive caching headers since key rotation is infrequent.
    """
    return JSONResponse(
        content=get_jwks(),
        headers={"Cache-Control": "public, max-age=3600"},
    )


@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server_metadata():
    """The identity provider's endpoints, in RFC 8414's shape, on the gateway's host.

    The protected-resource document names the provider, which is where clients
    following RFC 9728 look. Some MCP clients look on the server's own host
    instead; this serves them. Its issuer is the provider's, which an RFC 8414
    client that checks it against this host will refuse.
    """
    provider = await run_in_threadpool(OIDCClient)
    grant_types = ["authorization_code", "refresh_token"]
    if provider.device_authorization_endpoint:
        grant_types.append("urn:ietf:params:oauth:grant-type:device_code")
    endpoints = {
        "issuer": provider.issuer,
        "authorization_endpoint": provider.authorization_endpoint,
        "token_endpoint": provider.token_endpoint,
        "device_authorization_endpoint": provider.device_authorization_endpoint,
        "registration_endpoint": provider.registration_endpoint,
        "jwks_uri": provider.jwks_uri,
    }
    return JSONResponse(
        {
            **{name: url for name, url in endpoints.items() if url},
            "response_types_supported": ["code"],
            "grant_types_supported": grant_types,
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
                "none",
            ],
            # Advertise the same API scopes as the protected-resource metadata.
            "scopes_supported": settings.gateway_api_scopes,
            "code_challenge_methods_supported": ["S256"],
        }
    )


@app.get("/")
async def root():
    """Send a browser to the gateway's own page."""
    return RedirectResponse(url=HOME, status_code=302)


def _database_reachable() -> bool:
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError:
        logger.exception("The health check could not reach the database")
        return False


@app.get("/health")
async def health_check():
    """Whether the gateway can serve requests: 200 when it reaches its database."""
    if await run_in_threadpool(_database_reachable):
        return {"status": "healthy"}
    return JSONResponse({"status": "unhealthy"}, status_code=503)


if __name__ == "__main__":
    uvicorn.run(
        "mcp_gateway.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
