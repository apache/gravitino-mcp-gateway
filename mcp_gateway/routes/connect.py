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

"""The gateway's own pages: where a sign-in ends, and connecting to MCP servers.

Connecting gets a person their own token for a server, from the identity
provider for servers that use single sign-on; servers with their own sign-in
continue in mcp_oauth.
"""

import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ..config import settings
from ..database import get_db
from ..models import MCPCatalog, OAuthState, User
from ..oauth.oidc_client import OIDCClient
from ..oauth.token_manager import TokenManager
from ..oauth_auth import get_user_from_bearer_token
from ..pages import (
    expired_sign_in_page,
    message_page,
    refused_sign_in_page,
    wrong_account_page,
)
from ..sessions import session_user, session_user_id, sign_in_redirect

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/portal", tags=["Connect"])


@router.get("", response_class=HTMLResponse)
async def home(request: Request, db: Session = Depends(get_db)):
    """Where a sign-in ends when nothing asked to go elsewhere."""
    user = session_user(request, db)
    if user is None:
        return sign_in_redirect(request)
    return message_page(
        request,
        "Signed in",
        f"You are signed in to the MCP gateway as {user.username}. Gravitino's "
        "web UI lists your MCP servers and your access to them.",
        form=("/portal/logout", "Sign out"),
    )


@router.get("/connect/{service}")
async def initiate_oauth(
    service: str,
    request: Request,
    return_to: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """
    Start connecting the signed-in person to an MCP server.

    For a server with single sign-on, the person signs in at the identity
    provider for the server's scopes, and the gateway keeps that token.
    """
    user = session_user(request, db)
    if user is None:
        return sign_in_redirect(request)

    mcp = MCPCatalog.find_active(db, service)

    if not mcp or mcp.is_hidden_from(user):
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")

    # A server with its own sign-in.
    if mcp.auth_type == "oauth" and not mcp.auto_sso_enabled:
        url = f"/portal/connect-mcp-oauth/{quote(service, safe='')}"
        if return_to:
            url += f"?{urlencode({'return_to': return_to})}"
        return RedirectResponse(url=url)

    state = secrets.token_urlsafe(32)
    oauth_state_record = OAuthState(
        state=state,
        user_id=user.id,
        service=service,
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    db.add(oauth_state_record)
    db.commit()

    # offline_access, for a refresh token.
    scope = "openid profile email offline_access"
    if settings.OIDC_PROVIDER != "azure":
        # Other providers add the server's audience through its configured scopes.
        if mcp.oauth_scopes:
            scope = f"{scope} {mcp.oauth_scopes}"
    elif mcp.audience and mcp.audience != settings.GATEWAY_OAUTH_CLIENT_ID:
        # Entra issues a token for one app at a time, so ask for the server's app.
        scope = f"api://{mcp.audience}/.default offline_access"

    # One callback for every server; the state names the server.
    redirect_uri = f"{settings.GATEWAY_BASE_URL}/auth/oauth/callback"

    oidc_client = await run_in_threadpool(OIDCClient)
    auth_url = oidc_client.get_authorization_url(
        client_id=settings.GATEWAY_OAUTH_CLIENT_ID,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
    )

    return RedirectResponse(url=auth_url)


async def oauth_callback(
    request: Request,
    code: Optional[str] = Query(None),
    state: str = Query(...),
    error: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Finish connecting: /auth/oauth/callback hands over a sign-in whose state
    names an MCP server."""
    oauth_state = db.query(OAuthState).filter(OAuthState.state == state).first()
    if not oauth_state:
        return expired_sign_in_page(request)
    if oauth_state.expires_at < datetime.utcnow():
        db.delete(oauth_state)
        db.commit()
        return expired_sign_in_page(request)

    service = oauth_state.service
    user_id = oauth_state.user_id

    # Store the token only for the person who started connecting. The callback
    # runs in whichever browser opens the provider's redirect, so a link sent to
    # someone else must not save their token under the sender's account.
    if session_user_id(request) != user_id:
        db.delete(oauth_state)
        db.commit()
        logger.warning(
            "Refused connect callback for service=%s: browser not signed in as "
            "user_id=%s",
            service,
            user_id,
        )
        return wrong_account_page(request)

    db.delete(oauth_state)
    db.commit()
    if error or not code:
        return refused_sign_in_page(request, error, service)

    oidc_client = await run_in_threadpool(OIDCClient)
    redirect_uri = f"{settings.GATEWAY_BASE_URL}/auth/oauth/callback"

    try:
        token_response = await run_in_threadpool(
            oidc_client.exchange_code_for_token,
            code=code,
            client_id=settings.GATEWAY_OAUTH_CLIENT_ID,
            client_secret=settings.GATEWAY_OAUTH_CLIENT_SECRET,
            redirect_uri=redirect_uri,
            state=state,
        )

        if not token_response.get("refresh_token"):
            logger.warning(
                "No refresh token for service=%s; the person must connect again "
                "when the token expires",
                service,
            )
    except Exception as e:  # pylint: disable=broad-exception-caught
        # The error can name the identity provider's token URL, which is for admins.
        logger.error("OAuth token exchange failed: %s", str(e))
        return message_page(
            request,
            "Not connected",
            "The gateway could not finish connecting. Try again, or ask an admin "
            "to check the server's sign-in settings.",
            status_code=500,
        )

    await TokenManager(db).store_user_oauth_token(
        user_id=user_id,
        service=service,
        access_token=token_response["access_token"],
        refresh_token=token_response.get("refresh_token"),
        expires_in=token_response.get("expires_in", 3600),
    )

    return message_page(
        request, "Connected", f"Connected to {service}. You can close this window."
    )


@router.post("/disconnect/{service}")
async def disconnect_service(
    service: str,
    user: User = Depends(get_user_from_bearer_token),
    db: Session = Depends(get_db),
):
    """Delete the caller's token for a server."""
    await TokenManager(db).disconnect_user_service_async(user.id, service)

    return {"message": f"Disconnected {service} successfully"}
