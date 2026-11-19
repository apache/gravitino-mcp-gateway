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
Connecting to MCP servers with their own sign-in, found by discovery (RFC 9728/8414).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import quote

import httpx
import jwt
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import MCPCatalog
from ..oauth.mcp_oauth_discovery import (
    OAuthServerMetadata,
    build_authorize_url,
    parse_token_response,
    register_oauth_client,
    resolve_oauth_metadata,
)
from ..oauth.token_encryption import get_token_encryption
from ..oauth.token_manager import TokenManager
from ..pages import (
    expired_sign_in_page,
    message_page,
    refused_sign_in_page,
    wrong_account_page,
)
from ..sessions import (
    cookie_name,
    safe_return_url,
    session_user,
    session_user_id,
    sign_in_redirect,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/portal", tags=["MCP OAuth"])


def _public_base_url() -> str:
    return settings.GATEWAY_BASE_URL.rstrip("/")


def _callback_redirect_uri(service: str) -> str:
    """Where a server's sign-in sends the browser back: one address per server.

    A server's authorization server accepts only the addresses registered for
    its client, so a code it issues can't come back as another server's, and
    be sent to that server's token endpoint (a mix-up attack, RFC 9700 4.4).
    """
    return f"{_public_base_url()}/portal/callback/mcp-oauth/{quote(service, safe='')}"


def _oauth_cookie_secure() -> bool:
    return _public_base_url().startswith("https://")


def state_cookie() -> str:
    """The connect flow's state cookie, with the __Host- prefix over HTTPS."""
    return cookie_name("mcp_oauth_state", _oauth_cookie_secure())


def _clear_state_cookie(response) -> None:
    response.delete_cookie(
        state_cookie(),
        path="/",
        secure=_oauth_cookie_secure(),
        httponly=True,
        samesite="lax",
    )


def _uses_client_secret(mcp: MCPCatalog) -> bool:
    return bool(mcp.oauth_client_secret_encrypted)


async def _resolve_client_id(
    mcp: MCPCatalog,
    metadata: OAuthServerMetadata,
    redirect_uri: str,
    db: Session,
) -> str:
    """Return the OAuth client_id for this MCP.

    The server's ``oauth_client_id`` if an admin set one. Otherwise, if the
    authorization server has a ``registration_endpoint``, the gateway registers
    a client once (RFC 7591) and keeps its ID for later connects.
    """
    if mcp.oauth_client_id:
        return mcp.oauth_client_id
    if not metadata.registration_endpoint:
        raise ValueError(
            "OAuth client_id is not configured and server does not support DCR"
        )

    # One registration per server: lock the row, and read it from the database
    # rather than the session, to see a client another connect just registered.
    row = (
        db.query(MCPCatalog)
        .filter(MCPCatalog.id == mcp.id)
        .with_for_update()
        .populate_existing()
        .one()
    )
    if row.oauth_client_id:
        return row.oauth_client_id

    client_id = await register_oauth_client(
        metadata.registration_endpoint, redirect_uri
    )
    if client_id in settings.gateway_audiences:
        # A server that names the gateway's own client must not receive its tokens.
        db.rollback()
        raise ValueError("The authorization server returned the gateway's client ID")
    row.oauth_client_id = client_id
    db.commit()
    logger.info("Registered dynamic OAuth client for service=%s", row.service_id)
    return client_id


@router.get("/connect-mcp-oauth/{service}")
async def connect_mcp_oauth(
    service: str,
    request: Request,
    return_to: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Discover OAuth metadata and redirect the user to authorize with PKCE.

    ``return_to`` is where to send the browser afterwards, such as the
    Gravitino web UI page that started connecting.
    """
    user = session_user(request, db)
    if user is None:
        return sign_in_redirect(request)
    mcp = MCPCatalog.find_active(db, service)
    if not mcp or mcp.is_hidden_from(user):
        return message_page(
            request, "Server not found", "No such MCP server.", status_code=404
        )
    if mcp.auth_type != "oauth" or mcp.auto_sso_enabled:
        return message_page(
            request,
            "No sign-in to connect",
            "This MCP server doesn't have a sign-in of its own.",
            status_code=400,
        )

    try:
        metadata = await resolve_oauth_metadata(
            mcp.mcp_url,
            mcp.oauth_metadata_url,
            has_client_secret=_uses_client_secret(mcp),
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("OAuth discovery failed for %s: %s", service, exc)
        # The error names the server's URL, which is for admins only.
        return message_page(
            request,
            "Not connected",
            "The gateway could not find this server's sign-in settings. Ask an "
            "admin to check its configuration.",
            status_code=502,
        )

    redirect_uri = _callback_redirect_uri(service)
    try:
        client_id = await _resolve_client_id(mcp, metadata, redirect_uri, db)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("OAuth client resolution failed for %s: %s", service, exc)
        # Like discovery errors, these name the sign-in service's URLs.
        return message_page(
            request,
            "Not connected",
            "The gateway could not register with this server's sign-in service. "
            "Ask an admin to check its configuration.",
            status_code=502,
        )

    return _authorize(
        metadata,
        {
            "service": service,
            "user_id": user.id,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "uses_client_secret": _uses_client_secret(mcp),
            "scope": metadata.format_scopes(mcp.oauth_scopes),
            "return_to": safe_return_url(return_to),
        },
    )


def _authorize(metadata: OAuthServerMetadata, flow: dict) -> RedirectResponse:
    """Send the browser to the server's sign-in, keeping ``flow`` in a signed cookie
    with the state and PKCE verifier the callback checks."""
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    state_value = secrets.token_urlsafe(32)
    state_token = jwt.encode(
        {
            "sub": json.dumps(
                {
                    **flow,
                    "state": state_value,
                    "code_verifier": code_verifier,
                    "token_endpoint": metadata.token_endpoint,
                    "issuer": metadata.issuer,
                }
            ),
            "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
        },
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    authorize_url = build_authorize_url(
        metadata,
        client_id=flow["client_id"],
        redirect_uri=flow["redirect_uri"],
        state=state_value,
        code_challenge=code_challenge,
        scope=flow["scope"],
    )
    logger.info(
        "MCP OAuth connect: redirecting service=%s scope=%r",
        flow["service"],
        flow["scope"],
    )
    response = RedirectResponse(url=authorize_url, status_code=302)
    response.set_cookie(
        key=state_cookie(),
        value=state_token,
        max_age=600,
        httponly=True,
        secure=_oauth_cookie_secure(),
        samesite="lax",
    )
    return response


def _flow_state(
    request: Request, state: Optional[str], service: str, iss: Optional[str]
) -> Optional[dict]:
    """The connect flow this browser started, if ``state`` is that flow's and the
    browser came back from that flow's server."""
    try:
        payload = jwt.decode(
            request.cookies.get(state_cookie()) or "",
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        flow = json.loads(payload["sub"])
    except (jwt.PyJWTError, json.JSONDecodeError, KeyError, TypeError):
        return None
    expected = flow.get("state")
    if not isinstance(expected, str) or not secrets.compare_digest(
        state or "", expected
    ):
        return None
    # A code that comes back to another server's address, or from another
    # authorization server (RFC 9207), was issued for another server's flow.
    if flow.get("service") != service or (
        iss is not None and iss != flow.get("issuer")
    ):
        logger.warning(
            "Refused MCP OAuth callback for service=%s: the flow was for %s",
            service,
            flow.get("service"),
        )
        return None
    return flow


async def _redeem_code(flow: dict, code: str, mcp: MCPCatalog) -> dict:
    """The token response for ``code``, from the token endpoint the flow found.

    Raises ValueError, with a message for the person, when there is none.
    """
    body = {
        "grant_type": "authorization_code",
        "client_id": flow["client_id"],
        "code": code,
        "redirect_uri": flow["redirect_uri"],
        "code_verifier": flow["code_verifier"],
    }
    if flow.get("uses_client_secret") and mcp.oauth_client_secret_encrypted:
        encryptor = await get_token_encryption()
        body["client_secret"] = encryptor.decrypt(mcp.oauth_client_secret_encrypted)
    try:
        async with httpx.AsyncClient(
            timeout=15.0, verify=settings.upstream_tls_verify
        ) as client:
            resp = await client.post(
                flow["token_endpoint"],
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        if resp.status_code >= 400:
            # The reply stays in the log: the token endpoint comes from the
            # server's metadata, so its reply is not the gateway's to show.
            logger.error(
                "MCP OAuth token exchange failed: status=%s body=%s",
                resp.status_code,
                resp.text[:500],
            )
            raise ValueError(
                f"The server's sign-in did not issue a token (HTTP {resp.status_code}). "
                "Try connecting again, or ask an admin to check its sign-in settings."
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise ValueError(
                "The server's sign-in sent a reply that isn't JSON."
            ) from exc
    except httpx.RequestError as exc:
        logger.error("MCP OAuth token exchange for %s failed: %s", mcp.service_id, exc)
        raise ValueError(
            "The gateway could not reach the server's sign-in service."
        ) from exc


@router.get("/callback/mcp-oauth/{service}")
async def callback_mcp_oauth(  # pylint: disable=too-many-arguments
    service: str,
    request: Request,
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    iss: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Where a server's own sign-in sends the browser back: store the token."""
    flow = _flow_state(request, state, service, iss)
    if flow is None:
        return expired_sign_in_page(request)
    # Only after the state checks out: anyone can send a browser here with an
    # error of their own.
    if error or not code:
        return refused_sign_in_page(request, error, service)

    # The state cookie ties the flow to the browser that started it; also make
    # sure that browser is still signed in as the person who started it.
    user_id = flow["user_id"]
    if session_user_id(request) != user_id:
        logger.warning(
            "Refused MCP OAuth callback for service=%s: browser not signed in as "
            "user_id=%s",
            service,
            user_id,
        )
        response = wrong_account_page(request)
        _clear_state_cookie(response)
        return response

    mcp = MCPCatalog.find_active(db, service)
    if not mcp:
        return message_page(
            request, "Server not found", "No such MCP server.", status_code=404
        )
    try:
        access_token, refresh_token, expires_in = parse_token_response(
            await _redeem_code(flow, code, mcp)
        )
    except ValueError as exc:
        return message_page(request, "Not connected", str(exc), status_code=502)

    await TokenManager(db).store_user_oauth_token(
        user_id=user_id,
        service=service,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
    )
    logger.info("User id=%s connected to MCP OAuth service=%s", user_id, service)
    response = _connected(request, service, flow.get("return_to"))
    _clear_state_cookie(response)
    return response


def _connected(request: Request, service: str, return_to: Optional[str]):
    """Back to where connecting started, such as Gravitino's web UI, or a page saying it worked."""
    if return_to:
        return RedirectResponse(url=return_to, status_code=302)
    return message_page(
        request, "Connected", f"Connected to {service}. You can close this window."
    )
