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

"""Signing people in to the gateway, and out, and renewing the CLI's token."""

import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode

import jwt
import requests
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ..config import settings
from ..database import get_db
from ..models import OAuthState, User
from ..oauth.oidc_client import OIDCClient, get_configured_issuer
from ..oauth.token_manager import GATEWAY_TOKEN_SERVICE, TokenManager
from ..oauth_auth import email_from_claims, sync_person
from ..pages import HOME, message_page, refused_sign_in_page
from ..sessions import (
    clear_session_cookie,
    cookie_name,
    safe_return_url,
    session_user_id,
    set_session_cookie,
)
from .connect import oauth_callback as connect_callback

logger = logging.getLogger(__name__)

router = APIRouter()
# The gateway's own pages, outside /auth.
pages_router = APIRouter()


# Ties a sign-in to the browser that started it. Without it, someone could
# finish their own sign-in in another person's browser, leaving that browser in
# their session, and anything the person then connected would be saved for them.
_CALLBACK_PATH = "/auth/oauth/callback"


def _login_nonce_cookie() -> str:
    return cookie_name("login_nonce", not settings.DEBUG)


def _with_query(url: str, params: dict) -> str:
    """Append query parameters, skipping empty values."""
    query = urlencode({key: value for key, value in params.items() if value})
    if not query:
        return url
    return f"{url}{'&' if '?' in url else '?'}{query}"


@pages_router.get("/portal/logout", response_class=HTMLResponse)
async def confirm_logout(request: Request):
    """Ask before signing out.

    Any site can send a browser to this link, so it changes nothing; the
    form's POST, which SameSite=Lax cookies don't accompany from other sites,
    signs out.
    """
    return message_page(
        request,
        "Sign out",
        "Sign out of the MCP gateway?",
        form=("/portal/logout", "Sign out"),
    )


@pages_router.post("/portal/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    """Sign out: delete the person's gateway token and the tokens exchanged for
    it, clear the session, and end the identity provider's session."""
    user_id = session_user_id(request)
    if user_id is not None:
        try:
            await TokenManager(db=db).delete_all_user_tokens(user_id)
        except Exception:  # pylint: disable=broad-exception-caught
            # The person is signed out of the gateway all the same.
            logger.exception("Could not delete the tokens of user %s", user_id)

    # Clear the session cookie, then end the provider's session too so the next
    # login asks for credentials again.
    login_url = f"{settings.GATEWAY_BASE_URL}/auth/oauth/login"
    provider = await run_in_threadpool(OIDCClient)
    if provider.end_session_endpoint:
        redirect_url = _with_query(
            provider.end_session_endpoint,
            {
                "client_id": settings.GATEWAY_OAUTH_CLIENT_ID,
                "post_logout_redirect_uri": login_url,
            },
        )
    else:
        redirect_url = login_url
    logger.info("Clearing the session cookies and redirecting to %s", redirect_url)

    response = RedirectResponse(url=redirect_url, status_code=302)
    clear_session_cookie(response)
    return response


@router.get("/oauth/login")
async def oauth_login(
    request: Request, next_url: Optional[str] = Query(None, alias="next")
):
    """Start the OIDC login flow for a person.

    Sends the browser to the identity provider, which redirects back to
    /auth/oauth/callback.

    Endpoint: GET /auth/oauth/login?next=/some/path
    """

    # Check if OAuth is configured
    if not settings.GATEWAY_OAUTH_CLIENT_ID or not settings.GATEWAY_OAUTH_CLIENT_SECRET:
        raise HTTPException(
            status_code=503,
            detail="OAuth not configured. Set GATEWAY_OAUTH_CLIENT_ID and GATEWAY_OAUTH_CLIENT_SECRET",
        )

    # Use signed JWT as state (self-validating, no storage needed)
    browser_nonce = secrets.token_urlsafe(32)
    state_payload = {
        "purpose": "gateway_login",
        "browser": browser_nonce,
        "next_url": next_url or HOME,
        "exp": datetime.utcnow() + timedelta(minutes=10),  # State expires in 10 minutes
        "iat": datetime.utcnow(),
    }
    state = jwt.encode(
        state_payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )

    provider = await run_in_threadpool(OIDCClient)
    if not provider.authorization_endpoint:
        raise HTTPException(
            status_code=503,
            detail="OIDC provider not configured. Set OIDC_DISCOVERY_URL or OIDC_AUTHORIZATION_ENDPOINT",
        )

    auth_url = provider.get_authorization_url(
        client_id=settings.GATEWAY_OAUTH_CLIENT_ID,
        redirect_uri=f"{settings.GATEWAY_BASE_URL}{_CALLBACK_PATH}",
        scope=settings.gateway_login_scopes,
        state=state,
    )

    response = RedirectResponse(url=auth_url)
    response.set_cookie(
        key=_login_nonce_cookie(),
        value=browser_nonce,
        max_age=600,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="lax",
        path="/",
    )
    return response


def _decode_gateway_state(state: str) -> dict:
    """Validate a gateway-login state JWT and return its routing data.

    Raises HTTPException(400) for expired, malformed, or wrong-purpose tokens.
    """
    try:
        state_payload = jwt.decode(
            state, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
    except jwt.ExpiredSignatureError as e:
        raise HTTPException(
            status_code=400, detail="OAuth state expired. Please try logging in again."
        ) from e
    except jwt.InvalidTokenError as e:
        logger.error("OAuth callback: Invalid state token - %s", e)
        raise HTTPException(status_code=400, detail="Invalid state parameter") from e

    if state_payload.get("purpose") != "gateway_login":
        raise HTTPException(status_code=400, detail="Invalid state: wrong purpose")

    next_url = state_payload.get("next_url", HOME)
    logger.info("OAuth callback: Valid state, next_url=%r", next_url)
    return {"next_url": next_url, "browser": state_payload.get("browser")}


def _started_in_this_browser(request: Request, state_data: dict) -> bool:
    """Whether the sign-in's state matches this browser's login cookie."""
    expected = state_data.get("browser")
    actual = request.cookies.get(_login_nonce_cookie())
    return bool(expected and actual) and secrets.compare_digest(expected, actual)


def _id_token_claims(id_token: Optional[str], issuer: Optional[str]) -> dict:
    """The claims of a sign-in's ID token, once its issuer, audience and expiry check out.

    The token came straight from the token endpoint over TLS, so its signature
    need not be checked (OIDC Core 3.1.3.7); the section's other checks apply.
    """
    if not id_token or not issuer:
        raise HTTPException(
            status_code=502, detail="The identity provider sent no usable ID token"
        )
    try:
        return jwt.decode(
            id_token,
            audience=settings.GATEWAY_OAUTH_CLIENT_ID,
            issuer=issuer,
            options={
                "verify_signature": False,
                "verify_aud": True,
                "verify_iss": True,
                "verify_exp": True,
                "require": ["iss", "aud", "exp"],
            },
        )
    except jwt.InvalidTokenError as e:
        logger.warning("Login refused: the ID token is not for this gateway: %s", e)
        raise HTTPException(
            status_code=403, detail="The sign-in is not for this gateway"
        ) from e


async def _signed_in_person(db: Session, code: str, state: str) -> User:
    """The person a sign-in's code is for, with their gateway token stored."""
    provider = await run_in_threadpool(OIDCClient)
    if not provider.token_endpoint:
        raise HTTPException(
            status_code=503,
            detail="OIDC provider not configured. Set OIDC_DISCOVERY_URL or OIDC_TOKEN_ENDPOINT",
        )
    tokens = await run_in_threadpool(
        provider.exchange_code_for_token,
        code=code,
        client_id=settings.GATEWAY_OAUTH_CLIENT_ID,
        client_secret=settings.GATEWAY_OAUTH_CLIENT_SECRET,
        redirect_uri=f"{settings.GATEWAY_BASE_URL}{_CALLBACK_PATH}",
        state=state,
    )

    claims = _id_token_claims(
        tokens.get("id_token"), await run_in_threadpool(get_configured_issuer)
    )
    email = email_from_claims(claims)
    if not email:
        logger.warning("Login refused: no verified email or account name")
        raise HTTPException(
            status_code=403,
            detail="Your identity provider did not send a verified email address",
        )
    user = await sync_person(db, claims, email.lower(), tokens.get("access_token"))
    if user is None:
        raise HTTPException(status_code=403, detail="This account can't sign in")

    # Kept, encrypted, so that servers with single sign-on work without
    # another sign-in.
    await TokenManager(db).store_user_oauth_token(
        user_id=user.id,
        service=GATEWAY_TOKEN_SERVICE,
        access_token=tokens["access_token"],
        refresh_token=tokens.get("refresh_token"),
        expires_in=tokens.get("expires_in", 3600),
    )
    return user


@router.get("/oauth/callback")
async def oauth_callback(
    request: Request,
    db: Session = Depends(get_db),
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
):
    """Where the identity provider sends the browser back, after a person signs
    in to the gateway or connects a server with single sign-on."""
    # Connecting to a server stores a random state; signing in signs one.
    if state and db.query(OAuthState).filter(OAuthState.state == state).first():
        return await connect_callback(
            request=request, code=code, state=state, error=error, db=db
        )
    if not state:
        raise HTTPException(status_code=400, detail="Missing the state parameter")

    state_data = _decode_gateway_state(state)
    if not _started_in_this_browser(request, state_data):
        raise HTTPException(
            status_code=400,
            detail="This sign-in was started in another browser. Please sign in again.",
        )
    # Only after the state checks out: anyone can send a browser here with an
    # error of their own.
    if error or not code:
        return refused_sign_in_page(request, error)

    try:
        user = await _signed_in_person(db, code, state)
    except HTTPException:
        raise
    except requests.HTTPError as e:
        logger.error(
            "OAuth callback: code exchange failed: %s",
            e.response.text if e.response is not None else e,
        )
        raise HTTPException(
            status_code=400, detail="Failed to exchange the authorization code"
        ) from e
    except Exception as e:
        logger.error("OAuth callback failed: %s", e)
        raise HTTPException(status_code=500, detail="OAuth callback failed") from e

    # The next page came from a query parameter, so it is checked even though
    # it round-tripped through the signed state.
    next_url = state_data.get("next_url") or HOME
    if not next_url.startswith("/") or safe_return_url(next_url) is None:
        next_url = HOME

    response = RedirectResponse(url=next_url, status_code=302)
    set_session_cookie(response, user.id)
    # The sign-in is done; its nonce must not be reused.
    response.delete_cookie(
        key=_login_nonce_cookie(),
        path="/",
        secure=not settings.DEBUG,
        httponly=True,
        samesite="lax",
    )
    return response


class RefreshTokenRequest(BaseModel):
    refresh_token: str


@router.post("/refresh")
async def refresh_access_token(
    refresh_request: RefreshTokenRequest, db: Session = Depends(get_db)
):
    """
    Generic OIDC token refresh endpoint for CLI.
    Works with any OIDC provider (Azure AD, Okta, Auth0, Google, Keycloak, etc.)

    Note: This endpoint does NOT require a valid bearer token, as the access token
    may be expired. It only validates the refresh token with the OIDC provider.
    """

    try:
        # Use generic OIDC client for provider-agnostic refresh. The client is
        # synchronous, so it runs in a worker thread to keep the event loop free.
        oidc_client = await run_in_threadpool(OIDCClient)
        token_response = await run_in_threadpool(
            oidc_client.refresh_access_token,
            refresh_token=refresh_request.refresh_token,
            client_id=settings.GATEWAY_OAUTH_CLIENT_ID,
            client_secret=settings.GATEWAY_OAUTH_CLIENT_SECRET,
        )

        # Decode the new access token to get user info (without verification since we trust OIDC provider)
        decoded = jwt.decode(
            token_response["access_token"], options={"verify_signature": False}
        )

        user_email = email_from_claims(decoded)
        if not user_email:
            raise HTTPException(
                status_code=400, detail="Unable to extract user email from token"
            )

        user = User.find_person(db, user_email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Update stored tokens in database
        token_manager = TokenManager(db)
        await token_manager.store_user_oauth_token(
            user_id=user.id,
            service=GATEWAY_TOKEN_SERVICE,
            access_token=token_response["access_token"],
            refresh_token=token_response.get(
                "refresh_token", refresh_request.refresh_token
            ),
            expires_in=token_response.get("expires_in", 3600),
        )

        logger.info(
            "Refreshed OIDC token for user %s (provider: %s)",
            user.username,
            oidc_client.provider,
        )

        return {
            "access_token": token_response["access_token"],
            "refresh_token": token_response.get(
                "refresh_token", refresh_request.refresh_token
            ),
            "expires_in": token_response.get("expires_in", 3600),
            "token_type": "Bearer",
        }

    # NOTE: this deliberately swallows HTTPException too. Collapsing every
    # failure (bad token, unknown user, provider outage) into one opaque 401
    # is what stops this unauthenticated endpoint from confirming whether an
    # account exists. Do not add `except HTTPException: raise` here.
    except Exception as e:
        logger.error("Token refresh failed: %s", e)
        raise HTTPException(
            status_code=401, detail="Failed to refresh token. Please log in again."
        ) from e
