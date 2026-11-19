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

"""The device authorization grant (RFC 8628), with which the CLI and the Slack
bot get a person's gateway token.

Whoever polls with an approved device code gets the person's tokens, so the
person types the code themselves, sees who asked for it, from where and when,
and approves or denies it (RFC 8628 section 5.4); a link can't fill it in.
"""

import logging
import secrets
import string
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import DeviceCode, OAuthToken, User
from ..oauth.token_encryption import get_token_encryption
from ..oauth.token_manager import GATEWAY_TOKEN_SERVICE
from ..pages import templates
from ..sessions import session_user, sign_in_redirect

logger = logging.getLogger(__name__)
router = APIRouter()

DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
DEFAULT_CLIENT_ID = "gravitino-mcp-cli"
DEVICE_CODE_EXPIRY_SECONDS = 600
POLL_INTERVAL_SECONDS = 5
_CLIENT_NAMES = {
    "gravitino-mcp-cli": "the gravitino-mcp CLI",
    "gravitino-mcp-slack": "the MCP gateway's Slack bot",
}
_USER_CODE_CHARS = string.ascii_uppercase + string.digits


class DeviceCodeRequest(BaseModel):
    """Request to start the device flow."""

    client_id: Optional[str] = DEFAULT_CLIENT_ID


class DeviceCodeResponse(BaseModel):
    """The codes for one device flow."""

    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int


class DeviceTokenRequest(BaseModel):
    """A poll for the token of a device code."""

    device_code: str
    grant_type: str = DEVICE_GRANT_TYPE


def generate_user_code() -> str:
    """A code a person can type, such as WXYZ-1234."""
    code = "".join(secrets.choice(_USER_CODE_CHARS) for _ in range(8))
    return f"{code[:4]}-{code[4:]}"


def _normalize_user_code(raw: Optional[str]) -> str:
    """The code as stored: upper case, with the hyphen people may leave out."""
    code = "".join(c for c in (raw or "").upper() if c in _USER_CODE_CHARS)
    return f"{code[:4]}-{code[4:]}" if len(code) == 8 else code


def _page(
    request: Request, user: User, *, status_code: int = 200, **context
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "device_approval.html",
        {"user": user, **context},
        status_code=status_code,
    )


def _token_error(error: str, description: str) -> JSONResponse:
    """An error from the token endpoint, as RFC 8628 section 3.5 names them."""
    return JSONResponse(
        {"error": error, "error_description": description}, status_code=400
    )


@router.post("/api/v1/device/code", response_model=DeviceCodeResponse)
async def request_device_code(
    body: DeviceCodeRequest, request: Request, db: Session = Depends(get_db)
):
    """Start the device flow: the client shows the user code and polls with the device code."""
    client_id = (body.client_id or DEFAULT_CLIENT_ID).strip()
    if client_id not in settings.device_flow_allowed_client_ids:
        return JSONResponse(
            {"error": "invalid_client", "error_description": "Unknown client_id"},
            status_code=400,
        )
    entry = DeviceCode(
        device_code=secrets.token_urlsafe(32),
        user_code=generate_user_code(),
        client_id=client_id,
        requested_from=request.client.host if request.client else None,
        requested_by_agent=(request.headers.get("user-agent") or "")[:255] or None,
        expires_at=datetime.utcnow() + timedelta(seconds=DEVICE_CODE_EXPIRY_SECONDS),
    )
    db.add(entry)
    db.commit()
    logger.info("Device code requested by %s for %s", entry.requested_from, client_id)
    return DeviceCodeResponse(
        device_code=entry.device_code,
        user_code=entry.user_code,
        verification_uri=f"{settings.GATEWAY_BASE_URL}/device",
        expires_in=DEVICE_CODE_EXPIRY_SECONDS,
        interval=POLL_INTERVAL_SECONDS,
    )


@router.get("/device", response_class=HTMLResponse)
async def device_page(request: Request, db: Session = Depends(get_db)):
    """Ask the signed-in person for the code their CLI shows."""
    user = session_user(request, db)
    if user is None or not _has_gateway_token(db, user):
        # Signing in stores the gateway token that approving hands over.
        return sign_in_redirect(request, target="/device")
    return _page(request, user)


@router.post("/device", response_class=HTMLResponse)
async def review_device_code(request: Request, db: Session = Depends(get_db)):
    """Show what asked for the code the person typed, to approve or deny."""
    user = session_user(request, db)
    if user is None:
        return sign_in_redirect(request, target="/device")
    form = await request.form()
    user_code = _normalize_user_code(form.get("user_code"))
    entry = _pending(db, user_code)
    if isinstance(entry, str):
        return _page(request, user, error=entry)
    if entry.approval_csrf_user_id not in (None, user.id):
        # Someone else is reviewing it; they alone may approve it.
        return _page(request, user, error="Someone else is reviewing this code.")
    entry.approval_csrf = secrets.token_urlsafe(32)
    entry.approval_csrf_user_id = user.id
    db.commit()
    return _page(
        request,
        user,
        entry=entry,
        client_name=_CLIENT_NAMES.get(entry.client_id, entry.client_id),
    )


@router.post("/device/approve", response_class=HTMLResponse)
async def decide_device_code(request: Request, db: Session = Depends(get_db)):
    """Approve or deny a code the person reviewed, with the token the review issued."""
    user = session_user(request, db)
    if user is None:
        return sign_in_redirect(request, target="/device")
    form = await request.form()
    action = form.get("action")
    if action not in ("approve", "deny"):
        return _page(request, user, error="Choose Approve or Deny.", status_code=400)
    entry = _pending(db, _normalize_user_code(form.get("user_code")))
    if isinstance(entry, str):
        return _page(request, user, error=entry)
    approval_csrf = form.get("approval_csrf") or ""
    if not (
        entry.approval_csrf
        and entry.approval_csrf_user_id == user.id
        and secrets.compare_digest(entry.approval_csrf, approval_csrf)
    ):
        return _page(
            request,
            user,
            error="This review has expired. Enter the code again.",
            status_code=403,
        )
    entry.approval_csrf = None
    if action == "deny":
        entry.denied = True
        db.commit()
        logger.info("%s denied a device code", user.username)
        return _page(request, user, success="Denied. You can close this window.")
    entry.user_id = user.id
    entry.approved = True
    db.commit()
    logger.info("%s approved a device code for %s", user.username, entry.client_id)
    return _page(
        request,
        user,
        success="Approved. You can close this window and return to your CLI.",
    )


@router.post("/api/v1/device/token")
async def poll_device_token(body: DeviceTokenRequest, db: Session = Depends(get_db)):
    """The person's gateway token, once they approve; one poll gets it."""
    if body.grant_type != DEVICE_GRANT_TYPE:
        return _token_error("unsupported_grant_type", "Use the device code grant")
    entry = (
        db.query(DeviceCode).filter(DeviceCode.device_code == body.device_code).first()
    )
    unready = _unready(db, entry)
    if unready is not None:
        return unready

    user = (
        db.query(User)
        .filter(
            User.id == entry.user_id,
            User.is_active.is_(True),
            User.is_service_account.is_(False),
        )
        .first()
    )
    tokens = await _gateway_tokens(db, user) if user is not None else None
    # Deleting the code is what hands the tokens over, so two polls can't both.
    consumed = (
        db.query(DeviceCode)
        .filter(DeviceCode.id == entry.id)
        .delete(synchronize_session=False)
    )
    db.commit()
    if consumed != 1:
        return _token_error("invalid_grant", "Unknown or used device code")
    if tokens is None:
        return _token_error("invalid_grant", "Sign in on the gateway again")
    access_token, refresh_token, expires_in = tokens
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin,
        },
    }


def _unready(db: Session, entry: Optional[DeviceCode]) -> Optional[JSONResponse]:
    """The poll's answer while ``entry`` has no tokens to hand over, else None."""
    if entry is None:
        return _token_error("invalid_grant", "Unknown or used device code")
    if entry.expires_at < datetime.utcnow() or entry.denied:
        db.delete(entry)
        db.commit()
        if entry.denied:
            return _token_error("access_denied", "The person denied the request")
        return _token_error("expired_token", "The device code expired")
    if not entry.approved or not entry.user_id:
        return _token_error("authorization_pending", "Waiting for the person")
    return None


def _pending(db: Session, user_code: str):
    """The pending device code ``user_code`` names, or why there is none."""
    entry = (
        db.query(DeviceCode).filter(DeviceCode.user_code == user_code).first()
        if user_code
        else None
    )
    if entry is None or entry.client_id not in settings.device_flow_allowed_client_ids:
        return "No such code. Check it against your CLI."
    if entry.expires_at < datetime.utcnow():
        return "This code has expired. Sign in from your CLI again."
    if entry.approved or entry.denied:
        return "This code has already been used."
    return entry


def _has_gateway_token(db: Session, user: User) -> bool:
    return (
        db.query(OAuthToken.id)
        .filter(
            OAuthToken.user_id == user.id,
            OAuthToken.service == GATEWAY_TOKEN_SERVICE,
        )
        .first()
        is not None
    )


async def _gateway_tokens(db: Session, user: User) -> Optional[tuple]:
    """The person's stored gateway tokens and their lifetime, or None."""
    stored = (
        db.query(OAuthToken)
        .filter(
            OAuthToken.user_id == user.id,
            OAuthToken.service == GATEWAY_TOKEN_SERVICE,
        )
        .first()
    )
    if stored is None:
        return None
    encryption = await get_token_encryption()
    access_token = encryption.decrypt(stored.access_token_encrypted)
    if access_token is None:
        logger.error("The gateway token of %s can't be decrypted", user.username)
        return None
    refresh_token = (
        encryption.decrypt(stored.refresh_token_encrypted)
        if stored.refresh_token_encrypted
        else None
    )
    expires_in = int((stored.expires_at - datetime.utcnow()).total_seconds())
    return access_token, refresh_token, max(expires_in, 0)
