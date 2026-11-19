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
Service-account-only API — retrieve a human user's OAuth tokens.

Only callers authenticated as a registered service account (is_service_account=True)
are allowed.  Human user JWTs are rejected with 403.

Endpoint
--------
POST /api/sa/user-tokens

Request body (JSON):
    {
        "event": <Bolt event dict with user, channel>,
        "app_name": "<display name shown in approval message>",
        "slack_signature": "v0=<hmac_sha256_hex>"
    }

``slack_signature`` is an HMAC of the body with the signing secret in the
caller's ``additional_config.slack_signing_secret``; ``fetch_slack_user_token``
in ``mcp_gateway_sdk`` makes it. It proves no more than the caller's token: the
person's approval in Slack is what protects them.

The bot calls this endpoint repeatedly. MCP Gateway drives an approval state machine:
- User must have an active ``slack_gateway`` session (via ``/gravitino-mcp login``);
  otherwise the request fails immediately with 404.
- No active approval → create pending, send ephemeral approval in channel → 202
- Pending → 202
- Approved (within TTL) → 200 with token
- Denied or expired records are ignored for lookup; expired rows are periodically
  deleted by a background task. A new approval request is created on next call when
  none is active.

Returns the decrypted access_token for the user for service ``slack_gateway``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.orm import Session

from mcp_gateway_sdk import verify_user_tokens_body

from ..audit import AuditLogger
from ..config import settings
from ..database import get_db
from ..models import ServiceAccountCredentials, SlackTokenApproval, User
from ..oauth.token_manager import SLACK_TOKEN_SERVICE, TokenManager
from ..oauth_auth import get_user_from_bearer_token
from ..slack_service import (
    get_slack_web_client,
    lookup_slack_user_email,
    send_token_approval_message,
)

logger = logging.getLogger(__name__)


def _require_enabled() -> None:
    """Answer as if the route did not exist unless SLACK_USER_TOKENS_ENABLED is set."""
    if not settings.SLACK_USER_TOKENS_ENABLED:
        raise HTTPException(status_code=404, detail="Not Found")


router = APIRouter(
    prefix="/api/sa",
    tags=["Service Account — User Tokens"],
    dependencies=[Depends(_require_enabled)],
)

_TOKEN_RETRIEVAL_KEY = "token_retrieval_services"
_SLACK_SIGNING_SECRET_KEY = "slack_signing_secret"
_APPROVAL_TTL = timedelta(minutes=30)
_SERVICE = SLACK_TOKEN_SERVICE
_SEND_MAX_ATTEMPTS = 3
_SEND_BASE_DELAY = 1.0  # seconds; doubles each attempt: 1s, 2s, 4s
_LOGIN_REQUIRED_DETAIL = "No user token exists. Ask the user to log in to MCP Gateway using /gravitino-mcp login."


# ---------------------------------------------------------------------------
# Dependency: caller must be a service account
# ---------------------------------------------------------------------------


def _require_service_account(
    request: Request,
    current_user: User = Depends(get_user_from_bearer_token),
) -> User:
    """
    Allow only service accounts.

    Human user JWTs (where is_service_account is not set on request.state)
    receive 403 so they cannot impersonate other users via this endpoint.
    """
    if not getattr(request.state, "is_service_account", False):
        raise HTTPException(
            status_code=403,
            detail="This endpoint is restricted to registered service accounts.",
        )
    return current_user


# ---------------------------------------------------------------------------
# Authorization: verify SA's additional_config grants token retrieval
# ---------------------------------------------------------------------------


def _get_sa_credentials(caller: User, db: Session) -> ServiceAccountCredentials:
    sa_creds = (
        db.query(ServiceAccountCredentials)
        .filter(ServiceAccountCredentials.service_account_id == caller.id)
        .first()
    )
    if not sa_creds:
        logger.warning(
            "SA '%s' (id=%s) has no credentials row — denying token retrieval",
            caller.username,
            caller.id,
        )
        raise HTTPException(
            status_code=403,
            detail="Service account has no credentials configured.",
        )
    return sa_creds


def _check_sa_token_retrieval_authorization(
    caller: User,
    service: str,
    db: Session,
) -> ServiceAccountCredentials:
    """
    Verify the calling service account is explicitly authorized to retrieve
    tokens for *service* via its ``additional_config``.

    The SA's ``ServiceAccountCredentials.additional_config`` must contain:

        { "token_retrieval_services": "slack_gateway" }

    If the key is absent, empty, or does not match *service*, the call is
    rejected with 403.
    """
    sa_creds = _get_sa_credentials(caller, db)

    config: dict = sa_creds.additional_config or {}
    allowed_service: str = (config.get(_TOKEN_RETRIEVAL_KEY) or "").strip()

    if not allowed_service:
        logger.warning(
            "SA '%s' denied token retrieval for service '%s': "
            "'%s' not set in additional_config",
            caller.username,
            service,
            _TOKEN_RETRIEVAL_KEY,
        )
        raise HTTPException(
            status_code=403,
            detail=(
                f"Service account '{caller.username}' is not authorized to retrieve "
                f"tokens. Set '{_TOKEN_RETRIEVAL_KEY}' in its additional_config."
            ),
        )

    if service != allowed_service:
        logger.warning(
            "SA '%s' denied token retrieval for service '%s': allowed service is '%s'",
            caller.username,
            service,
            allowed_service,
        )
        raise HTTPException(
            status_code=403,
            detail=(
                f"Service account '{caller.username}' is not authorized to retrieve "
                f"tokens for service '{service}'. "
                f"Allowed: '{allowed_service}'."
            ),
        )

    return sa_creds


def _get_slack_signing_secret(sa_creds: ServiceAccountCredentials) -> str:
    config: dict = sa_creds.additional_config or {}
    secret = (config.get(_SLACK_SIGNING_SECRET_KEY) or "").strip()
    if not secret:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Service account is not configured for Slack request verification. "
                f"Set '{_SLACK_SIGNING_SECRET_KEY}' in additional_config."
            ),
        )
    return secret


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class UserTokensRequest(BaseModel):
    event: dict
    app_name: str = Field(..., min_length=1)
    slack_signature: str


class UserTokenEntry(BaseModel):
    service: str
    access_token: str


class UserTokensResponse(BaseModel):
    email: str
    token: UserTokenEntry


class UserApprovalPending(BaseModel):
    status: str = "pending"


def _extract_slack_event_fields(event: dict) -> tuple[str, str]:
    """Return (slack_user_id, channel) from a Bolt event dict."""
    event_type = event.get("type")
    if event_type not in ("message", "app_mention"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported Slack event type '{event_type}'",
        )

    slack_user_id = event.get("user")
    if not slack_user_id or not isinstance(slack_user_id, str):
        raise HTTPException(status_code=400, detail="Missing user in Slack event")

    channel = event.get("channel")
    if not channel or not isinstance(channel, str):
        raise HTTPException(status_code=400, detail="Missing channel in Slack event")

    return slack_user_id, channel


async def _resolve_slack_user_email(slack_user_id: str) -> tuple[str, str]:
    """Return ``(email_norm, lookup_email)``. Raises HTTPException on lookup failure."""
    lookup = await lookup_slack_user_email(slack_user_id)
    if lookup.user_not_found:
        raise HTTPException(
            status_code=404,
            detail=f"No user found with slack user id '{slack_user_id}'.",
        )
    if lookup.email_missing or not lookup.email:
        raise HTTPException(
            status_code=404,
            detail=f"No email found for user with slack user id '{slack_user_id}'.",
        )
    email_norm = lookup.email.strip().lower()
    return email_norm, lookup.email


async def _send_approval_request(
    channel: str, slack_user_id: str, app_name: str, approval: SlackTokenApproval
) -> bool:
    """Ask the person in Slack to approve, trying a few times; False if Slack refused."""
    slack_client = await get_slack_web_client()
    for attempt in range(1, _SEND_MAX_ATTEMPTS + 1):
        if await send_token_approval_message(
            slack_client,
            channel=channel,
            slack_user_id=slack_user_id,
            app_name=app_name,
            approval_id=approval.id,
        ):
            return True
        if attempt < _SEND_MAX_ATTEMPTS:
            delay = _SEND_BASE_DELAY * (2 ** (attempt - 1))
            logger.warning(
                "Approval message send attempt %d/%d failed, retrying in %.0fs",
                attempt,
                _SEND_MAX_ATTEMPTS,
                delay,
            )
            await asyncio.sleep(delay)
    return False


async def _get_slack_user_oauth_token(
    db: Session,
    *,
    email_norm: str,
    lookup_email: str,
    retrieve: bool,
    request: Request | None = None,
    caller: User | None = None,
) -> UserTokensResponse | None:
    """
    Verify or return the user's ``slack_gateway`` OAuth token.

    When *retrieve* is False, returns None after a successful login check.
    When *retrieve* is True, returns the token response and records an audit entry.
    """
    user = User.find_person(db, email_norm)
    if not user:
        raise HTTPException(
            status_code=404,
            detail=f"No active human user found with email '{lookup_email}'.",
        )

    token_manager = TokenManager(db)
    access_token = await token_manager.get_user_oauth_token(
        user.id,
        _SERVICE,
        gateway_token=None,
        auto_connect=False,
    )
    if not access_token:
        raise HTTPException(status_code=404, detail=_LOGIN_REQUIRED_DETAIL)

    if not retrieve:
        return None

    if request is None or caller is None:
        raise RuntimeError("request and caller are required when retrieve=True")

    async with AuditLogger.track_tool_call(
        db=db,
        user=caller,
        service="mcp-gateway",
        tool_name="get_user_tokens",
        method="POST /api/sa/user-tokens",
        request_params={"email": email_norm, "service": _SERVICE},
        request=request,
    ) as tracker:
        response = UserTokensResponse(
            email=user.email,
            token=UserTokenEntry(service=_SERVICE, access_token=access_token),
        )
        tracker.set_response({"target_user": user.email, "service": _SERVICE})
        return response


def _get_active_approval(
    db: Session,
    *,
    sa_id: int,
    slack_user_id: str,
    app_name: str,
) -> SlackTokenApproval | None:
    now = datetime.utcnow()
    return (
        db.query(SlackTokenApproval)
        .filter(
            SlackTokenApproval.requesting_sa_id == sa_id,
            SlackTokenApproval.slack_user_id == slack_user_id,
            SlackTokenApproval.app_name == app_name,
            SlackTokenApproval.status.notin_(["denied", "failed"]),
            SlackTokenApproval.expires_at > now,
        )
        .order_by(SlackTokenApproval.created_at.desc())
        .first()
    )


def _create_pending_approval(
    db: Session,
    *,
    sa_id: int,
    slack_user_id: str,
    app_name: str,
) -> SlackTokenApproval:
    approval = SlackTokenApproval(
        id=str(uuid.uuid4()),
        requesting_sa_id=sa_id,
        slack_user_id=slack_user_id,
        app_name=app_name,
        status="pending",
        expires_at=datetime.utcnow() + _APPROVAL_TTL,
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)
    return approval


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@router.post(
    "/user-tokens",
    summary="Retrieve a user's OAuth tokens through authorized service accounts only",
    description=(
        "Submit the Slack Bolt event and app display name. "
        "Restricted to authenticated service accounts; human callers receive 403. "
        "Returns 202 while waiting for user approval, 200 with token once approved."
    ),
    responses={
        200: {"model": UserTokensResponse},
        202: {"model": UserApprovalPending},
    },
)
async def get_user_tokens(  # pylint: disable=too-many-locals
    request: Request,
    caller: User = Depends(_require_service_account),
    db: Session = Depends(get_db),
):
    raw_body = await request.body()
    sa_creds = _check_sa_token_retrieval_authorization(caller, _SERVICE, db)
    signing_secret = _get_slack_signing_secret(sa_creds)

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail="Invalid JSON body") from exc

    try:
        body = UserTokensRequest.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    try:
        verify_user_tokens_body(body.model_dump(), signing_secret)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    slack_user_id, channel = _extract_slack_event_fields(body.event)
    app_name = body.app_name.strip()

    approval = _get_active_approval(
        db,
        sa_id=caller.id,
        slack_user_id=slack_user_id,
        app_name=app_name,
    )

    if not approval:
        email_norm, lookup_email = await _resolve_slack_user_email(slack_user_id)
        await _get_slack_user_oauth_token(
            db,
            email_norm=email_norm,
            lookup_email=lookup_email,
            retrieve=False,
        )

    if not approval:
        approval = _create_pending_approval(
            db,
            sa_id=caller.id,
            slack_user_id=slack_user_id,
            app_name=app_name,
        )
        # The caller picks its display name, so the person is also shown which
        # registered service account would get their token.
        shown_as = f"{app_name} (service account {caller.username})"
        if not await _send_approval_request(channel, slack_user_id, shown_as, approval):
            approval.status = "failed"
            db.commit()
            raise HTTPException(
                status_code=503,
                detail="Could not deliver approval message via Slack. Please try again.",
            )

        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content=UserApprovalPending().model_dump(),
        )

    if approval.status == "pending":
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content=UserApprovalPending().model_dump(),
        )

    if approval.status != "approved":
        raise HTTPException(status_code=403, detail="Token request was not approved.")

    email_norm, lookup_email = await _resolve_slack_user_email(slack_user_id)
    return await _get_slack_user_oauth_token(
        db,
        email_norm=email_norm,
        lookup_email=lookup_email,
        retrieve=True,
        request=request,
        caller=caller,
    )
