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

"""The gateway's session cookie, for its own pages.

Browsers keep a cookie whose name starts with __Host- only if this host set it,
over HTTPS, with Path=/ and no Domain, so a sibling subdomain or another local
port cannot plant one. A planted session would put another person's browser in
the attacker's session, where anything the person connects is saved for the
attacker. Browsers accept the prefix only on Secure cookies, so a cookie that
can't be Secure keeps its plain name.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode, urlsplit

import jwt
from fastapi import Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from .config import settings
from .models import User

SESSION_TYPE = "gateway_session"
SESSION_MAX_AGE = 8 * 3600


def cookie_name(name: str, secure: bool) -> str:
    """The name to give a cookie, with the __Host- prefix when it is Secure."""
    return f"__Host-{name}" if secure else name


def session_cookie_name() -> str:
    """The session cookie's name; it is Secure unless DEBUG is on."""
    return cookie_name("session", not settings.DEBUG)


def session_user_id(request: Request) -> Optional[int]:
    """The user ID in the session cookie, or None without a valid one.

    Only session tokens count: other tokens the gateway signs with the same key,
    such as login states, are not sessions.
    """
    token = request.cookies.get(session_cookie_name())
    if not token:
        return None
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
    except jwt.PyJWTError:
        return None
    if payload.get("type") != SESSION_TYPE:
        return None
    return payload.get("user_id")


def session_user(request: Request, db: Session) -> Optional[User]:
    """The active user the session cookie belongs to, or None."""
    user_id = session_user_id(request)
    if user_id is None:
        return None
    return db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()


def set_session_cookie(response: Response, user_id: int) -> None:
    """Start a session for ``user_id`` in the browser the response goes to."""
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "user_id": user_id,
            "type": SESSION_TYPE,
            "iat": now,
            "exp": now + timedelta(seconds=SESSION_MAX_AGE),
        },
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    response.set_cookie(
        key=session_cookie_name(),
        value=token,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="lax",
        max_age=SESSION_MAX_AGE,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=session_cookie_name(),
        path="/",
        secure=not settings.DEBUG,
        httponly=True,
        samesite="lax",
    )


def sign_in_redirect(
    request: Request, target: Optional[str] = None
) -> RedirectResponse:
    """Send a signed-out browser to sign in, and then back to ``target``, by
    default the page it asked for."""
    if target is None:
        target = request.url.path
        if request.url.query:
            target += f"?{request.url.query}"
    return RedirectResponse(
        f"/auth/oauth/login?{urlencode({'next': target})}", status_code=302
    )


def safe_return_url(value: Optional[str]) -> Optional[str]:
    """``value`` if it is a page of this gateway or of an origin it serves, else None.

    The web UI sends people here and asks to have them back; any other address
    would make the gateway an open redirect.
    """
    if not value:
        return None
    if value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    origin = f"{parts.scheme}://{parts.netloc}"
    allowed = {o.strip().rstrip("/") for o in settings.CORS_ALLOWED_ORIGINS.split(",")}
    return value if origin in allowed - {"*", ""} else None
