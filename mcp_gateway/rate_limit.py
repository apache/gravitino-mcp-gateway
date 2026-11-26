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

"""Rate limits on calls to MCP servers.

Three scopes are limited, each by requests per window and by calls in flight:

- ``user``: one person's calls to one server;
- ``server``: everyone's calls to one server;
- ``tool``: one person's calls of one tool (``tools/call`` only).

Requests per window are counted in the database (fixed windows), so the limit
holds however many replicas run. Calls in flight are counted in the process:
a count in the database would outlive a replica that died mid-call, so the
concurrent limits hold per replica. A limit of 0 is no limit. A server's
``rate_limits`` in the catalog overrides the ``RATE_LIMIT_*`` settings.
"""

import hashlib
import logging
import time
from dataclasses import dataclass
from threading import Lock
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import settings
from .database import SessionLocal
from .models import MCPCatalog, RateLimitWindow

logger = logging.getLogger(__name__)

# Windows older than this are of no use; the longest is an hour.
_KEEP_SECONDS = 7200


class ToolLimits(BaseModel):
    """Limits for one tool; fields left out use the server's."""

    model_config = ConfigDict(extra="forbid")

    requests: Optional[int] = Field(None, ge=0)
    concurrent: Optional[int] = Field(None, ge=0)


class RateLimitOverrides(BaseModel):
    """What a server's ``rate_limits`` may hold; fields left out use the defaults."""

    model_config = ConfigDict(extra="forbid")

    user_requests: Optional[int] = Field(None, ge=0)
    server_requests: Optional[int] = Field(None, ge=0)
    tool_requests: Optional[int] = Field(None, ge=0)
    user_concurrent: Optional[int] = Field(None, ge=0)
    server_concurrent: Optional[int] = Field(None, ge=0)
    tool_concurrent: Optional[int] = Field(None, ge=0)
    tools: Optional[Dict[str, ToolLimits]] = None


def validated_overrides(value: Optional[dict]) -> Optional[dict]:
    """``value`` checked and cleaned of unset fields, for a server's rate_limits."""
    if value is None:
        return None
    return RateLimitOverrides.model_validate(value).model_dump(exclude_none=True)


class RateLimited(Exception):
    """A call over a limit: which scope's, and how many seconds until it may retry."""

    def __init__(self, scope: str, retry_after: int):
        self.scope = scope
        self.retry_after = max(1, retry_after)
        self.message = (
            f"Rate limit reached ({scope}). Retry in {self.retry_after} seconds."
        )
        super().__init__(self.message)


@dataclass(frozen=True)
class _Limit:
    scope: str
    key: str
    requests: int
    concurrent: int


def _now() -> float:
    return time.time()


def _limits(mcp: MCPCatalog, user_id: int, tool: Optional[str]) -> List[_Limit]:
    """The limits that apply to ``user_id``'s call of ``tool`` on ``mcp``."""
    overrides = mcp.rate_limits or {}

    def pick(scope: str, kind: str, tool_limits: Optional[dict] = None) -> int:
        """The tool's own limit, else the server's, else the default."""
        for value in ((tool_limits or {}).get(kind), overrides.get(f"{scope}_{kind}")):
            if value is not None:
                return value
        return getattr(settings, f"RATE_LIMIT_{scope.upper()}_{kind.upper()}")

    service = mcp.service_id
    limits = [
        _Limit(
            "user",
            f"user:{user_id}:{service}",
            pick("user", "requests"),
            pick("user", "concurrent"),
        ),
        _Limit(
            "server",
            f"server:{service}",
            pick("server", "requests"),
            pick("server", "concurrent"),
        ),
    ]
    if tool is not None:
        # A hash, since a tool's name is the caller's and may be long.
        digest = hashlib.sha256(tool.encode()).hexdigest()[:32]
        tool_limits = (overrides.get("tools") or {}).get(tool, {})
        limits.append(
            _Limit(
                "tool",
                f"tool:{user_id}:{service}:{digest}",
                pick("tool", "requests", tool_limits),
                pick("tool", "concurrent", tool_limits),
            )
        )
    return limits


# Calls in flight in this process, by key.
_in_flight: Dict[str, int] = {}
_in_flight_lock = Lock()


class Admission:
    """A call let through; release it when the call ends."""

    def __init__(self, keys: List[str]):
        self._keys = keys

    def release(self) -> None:
        """End the call's hold on the in-flight limits; harmless to repeat."""
        keys, self._keys = self._keys, []
        with _in_flight_lock:
            _release_keys(keys)


def _hit(db: Session, key: str, window_start: int, limit: int) -> bool:
    """Count one call in the window; False if the window is already full."""
    for _ in range(2):
        counted = db.execute(
            update(RateLimitWindow)
            .where(
                RateLimitWindow.key == key,
                RateLimitWindow.window_start == window_start,
                RateLimitWindow.count < limit,
            )
            .values(count=RateLimitWindow.count + 1)
        ).rowcount
        if counted:
            db.commit()
            return True
        if db.get(RateLimitWindow, (key, window_start)) is not None:
            db.rollback()
            return False
        db.add(RateLimitWindow(key=key, window_start=window_start, count=1))
        try:
            db.commit()
            return True
        except IntegrityError:
            # Another replica counted first; count on top of its row.
            db.rollback()
    return False


def _count_request(limit: _Limit) -> None:
    window = settings.RATE_LIMIT_WINDOW_SECONDS
    now = int(_now())
    start = now - now % window
    try:
        # A session of its own: the request's holds no transaction of the counter's.
        with SessionLocal() as db:
            counted = _hit(db, limit.key, start, limit.requests)
    except Exception:  # pylint: disable=broad-exception-caught
        # A limiter that fails must not take the gateway down with it.
        logger.exception("Could not count calls for %s", limit.key)
        return
    if not counted:
        raise RateLimited(limit.scope, start + window - now)


def admit(user_id: int, mcp: MCPCatalog, tool: Optional[str] = None) -> Admission:
    """Let ``user_id``'s call of ``tool`` (None for other methods) on ``mcp`` through.

    Raises RateLimited when a limit is reached. The caller releases what it
    returns once the call ends.
    """
    limits = _limits(mcp, user_id, tool)
    held: List[str] = []
    with _in_flight_lock:
        for limit in limits:
            if not limit.concurrent:
                continue
            if _in_flight.get(limit.key, 0) >= limit.concurrent:
                _release_keys(held)
                raise RateLimited(limit.scope, 1)
            _in_flight[limit.key] = _in_flight.get(limit.key, 0) + 1
            held.append(limit.key)
    admission = Admission(held)
    try:
        for limit in limits:
            if limit.requests:
                _count_request(limit)
    except RateLimited:
        admission.release()
        raise
    return admission


def _release_keys(keys: List[str]) -> None:
    """Undo holds taken under ``_in_flight_lock``."""
    for key in keys:
        _in_flight[key] -= 1
        if not _in_flight[key]:
            del _in_flight[key]


def purge_windows(db: Session) -> int:
    """Delete the windows that are over for good, and return how many."""
    return (
        db.query(RateLimitWindow)
        .filter(RateLimitWindow.window_start < int(_now()) - _KEEP_SECONDS)
        .delete(synchronize_session=False)
    )
