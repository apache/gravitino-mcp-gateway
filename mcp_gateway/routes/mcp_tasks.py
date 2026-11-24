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

"""MCP tasks (spec 2025-11-25) through the gateway.

A server chooses its task IDs, so the gateway cannot tell whose a task is. It
hands clients a signed token in place of the server's ID, holding the person,
the server and the server's ID. Like a session ID, the token keeps no state at
the gateway, and any replica can check it. A task ID that is not the caller's
for this server is refused as unknown, before the server is called.
"""

import copy
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt as pyjwt

from ..config import settings

# Methods that act on one task. tasks/list is not offered: with a shared
# upstream identity the server cannot say which tasks are the caller's.
TASK_METHODS = frozenset({"tasks/get", "tasks/result", "tasks/cancel"})
RELATED_TASK = "io.modelcontextprotocol/related-task"

# A token outlives the task by no more than this, or lasts this long when the
# server gives the task no lifetime.
_DEFAULT_TTL = 86400  # 24 hours


def _lifetime(task: dict) -> timedelta:
    """How long a token for ``task`` is good: the task's ttl (milliseconds), capped."""
    ttl = task.get("ttl")
    if isinstance(ttl, (int, float)) and not isinstance(ttl, bool) and ttl > 0:
        return min(timedelta(milliseconds=ttl), timedelta(seconds=_DEFAULT_TTL))
    return timedelta(seconds=_DEFAULT_TTL)


def _wrap(user_id: int, service: str, task: dict) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "u": user_id,
        "s": service,
        "t": task["taskId"],
        "iat": now,
        "exp": now + _lifetime(task),
    }
    return pyjwt.encode(
        claims, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )


def unwrap_task_id(token: Any, user_id: int, service: str) -> Optional[str]:
    """The server's ID for ``token``, or None if it is not a task of this person on this server."""
    if not isinstance(token, str):
        return None
    try:
        claims = pyjwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
    except pyjwt.InvalidTokenError:
        return None
    upstream_id = claims.get("t")
    if (claims.get("u"), claims.get("s")) != (user_id, service):
        return None
    return upstream_id if isinstance(upstream_id, str) else None


def wrap_task_ids(message: dict, user_id: int, service: str, method: str) -> dict:
    """``message``, the server's reply to ``method``, with its task IDs replaced by tokens.

    A task-creating ``tools/call`` reply holds the task in ``result.task``;
    ``tasks/get`` and ``tasks/cancel`` reply with the task as the result; any
    reply may name its task in ``result._meta``. A task the server sends
    without an ID is dropped, so that no server ID reaches the client.
    """
    result = message.get("result")
    if not isinstance(result, dict):
        return message
    result = copy.deepcopy(result)
    if method in ("tasks/get", "tasks/cancel") and isinstance(
        result.get("taskId"), str
    ):
        result["taskId"] = _wrap(user_id, service, result)
    task = result.get("task")
    if isinstance(task, dict):
        if isinstance(task.get("taskId"), str):
            task["taskId"] = _wrap(user_id, service, task)
        else:
            del result["task"]
    meta = result.get("_meta")
    related = meta.get(RELATED_TASK) if isinstance(meta, dict) else None
    if isinstance(related, dict) and isinstance(related.get("taskId"), str):
        related["taskId"] = _wrap(user_id, service, related)
    return {**message, "result": result}
