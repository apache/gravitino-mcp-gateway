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

"""Gravitino's service admins are the gateway's admins too.

With GRAVITINO_URI set, the gateway asks Gravitino's GET /api/authn/me whether a
person is a service admin, with the token it sends Gravitino's MCP server for
them, forwarded or exchanged. People in ADMIN_EMAILS stay admins either way.
"""

import logging
import time
from typing import Optional

import httpx
from sqlalchemy.orm import Session

from .catalog_defaults import GRAVITINO_SERVICE_ID
from .config import settings
from .models import User
from .oauth.token_manager import TokenManager

logger = logging.getLogger(__name__)

# Gravitino's answer is reused for this long, so a change to its service admins
# takes up to this long to reach the gateway.
_ANSWER_SECONDS = 300
# When Gravitino can't answer, only ADMIN_EMAILS count, and it is asked again
# after this long rather than on every request.
_RETRY_SECONDS = 30
# User ID -> (when the answer expires, the answer)
_answers: dict[int, tuple[float, bool]] = {}


def reset_cache() -> None:
    """Forget Gravitino's answers, so the next check asks again."""
    _answers.clear()


async def is_gravitino_service_admin(
    db: Session, user: User, token: Optional[str]
) -> bool:
    """Whether Gravitino says ``user`` is a service admin.

    ``token`` is the person's token from the identity provider. Without
    GRAVITINO_URI, a token, or an answer from Gravitino, the answer is no.
    """
    if not settings.GRAVITINO_URI or not token:
        return False
    now = time.monotonic()
    cached = _answers.get(user.id)
    if cached and now < cached[0]:
        return cached[1]
    try:
        gravitino_token = (
            await TokenManager(db).get_user_oauth_token(
                user.id, GRAVITINO_SERVICE_ID, gateway_token=token
            )
            or token
        )
        async with httpx.AsyncClient(
            timeout=5.0, verify=settings.upstream_tls_verify
        ) as client:
            response = await client.get(
                f"{settings.GRAVITINO_URI.rstrip('/')}/api/authn/me",
                headers={
                    "Authorization": f"Bearer {gravitino_token}",
                    "Accept": "application/vnd.gravitino.v1+json",
                },
            )
        response.raise_for_status()
        answer = response.json().get("serviceAdmin") is True
    except (httpx.HTTPError, ValueError) as e:
        logger.warning(
            "Could not ask Gravitino whether %s is a service admin: %s", user.email, e
        )
        _answers[user.id] = (now + _RETRY_SECONDS, False)
        return False
    _answers[user.id] = (now + _ANSWER_SECONDS, answer)
    return answer
