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
Downstream MCP auth helpers: effective auth strategy and credential forwarding.
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from ..config import settings
from ..models import MCPCatalog, ServiceAccountCredentials, User
from .secret_storage import get_secret_storage
from .token_encryption import SECRET_NAME as ENCRYPTION_KEY_SECRET

logger = logging.getLogger(__name__)

# Keys in ``ServiceAccountCredentials.additional_config`` JSON (per MCP service id).
DOWNSTREAM_CREDENTIALS = "downstream_credentials"
SECRET_REF = "secret_ref"
AUTH_HEADER_TYPE = "auth_header_type"
USERNAME = "username"

AUTH_HEADER_BASIC = "basic"
AUTH_HEADER_BEARER = "bearer"
_VALID_AUTH_HEADER_TYPES = frozenset({AUTH_HEADER_BASIC, AUTH_HEADER_BEARER})


def secret_ref_allowed(secret_ref: str) -> bool:
    """Whether a service account may forward the secret named ``secret_ref``.

    The gateway's identity can read secrets other than service accounts', such
    as its own encryption key or, in a shared cloud account, other services'.
    An admin must not be able to read those by naming them here.
    """
    return secret_ref != ENCRYPTION_KEY_SECRET and secret_ref.startswith(
        settings.SERVICE_ACCOUNT_SECRET_PREFIX
    )


def refused_secret_refs(additional_config: Optional[Dict[str, Any]]) -> list[str]:
    """The secret names in a service account's config that it may not forward."""
    forwarding = (additional_config or {}).get(DOWNSTREAM_CREDENTIALS)
    if not isinstance(forwarding, dict):
        return []
    refs = [cfg.get(SECRET_REF) for cfg in forwarding.values() if isinstance(cfg, dict)]
    return [
        ref
        for ref in refs
        if isinstance(ref, str) and ref.strip() and not secret_ref_allowed(ref.strip())
    ]


def effective_auth_type(mcp: MCPCatalog, user: User) -> str:
    """Pick downstream auth strategy.

    Service-account callers use ``mcp.service_auth_type`` when set; otherwise fall
    back to ``mcp.auth_type``. Human callers always use ``mcp.auth_type``.
    """
    service_auth_type = getattr(mcp, "service_auth_type", None)
    if user.is_service_account and service_auth_type and str(service_auth_type).strip():
        return str(service_auth_type).strip()
    return mcp.auth_type


async def build_credential_forward_headers(  # pylint: disable=too-many-return-statements
    db: Session, user: User, service: str
) -> Optional[Dict[str, str]]:
    """Resolve Authorization header from SA ``additional_config`` + ``DOWNSTREAM_CREDENTIALS``.

    ``SECRET_REF`` is passed to :meth:`SecretStorage.get_secret` — for GCP that is the
    short secret **id** inside ``GCP_PROJECT_ID`` (not a full ``projects/…`` resource path).
    """
    if not user.is_service_account:
        return None

    sa = (
        db.query(ServiceAccountCredentials)
        .filter(ServiceAccountCredentials.service_account_id == user.id)
        .first()
    )
    if not sa:
        return None

    cfg_any: Any = (
        (sa.additional_config or {}).get(DOWNSTREAM_CREDENTIALS, {}).get(service)
    )
    if not isinstance(cfg_any, dict):
        return None

    cfg: Dict[str, Any] = cfg_any

    secret_ref = cfg.get(SECRET_REF)
    if not secret_ref or not isinstance(secret_ref, str) or not secret_ref.strip():
        return None

    auth_raw = cfg.get(AUTH_HEADER_TYPE)
    if not auth_raw or not isinstance(auth_raw, str) or not auth_raw.strip():
        return None
    header_type = auth_raw.strip().lower()
    if header_type not in _VALID_AUTH_HEADER_TYPES:
        logger.warning(
            "credential_forward: invalid %s=%r for user_id=%s service=%s",
            AUTH_HEADER_TYPE,
            auth_raw,
            user.id,
            service,
        )
        return None

    if header_type == AUTH_HEADER_BASIC:
        username = cfg.get(USERNAME)
        if not username or not isinstance(username, str) or not username.strip():
            return None

    if not secret_ref_allowed(secret_ref.strip()):
        logger.warning(
            "credential_forward: refused secret %r for user_id=%s service=%s; "
            "names must start with SERVICE_ACCOUNT_SECRET_PREFIX",
            secret_ref[:64],
            user.id,
            service,
        )
        return None

    storage = get_secret_storage()
    credential = await storage.get_secret(secret_ref.strip())
    if not credential:
        logger.warning(
            "credential_forward: could not fetch secret for user_id=%s service=%s ref=%s",
            user.id,
            service,
            secret_ref[:64],
        )
        return None

    if header_type == AUTH_HEADER_BASIC:
        username = cfg[USERNAME].strip()
        encoded = base64.b64encode(f"{username}:{credential}".encode()).decode()
        return {"Authorization": f"Basic {encoded}"}
    return {"Authorization": f"Bearer {credential}"}
