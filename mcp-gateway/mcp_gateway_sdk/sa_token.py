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
Workload identity tokens with which service accounts call the MCP gateway.

The token's audience is the gateway's own URL, which the gateway always
accepts, unless the caller names another. It is never taken from the gateway's
discovery documents: whoever answers those could otherwise choose a token for
another service, such as AWS STS.
"""

from __future__ import annotations

import os
import time
from typing import Any, Literal, Optional
from urllib.parse import urlencode, urlsplit

import jwt
import requests

from .aws_token import get_aws_identity_token

SaTokenSource = Literal["google", "aws"]

GCP_IDENTITY_PATH = "metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
GCP_METADATA_FLAVOR = "Google"
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class GatewaySATokenError(Exception):
    """Failed to fetch an identity token from the GCE metadata server."""


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(
            (token or "").strip(),
            options={"verify_signature": False},
            algorithms=["RS256", "HS256"],
        )
    except jwt.PyJWTError as exc:
        raise GatewaySATokenError(f"Failed to decode JWT: {exc}") from exc


def _resolve_gateway_url(gateway_env: Optional[str]) -> str:
    """Return the gateway base URL.

    *gateway_env* is the gateway URL, ``"local"`` for a gateway on this machine,
    or ``None`` to read ``MCP_GATEWAY_URL``. Only a gateway on this machine may
    use plain http, since the token is a credential.
    """
    if gateway_env is None:
        gateway_env = os.getenv("MCP_GATEWAY_URL", "").strip()
        if not gateway_env:
            raise ValueError("No gateway URL given and MCP_GATEWAY_URL is not set")
    if gateway_env == "local":
        return "http://localhost:8000"
    parts = urlsplit(gateway_env)
    if parts.scheme == "https" or (
        parts.scheme == "http" and parts.hostname in _LOCAL_HOSTS
    ):
        return gateway_env.rstrip("/")
    raise ValueError(f"The gateway must be an https URL: {gateway_env!r}")


def _get_google_identity_token(
    audience: str,
    timeout: float,
) -> str:
    query = urlencode({"audience": audience, "format": "full"})
    url = f"http://{GCP_IDENTITY_PATH}?{query}"

    try:
        response = requests.get(
            url,
            headers={"Metadata-Flavor": GCP_METADATA_FLAVOR},
            timeout=timeout,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise GatewaySATokenError(
            f"GCP metadata identity request failed for audience={audience!r}: {exc}"
        ) from exc

    token = (response.text or "").strip()
    if not token:
        raise GatewaySATokenError(
            "GCP metadata server returned an empty identity token"
        )
    return token


def get_gateway_sa_token(
    gateway_env: Optional[str] = None,
    *,
    source: SaTokenSource = "google",
    audience: Optional[str] = None,
    timeout: float = 10.0,
) -> str:
    """
    Fetch a service-account JWT for MCP Gateway.

    *gateway_env* is the gateway URL, ``"local"``, or ``None`` to read
    ``MCP_GATEWAY_URL``. The token's audience is the gateway's URL, or
    *audience*, such as the gateway's JWT_AUDIENCE.

    ``source="google"`` — GCP metadata identity token (GCE / GKE workload identity).
    ``source="aws"`` — EKS in-cluster Kubernetes TokenRequest (see ``aws_token``).
    """
    audience = audience or _resolve_gateway_url(gateway_env)

    if source == "aws":
        return get_aws_identity_token(audience, timeout=timeout)

    return _get_google_identity_token(audience, timeout=timeout)


def is_token_expired(
    token: str,
    *,
    leeway_seconds: int = 30,
    now: Optional[float] = None,
) -> bool:
    """Return True if the JWT is past its ``exp`` claim (signature not verified)."""
    payload = _decode_jwt_payload(token)
    exp = payload.get("exp")
    if exp is None:
        return True
    try:
        exp_ts = float(exp)
    except (TypeError, ValueError) as exc:
        raise GatewaySATokenError(f"Invalid JWT exp claim: {exp!r}") from exc

    current = time.time() if now is None else now
    return current >= (exp_ts - leeway_seconds)
