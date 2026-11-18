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
EKS / in-cluster Kubernetes TokenRequest helper for MCP Gateway.

Mints a service account JWT with a custom OIDC audience by calling the
Kubernetes ``ServiceAccount`` token subresource — not AWS STS.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

import jwt
import requests

_DEFAULT_SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
_DEFAULT_BOUND_TOKEN_PATH = _DEFAULT_SA_DIR / "token"
_DEFAULT_NAMESPACE_PATH = _DEFAULT_SA_DIR / "namespace"
_DEFAULT_CA_CERT_PATH = _DEFAULT_SA_DIR / "ca.crt"
_DEFAULT_KUBERNETES_HOST = "https://kubernetes.default.svc"


class GatewayAwsTokenError(Exception):
    """Failed to read in-cluster secrets or call the Kubernetes TokenRequest API."""


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    """
    Parse JWT claims without verifying the signature.

    A public key / JWKS is **not** required here: ``verify_signature`` is off, so
    this only base64-decodes the payload (same pattern as ``sa_token._decode_jwt_payload``).
    Trust for the bound token is enforced by the Kubernetes API server when we
    POST TokenRequest; trust for the minted token is enforced by MCP Gateway.
    """
    try:
        return jwt.decode(
            (token or "").strip(),
            options={"verify_signature": False},
            algorithms=["RS256", "RS384", "RS512", "HS256"],
        )
    except jwt.PyJWTError as exc:
        raise GatewayAwsTokenError(f"Failed to decode JWT: {exc}") from exc


def service_account_name_from_token(token: str) -> str:
    """Return the Kubernetes ServiceAccount name in a bound service account token."""
    claims = _decode_jwt_payload(token)

    k8s = claims.get("kubernetes.io")
    if isinstance(k8s, dict):
        sa_block = k8s.get("serviceaccount")
        if isinstance(sa_block, dict):
            raw_name = sa_block.get("name")
            if isinstance(raw_name, str) and raw_name.strip():
                return raw_name.strip()

    raise GatewayAwsTokenError(
        "Could not derive the ServiceAccount name from the token "
        "(expected the kubernetes.io serviceaccount name claim)"
    )


def read_namespace_from_filesystem(
    namespace_path: Path | str = _DEFAULT_NAMESPACE_PATH,
) -> str:
    """Read the pod namespace from the standard ServiceAccount mount file."""
    path = Path(namespace_path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GatewayAwsTokenError(f"Cannot read namespace file {path}: {exc}") from exc
    ns = raw.strip()
    if not ns:
        raise GatewayAwsTokenError(f"Namespace file {path} is empty")
    return ns


def get_aws_identity_token(audience: str, timeout: float = 10.0) -> str:
    """
    Mint a JWT for MCP Gateway by calling the in-cluster Kubernetes TokenRequest API.

    Reads bound token, namespace, and CA from the standard ServiceAccount mount
    and POSTs to ``kubernetes.default.svc``.

    The **bound token** at ``.../serviceaccount/token`` is the pod's default
    in-cluster JWT (on EKS, ``iss`` is the cluster OIDC URL; ``aud`` is typically
    ``https://kubernetes.default.svc``). It is used only as ``Authorization`` to
    call the API server's TokenRequest subresource; the returned ``status.token``
    is the new JWT, for ``audience``.
    """

    # Single-line RS256 JWT; .strip() removes trailing newline from the mount file.
    token_path = _DEFAULT_BOUND_TOKEN_PATH
    try:
        bound_token = token_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise GatewayAwsTokenError(
            f"Cannot read bound token file {token_path}: {exc}"
        ) from exc
    if not bound_token:
        raise GatewayAwsTokenError(f"Bound token file {token_path} is empty")

    sa_name = service_account_name_from_token(bound_token)
    namespace = read_namespace_from_filesystem(_DEFAULT_NAMESPACE_PATH)

    ca = _DEFAULT_CA_CERT_PATH
    if not ca.is_file():
        raise GatewayAwsTokenError(f"CA cert file not found: {ca}")

    url = (
        f"{_DEFAULT_KUBERNETES_HOST.rstrip('/')}/api/v1/namespaces/"
        f"{quote(namespace, safe='')}/serviceaccounts/"
        f"{quote(sa_name, safe='')}/token"
    )

    body = {
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": {
            "audiences": [audience],
            "expirationSeconds": 3600,
        },
    }

    try:
        response = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {bound_token}",
                "Content-Type": "application/json",
            },
            data=json.dumps(body),
            verify=str(ca),
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise GatewayAwsTokenError(f"TokenRequest POST failed: {exc}") from exc

    if not response.ok:
        detail = (response.text or "")[:2000]
        raise GatewayAwsTokenError(
            f"TokenRequest returned {response.status_code}: {detail}"
        )

    try:
        data = response.json()
    except ValueError as exc:
        raise GatewayAwsTokenError("TokenRequest response is not valid JSON") from exc

    minted = data.get("status", {}).get("token")
    if not minted or not isinstance(minted, str) or not minted.strip():
        raise GatewayAwsTokenError("TokenRequest response missing status.token")

    return minted.strip()
