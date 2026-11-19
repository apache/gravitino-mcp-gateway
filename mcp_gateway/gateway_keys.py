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
The tokens the gateway signs for MCP servers (RS256), and the key that signs them.

MCP servers fetch the public key from /.well-known/jwks.json, so they can
verify the tokens but not forge them.

Key loading priority:
  1. GATEWAY_RSA_PRIVATE_KEY env var (PEM-encoded string)
  2. GATEWAY_RSA_PRIVATE_KEY_FILE env var (path to PEM file)
  3. Auto-generate an ephemeral key pair (dev/test only — logs a warning)
"""

import base64
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .config import settings

logger = logging.getLogger(__name__)

# Module-level singletons (populated on first access)
_private_key: Any = None  # pylint: disable=invalid-name
_public_jwk: Dict[str, Any] = {}
_kid: str = ""  # pylint: disable=invalid-name


def _base64url_encode(data: bytes) -> str:
    """RFC 7515 base64url encoding (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_to_base64url(n: int) -> str:
    """Encode an RSA integer parameter as base64url."""
    byte_length = (n.bit_length() + 7) // 8
    return _base64url_encode(n.to_bytes(byte_length, byteorder="big"))


def _load_or_generate_key():
    """Load RSA private key from config, or generate an ephemeral one for dev."""
    global _private_key, _public_jwk, _kid  # pylint: disable=global-statement

    pem_str = getattr(settings, "GATEWAY_RSA_PRIVATE_KEY", None)
    pem_file = getattr(settings, "GATEWAY_RSA_PRIVATE_KEY_FILE", None)

    if pem_str:
        # Pydantic may have collapsed \\n → literal backslash-n in env vars;
        # restore real newlines so PEM parsing works.
        pem_str = pem_str.replace("\\n", "\n")
        _private_key = serialization.load_pem_private_key(
            pem_str.encode(), password=None
        )
        logger.info(
            "Loaded gateway RSA private key from GATEWAY_RSA_PRIVATE_KEY env var"
        )
    elif pem_file:
        with open(pem_file, "rb") as f:
            _private_key = serialization.load_pem_private_key(f.read(), password=None)
        logger.info("Loaded gateway RSA private key from file: %s", pem_file)
    else:
        logger.warning(
            "GATEWAY_RSA_PRIVATE_KEY not set — generating ephemeral RSA key pair. "
            "This is fine for development but MUST be replaced with a persistent "
            "key in production (set GATEWAY_RSA_PRIVATE_KEY or GATEWAY_RSA_PRIVATE_KEY_FILE)."
        )
        _private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    # Derive the public key and build the JWKS entry
    pub = _private_key.public_key()
    pub_numbers = pub.public_numbers()

    # Key ID = SHA-256 thumbprint of the JWK (RFC 7638)
    # Build the canonical JWK for thumbprint computation (alphabetical keys, no whitespace)
    n_b64 = _int_to_base64url(pub_numbers.n)
    e_b64 = _int_to_base64url(pub_numbers.e)
    thumbprint_input = json.dumps(
        {"e": e_b64, "kty": "RSA", "n": n_b64},
        separators=(",", ":"),
        sort_keys=True,
    )
    _kid = _base64url_encode(hashlib.sha256(thumbprint_input.encode()).digest())

    _public_jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": _kid,
        "n": n_b64,
        "e": e_b64,
    }
    logger.info("Gateway JWKS kid=%s", _kid)


def get_private_key():
    """Return the RSA private key (for signing gateway JWTs)."""
    if _private_key is None:
        _load_or_generate_key()
    return _private_key


def get_kid() -> str:
    """Return the key ID for the current gateway signing key."""
    if not _kid:
        _load_or_generate_key()
    return _kid


def get_jwks() -> Dict[str, Any]:
    """Return the JWKS document (public keys only) for downstream verification."""
    if not _public_jwk:
        _load_or_generate_key()
    return {"keys": [_public_jwk]}


# How long a token the gateway signs for an MCP server lasts.
GATEWAY_JWT_LIFETIME = timedelta(minutes=15)


def mint_gateway_jwt(user, audience: str) -> str:
    """A short-lived token naming ``user``, for the MCP server ``audience`` alone.

    The subject is the gateway username, which comes from USER_ID_CLAIM, so
    it names the person the way the identity provider does. Service accounts'
    names are an admin's choice, so ``principal_type`` tells them apart.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.username,
        "email": user.email or "",
        "name": user.full_name or user.username,
        "preferred_username": user.username,
        "principal_type": "service_account" if user.is_service_account else "person",
        "iss": "gravitino-mcp-gateway",
        "aud": audience,
        "iat": now,
        "exp": now + GATEWAY_JWT_LIFETIME,
        "jti": str(uuid4()),
    }
    return jwt.encode(
        payload, get_private_key(), algorithm="RS256", headers={"kid": get_kid()}
    )
