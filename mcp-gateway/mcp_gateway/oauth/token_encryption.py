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
Token Encryption Utility - Industry Standard Approach
Uses AES-256-GCM for encrypting OAuth tokens in database
The key comes from TOKEN_ENCRYPTION_KEY, TOKEN_ENCRYPTION_KEY_FILE or the secret storage.
"""

import base64
import binascii
import logging
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..config import settings
from .secret_storage import get_secret_storage

logger = logging.getLogger(__name__)

SECRET_NAME = "mcp-gateway-encryption-key"


class TokenEncryption:
    """
    Encrypts/decrypts OAuth tokens using AES-256-GCM

    Industry standard approach:
    - One master key in Secret Manager
    - Encrypted tokens in database
    - Fast, scalable, cost-effective
    """

    def __init__(self, encryption_key: bytes):
        """
        Initialize with 32-byte encryption key

        Args:
            encryption_key: 32-byte AES-256 key from Secret Manager
        """
        if len(encryption_key) != 32:
            raise ValueError("Encryption key must be 32 bytes for AES-256")

        self.aesgcm = AESGCM(encryption_key)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a token using AES-256-GCM

        Args:
            plaintext: Token to encrypt

        Returns:
            Base64-encoded encrypted token with nonce
        """
        # Generate random 12-byte nonce for GCM
        nonce = os.urandom(12)

        # Encrypt
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

        # Combine nonce + ciphertext and base64 encode
        encrypted = nonce + ciphertext
        return base64.b64encode(encrypted).decode("utf-8")

    def decrypt(self, encrypted: str) -> Optional[str]:
        """
        Decrypt a token using AES-256-GCM

        Args:
            encrypted: Base64-encoded encrypted token

        Returns:
            Decrypted token or None if decryption fails
        """
        try:
            # Decode from base64
            encrypted_bytes = base64.b64decode(encrypted)

            # Extract nonce (first 12 bytes) and ciphertext
            nonce = encrypted_bytes[:12]
            ciphertext = encrypted_bytes[12:]

            # Decrypt
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")

        except Exception as e:  # pylint: disable=broad-exception-caught
            # Log error but don't expose details
            logger.error("Token decryption failed: %s", type(e).__name__)
            return None


# Global encryption instance (initialized on first use)
_token_encryption: Optional[TokenEncryption] = None


def _configured_key() -> Optional[str]:
    """The base64 key from TOKEN_ENCRYPTION_KEY or TOKEN_ENCRYPTION_KEY_FILE, if set."""
    if settings.TOKEN_ENCRYPTION_KEY:
        return settings.TOKEN_ENCRYPTION_KEY
    if settings.TOKEN_ENCRYPTION_KEY_FILE:
        with open(settings.TOKEN_ENCRYPTION_KEY_FILE, encoding="utf-8") as key_file:
            return key_file.read()
    return None


async def get_token_encryption() -> TokenEncryption:
    """
    Get or initialize the token encryption instance

    Lazy-loads the encryption key on first use

    Returns:
        TokenEncryption instance
    """
    global _token_encryption  # pylint: disable=global-statement

    if _token_encryption is None:
        encryption_key_b64 = _configured_key()
        if not encryption_key_b64:
            encryption_key_b64 = await get_secret_storage().get_secret(SECRET_NAME)

        if not encryption_key_b64:
            raise RuntimeError(
                "Encryption key not found. Set TOKEN_ENCRYPTION_KEY or "
                "TOKEN_ENCRYPTION_KEY_FILE, or store a base64-encoded 32-byte key "
                f"in the secret storage as {SECRET_NAME}"
            )

        try:
            encryption_key = base64.b64decode(encryption_key_b64.strip())
        except binascii.Error as e:
            raise RuntimeError("The token encryption key is not valid base64") from e

        _token_encryption = TokenEncryption(encryption_key)

    return _token_encryption
