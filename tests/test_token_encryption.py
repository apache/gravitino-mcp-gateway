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

"""Tests for mcp_gateway.oauth.token_encryption: AES-256-GCM and where its key comes from."""

import base64
import os
from unittest.mock import AsyncMock

import pytest

import mcp_gateway.oauth.token_encryption as te
from mcp_gateway.oauth.token_encryption import TokenEncryption, get_token_encryption


@pytest.fixture(name="enc")
def fixture_enc() -> TokenEncryption:
    return TokenEncryption(os.urandom(32))


@pytest.fixture(name="storage")
def fixture_storage(monkeypatch):
    """A secret storage holding no key; each test starts with no key loaded."""
    monkeypatch.setattr(te, "_token_encryption", None)
    storage = AsyncMock()
    storage.get_secret = AsyncMock(return_value=None)
    monkeypatch.setattr(te, "get_secret_storage", lambda: storage)
    return storage


# ---------------------------------------------------------------------------
# TokenEncryption
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [16, 64])
def test_a_key_that_is_not_32_bytes_is_rejected(length):
    with pytest.raises(ValueError, match="32 bytes"):
        TokenEncryption(os.urandom(length))


@pytest.mark.parametrize(
    "plaintext",
    ["my-oauth-access-token", "", "x" * 4096, "eyJhbGciOiJSUzI1NiJ9.üñîcödé.sig"],
    ids=["token", "empty", "long", "unicode"],
)
def test_a_token_round_trips(enc, plaintext):
    assert enc.decrypt(enc.encrypt(plaintext)) == plaintext


def test_the_same_token_encrypts_differently_each_time(enc):
    """A random nonce per encryption; identical ciphertext would leak equality."""
    assert enc.encrypt("same-token") != enc.encrypt("same-token")


def test_a_tampered_ciphertext_is_refused(enc):
    raw = bytearray(base64.b64decode(enc.encrypt("sensitive-token")))
    raw[15] ^= 0xFF  # a byte after the 12-byte nonce

    assert enc.decrypt(base64.b64encode(bytes(raw)).decode()) is None


def test_a_ciphertext_from_another_key_is_refused(enc):
    assert enc.decrypt(TokenEncryption(os.urandom(32)).encrypt("secret")) is None


@pytest.mark.parametrize(
    "garbage", ["not-valid-base64-!!!", "", "abc", "====", "a" * 100]
)
def test_decrypting_garbage_returns_none_rather_than_raising(enc, garbage):
    assert enc.decrypt(garbage) is None


# ---------------------------------------------------------------------------
# get_token_encryption
# ---------------------------------------------------------------------------


async def test_the_key_is_read_from_the_secret_storage_once(storage):
    storage.get_secret.return_value = base64.b64encode(os.urandom(32)).decode()

    first = await get_token_encryption()
    second = await get_token_encryption()

    assert first is second
    assert first.decrypt(first.encrypt("token")) == "token"
    storage.get_secret.assert_awaited_once()


async def test_without_a_key_anywhere_it_refuses_to_start(storage):
    with pytest.raises(RuntimeError, match="Encryption key not found"):
        await get_token_encryption()


async def test_a_configured_key_is_used_instead_of_the_secret_storage(
    storage, monkeypatch
):
    key = os.urandom(32)
    monkeypatch.setattr(
        te.settings, "TOKEN_ENCRYPTION_KEY", base64.b64encode(key).decode()
    )

    enc = await get_token_encryption()

    assert TokenEncryption(key).decrypt(enc.encrypt("token")) == "token"
    storage.get_secret.assert_not_awaited()


async def test_the_key_file_is_read(storage, monkeypatch, tmp_path):
    key = os.urandom(32)
    key_file = tmp_path / "token-encryption-key"
    key_file.write_text(base64.b64encode(key).decode() + "\n", encoding="utf-8")
    monkeypatch.setattr(te.settings, "TOKEN_ENCRYPTION_KEY_FILE", str(key_file))

    enc = await get_token_encryption()

    assert TokenEncryption(key).decrypt(enc.encrypt("token")) == "token"


async def test_a_key_that_is_not_base64_is_rejected(storage, monkeypatch):
    monkeypatch.setattr(te.settings, "TOKEN_ENCRYPTION_KEY", "not base64!")

    with pytest.raises(RuntimeError, match="not valid base64"):
        await get_token_encryption()
