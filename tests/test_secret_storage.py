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

"""Tests for mcp_gateway.oauth.secret_storage.

The cloud backends are built without their SDK-dependent ``__init__``, with a mock client.
"""

import json
from unittest.mock import MagicMock

import pytest

import mcp_gateway.oauth.secret_storage as ss
from mcp_gateway.config import settings
from mcp_gateway.oauth.secret_storage import (
    AWSSecretsManagerStorage,
    AzureKeyVaultStorage,
    GCPSecretManagerStorage,
    LocalSecretStorage,
    get_secret_storage,
)

CLOUD_BACKENDS = [
    pytest.param(
        AzureKeyVaultStorage, "get_secret", MagicMock(value="secret"), id="azure"
    ),
    pytest.param(
        AWSSecretsManagerStorage,
        "get_secret_value",
        {"SecretString": "secret"},
        id="aws",
    ),
    pytest.param(
        GCPSecretManagerStorage,
        "access_secret_version",
        MagicMock(payload=MagicMock(data=b"secret")),
        id="gcp",
    ),
]


def _cloud_storage(backend):
    storage = backend.__new__(backend)
    storage.client = MagicMock()
    storage.project_id = "proj"
    return storage


async def test_a_missing_file_holds_no_secrets_and_is_not_created(tmp_path):
    """A store the gateway only reads must not leave files behind."""
    path = tmp_path / "secrets.json"

    assert await LocalSecretStorage(str(path)).get_secret("any") is None
    assert not path.exists()


async def test_the_local_file_holds_the_secrets_it_was_given(tmp_path):
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps({"key": "value"}), encoding="utf-8")
    storage = LocalSecretStorage(str(path))

    assert await storage.get_secret("key") == "value"
    assert await storage.get_secret("other") is None


@pytest.mark.parametrize("backend, method, response", CLOUD_BACKENDS)
async def test_a_cloud_backend_returns_the_secret_it_reads(backend, method, response):
    storage = _cloud_storage(backend)
    getattr(storage.client, method).return_value = response

    assert await storage.get_secret("ref") == "secret"


@pytest.mark.parametrize("backend, method, response", CLOUD_BACKENDS)
async def test_a_cloud_backend_that_fails_returns_no_secret(backend, method, response):
    storage = _cloud_storage(backend)
    getattr(storage.client, method).side_effect = RuntimeError("boom")

    assert await storage.get_secret("ref") is None


@pytest.mark.parametrize(
    "setting, backend",
    [
        ("local", "LocalSecretStorage"),
        ("azure_keyvault", "AzureKeyVaultStorage"),
        ("aws_secrets", "AWSSecretsManagerStorage"),
        ("gcp_secret_manager", "GCPSecretManagerStorage"),
    ],
)
def test_the_configured_backend_is_built_once(monkeypatch, setting, backend):
    """Cloud clients are slow to build, so every call shares one."""
    ss._storage.cache_clear()  # pylint: disable=protected-access
    monkeypatch.setattr(settings, "SECRET_STORAGE_BACKEND", setting)
    monkeypatch.setattr(ss, backend, object)

    storage = get_secret_storage()

    assert type(storage) is object  # pylint: disable=unidiomatic-typecheck
    assert get_secret_storage() is storage
    ss._storage.cache_clear()  # pylint: disable=protected-access
