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

"""Where the gateway reads secrets: the token encryption key, and the secrets
service accounts forward. Local file, Azure Key Vault, AWS Secrets Manager or
GCP Secret Manager.

The cloud SDKs block, so their calls run in a worker thread, and each backend's
client is built once.
"""

import json
import logging
import os
from abc import ABC, abstractmethod
from functools import lru_cache
from typing import Optional

from starlette.concurrency import run_in_threadpool

from ..config import settings

logger = logging.getLogger(__name__)


class SecretStorage(ABC):
    """A store the gateway reads secrets from, by name."""

    @abstractmethod
    def _read(self, ref: str) -> Optional[str]:
        """The secret named ``ref``, or None; may block."""

    async def get_secret(self, ref: str) -> Optional[str]:
        """The secret named ``ref``, or None if the store can't give it."""
        try:
            return await run_in_threadpool(self._read, ref)
        except Exception:  # pylint: disable=broad-exception-caught
            logger.warning("Could not read secret %s", ref, exc_info=True)
            return None


class LocalSecretStorage(SecretStorage):
    """A JSON file of secrets by name, for development. The gateway only reads it."""

    def __init__(self, secrets_file: str = ".secrets.json"):
        self.secrets_file = secrets_file

    def _read(self, ref: str) -> Optional[str]:
        if not os.path.exists(self.secrets_file):
            return None
        with open(self.secrets_file, "r", encoding="utf-8") as f:
            return json.load(f).get(ref)


class AzureKeyVaultStorage(SecretStorage):
    """Azure Key Vault, at AZURE_KEY_VAULT_URL."""

    def __init__(self):
        from azure.identity import (  # pylint: disable=import-outside-toplevel
            DefaultAzureCredential,
        )
        from azure.keyvault.secrets import (  # pylint: disable=import-outside-toplevel
            SecretClient,
        )

        if not settings.AZURE_KEY_VAULT_URL:
            raise ValueError("AZURE_KEY_VAULT_URL not configured")
        self.client = SecretClient(
            vault_url=settings.AZURE_KEY_VAULT_URL, credential=DefaultAzureCredential()
        )

    def _read(self, ref: str) -> Optional[str]:
        return self.client.get_secret(ref).value


class AWSSecretsManagerStorage(SecretStorage):
    """AWS Secrets Manager, in AWS_SECRETS_REGION."""

    def __init__(self):
        import boto3  # pylint: disable=import-outside-toplevel

        if not settings.AWS_SECRETS_REGION:
            raise ValueError("AWS_SECRETS_REGION not configured")
        self.client = boto3.client(
            "secretsmanager", region_name=settings.AWS_SECRETS_REGION
        )

    def _read(self, ref: str) -> Optional[str]:
        return self.client.get_secret_value(SecretId=ref)["SecretString"]


class GCPSecretManagerStorage(SecretStorage):
    """GCP Secret Manager, in GCP_PROJECT_ID; the latest version of each secret."""

    def __init__(self):
        from google.cloud import (  # pylint: disable=import-outside-toplevel
            secretmanager,
        )

        if not settings.GCP_PROJECT_ID:
            raise ValueError("GCP_PROJECT_ID not configured")
        self.client = secretmanager.SecretManagerServiceClient()
        self.project_id = settings.GCP_PROJECT_ID

    def _read(self, ref: str) -> Optional[str]:
        name = f"projects/{self.project_id}/secrets/{ref}/versions/latest"
        response = self.client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")


_BACKENDS = {
    "azure_keyvault": "AzureKeyVaultStorage",
    "aws_secrets": "AWSSecretsManagerStorage",
    "gcp_secret_manager": "GCPSecretManagerStorage",
    "local": "LocalSecretStorage",
}


@lru_cache(maxsize=None)
def _storage(backend: str) -> SecretStorage:
    return globals()[_BACKENDS[backend]]()


def get_secret_storage() -> SecretStorage:
    """The secret store SECRET_STORAGE_BACKEND names, built once."""
    return _storage(settings.SECRET_STORAGE_BACKEND)
