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

"""Settings the gateway refuses at startup."""

import pytest
from pydantic import ValidationError

from mcp_gateway.config import Settings

PRODUCTION = {
    "ENVIRONMENT": "production",
    "CORS_ALLOWED_ORIGINS": "https://gravitino.example.com",
    "GATEWAY_BASE_URL": "https://mcp-gateway.example.com",
    # Read at startup only for its access: any readable file will do.
    "GATEWAY_RSA_PRIVATE_KEY_FILE": __file__,
    "TOKEN_ENCRYPTION_KEY_FILE": "/etc/mcp-gateway/token-key",
}


def _settings(**values):
    return Settings(_env_file=None, **values)


def test_a_complete_production_configuration_is_accepted():
    assert _settings(**PRODUCTION).ENVIRONMENT == "production"


@pytest.mark.parametrize("environment", ["production", "Production"])
@pytest.mark.parametrize(
    "setting, value",
    [
        ("DEBUG", True),
        ("CORS_ALLOWED_ORIGINS", "*"),
        ("GATEWAY_BASE_URL", "http://mcp-gateway.example.com"),
        ("GATEWAY_RSA_PRIVATE_KEY_FILE", None),
        ("TOKEN_ENCRYPTION_KEY_FILE", None),
        ("UPSTREAM_TLS_VERIFY", "false"),
    ],
)
def test_production_refuses_settings_only_safe_for_development(
    environment, setting, value
):
    with pytest.raises(ValidationError, match=setting):
        _settings(**{**PRODUCTION, "ENVIRONMENT": environment, setting: value})


def test_development_allows_them():
    settings = _settings(DEBUG=True, CORS_ALLOWED_ORIGINS="*", UPSTREAM_TLS_VERIFY="0")

    assert settings.DEBUG


@pytest.mark.parametrize(
    "values, setting",
    [
        # Sessions signed with a short key can be forged by guessing it.
        ({"JWT_SECRET_KEY": "too-short"}, "JWT_SECRET_KEY"),
        ({"JWT_ALGORITHM": "none"}, "JWT_ALGORITHM"),
        ({"JWT_AUDIENCE": "  "}, "JWT_AUDIENCE"),
        ({"SERVICE_ACCOUNT_SECRET_PREFIX": "  "}, "SERVICE_ACCOUNT_SECRET_PREFIX"),
        # A typo would otherwise read secrets from a local file the container loses.
        ({"SECRET_STORAGE_BACKEND": "gcp-secret-manager"}, "SECRET_STORAGE_BACKEND"),
        # Callers would otherwise send the gateway's credential, or their own, upstream.
        ({"MCP_FORWARD_HEADERS": "x-api-key,Authorization"}, "MCP_FORWARD_HEADERS"),
        ({"MCP_FORWARD_HEADERS": "x-api-key,cookie"}, "MCP_FORWARD_HEADERS"),
        ({"MCP_FORWARD_HEADERS": "x-api-key,Mcp-Session-Id"}, "MCP_FORWARD_HEADERS"),
        # A malformed entry used to be read as one more trusted issuer.
        ({"TRUSTED_ISSUER_JWKS": "https://issuer.example.com"}, "TRUSTED_ISSUER_JWKS"),
        (
            {"TRUSTED_ISSUER_JWKS": "https://i.example.com=http://keys"},
            "TRUSTED_ISSUER_JWKS",
        ),
        # Nobody could approve a token request: it would wait for ever.
        (
            {"SLACK_USER_TOKENS_ENABLED": "true", "SLACK_BOT_TOKEN": "xoxb-1"},
            "SLACK_USER_TOKENS_ENABLED",
        ),
    ],
)
def test_a_setting_that_would_weaken_access_control_is_refused(values, setting):
    with pytest.raises(ValidationError, match=setting):
        _settings(**values)


def test_a_signing_key_file_that_cant_be_read_is_refused(tmp_path):
    """Otherwise the first signed token fails, long after startup."""
    with pytest.raises(ValidationError, match="GATEWAY_RSA_PRIVATE_KEY_FILE"):
        _settings(GATEWAY_RSA_PRIVATE_KEY_FILE=str(tmp_path / "missing.pem"))


def test_values_are_normalized():
    """Redirect URIs are built by appending paths to the base URL."""
    settings = _settings(
        GATEWAY_BASE_URL="https://gw.example.com/",
        SECRET_STORAGE_BACKEND=" GCP_Secret_Manager ",
    )

    assert settings.GATEWAY_BASE_URL == "https://gw.example.com"
    assert settings.SECRET_STORAGE_BACKEND == "gcp_secret_manager"
