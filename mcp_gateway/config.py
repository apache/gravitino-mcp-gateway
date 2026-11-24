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
Configuration settings for the Gravitino MCP Gateway
"""

import os
import ssl
from functools import lru_cache
from typing import Dict, List, Literal, Optional

import httpx
from pydantic import ConfigDict, Field, field_validator, model_validator
from pydantic_settings import BaseSettings


def _header_names(value: str) -> list[str]:
    return [name.strip().lower() for name in value.split(",") if name.strip()]


@lru_cache(maxsize=4)
def _ca_bundle_context(path: str) -> ssl.SSLContext:
    """An SSL context that trusts httpx's default roots plus the CA bundle at ``path``.

    A private CA's bundle often holds only that CA, and servers with public
    certificates, such as SaaS sign-in, still need the roots httpx trusts when
    verification is on.
    """
    context = httpx.create_ssl_context()
    context.load_verify_locations(cafile=path)
    return context


_TRUE = ("", "true", "1", "yes")
_FALSE = ("false", "0", "no")
# The gateway signs sessions and states with JWT_SECRET_KEY; RFC 7518 asks for
# a key at least as long as the hash.
_MIN_SECRET_LENGTH = 32
# Headers the gateway sets on calls to MCP servers, which callers can't pass on.
_RESERVED_FORWARD_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "host",
    "mcp-session-id",
    "content-type",
    "content-length",
    "accept",
}
SECRET_STORAGE_BACKENDS = (
    "local",
    "gcp_secret_manager",
    "aws_secrets",
    "azure_keyvault",
)


class Settings(BaseSettings):
    """Application settings"""

    # "production" refuses settings only safe for development; see _check_production.
    ENVIRONMENT: str = "development"
    # Drops the Secure flag and __Host- prefix from cookies, for plain-HTTP testing.
    DEBUG: bool = False

    # Certificate checks on calls to MCP servers: "true", "false", or the path of
    # a CA bundle to check certificates against.
    UPSTREAM_TLS_VERIFY: str = "true"

    # Where the gateway listens.
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Prometheus metrics at GET /metrics, which is not authenticated: keep it
    # reachable only by the scraper.
    METRICS_ENABLED: bool = True

    # Export OpenTelemetry traces over OTLP. Needs the "otel" extra; the
    # endpoint comes from the standard OTEL_EXPORTER_OTLP_* variables.
    OTEL_ENABLED: bool = False

    # Origins that may call the API from a browser, comma-separated, such as
    # Gravitino's web UI. "*" is for development only.
    CORS_ALLOWED_ORIGINS: str = "*"

    # SQLite, or MySQL: "mysql+pymysql://user:password@host:3306/database".
    DATABASE_URL: str = "sqlite:///./mcp_gateway.db"
    # TLS for MySQL, as in MySQL's --ssl-mode: PREFERRED uses TLS when the server
    # offers it. REQUIRED does not check the server certificate.
    DATABASE_SSL_MODE: Literal[
        "DISABLED", "PREFERRED", "REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY"
    ] = "REQUIRED"
    # CA bundle for VERIFY_CA and VERIFY_IDENTITY; the system CAs are used when unset.
    DATABASE_SSL_CA: Optional[str] = None
    # MySQL connections each replica keeps open, and how many more it may open
    # when busy. MySQL allows 151 connections by default.
    DATABASE_POOL_SIZE: int = Field(10, ge=1)
    DATABASE_MAX_OVERFLOW: int = Field(10, ge=0)

    # Signs sessions, sign-in states and MCP session IDs. Required; generate one
    # with: python -c "import secrets; print(secrets.token_hex(32))"
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: Literal["HS256", "HS384", "HS512"] = "HS256"

    # The PEM RSA key that signs the tokens the gateway sends MCP servers, or a
    # file holding it (newlines can be literal \n in the variable). Without
    # one, each process generates its own, which production refuses.
    GATEWAY_RSA_PRIVATE_KEY: Optional[str] = None
    GATEWAY_RSA_PRIVATE_KEY_FILE: Optional[str] = None

    # "azure" applies Microsoft Entra ID's defaults; any other OIDC provider
    # works as "generic".
    OIDC_PROVIDER: Literal[
        "generic", "azure", "google", "okta", "auth0", "keycloak", "cognito"
    ] = "generic"
    # e.g. https://keycloak.example.com/realms/<realm>/.well-known/openid-configuration
    OIDC_DISCOVERY_URL: Optional[str] = None
    OIDC_ISSUER: Optional[str] = None
    OIDC_AUTHORIZATION_ENDPOINT: Optional[str] = None
    OIDC_TOKEN_ENDPOINT: Optional[str] = None
    OIDC_JWKS_URI: Optional[str] = None

    # Trusted issuers for service-account bearer tokens (comma-separated URLs).
    # A token's iss must match one of these or the iss pinned on its registration
    # before MCP Gateway fetches JWKS or discovery metadata.
    # e.g. "https://accounts.google.com,https://oidc.eks.us-west-2.amazonaws.com/id/ABC123"
    TRUSTED_ISSUERS: str = ""

    # Optional per-issuer JWKS overrides for service-account tokens
    # (comma-separated issuer=jwks_uri pairs).
    TRUSTED_ISSUER_JWKS: str = ""

    # Headers that describe a service account's workload (comma-separated, e.g.
    # "team,pipeline"). They are forwarded to MCP servers and written to the audit log;
    # a service-account request without one of the required headers is rejected.
    SERVICE_ACCOUNT_REQUIRED_HEADERS: str = ""
    SERVICE_ACCOUNT_OPTIONAL_HEADERS: str = ""
    # Service accounts can forward a secret to an MCP server (downstream_credentials in
    # their additional_config). The gateway can read other secrets too, so only names
    # with this prefix are forwarded; the gateway's own encryption key never is.
    SERVICE_ACCOUNT_SECRET_PREFIX: str = "mcp-gateway-sa-"
    # Caller headers passed through to MCP servers (comma-separated), such as an API key
    # an MCP server needs from the caller. Other caller headers are never forwarded.
    MCP_FORWARD_HEADERS: str = ""

    # Seconds every call to the identity provider may take: discovery, sign-in,
    # refresh and token exchange.
    OIDC_HTTP_TIMEOUT: float = 10.0
    # Seconds a fetched discovery document is reused; 0 fetches it every time.
    OIDC_DISCOVERY_CACHE_TTL: int = 3600

    # The gateway's OAuth client, for people's sign-in and token exchange.
    GATEWAY_OAUTH_CLIENT_ID: Optional[str] = None
    # Other clients whose tokens the gateway accepts from people, such as
    # Gravitino's web UI (comma-separated). Not for service accounts: a token
    # from one of these clients names a person by email, and signs them up.
    GATEWAY_OAUTH_ADDITIONAL_CLIENT_IDS: str = ""
    # Accept user tokens for JWT_AUDIENCE from any client of the OIDC provider, such as MCP
    # clients that register themselves (RFC 7591). Registered service accounts are unaffected.
    GATEWAY_OAUTH_ACCEPT_ANY_CLIENT: bool = False
    GATEWAY_OAUTH_CLIENT_SECRET: Optional[str] = None
    GATEWAY_BASE_URL: str = "http://localhost:8000"
    # How a user's gateway token is exchanged for an MCP server's token: "rfc8693"
    # (Keycloak, Okta, Auth0, ...) or "entra_obo". Defaults to entra_obo for azure.
    TOKEN_EXCHANGE_STYLE: Optional[Literal["rfc8693", "entra_obo"]] = None
    # Scopes the gateway's own sign-in asks for, space-separated. Defaults to
    # "openid profile email offline_access", plus "<client id>/.default" for azure.
    GATEWAY_LOGIN_SCOPES: Optional[str] = None
    # Scopes MCP clients should request, advertised in the OAuth discovery documents.
    # For azure, short names such as "user_access" (the default there) get the
    # api://<client id>/ prefix. Other providers advertise none by default.
    GATEWAY_API_SCOPES: Optional[str] = None

    # The audience people's tokens must have: the gateway's client ID, or the
    # API identifier its provider puts in tokens for it. Required.
    JWT_AUDIENCE: str

    # People who are gateway admins, by email (comma-separated).
    ADMIN_EMAILS: str = ""

    # The token claim that names a person: their gateway username, shown in the
    # audit log, and the subject of the tokens the gateway signs. People are still
    # found by their verified email. Set it to the claim Gravitino names people by
    # (gravitino.authenticator.oauth.principalFields), such as preferred_username,
    # and pick a claim people cannot change themselves.
    USER_ID_CLAIM: str = "email"

    # Where secrets are read from: the token encryption key, unless
    # TOKEN_ENCRYPTION_KEY gives it, and the secrets service accounts forward.
    # "local" is .secrets.json in the working directory.
    SECRET_STORAGE_BACKEND: str = "local"
    AZURE_KEY_VAULT_URL: Optional[str] = None
    AWS_SECRETS_REGION: Optional[str] = None
    GCP_PROJECT_ID: Optional[str] = None

    # Base64-encoded 32-byte key for stored OAuth tokens; used instead of the secret storage.
    TOKEN_ENCRYPTION_KEY: Optional[str] = None
    # File containing TOKEN_ENCRYPTION_KEY, for example a mounted Kubernetes secret.
    TOKEN_ENCRYPTION_KEY_FILE: Optional[str] = None

    # Registers Gravitino's MCP server (mcp-server) as "gravitino" at startup, for example
    # http://gravitino-mcp:8000/mcp. An existing "gravitino" entry is left as it is.
    GRAVITINO_MCP_URL: Optional[str] = None
    # Audience of the tokens Gravitino accepts. Defaults to JWT_AUDIENCE, which forwards
    # users' own tokens; anything else is reached by token exchange.
    GRAVITINO_MCP_AUDIENCE: Optional[str] = None
    # Gravitino's server, for example http://gravitino:8090. When set, Gravitino's
    # service admins are the gateway's admins too, alongside ADMIN_EMAILS.
    GRAVITINO_URI: Optional[str] = None

    # Whether the audit log keeps each call's response. Gateway admins, who with
    # GRAVITINO_URI include Gravitino's service admins, can read the audit log.
    AUDIT_LOG_RESPONSES: bool = False
    # Days the audit log keeps a call; 0 keeps them for ever.
    AUDIT_RETENTION_DAYS: int = Field(90, ge=0)

    # Seconds a tool call may take, such as a long query.
    MCP_TOOL_CALL_TIMEOUT: int = 1200
    # The largest request body the gateway reads, in bytes.
    MAX_REQUEST_BYTES: int = Field(10 * 1024 * 1024, ge=1024)

    # Tool-name prefixes each MCP server may list and call, as JSON keyed by service id;
    # servers not listed expose every tool. Gravitino is read-only unless changed here.
    MCP_TOOL_FILTERS: Dict[str, List[str]] = Field(
        default_factory=lambda: {"gravitino": ["get_", "list_", "load_", "metadata_"]}
    )

    # Slack, off unless set. The webhook gets access requests and decisions.
    SLACK_WEBHOOK_URL: Optional[str] = None
    # The bot invites approved people to SLACK_CHANNEL_ID (scopes users:read,
    # users:read.email, channels:write.invites) and, with the app token, runs
    # /gravitino-mcp over Socket Mode.
    SLACK_BOT_TOKEN: Optional[str] = None
    SLACK_APP_TOKEN: Optional[str] = None
    SLACK_CHANNEL_ID: Optional[str] = None
    # Lets Slack apps' service accounts get a person's token once they approve in
    # Slack (POST /api/v1/sa/user-tokens). Off unless a deployment needs it.
    SLACK_USER_TOKENS_ENABLED: bool = False

    @property
    def upstream_tls_verify(self) -> bool | ssl.SSLContext:
        """The ``verify`` argument for httpx clients that call MCP servers.

        Covers the servers and their OAuth authorization servers.
        """
        value = self.UPSTREAM_TLS_VERIFY.strip()
        if value.lower() in _TRUE:
            return True
        if value.lower() in _FALSE:
            return False
        return _ca_bundle_context(value)

    @field_validator("UPSTREAM_TLS_VERIFY")
    @classmethod
    def _check_ca_bundle(cls, value: str) -> str:
        """Refuse an unusable CA bundle at startup, rather than on every call."""
        stripped = value.strip()
        if stripped.lower() in _TRUE + _FALSE:
            return value
        if not os.path.isfile(stripped):
            raise ValueError(
                "UPSTREAM_TLS_VERIFY must be true, false, or the path of a CA "
                f"bundle file; {stripped!r} is not a file"
            )
        try:
            _ca_bundle_context(stripped)
        except OSError as error:
            raise ValueError(
                f"UPSTREAM_TLS_VERIFY: {stripped!r} holds no usable CA "
                f"certificates ({error})"
            ) from error
        return value

    @field_validator("ENVIRONMENT")
    @classmethod
    def _normalize_environment(cls, value: str) -> str:
        # "Production" must turn on the production checks too.
        return value.strip().lower()

    @field_validator("MCP_FORWARD_HEADERS")
    @classmethod
    def _check_forward_headers(cls, value: str) -> str:
        """Refuse headers the gateway sets itself, such as the one with its credential."""
        reserved = sorted(set(_header_names(value)) & _RESERVED_FORWARD_HEADERS)
        if reserved:
            raise ValueError(f"MCP_FORWARD_HEADERS can't forward {', '.join(reserved)}")
        return value

    @field_validator("SECRET_STORAGE_BACKEND")
    @classmethod
    def _check_secret_storage(cls, value: str) -> str:
        backend = value.strip().lower()
        if backend not in SECRET_STORAGE_BACKENDS:
            raise ValueError(
                f"SECRET_STORAGE_BACKEND must be one of {', '.join(SECRET_STORAGE_BACKENDS)}"
            )
        return backend

    @field_validator("GATEWAY_BASE_URL")
    @classmethod
    def _strip_base_url(cls, value: str) -> str:
        # Redirect URIs are built by appending paths to it.
        return value.strip().rstrip("/")

    @field_validator("GATEWAY_RSA_PRIVATE_KEY_FILE")
    @classmethod
    def _check_key_file(cls, value: Optional[str]) -> Optional[str]:
        """Refuse a signing key file that can't be read at startup, not on the first call."""
        if value and not os.access(value, os.R_OK):
            raise ValueError(f"GATEWAY_RSA_PRIVATE_KEY_FILE: {value!r} can't be read")
        return value

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def _check_secret_key(cls, value: str) -> str:
        if len(value) < _MIN_SECRET_LENGTH:
            raise ValueError(
                f"JWT_SECRET_KEY must be at least {_MIN_SECRET_LENGTH} characters; "
                'generate one with: python -c "import secrets; '
                'print(secrets.token_hex(32))"'
            )
        return value

    @field_validator("TRUSTED_ISSUER_JWKS")
    @classmethod
    def _check_issuer_jwks(cls, value: str) -> str:
        """Each entry pins an issuer's keys; a malformed one would trust an issuer."""
        for pair in filter(None, map(str.strip, value.split(","))):
            issuer, _, jwks_uri = pair.partition("=")
            if not issuer.strip() or not jwks_uri.strip().startswith("https://"):
                raise ValueError(
                    "TRUSTED_ISSUER_JWKS entries must be issuer=https://jwks-uri, "
                    f"not {pair!r}"
                )
        return value

    @field_validator("JWT_AUDIENCE", "SERVICE_ACCOUNT_SECRET_PREFIX")
    @classmethod
    def _check_not_blank(cls, value: str, info) -> str:
        if not value.strip():
            raise ValueError(f"{info.field_name} must not be empty")
        return value.strip()

    @model_validator(mode="after")
    def _check_slack_user_tokens(self) -> "Settings":
        """A person approves each token request through the bot, so it must run."""
        if self.SLACK_USER_TOKENS_ENABLED and not (
            self.SLACK_BOT_TOKEN and self.SLACK_APP_TOKEN
        ):
            raise ValueError(
                "SLACK_USER_TOKENS_ENABLED needs SLACK_BOT_TOKEN and SLACK_APP_TOKEN, "
                "for the bot that asks people to approve"
            )
        return self

    @model_validator(mode="after")
    def _check_production(self) -> "Settings":
        """With ENVIRONMENT=production, refuse settings that are only safe for development."""
        if self.ENVIRONMENT != "production":
            return self
        problems = []
        if self.DEBUG:
            problems.append("DEBUG must be false, or session cookies aren't Secure")
        if self.CORS_ALLOWED_ORIGINS.strip() == "*":
            problems.append("CORS_ALLOWED_ORIGINS must list the web UI's origins")
        if not self.GATEWAY_BASE_URL.startswith("https://"):
            problems.append("GATEWAY_BASE_URL must use https")
        if not (self.GATEWAY_RSA_PRIVATE_KEY or self.GATEWAY_RSA_PRIVATE_KEY_FILE):
            problems.append(
                "GATEWAY_RSA_PRIVATE_KEY or GATEWAY_RSA_PRIVATE_KEY_FILE must be "
                "set, so that every replica signs with the key that "
                "/.well-known/jwks.json serves"
            )
        if not (
            self.TOKEN_ENCRYPTION_KEY
            or self.TOKEN_ENCRYPTION_KEY_FILE
            or self.SECRET_STORAGE_BACKEND != "local"
        ):
            problems.append(
                "TOKEN_ENCRYPTION_KEY, TOKEN_ENCRYPTION_KEY_FILE or a secret "
                "storage backend must hold the token encryption key"
            )
        if self.UPSTREAM_TLS_VERIFY.strip().lower() in _FALSE:
            problems.append(
                "UPSTREAM_TLS_VERIFY must not be false; give the path of a CA "
                "bundle for servers with private certificates"
            )
        if problems:
            raise ValueError("ENVIRONMENT=production, but " + "; ".join(problems))
        return self

    @property
    def device_flow_allowed_client_ids(self) -> set[str]:
        """OAuth client IDs permitted to start a device authorization request."""
        allowed = {"gravitino-mcp-cli", "gravitino-mcp-slack"}
        allowed.update(self.gateway_oauth_client_ids)
        return allowed

    @property
    def service_account_required_headers(self) -> list[str]:
        """SERVICE_ACCOUNT_REQUIRED_HEADERS as a list of lowercase names."""
        return _header_names(self.SERVICE_ACCOUNT_REQUIRED_HEADERS)

    @property
    def service_account_optional_headers(self) -> list[str]:
        """SERVICE_ACCOUNT_OPTIONAL_HEADERS as a list of lowercase names."""
        return _header_names(self.SERVICE_ACCOUNT_OPTIONAL_HEADERS)

    @property
    def mcp_forward_headers(self) -> list[str]:
        """MCP_FORWARD_HEADERS as a list of lowercase names."""
        return _header_names(self.MCP_FORWARD_HEADERS)

    @property
    def admin_emails(self) -> set[str]:
        """ADMIN_EMAILS as a set of lowercase addresses."""
        return {e.strip().lower() for e in self.ADMIN_EMAILS.split(",") if e.strip()}

    @property
    def gateway_oauth_client_ids(self) -> list[str]:
        """GATEWAY_OAUTH_CLIENT_ID plus GATEWAY_OAUTH_ADDITIONAL_CLIENT_IDS.

        Empty when neither is set, so an unconfigured gateway accepts no
        human tokens.
        """
        ids = []
        if self.GATEWAY_OAUTH_CLIENT_ID:
            ids.append(self.GATEWAY_OAUTH_CLIENT_ID)
        ids.extend(
            c.strip()
            for c in self.GATEWAY_OAUTH_ADDITIONAL_CLIENT_IDS.split(",")
            if c.strip()
        )
        return ids

    model_config = ConfigDict(env_file=".env", case_sensitive=True)

    @property
    def gateway_login_scopes(self) -> str:
        """Scopes the gateway asks for when it sends a user to the identity provider."""
        if self.GATEWAY_LOGIN_SCOPES:
            return self.GATEWAY_LOGIN_SCOPES
        scopes = ["openid", "profile", "email", "offline_access"]
        if self.OIDC_PROVIDER == "azure" and self.GATEWAY_OAUTH_CLIENT_ID:
            # Entra only issues a token for the gateway itself when asked for it.
            scopes.append(f"{self.GATEWAY_OAUTH_CLIENT_ID}/.default")
        else:
            # The scopes MCP clients ask for, such as one that puts the gateway
            # in the token's audience, so the stored token is like theirs.
            scopes += [s for s in self.gateway_api_scopes if s not in scopes]
        return " ".join(scopes)

    @property
    def gateway_api_scopes(self) -> list[str]:
        """Scopes advertised to MCP clients in the OAuth discovery documents."""
        configured = self.GATEWAY_API_SCOPES
        if configured is None:
            configured = "user_access" if self.OIDC_PROVIDER == "azure" else ""
        scopes = configured.split()
        client_id = self.GATEWAY_OAUTH_CLIENT_ID
        if self.OIDC_PROVIDER == "azure" and client_id:
            return [s if "://" in s else f"api://{client_id}/{s}" for s in scopes]
        return scopes

    @property
    def oauth_resource(self) -> str:
        """The resource identifier in the protected-resource metadata (RFC 9728)."""
        if self.OIDC_PROVIDER == "azure" and self.GATEWAY_OAUTH_CLIENT_ID:
            # Entra rejects a URL as the resource (AADSTS90009); it wants the app id.
            return self.GATEWAY_OAUTH_CLIENT_ID
        return self.GATEWAY_BASE_URL.rstrip("/")

    @property
    def token_exchange_style(self) -> str:
        """TOKEN_EXCHANGE_STYLE, or the provider's default."""
        if self.TOKEN_EXCHANGE_STYLE:
            return self.TOKEN_EXCHANGE_STYLE
        return "entra_obo" if self.OIDC_PROVIDER == "azure" else "rfc8693"

    @property
    def service_account_audiences(self) -> list[str]:
        """Audiences a workload's token may carry: JWT_AUDIENCE, or the gateway itself.

        The SDK asks for a token for the gateway's URL unless told otherwise.
        """
        return list(
            dict.fromkeys(
                (
                    self.JWT_AUDIENCE,
                    self.oauth_resource,
                    self.GATEWAY_BASE_URL.rstrip("/"),
                )
            )
        )

    @property
    def gateway_audiences(self) -> set[str]:
        """Client id and audience of the gateway's own tokens."""
        return {
            value
            for value in (self.GATEWAY_OAUTH_CLIENT_ID, self.JWT_AUDIENCE)
            if value
        }

    def trusted_issuer_set(self) -> frozenset[str]:
        """Issuers allowed for service-account bearer tokens from configuration."""
        if not self.TRUSTED_ISSUERS.strip():
            return frozenset()
        return frozenset(
            issuer.strip()
            for issuer in self.TRUSTED_ISSUERS.split(",")
            if issuer.strip()
        )

    def trusted_issuer_jwks_map(self) -> dict[str, Optional[str]]:
        """Map of trusted service-account issuers to optional pinned JWKS URIs."""
        mapping: dict[str, Optional[str]] = {
            issuer: None for issuer in self.trusted_issuer_set()
        }
        if not self.TRUSTED_ISSUER_JWKS.strip():
            return mapping
        for pair in filter(None, map(str.strip, self.TRUSTED_ISSUER_JWKS.split(","))):
            issuer, jwks_uri = pair.split("=", 1)
            mapping[issuer.strip()] = jwks_uri.strip()
        return mapping


# MCP_GATEWAY_ENV_FILE names another file of settings, or with "" none at all.
settings = Settings(_env_file=os.environ.get("MCP_GATEWAY_ENV_FILE", ".env") or None)
