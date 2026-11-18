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

"""The gateway's client of its OpenID Connect provider: discovery, sign-in,
refresh and token exchange, with any provider."""

import base64
import hashlib
import hmac
import logging
import threading
import time
from typing import Any, Dict, Optional, Tuple

import requests

from ..config import settings

logger = logging.getLogger(__name__)


def pkce_verifier(state: str) -> str:
    """The PKCE code verifier (RFC 7636) of the sign-in whose state is ``state``.

    It is derived from the state with JWT_SECRET_KEY, so the gateway keeps
    nothing: the state goes through the browser, but the verifier never does,
    so a code taken from a browser can't be redeemed in another sign-in.
    """
    digest = hmac.new(
        settings.JWT_SECRET_KEY.encode(), b"pkce:" + state.encode(), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def pkce_challenge(verifier: str) -> str:
    """The S256 code challenge for ``verifier``."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# Process-wide cache of provider discovery documents, keyed by discovery URL.
# OIDCClient is constructed per request (TokenManager builds one for every MCP
# call), so an uncached lookup here means a provider round-trip on every request.
_discovery_lock = threading.Lock()
_discovery_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_discovery_failed_until: Dict[str, float] = {}

# After a failed fetch, serve stale/fallback config for this long before retrying,
# so an outage at the provider cannot turn every request into a timeout wait.
_DISCOVERY_RETRY_BACKOFF = 30.0


def reset_discovery_cache() -> None:
    """Clear cached discovery documents. Intended for tests and config reloads."""
    with _discovery_lock:
        _discovery_cache.clear()
        _discovery_failed_until.clear()


def _get_discovery_document(url: str) -> Optional[Dict[str, Any]]:
    """
    Fetch a provider's discovery document, cached process-wide for
    ``OIDC_DISCOVERY_CACHE_TTL`` seconds.

    The fetch happens under a lock so that concurrent callers collapse into a
    single request rather than each issuing their own.
    """
    ttl = settings.OIDC_DISCOVERY_CACHE_TTL
    now = time.monotonic()

    if ttl > 0:
        cached = _discovery_cache.get(url)
        if cached and cached[0] > now:
            return cached[1]

    with _discovery_lock:
        # Another thread may have populated the cache while we waited.
        now = time.monotonic()
        cached = _discovery_cache.get(url)
        if ttl > 0 and cached and cached[0] > now:
            return cached[1]

        if _discovery_failed_until.get(url, 0.0) > now:
            # Still in backoff: prefer a stale document over stalling again.
            return cached[1] if cached else None

        try:
            response = requests.get(url, timeout=settings.OIDC_HTTP_TIMEOUT)
            response.raise_for_status()
            document = response.json()
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning("Could not auto-discover OIDC endpoints from %s: %s", url, e)
            _discovery_failed_until[url] = now + _DISCOVERY_RETRY_BACKOFF
            return cached[1] if cached else None

        _discovery_failed_until.pop(url, None)
        if ttl > 0:
            _discovery_cache[url] = (now + ttl, document)
        return document


def get_configured_issuer() -> Optional[str]:
    """Return the configured human-user OIDC issuer from settings or discovery."""
    if settings.OIDC_ISSUER:
        return settings.OIDC_ISSUER
    if settings.OIDC_DISCOVERY_URL:
        document = _get_discovery_document(settings.OIDC_DISCOVERY_URL)
        if document is not None:
            issuer = document.get("issuer")
            if isinstance(issuer, str) and issuer.strip():
                return issuer.strip()
    return None


class OIDCClient:
    """Generic OIDC client for OAuth 2.0 flows"""

    def __init__(self, provider: str = None):
        """
        Initialize OIDC client

        Args:
            provider: Provider name (azure, google, okta, auth0, keycloak, cognito)
        """
        self.provider = provider or settings.OIDC_PROVIDER
        self._discovery_cache: Optional[Dict] = None
        self._load_configuration()

    def _load_configuration(self):
        """Load OIDC provider configuration from discovery endpoint or settings"""
        if settings.OIDC_DISCOVERY_URL:
            document = _get_discovery_document(settings.OIDC_DISCOVERY_URL)
            if document is not None:
                # Copy so a caller mutating its own view cannot corrupt the
                # process-wide cache shared by every other client.
                self._discovery_cache = dict(document)
                return

        # Fallback to manual configuration
        self._discovery_cache = {
            "issuer": settings.OIDC_ISSUER,
            "authorization_endpoint": settings.OIDC_AUTHORIZATION_ENDPOINT,
            "token_endpoint": settings.OIDC_TOKEN_ENDPOINT,
            "jwks_uri": settings.OIDC_JWKS_URI,
        }

    @property
    def authorization_endpoint(self) -> str:
        """Get authorization endpoint URL"""
        return self._discovery_cache.get("authorization_endpoint")

    @property
    def token_endpoint(self) -> str:
        """Get token endpoint URL"""
        return self._discovery_cache.get("token_endpoint")

    @property
    def jwks_uri(self) -> str:
        """Get JWKS URI for token validation"""
        return self._discovery_cache.get("jwks_uri")

    @property
    def issuer(self) -> Optional[str]:
        """The provider's issuer identifier."""
        return self._discovery_cache.get("issuer")

    @property
    def end_session_endpoint(self) -> Optional[str]:
        """RP-initiated logout endpoint, when the provider has one."""
        return self._discovery_cache.get("end_session_endpoint")

    @property
    def device_authorization_endpoint(self) -> Optional[str]:
        """Device authorization endpoint (RFC 8628), when the provider has one."""
        return self._discovery_cache.get("device_authorization_endpoint")

    @property
    def registration_endpoint(self) -> Optional[str]:
        """Dynamic client registration endpoint (RFC 7591), when the provider has one."""
        return self._discovery_cache.get("registration_endpoint")

    def get_authorization_url(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: str,
    ) -> str:
        """Where to send a person to sign in: an authorization code request with
        PKCE, whose verifier comes from ``state``."""
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "response_type": "code",
            "code_challenge": pkce_challenge(pkce_verifier(state)),
            "code_challenge_method": "S256",
        }

        # Provider-specific parameters
        if self.provider == "azure":
            params["response_mode"] = "query"

        query_string = "&".join(
            f"{k}={requests.utils.quote(v)}" for k, v in params.items()
        )
        return f"{self.authorization_endpoint}?{query_string}"

    def exchange_code_for_token(  # pylint: disable=too-many-arguments
        self,
        code: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        state: str,
    ) -> Dict[str, Any]:
        """The tokens for a sign-in's code; ``state`` is the sign-in's, for PKCE."""
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "code_verifier": pkce_verifier(state),
        }

        response = requests.post(
            self.token_endpoint, data=data, timeout=settings.OIDC_HTTP_TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    def refresh_access_token(
        self, refresh_token: str, client_id: str, client_secret: str
    ) -> Dict[str, Any]:
        """
        Refresh an expired access token using refresh token

        Args:
            refresh_token: Refresh token from previous auth
            client_id: OAuth client ID
            client_secret: OAuth client secret

        Returns:
            New token response with access_token, refresh_token, expires_in
        """
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }

        response = requests.post(
            self.token_endpoint, data=data, timeout=settings.OIDC_HTTP_TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    def exchange_token_on_behalf_of(
        self,
        user_access_token: str,
        client_id: str,
        client_secret: str,
        target_scope: str,
    ) -> Dict[str, Any]:
        """
        Exchange the user's gateway token for a token for another API with
        Microsoft Entra ID's On-Behalf-Of request.

        Args:
            user_access_token: User's access token for Gateway
            client_id: Gateway's OAuth client ID
            client_secret: Gateway's OAuth client secret
            target_scope: Scope for target resource (e.g., "api://<app id>/.default")

        Returns:
            Token response with access_token for target resource

        Raises:
            requests.HTTPError: If token exchange fails
        """
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "client_id": client_id,
            "client_secret": client_secret,
            "assertion": user_access_token,  # User's token for Gateway
            "scope": target_scope,
            "requested_token_use": "on_behalf_of",
        }

        response = requests.post(
            self.token_endpoint, data=data, timeout=settings.OIDC_HTTP_TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    def exchange_token_rfc8693(
        self,
        user_access_token: str,
        client_id: str,
        client_secret: str,
        target_audience: str,
        scope: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Exchange the user's gateway token for a token for ``target_audience``
        with an RFC 8693 token exchange (Keycloak, Okta, Auth0 and others).

        Args:
            user_access_token: User's access token for Gateway
            client_id: Gateway's OAuth client ID
            client_secret: Gateway's OAuth client secret
            target_audience: Audience (client id or API identifier) of the target service
            scope: Optional scopes to request for the target service

        Returns:
            Token response with access_token for target resource

        Raises:
            requests.HTTPError: If token exchange fails
        """
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": client_id,
            "client_secret": client_secret,
            "subject_token": user_access_token,  # the user's gateway token
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": target_audience,  # Target resource
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }
        if scope:
            data["scope"] = scope

        response = requests.post(
            self.token_endpoint, data=data, timeout=settings.OIDC_HTTP_TIMEOUT
        )
        response.raise_for_status()
        return response.json()
