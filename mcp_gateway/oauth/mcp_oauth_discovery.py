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
OAuth metadata discovery for MCP servers (RFC 9728 + RFC 8414) and DCR (RFC 7591).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urlsplit

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 86400  # 24 hours
_metadata_cache: Dict[str, tuple[float, "OAuthServerMetadata"]] = {}

_DEFAULT_TTL_SECONDS = 3600
# A provider that omits expires_in and issues no refresh token is handing out a
# credential that stays valid until revoked (e.g. Slack classic xoxp user tokens,
# issued whenever token rotation is off). Storing a short TTL would make the
# web UI show it as expired and trigger a refresh that cannot succeed.
_NON_EXPIRING_TTL_SECONDS = 365 * 24 * 3600

CANDIDATE_URLS = [
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
]


@dataclass(frozen=True)
class OAuthServerMetadata:
    """Discovered OAuth authorization server metadata."""

    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: Optional[str] = None
    scopes_supported: Optional[List[str]] = None
    issuer: Optional[str] = None

    def format_scopes(self, override: Optional[str] = None) -> str:
        """Return scope string for authorize requests."""
        if override:
            return override.strip()
        if self.scopes_supported:
            return " ".join(self.scopes_supported)
        return ""


def require_https(url: str) -> None:
    """Refuse an authorization server URL that isn't https, unless DEBUG is on.

    Codes, refresh tokens and client secrets go to these URLs.
    """
    if not settings.DEBUG and not url.startswith("https://"):
        raise ValueError(f"{url} must use https")


def _origin_and_path(mcp_url: str) -> tuple[str, str]:
    parsed = urlparse(mcp_url.rstrip("/"))
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or ""
    return origin, path


def _protected_resource_urls(mcp_url: str) -> List[str]:
    """Candidate RFC 9728 protected-resource metadata URLs."""
    origin, path = _origin_and_path(mcp_url)
    urls: List[str] = []
    if path and path != "/":
        urls.append(f"{origin}/.well-known/oauth-protected-resource{path}")
    urls.append(f"{origin}/.well-known/oauth-protected-resource")
    return urls


async def _fetch_json(url: str) -> Optional[Dict[str, Any]]:
    # Metadata lives at its well-known URL; a redirect could send the gateway's
    # request anywhere, so it counts as no metadata.
    async with httpx.AsyncClient(
        timeout=15.0, follow_redirects=False, verify=settings.upstream_tls_verify
    ) as client:
        resp = await client.get(url, headers={"Accept": "application/json"})
        if resp.status_code >= 300:
            logger.info(
                "OAuth discovery: %s returned HTTP %s",
                url,
                resp.status_code,
            )
            return None
        logger.info("OAuth discovery: %s returned HTTP %s", url, resp.status_code)
        return resp.json()


def _metadata_from_auth_server_doc(
    data: Dict[str, Any], issuer: Optional[str] = None
) -> OAuthServerMetadata:
    """The endpoints in an authorization server's metadata document.

    ``issuer`` is the server the document was fetched for. Its document must
    not name another (RFC 8414 section 3.3), and the endpoints of an https
    server must use https.
    """
    authorization_endpoint = data.get("authorization_endpoint", "")
    token_endpoint = data.get("token_endpoint", "")
    if not authorization_endpoint or not token_endpoint:
        raise ValueError("authorization server metadata missing required endpoints")
    named = data.get("issuer")
    if issuer and named and str(named).rstrip("/") != issuer.rstrip("/"):
        raise ValueError(f"metadata of {issuer} names another issuer, {named}")
    endpoints = (authorization_endpoint, token_endpoint)
    if data.get("registration_endpoint"):
        endpoints += (data["registration_endpoint"],)
    for url in endpoints:
        require_https(str(url))
    scopes = data.get("scopes_supported")
    return OAuthServerMetadata(
        authorization_endpoint=authorization_endpoint,
        token_endpoint=token_endpoint,
        registration_endpoint=data.get("registration_endpoint"),
        scopes_supported=list(scopes) if scopes else None,
        issuer=data.get("issuer"),
    )


async def _fetch_authorization_server_metadata(
    candidate_urls: List[str], issuer: Optional[str] = None
) -> OAuthServerMetadata:
    last_error: Optional[Exception] = None
    for url in candidate_urls:
        try:
            data = await _fetch_json(url)
            if data:
                return _metadata_from_auth_server_doc(data, issuer)
        except (ValueError, TypeError, httpx.HTTPError) as exc:
            last_error = exc
            continue
    if last_error:
        raise last_error
    raise ValueError(
        f"could not fetch authorization server metadata from {candidate_urls}"
    )


def _cached_metadata(cache_key: str) -> Optional[OAuthServerMetadata]:
    cached = _metadata_cache.get(cache_key)
    if cached and (time.time() - cached[0]) < _CACHE_TTL_SECONDS:
        logger.info("OAuth discovery: cache hit for %s", cache_key)
        return cached[1]
    return None


async def resolve_oauth_metadata(
    mcp_url: str, metadata_url: Optional[str] = None, *, has_client_secret=False
) -> OAuthServerMetadata:
    """
    Resolve OAuth metadata for an MCP server.

    When ``metadata_url`` is configured on the catalog entry, fetch that
    RFC 8414 authorization-server document directly. Otherwise fall back to
    well-known discovery from ``mcp_url``. A client secret goes only to a token
    endpoint an admin named, never to one the MCP server points to.
    """
    if not metadata_url:
        if has_client_secret:
            raise ValueError(
                "a server with a client secret needs its authorization server "
                "metadata URL"
            )
        return await discover_oauth_metadata(mcp_url)

    cache_key = metadata_url.rstrip("/")
    cached = _cached_metadata(cache_key)
    if cached:
        return cached

    logger.info("OAuth discovery: using configured metadata_url=%s", cache_key)
    metadata = await _fetch_authorization_server_metadata([metadata_url])
    logger.info(
        "OAuth discovery: selected authorization_endpoint=%s token_endpoint=%s",
        metadata.authorization_endpoint,
        metadata.token_endpoint,
    )
    _metadata_cache[cache_key] = (time.time(), metadata)
    return metadata


async def discover_oauth_metadata(mcp_url: str) -> OAuthServerMetadata:
    """
    Discover OAuth endpoints for an MCP server URL.

    Tries RFC 9728 protected-resource metadata first, then falls back to
    RFC 8414 authorization-server metadata at the MCP origin.
    """
    cache_key = mcp_url.rstrip("/")
    cached = _cached_metadata(cache_key)
    if cached:
        return cached

    origin, _path = _origin_and_path(mcp_url)
    logger.info("OAuth discovery: starting for mcp_url=%s origin=%s", mcp_url, origin)
    metadata: Optional[OAuthServerMetadata] = None

    for pr_url in _protected_resource_urls(mcp_url):
        logger.info(
            "OAuth discovery: trying protected resource metadata url=%s", pr_url
        )
        pr_data = await _fetch_json(pr_url)
        if not pr_data:
            logger.info(
                "OAuth discovery: protected resource metadata unavailable at %s",
                pr_url,
            )
            continue
        auth_servers = pr_data.get("authorization_servers") or []
        if not auth_servers:
            logger.info(
                "OAuth discovery: no authorization_servers in protected resource metadata at %s",
                pr_url,
            )
            continue
        logger.info(
            "OAuth discovery: using authorization_server=%s from protected resource metadata",
            auth_servers[0],
        )
        base = str(auth_servers[0]).rstrip("/")
        # The MCP server names this host, so it must not be plain http.
        require_https(base)
        candidate_urls = [f"{base}{url}" for url in CANDIDATE_URLS]
        metadata = await _fetch_authorization_server_metadata(candidate_urls, base)
        break

    if metadata is None:
        candidate_urls = [f"{origin}{url}" for url in CANDIDATE_URLS]
        metadata = await _fetch_authorization_server_metadata(candidate_urls, origin)

    logger.info(
        "OAuth discovery: selected authorization_endpoint=%s token_endpoint=%s registration_endpoint=%s",
        metadata.authorization_endpoint,
        metadata.token_endpoint,
        metadata.registration_endpoint,
    )
    _metadata_cache[cache_key] = (time.time(), metadata)
    return metadata


def clear_discovery_cache() -> None:
    """Clear cached discovery results (for tests)."""
    _metadata_cache.clear()


async def register_oauth_client(
    registration_endpoint: str,
    redirect_uri: str,
    *,
    client_name: str = "MCP Gateway",
) -> str:
    """
    Register a public OAuth client via RFC 7591 dynamic client registration.

    Always uses ``token_endpoint_auth_method: none`` (public PKCE client).
    Confidential clients are not created here; an admin sets the server's
    ``oauth_client_id`` and ``oauth_client_secret`` when the provider requires
    a client secret.

    Returns the issued client_id.
    """
    async with httpx.AsyncClient(
        timeout=15.0, verify=settings.upstream_tls_verify
    ) as client:
        resp = await client.post(
            registration_endpoint,
            json={
                "client_name": client_name,
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
    client_id = data.get("client_id")
    if not client_id:
        raise ValueError("registration response missing client_id")
    return str(client_id)


def scope_param_for_authorize(scope: str, authorization_endpoint: str) -> str:
    """Slack expects comma-separated scopes; most providers use space-separated."""
    host = urlsplit(authorization_endpoint).hostname or ""
    if host == "slack.com" or host.endswith(".slack.com"):
        return scope.replace(" ", ",")
    return scope


def build_authorize_url(
    metadata: OAuthServerMetadata,
    *,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    scope: str,
) -> str:
    """Build authorization redirect URL with PKCE."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if scope:
        params["scope"] = scope_param_for_authorize(
            scope, metadata.authorization_endpoint
        )
    return f"{metadata.authorization_endpoint}?{urlencode(params)}"


def parse_token_response(data: Dict[str, Any]) -> tuple[str, Optional[str], int]:
    """
    Normalize token endpoint JSON into (access_token, refresh_token, expires_in).

    Handles Slack's {ok, access_token} wrapper. When the provider omits
    ``expires_in``, the token is treated as non-expiring if no refresh token
    came with it, and as a one-hour token otherwise.
    """
    if data.get("ok") is False:
        raise ValueError(data.get("error", "token exchange failed"))
    access_token = data.get("access_token")
    if not access_token:
        authed = data.get("authed_user") or {}
        access_token = authed.get("access_token")
    if not access_token:
        raise ValueError("token response missing access_token")

    refresh_token = data.get("refresh_token")
    raw_expires_in = data.get("expires_in")
    if raw_expires_in:
        expires_in = int(raw_expires_in)
    elif refresh_token:
        expires_in = _DEFAULT_TTL_SECONDS
    else:
        expires_in = _NON_EXPIRING_TTL_SECONDS
    return access_token, refresh_token, expires_in
