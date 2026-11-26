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

"""People's tokens for MCP servers: stored, refreshed and exchanged.

Tokens are encrypted with AES-256-GCM before they are stored in the database.
"""

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import httpx
import requests
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ..config import settings
from ..metrics import record_token_refresh
from ..models import MCPCatalog, OAuthToken, User
from ..telemetry import span
from .mcp_oauth_discovery import parse_token_response, resolve_oauth_metadata
from .oidc_client import OIDCClient
from .token_encryption import get_token_encryption

logger = logging.getLogger(__name__)

# The person's own gateway token, kept for the device flow and token exchange.
GATEWAY_TOKEN_SERVICE = "gateway"
# The gateway token a person signed in with through the Slack bot.
SLACK_TOKEN_SERVICE = "slack_gateway"
# Names the gateway stores its own tokens under, which no server may take.
RESERVED_SERVICE_IDS = frozenset({GATEWAY_TOKEN_SERVICE, SLACK_TOKEN_SERVICE})
# A token this close to expiring is refreshed, so it doesn't expire in flight.
EXPIRY_LEEWAY = timedelta(seconds=60)
# One refresh at a time per person and server, within a process; a row lock
# does the same across replicas. Providers that rotate refresh tokens reject
# the second use of one, and may revoke the person's session.
_refresh_locks: Dict[tuple, asyncio.Lock] = defaultdict(asyncio.Lock)


def token_expired(expires_at: Optional[datetime]) -> bool:
    """Whether a token that expires at ``expires_at`` should no longer be used."""
    return expires_at is not None and datetime.utcnow() >= expires_at - EXPIRY_LEEWAY


class TokenManager:
    """
    A person's tokens for MCP servers.

    For a server with single sign-on, the gateway exchanges the person's
    gateway token for one for the server (RFC 8693, or Entra's on-behalf-of
    flow), or forwards it when the server accepts the gateway's own tokens.
    For a server with its own sign-in, the person connects once, and the
    gateway refreshes the token it got. Service accounts have no tokens here;
    they reach servers with the server's service-account auth type.
    """

    def __init__(self, db: Session):
        self.db = db
        self._oidc_client: Optional[OIDCClient] = None

    @property
    def oidc_client(self) -> OIDCClient:
        """The identity provider's client; building it can fetch its discovery document."""
        if self._oidc_client is None:
            self._oidc_client = OIDCClient()
        return self._oidc_client

    async def _provider(self) -> OIDCClient:
        """The identity provider's client, built in a worker thread if need be."""
        return await run_in_threadpool(lambda: self.oidc_client)

    async def store_user_oauth_token(
        self,
        user_id: int,
        service: str,
        access_token: str,
        refresh_token: Optional[str] = None,
        expires_in: int = 3600,
    ):
        """Store, encrypted, a person's token for ``service``, replacing any before it.

        ``service`` is a server ID, or GATEWAY_TOKEN_SERVICE for their gateway
        token. ``expires_in`` is in seconds.
        """
        token_encryption = await get_token_encryption()

        # Encrypt tokens
        access_token_encrypted = token_encryption.encrypt(access_token)
        refresh_token_encrypted = None
        if refresh_token:
            refresh_token_encrypted = token_encryption.encrypt(refresh_token)

        values = {
            "access_token_encrypted": access_token_encrypted,
            "refresh_token_encrypted": refresh_token_encrypted,
            "expires_at": datetime.utcnow() + timedelta(seconds=expires_in),
        }
        if self._update_stored(user_id, service, values):
            self.db.commit()
            return
        self.db.add(OAuthToken(user_id=user_id, service=service, **values))
        try:
            self.db.commit()
        except IntegrityError:
            # A concurrent request stored one first; this token is as good.
            self.db.rollback()
            self._update_stored(user_id, service, values)
            self.db.commit()

    def _stored(
        self, user_id: int, service: str, *, lock: bool = False
    ) -> Optional[OAuthToken]:
        query = (
            self.db.query(OAuthToken)
            .populate_existing()
            .filter(OAuthToken.user_id == user_id, OAuthToken.service == service)
        )
        return (query.with_for_update() if lock else query).first()

    def _update_stored(self, user_id: int, service: str, values: dict) -> bool:
        oauth_token = self._stored(user_id, service)
        if oauth_token is None:
            return False
        for name, value in values.items():
            setattr(oauth_token, name, value)
        oauth_token.updated_at = datetime.utcnow()
        return True

    async def get_user_oauth_token(
        self,
        user_id: int,
        service: str,
        gateway_token: Optional[str] = None,
        auto_connect: bool = True,
    ) -> Optional[str]:
        """
        A person's token for ``service``, or None if they must connect it.

        1. A stored token that is valid, or that refreshes.
        2. For a server with single sign-on that accepts the gateway's own
           tokens, the person's gateway token, ``gateway_token`` if none is stored.
        3. For another server with single sign-on, with ``auto_connect``, a
           token exchanged for ``gateway_token``.
        """
        oauth_token = self._stored(user_id, service)
        if oauth_token is not None and token_expired(oauth_token.expires_at):
            oauth_token = await self._renew_expired_token(user_id, service, oauth_token)
        if oauth_token is None:
            if service in RESERVED_SERVICE_IDS:
                return None
            return await self._single_sign_on_token(
                user_id, service, gateway_token, auto_connect
            )
        token_encryption = await get_token_encryption()
        return token_encryption.decrypt(oauth_token.access_token_encrypted)

    async def _single_sign_on_token(
        self,
        user_id: int,
        service: str,
        gateway_token: Optional[str],
        auto_connect: bool,
    ) -> Optional[str]:
        """A token for a server with single sign-on, forwarded or exchanged, or None."""
        mcp = MCPCatalog.find_active(self.db, service)
        # Only an admin sets single sign-on, so a server with its own sign-in
        # never gets the gateway token, whatever its client ID is.
        if mcp is None or not mcp.auto_sso_enabled:
            return None
        if mcp.audience in settings.gateway_audiences:
            stored = await self.get_user_oauth_token(
                user_id, GATEWAY_TOKEN_SERVICE, auto_connect=False
            )
            return stored or gateway_token
        if not (auto_connect and gateway_token):
            return None
        result = await self.connect_mcp_with_obo(
            user_id=user_id, service=service, gateway_token=gateway_token
        )
        if not result["success"]:
            logger.warning(
                "Token exchange for user %s on %s failed: %s %s",
                user_id,
                service,
                result.get("error"),
                result.get("hint", ""),
            )
            return None
        return await self.get_user_oauth_token(user_id, service, auto_connect=False)

    async def _renew_expired_token(
        self, user_id: int, service: str, oauth_token: OAuthToken
    ) -> Optional[OAuthToken]:
        """Refresh an expired token; None when it has no refresh token or refreshing fails."""
        if not oauth_token.refresh_token_encrypted:
            return None
        async with _refresh_locks[(user_id, service)]:
            # The row lock serializes refreshes across replicas too; another
            # request may have refreshed the token while this one waited.
            current = self._stored(user_id, service, lock=True)
            if current is None or not token_expired(current.expires_at):
                self.db.commit()  # Releases the row lock.
                return current
            success = bool(current.refresh_token_encrypted) and (
                await self._refresh_user_token(user_id, service, current)
            )
            record_token_refresh(service, success)
            # Storing the refreshed token commits; otherwise release the lock.
            self.db.commit()
            return self._stored(user_id, service) if success else None

    async def _refresh_user_token(
        self, user_id: int, service: str, oauth_token: OAuthToken
    ) -> bool:
        """Refresh an expired token; False when the person must connect again."""
        with span("mcp.token_refresh", {"mcp.server.id": service}):
            return await self._refresh_user_token_unspanned(
                user_id, service, oauth_token
            )

    async def _refresh_user_token_unspanned(
        self, user_id: int, service: str, oauth_token: OAuthToken
    ) -> bool:
        """The refresh itself."""
        try:
            refresh_token = (await get_token_encryption()).decrypt(
                oauth_token.refresh_token_encrypted
            )
            if not refresh_token:
                logger.error(
                    "No refresh token for user=%s, service=%s", user_id, service
                )
                return False

            # Not only active servers: a server with its own sign-in must never
            # have its token replaced by one from the gateway's provider.
            mcp = (
                self.db.query(MCPCatalog)
                .filter(MCPCatalog.service_id == service)
                .first()
            )
            if mcp and mcp.auth_type == "oauth" and not mcp.auto_sso_enabled:
                return await self._refresh_mcp_oauth_token(user_id, mcp, refresh_token)

            token_response = await run_in_threadpool(
                (await self._provider()).refresh_access_token,
                refresh_token=refresh_token,
                client_id=settings.GATEWAY_OAUTH_CLIENT_ID,
                client_secret=settings.GATEWAY_OAUTH_CLIENT_SECRET,
            )
            await self.store_user_oauth_token(
                user_id=user_id,
                service=service,
                access_token=token_response["access_token"],
                refresh_token=token_response.get("refresh_token", refresh_token),
                expires_in=token_response.get("expires_in", 3600),
            )
            return True
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(
                "Token refresh failed for user=%s, service=%s: %s", user_id, service, e
            )
            return False

    async def _refresh_mcp_oauth_token(  # pylint: disable=too-many-locals
        self, user_id: int, mcp: MCPCatalog, refresh_token: str
    ) -> bool:
        """Refresh via well-known OAuth token endpoint discovered from the MCP catalog."""

        refresh_value = refresh_token
        service = mcp.service_id
        if not refresh_value:
            logger.error(
                "MCP OAuth refresh: empty refresh token for user=%s service=%s",
                user_id,
                service,
            )
            return False

        client_id = mcp.oauth_client_id or ""
        try:
            metadata = await resolve_oauth_metadata(
                mcp.mcp_url,
                mcp.oauth_metadata_url,
                has_client_secret=bool(mcp.oauth_client_secret_encrypted),
            )
            token_endpoint = metadata.token_endpoint
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error(
                "MCP OAuth refresh: discovery failed for user=%s service=%s: %s",
                user_id,
                service,
                exc,
            )
            return False

        if not client_id or not token_endpoint:
            logger.error(
                "MCP OAuth refresh: missing client_id or token_endpoint for user=%s service=%s",
                user_id,
                service,
            )
            return False

        body = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_value,
        }
        if mcp.oauth_client_secret_encrypted:
            encryption = await get_token_encryption()
            client_secret = encryption.decrypt(mcp.oauth_client_secret_encrypted)
            if client_secret is None:
                logger.error(
                    "MCP OAuth refresh: the client secret of %s can't be read", service
                )
                return False
            body["client_secret"] = client_secret

        try:
            async with httpx.AsyncClient(
                timeout=15.0, verify=settings.upstream_tls_verify
            ) as client:
                resp = await client.post(
                    token_endpoint,
                    data=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                resp.raise_for_status()
                data = resp.json()

            access_token, new_refresh, expires_in = parse_token_response(data)
            await self.store_user_oauth_token(
                user_id=user_id,
                service=service,
                access_token=access_token,
                refresh_token=new_refresh or refresh_value,
                expires_in=expires_in,
            )
            logger.info("MCP OAuth refresh successful for user=%s", user_id)
            return True
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error(
                "MCP OAuth refresh failed for user=%s service=%s: %s",
                user_id,
                service,
                exc,
            )
            return False

    async def disconnect_user_service_async(self, user_id: int, service: str):
        """Delete the person's token for ``service``."""
        self.db.query(OAuthToken).filter(
            OAuthToken.user_id == user_id, OAuthToken.service == service
        ).delete()
        self.db.commit()

    async def delete_all_user_tokens(self, user_id: int):
        """On sign-out, delete the person's gateway tokens, the one kept for Slack
        included, and the tokens got with them.

        Tokens for servers with their own sign-in stay: the person connected
        each of those themselves.
        """
        single_sign_on = select(MCPCatalog.service_id).where(
            MCPCatalog.auto_sso_enabled.is_(True)
        )
        deleted = (
            self.db.query(OAuthToken)
            .filter(
                OAuthToken.user_id == user_id,
                or_(
                    OAuthToken.service.in_(RESERVED_SERVICE_IDS),
                    OAuthToken.service.in_(single_sign_on),
                ),
            )
            .delete(synchronize_session="fetch")
        )
        self.db.commit()
        logger.info("Signed out user_id=%s: deleted %s token(s)", user_id, deleted)

    async def get_token(
        self, user_id: int, service: str, bearer_token: Optional[str] = None
    ) -> Optional[str]:
        """The caller's token for ``service``, or None if they must connect it.

        ``bearer_token``, the token the person called the gateway with, lets a
        server with single sign-on get one without the person connecting.
        Service accounts have none: they reach servers with the server's
        service-account auth type.
        """
        user = self.db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise ValueError(f"User {user_id} not found")
        if user.is_service_account:
            return None
        return await self.get_user_oauth_token(
            user_id,
            service,
            gateway_token=bearer_token,
            auto_connect=bearer_token is not None,
        )

    async def connect_mcp_with_obo(
        self,
        user_id: int,
        service: str,
        gateway_token: str,
    ) -> Dict[str, Any]:
        """
        Connect a user to an MCP server without another login, by exchanging
        their gateway token for a token for that server.

        TOKEN_EXCHANGE_STYLE picks the request. With "rfc8693" (Keycloak, Okta,
        Auth0, ...) the provider must let the gateway's client exchange tokens
        for the server's audience. With "entra_obo" (Microsoft Entra ID
        On-Behalf-Of) the gateway's app needs API permission to the server's app.

        Returns {"success": True, ...}, or {"success": False, "error": ...}
        with a "hint" for the admin when the provider refused.
        """
        mcp = MCPCatalog.find_active(self.db, service)
        if not mcp:
            return {
                "success": False,
                "error": f"MCP service '{service}' not found in catalog",
            }

        on_behalf_of = settings.token_exchange_style == "entra_obo"
        if on_behalf_of and not mcp.audience:
            return {
                "success": False,
                "error": f"MCP service '{service}' has no app ID for the On-Behalf-Of exchange",
            }

        try:
            result = await self._exchange_token(mcp, gateway_token, on_behalf_of)
        except (requests.ConnectionError, requests.Timeout) as e:
            # Not the person's fault: their sign-in is fine, the provider is not reachable.
            logger.warning(
                "Token exchange for %s could not reach the provider: %s", service, e
            )
            return {
                "success": False,
                "error": "Token exchange failed: the identity provider could not be reached",
            }
        except requests.HTTPError as e:
            error_detail = "Unknown error"
            try:
                error_data = e.response.json()
                error_detail = error_data.get(
                    "error_description", error_data.get("error", str(e))
                )
            except Exception:  # pylint: disable=broad-exception-caught
                error_detail = str(e)

            hint = (
                "Ensure the gateway's app has API permission to the MCP server's "
                "app and the user has consented"
                if on_behalf_of
                else "Ensure the provider lets the gateway's client exchange tokens "
                "for the MCP server's audience"
            )
            return {
                "success": False,
                "error": f"Token exchange failed: {error_detail}",
                "hint": hint,
            }

        await self.store_user_oauth_token(
            user_id=user_id,
            service=service,
            access_token=result["access_token"],
            refresh_token=result.get("refresh_token"),  # Exchanges may not return one
            expires_in=result.get("expires_in", 3600),
        )

        return {
            "success": True,
            "message": f"Connected to {service} by token exchange (no additional login)",
            "expires_in": result.get("expires_in", 3600),
        }

    async def _exchange_token(
        self, mcp: MCPCatalog, gateway_token: str, on_behalf_of: bool
    ) -> Dict[str, Any]:
        """Exchange the user's gateway token for a token for ``mcp``."""
        with span("mcp.token_exchange", {"mcp.server.id": mcp.service_id}):
            return await self._exchange_token_unspanned(
                mcp, gateway_token, on_behalf_of
            )

    async def _exchange_token_unspanned(
        self, mcp: MCPCatalog, gateway_token: str, on_behalf_of: bool
    ) -> Dict[str, Any]:
        """The exchange itself."""
        if on_behalf_of:
            target_scope = mcp.oauth_scopes or f"api://{mcp.audience}/.default"
            logger.info(
                "On-Behalf-Of exchange: service=%s, scope=%s",
                mcp.service_id,
                target_scope,
            )
            return await run_in_threadpool(
                (await self._provider()).exchange_token_on_behalf_of,
                user_access_token=gateway_token,
                client_id=settings.GATEWAY_OAUTH_CLIENT_ID,
                client_secret=settings.GATEWAY_OAUTH_CLIENT_SECRET,
                target_scope=target_scope,
            )

        audience = mcp.audience or mcp.service_id
        logger.info(
            "Token exchange: service=%s, audience=%s, scope=%s",
            mcp.service_id,
            audience,
            mcp.oauth_scopes,
        )
        return await run_in_threadpool(
            (await self._provider()).exchange_token_rfc8693,
            user_access_token=gateway_token,
            client_id=settings.GATEWAY_OAUTH_CLIENT_ID,
            client_secret=settings.GATEWAY_OAUTH_CLIENT_SECRET,
            target_audience=audience,
            scope=mcp.oauth_scopes,
        )
