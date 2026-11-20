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
The local proxy: MCP clients call http://localhost:8001/mcp/<server>, and it
forwards each call to the gateway the user signed in to, with their token.

Any program this user runs can call it, and so can other users of the same
machine; it refuses web pages. On a shared machine, use MCP clients that sign
in themselves instead.
"""

import asyncio
import json
import logging
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlsplit

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

from mcp_gateway.log_filter import install_sensitive_data_filter

from .auth import TOKEN_FILE, write_private_file
from .constants import (
    DEFAULT_GATEWAY_URL,
    PROXY_ID_FILE,
    PROXY_REQUEST_TIMEOUT,
    TOKEN_REFRESH_MARGIN_SECONDS,
)
from .proxy_identity import proof

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Headers for one connection, and those that describe a body httpx has decoded.
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
}
_REQUEST_HEADERS_DROPPED = _HOP_BY_HOP | {"host", "content-length", "accept-encoding"}
# WWW-Authenticate makes MCP clients start signing in, which the proxy does for them.
_RESPONSE_HEADERS_DROPPED = _HOP_BY_HOP | {
    "content-encoding",
    "content-length",
    "www-authenticate",
}

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
# The gateway's server IDs, as its admin API checks them.
_SERVER_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,99}$")


def is_local_request(headers) -> bool:
    """Whether a request comes from a program on this machine, not a web page.

    The proxy adds the user's token to everything it forwards. A web page can
    send requests to localhost, and DNS rebinding can point the page's own host
    name at 127.0.0.1, so the Host must be a loopback name. Browsers mark what
    pages send with Origin or Sec-Fetch-Site; MCP clients run outside a browser
    and send neither. Sec-Fetch-Site is "none" only for a URL the user typed.
    """
    host_header = headers.get("host", "")
    if "@" in host_header:
        return False
    try:
        host = urlsplit(f"//{host_header}").hostname or ""
    except ValueError:
        return False
    if host not in _LOOPBACK_HOSTS:
        return False
    if "origin" in headers:
        return False
    return headers.get("sec-fetch-site", "none") == "none"


class TokenManager:  # pylint: disable=too-many-instance-attributes
    """Manages OAuth tokens for the proxy"""

    def __init__(self, token_file: Path):
        self.token_file = token_file
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._expires_at: Optional[datetime] = None
        self._gateway_url = DEFAULT_GATEWAY_URL
        # Whether the last refresh found the gateway unreachable.
        self.gateway_unreachable = False
        self._refresh_lock = asyncio.Lock()
        self._token_file_mtime: Optional[float] = None
        self._refresh_task: Optional[asyncio.Task] = None
        self.load_tokens()

    def load_tokens(self):
        """Load tokens from file; without one, the user has logged out."""
        if not self.token_file.exists():
            logger.warning("Token file not found: %s", self.token_file)
            self._access_token = self._refresh_token = None
            self._token_file_mtime = None
            return

        try:

            self._token_file_mtime = self.token_file.stat().st_mtime
            with open(self.token_file, encoding="utf-8") as f:
                data = json.load(f)
                self._access_token = data.get("access_token")
                self._refresh_token = data.get("refresh_token")
                self._gateway_url = data.get("gateway_url", DEFAULT_GATEWAY_URL)
                expires_in = data.get("expires_in", 3600)
                created_at = data.get("created_at")

                if created_at:
                    created_dt = datetime.fromisoformat(created_at)
                    # Normalize to naive UTC to avoid comparison errors when
                    # created_at was saved as a timezone-aware ISO string
                    if created_dt.tzinfo is not None:
                        created_dt = created_dt.replace(tzinfo=None)
                    self._expires_at = created_dt + timedelta(seconds=expires_in)
                else:
                    # Assume token was just created
                    now = datetime.now(timezone.utc).replace(tzinfo=None)
                    self._expires_at = now + timedelta(seconds=expires_in)

                logger.info(
                    "Tokens loaded successfully. Gateway: %s", self._gateway_url
                )
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Error loading tokens: %s", e)

    def _check_token_file_changed(self):
        """Reload tokens from file if it was modified externally (e.g. by CLI)"""
        try:
            if not self.token_file.exists():
                if self._access_token:
                    logger.info("Token file removed; the user logged out")
                    self.load_tokens()
                return
            current_mtime = self.token_file.stat().st_mtime
            if self._token_file_mtime is None or current_mtime > self._token_file_mtime:
                logger.info("Token file changed on disk, reloading...")
                self.load_tokens()
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning("Error checking token file mtime: %s", e)

    def save_tokens(
        self, access_token: str, refresh_token: str, expires_in: int = 3600
    ):
        """Save tokens to file"""
        try:
            data = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "gateway_url": self._gateway_url,
                "expires_in": expires_in,
                # Naive UTC, as auth.save_tokens writes it.
                "created_at": datetime.utcnow().isoformat(),
            }
            write_private_file(self.token_file, json.dumps(data, indent=2))
            self._token_file_mtime = self.token_file.stat().st_mtime

            self._access_token = access_token
            self._refresh_token = refresh_token
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            self._expires_at = now + timedelta(seconds=expires_in)

            logger.info("Tokens saved successfully")
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Error saving tokens: %s", e)

    def is_token_valid(self) -> bool:
        """Whether the token is good and not yet due for a refresh."""
        if not self._access_token:
            return False
        if not self._expires_at:
            return True  # Assume valid if no expiry
        now = datetime.now(timezone.utc).replace(tzinfo=None)  # Convert to naive UTC
        return self._expires_at > now + timedelta(seconds=TOKEN_REFRESH_MARGIN_SECONDS)

    def _has_expired(self) -> bool:
        """Whether the token's lifetime is over."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        return self._expires_at is not None and self._expires_at <= now

    def get_gateway_url(self) -> str:
        """Get the gateway URL"""
        return self._gateway_url

    async def refresh_access_token(self, rejected: Optional[str] = None) -> bool:
        """Refresh the access token, one refresh at a time.

        ``rejected`` is a token the gateway refused, which is refreshed even if
        it hasn't expired, as when the identity provider revoked it.
        """
        async with self._refresh_lock:
            self.gateway_unreachable = False
            # Another request may have refreshed it while this one waited.
            if self.is_token_valid() and self._access_token != rejected:
                return True

            if not self._refresh_token:
                logger.error("No refresh token available")
                return False

            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
                    response = await client.post(
                        f"{self._gateway_url}/auth/refresh",
                        json={"refresh_token": self._refresh_token},
                    )

                    if response.status_code == 200:
                        data = response.json()
                        self.save_tokens(
                            data["access_token"],
                            data.get("refresh_token", self._refresh_token),
                            data.get("expires_in", 3600),
                        )
                        logger.info("Access token refreshed successfully")
                        return True
                    # A load balancer answers 502 or 503 while the gateway restarts.
                    self.gateway_unreachable = response.status_code >= 500
                    logger.error(
                        "Failed to refresh token: %s - %s",
                        response.status_code,
                        response.text,
                    )
                    return False
            except (httpx.ConnectError, httpx.ConnectTimeout) as e:
                logger.error("Could not reach the gateway to refresh the token: %s", e)
                self.gateway_unreachable = True
                return False
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error("Error refreshing token: %s", e)
                return False

    async def get_valid_token(self) -> Optional[str]:
        """Get a valid access token, refreshing if necessary"""
        # Check if the token file was modified externally (e.g. by `gravitino-mcp whoami`)
        self._check_token_file_changed()

        if self.is_token_valid():
            return self._access_token

        logger.info("Token expired or expiring soon, refreshing...")
        if await self.refresh_access_token():
            return self._access_token
        # A token that hasn't expired still works once the gateway answers.
        if self.gateway_unreachable and not self._has_expired():
            return self._access_token

        logger.error("Failed to get valid token")
        return None

    async def start_background_refresh(self):
        """Start a background task that refreshes the token before it expires"""
        self._refresh_task = asyncio.create_task(self._background_refresh_loop())

    async def stop_background_refresh(self):
        """Cancel the background refresh task"""
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass

    async def _background_refresh_loop(self):
        """Periodically refresh the token before it expires"""
        while True:
            try:
                # Check for external file changes first
                self._check_token_file_changed()

                if self._expires_at:
                    now = datetime.now(timezone.utc).replace(tzinfo=None)
                    time_until_expiry = (self._expires_at - now).total_seconds()
                    # Refresh in the token's last minute
                    sleep_seconds = max(
                        time_until_expiry - TOKEN_REFRESH_MARGIN_SECONDS, 30
                    )
                else:
                    # No expiry info — check again in 5 minutes
                    sleep_seconds = 300

                await asyncio.sleep(sleep_seconds)

                if not self.is_token_valid():
                    logger.info(
                        "Background refresh: token expiring soon, refreshing..."
                    )
                    await self.refresh_access_token()
            except asyncio.CancelledError:
                break
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error("Background refresh error: %s", e)
                await asyncio.sleep(60)  # Retry after 1 minute on error


# Maximum number of retries for transient connection errors
PROXY_MAX_RETRIES = 2


def _unreachable(gateway_url: str) -> Response:
    """The answer when the gateway can't be reached, in plain text so that MCP
    clients don't take it for a request to sign in."""
    logger.error("Failed to connect to the gateway at %s", gateway_url)
    return Response(
        content=f"Could not reach the MCP gateway at {gateway_url}",
        status_code=503,
        media_type="text/plain",
    )


class AuthProxy:
    """HTTP proxy that auto-injects OAuth tokens"""

    def __init__(self, token_manager: TokenManager, proxy_id: str = ""):
        self.token_manager = token_manager
        # Lets the CLI tell this user's proxy from another program on the port.
        self.proxy_id = proxy_id
        self._http_client: Optional[httpx.AsyncClient] = None

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            await self._startup()
            await self.token_manager.start_background_refresh()
            yield
            await self.token_manager.stop_background_refresh()
            await self._shutdown()

        self.app = FastAPI(title="MCP Gateway Auth Proxy", lifespan=lifespan)

        @self.app.middleware("http")
        async def refuse_web_pages(request: Request, call_next):
            if not is_local_request(request.headers):
                logger.warning(
                    "Refused request from origin=%s host=%s",
                    request.headers.get("origin"),
                    request.headers.get("host"),
                )
                return Response(
                    content="Requests from web pages are not allowed",
                    status_code=403,
                    media_type="text/plain",
                )
            return await call_next(request)

        self.app.add_api_route("/", self.root_handler, methods=["GET"])
        self.app.add_api_route("/health", self.health_handler, methods=["GET"])

        # Block ALL OAuth/OIDC discovery endpoints — this is an auth proxy, not an OAuth server.
        # Claude Code probes multiple RFC 9728 / RFC 8414 / OIDC paths, including path-specific
        # variants like /.well-known/oauth-authorization-server/mcp/{service}. If ANY of these
        # leak through to the gateway, the gateway returns a JSON 404 (application/json), which
        # Claude Code may interpret as OAuth-capable → shows "needs authentication".
        # Using a single catch-all for /.well-known/ ensures no variant leaks through.
        self.app.add_api_route(
            "/.well-known/{path:path}", self.oauth_not_supported, methods=["GET"]
        )

        # Block OAuth Dynamic Client Registration (RFC 7591) — Claude Code tries POST /register
        # after discovery. Must not leak to the gateway.
        self.app.add_api_route("/register", self.oauth_not_supported, methods=["POST"])

        # Block metadata endpoints that might trigger OAuth in VS Code
        self.app.add_api_route(
            "/mcp/{service}/", self.mcp_metadata_handler, methods=["GET"]
        )
        self.app.add_api_route(
            "/mcp/{service}/.well-known/{path:path}",
            self.oauth_not_supported,
            methods=["GET"],
        )

        # Only MCP calls are forwarded, not the gateway's API.
        self.app.add_api_route(
            "/mcp/{path:path}",
            self.proxy_request,
            methods=["GET", "POST", "DELETE", "OPTIONS", "HEAD"],
        )
        self.app.add_api_route(
            "/{path:path}",
            self.oauth_not_supported,
            methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
        )

    async def _startup(self):
        """Create shared HTTP client with connection pooling"""
        self._http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=30.0,
                read=float(PROXY_REQUEST_TIMEOUT),
                write=30.0,
                pool=30.0,
            ),
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
                keepalive_expiry=30.0,
            ),
        )

    async def _shutdown(self):
        """Close shared HTTP client"""
        if self._http_client:
            await self._http_client.aclose()

    async def root_handler(self):
        """Handle root path requests - don't trigger OAuth discovery"""
        return {
            "service": "MCP Gateway Auth Proxy",
            "status": "ready",
            "message": "MCP endpoints available at /mcp/{service}",
        }

    async def health_handler(self, request: Request):
        """Answer for the proxy itself, proving it knows the ID only this user can read."""
        return {
            "status": "healthy",
            "proof": proof(self.proxy_id, request.query_params.get("nonce", "")),
        }

    async def oauth_not_supported(self):
        """Return plain 404 for OAuth discovery endpoints.

        IMPORTANT: The body must NOT contain an ``error`` key — RFC 6749 §5.2
        defines ``{"error": "..."}`` as a valid OAuth error response, and MCP
        clients (Claude Code, Goose, etc.) will interpret it as "this server
        uses OAuth" and show a "needs authentication" prompt.  A plain 404 with
        no OAuth-shaped body tells the client to skip OAuth discovery entirely.
        """
        return Response(content="Not Found", status_code=404, media_type="text/plain")

    async def mcp_metadata_handler(self, service: str):
        """Handle MCP metadata requests - return simple response without triggering OAuth"""
        return {
            "service": service,
            "transport": "http",
            "authentication": "transparent",
            "message": "Authentication handled by proxy. No OAuth required.",
        }

    @staticmethod
    def _sanitize_response_headers(raw_headers: dict) -> dict:
        """The gateway's response headers that still describe the forwarded response.

        httpx hands over a decoded body, and MCP clients take WWW-Authenticate
        to mean they must sign in, which the proxy does for them.
        """
        return {
            k: v
            for k, v in raw_headers.items()
            if k.lower() not in _RESPONSE_HEADERS_DROPPED
        }

    async def _make_request(self, request_method, target_url, headers, body):
        """
        Send a single proxied request. Returns a Response.
        Handles both SSE streaming and buffered paths.
        """
        accept = headers.get("Accept", headers.get("accept", ""))
        may_stream = "text/event-stream" in accept

        if may_stream:
            stream_ctx = self._http_client.stream(
                method=request_method,
                url=target_url,
                headers=headers,
                content=body,
            )
            response = await stream_ctx.__aenter__()

            content_type = response.headers.get("content-type", "")
            if "text/event-stream" in content_type:

                async def stream_generator(_ctx=stream_ctx, _resp=response):
                    try:
                        async for chunk in _resp.aiter_bytes():
                            yield chunk
                    finally:
                        await _ctx.__aexit__(None, None, None)

                return StreamingResponse(
                    stream_generator(),
                    status_code=response.status_code,
                    headers=self._sanitize_response_headers(dict(response.headers)),
                    media_type=content_type,
                )
            body_bytes = await response.aread()
            await stream_ctx.__aexit__(None, None, None)
            return Response(
                content=body_bytes,
                status_code=response.status_code,
                headers=self._sanitize_response_headers(dict(response.headers)),
            )

        response = await self._http_client.request(
            method=request_method,
            url=target_url,
            headers=headers,
            content=body,
        )
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=self._sanitize_response_headers(dict(response.headers)),
        )

    async def proxy_request(self, request: Request, path: str):
        """Proxy an MCP call to the gateway, with the user's token."""
        mcp_path = _mcp_path(path)
        if mcp_path is None:
            return await self.oauth_not_supported()
        return await self._forward(request, mcp_path)

    def _no_token(self) -> Response:
        """The answer when there's no token to send: the gateway didn't answer,
        or the sign-in has ended."""
        if self.token_manager.gateway_unreachable:
            return _unreachable(self.token_manager.get_gateway_url())
        # Return 503 (not 401!) — a 401 tells MCP clients "needs OAuth"
        # and triggers persistent "needs authentication" badges.
        return Response(
            content="No valid token available. Please run: gravitino-mcp login",
            status_code=503,
            media_type="text/plain",
        )

    async def _forward(self, request: Request, mcp_path: str):
        """Forward the call to ``/mcp/<mcp_path>`` on the gateway of the latest login."""
        try:
            # Get valid token
            token = await self.token_manager.get_valid_token()
            if not token:
                return self._no_token()

            headers = {
                k: v
                for k, v in request.headers.items()
                if k.lower() not in _REQUEST_HEADERS_DROPPED
            }
            headers["Authorization"] = f"Bearer {token}"

            # The gateway of the latest login, which may have changed.
            target_url = f"{self.token_manager.get_gateway_url()}/mcp/{mcp_path}"
            if request.url.query:
                target_url += f"?{request.url.query}"

            # Read request body
            body = await request.body()

            # Forward request with retry for transient errors
            _last_exc = None
            for attempt in range(1, PROXY_MAX_RETRIES + 1):
                try:
                    resp = await self._make_request(
                        request.method, target_url, headers, body
                    )

                    # The gateway refused the token: refresh it and retry once.
                    if resp.status_code == 401 and attempt == 1:
                        logger.info(
                            "Backend returned 401, refreshing token and retrying"
                        )
                        if await self.token_manager.refresh_access_token(
                            rejected=token
                        ):
                            token = await self.token_manager.get_valid_token()
                            headers["Authorization"] = f"Bearer {token}"
                            continue
                    return resp
                # Retried only when nothing reached the gateway: a tool call
                # may not be safe to run twice.
                except httpx.ConnectError as e:
                    _last_exc = e
                    if attempt < PROXY_MAX_RETRIES:
                        logger.warning(
                            "Transient error on attempt %s/%s, retrying: %s: %s",
                            attempt,
                            PROXY_MAX_RETRIES,
                            type(e).__name__,
                            e,
                        )
                        await asyncio.sleep(0.5 * attempt)
                        continue
                    raise

        except httpx.ConnectError:
            return _unreachable(self.token_manager.get_gateway_url())
        except httpx.TimeoutException as e:
            logger.error("Proxy timeout: %s: %s", type(e).__name__, e)
            return Response(
                content=f"Proxy timeout after {PROXY_REQUEST_TIMEOUT}s: {type(e).__name__}",
                status_code=504,
                media_type="text/plain",
            )
        except httpx.RemoteProtocolError as e:
            logger.error(
                "Proxy connection dropped: %s: %s", type(e).__name__, e, exc_info=True
            )
            return Response(
                content=f"Connection to backend was reset: {type(e).__name__}: {str(e)}",
                status_code=502,
                media_type="text/plain",
            )
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Proxy error: %s: %s", type(e).__name__, e, exc_info=True)
            return Response(
                content=f"Proxy error: {type(e).__name__}: {str(e)}",
                status_code=500,
                media_type="text/plain",
            )


def _mcp_path(path: str) -> Optional[str]:
    """``path``, under /mcp/, re-encoded, or None if it could leave /mcp/<server>.

    The path arrives decoded, so ``%2e%2e`` and ``%2f`` are ``..`` and ``/`` by
    now, and httpx would resolve them, sending the user's token to another
    part of the gateway's API.
    """
    segments = path.split("/")
    if segments[-1] == "":
        segments = segments[:-1]
    if (
        not segments
        or not _SERVER_ID.match(segments[0])
        or "\\" in path
        or any(segment in ("", ".", "..") for segment in segments)
    ):
        return None
    return "/".join(quote(segment, safe="") for segment in segments) + (
        "/" if path.endswith("/") else ""
    )


def start_proxy(port: int = 8001, token_file: Optional[Path] = None):
    """Start the auth proxy server"""
    token_file = token_file or TOKEN_FILE
    install_sensitive_data_filter()
    proxy_id = secrets.token_hex(16)
    write_private_file(PROXY_ID_FILE, proxy_id)

    token_manager = TokenManager(token_file)
    logger.info("Starting MCP Gateway Auth Proxy on port %s", port)
    logger.info("Using token file: %s", token_file)
    logger.info("Forwarding to: %s", token_manager.get_gateway_url())
    logger.info("Request timeout: %ss", PROXY_REQUEST_TIMEOUT)

    try:
        uvicorn.run(
            AuthProxy(token_manager, proxy_id).app,
            host="127.0.0.1",
            port=port,
            log_level="info",
            access_log=True,
        )
    finally:
        PROXY_ID_FILE.unlink(missing_ok=True)


if __name__ == "__main__":
    # Can be run standalone: python -m mcp_gateway_cli.proxy_daemon
    start_proxy()
