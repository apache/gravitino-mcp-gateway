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
OAuth Device Flow for CLI Authentication
"""

import json
import os
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlsplit

import requests

from .constants import CONFIG_DIR, DEFAULT_GATEWAY_URL, TOKEN_REFRESH_MARGIN_SECONDS
from .device_flow import PollStatus, poll_device_token_until_done, request_device_code

TOKEN_FILE = CONFIG_DIR / "tokens"


class GatewayUnreachable(Exception):
    """The gateway didn't answer, as when it is down or the network can't reach it."""

    def __init__(self, gateway_url: str):
        super().__init__(
            f"Cannot reach {gateway_url}. "
            "Check the URL and that your network can reach it."
        )


def save_tokens(
    access_token: str,
    refresh_token: str,
    gateway_url: str,
    expires_in: int = 3600,
):
    """Save OAuth tokens and the gateway URL to file"""
    data = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "gateway_url": gateway_url,
        "expires_in": expires_in,
        "created_at": datetime.utcnow().isoformat(),
    }

    write_private_file(TOKEN_FILE, json.dumps(data, indent=2))


def write_private_file(path: Path, text: str) -> None:
    """Replace ``path`` with ``text``, readable only by this user.

    The CLI and the proxy both write the token file, so it is replaced whole,
    and a reader never sees half of it.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkdir's mode applies only to a directory it creates.
    path.parent.chmod(0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(temporary, path)


def load_tokens() -> Optional[Dict]:
    """Load OAuth tokens from file"""
    if not TOKEN_FILE.exists():
        return None

    try:
        with open(TOKEN_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def get_gateway_url() -> str:
    """Get gateway URL from environment, saved tokens, or the local default"""
    # 1. Check environment variable
    env_url = os.getenv("MCP_GATEWAY_URL")
    if env_url:
        return env_url

    # 2. Check saved tokens
    tokens = load_tokens()
    if tokens and "gateway_url" in tokens:
        return tokens["gateway_url"]

    # 3. Default to a gateway on this machine
    return DEFAULT_GATEWAY_URL


def is_secure_gateway(gateway_url: str) -> bool:
    """Whether tokens may go to ``gateway_url``: over https, or to this machine."""
    parts = urlsplit(gateway_url)
    return parts.scheme == "https" or (
        parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1")
    )


def device_flow_login(gateway_url: str) -> bool:
    """
    Perform OAuth device flow login
    Returns True if successful, False otherwise
    """
    if not is_secure_gateway(gateway_url):
        print(
            f"The gateway must be an https URL, or one on this machine: {gateway_url}"
        )
        return False
    print(f"Authenticating with {gateway_url}...")

    # Step 1: Request device code
    try:
        device_data = request_device_code(gateway_url)
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Failed to request device code: {e}")
        return False

    verification_uri = device_data.verification_uri
    if not verification_uri.startswith(("https://", "http://")):
        print(f"The gateway sent an unexpected sign-in address: {verification_uri}")
        return False
    user_code = device_data.user_code
    expires_in = device_data.expires_in
    interval = device_data.interval

    print("\n" + "=" * 60)
    print("Please complete the following steps:")
    print("=" * 60)
    print(f"\n1. Opening browser to: {verification_uri}")
    print(f"2. Enter this code: {user_code}")
    print("\n" + "=" * 60)

    try:
        opened = webbrowser.open(verification_uri)
    except Exception:  # pylint: disable=broad-exception-caught
        opened = False
    print(
        "Browser opened automatically"
        if opened
        else "Open the URL above in a browser, on any device"
    )

    print(f"\nWaiting for approval (expires in {expires_in} seconds)...")

    result = poll_device_token_until_done(
        gateway_url,
        device_data.device_code,
        expires_in=expires_in,
        interval=interval,
        on_pending=lambda: print(".", end="", flush=True),
    )

    if result.status == PollStatus.SUCCESS and result.token_data:
        token_data = result.token_data
        save_tokens(
            token_data["access_token"],
            token_data.get("refresh_token", ""),
            gateway_url,
            token_data.get("expires_in", 3600),
        )
        print("\nSuccessfully authenticated!")
        print(f"Tokens saved to: {TOKEN_FILE}")
        print(f"Gateway: {gateway_url}")
        print("Tokens will auto-refresh before expiry")
        return True

    if result.status == PollStatus.EXPIRED:
        print("\nTimeout - device code expired")
        return False

    desc = result.error_description or result.error or "Unknown error"
    print(f"\nError: {desc}")
    return False


def get_access_token() -> Optional[str]:
    """A valid access token for the gateway the CLI talks to, refreshed if need be.

    None when the saved sign-in is for another gateway, such as when
    MCP_GATEWAY_URL names one: the token must not go anywhere but where it came from.
    """
    tokens = load_tokens()
    if not tokens:
        return None
    signed_in_at = tokens.get("gateway_url")
    if signed_in_at and signed_in_at != get_gateway_url():
        print(
            f"Your sign-in is for {signed_in_at}, not {get_gateway_url()}. "
            "Run 'gravitino-mcp login' to sign in there."
        )
        return None

    access_token = tokens.get("access_token")
    created_at = tokens.get("created_at")
    if not created_at:
        return access_token
    expires_in = tokens.get("expires_in", 3600)
    expires_at = datetime.fromisoformat(created_at) + timedelta(seconds=expires_in)
    if expires_at - datetime.utcnow() > timedelta(seconds=TOKEN_REFRESH_MARGIN_SECONDS):
        return access_token
    return _refreshed(access_token, expires_at)


def _refreshed(access_token: Optional[str], expires_at: datetime) -> Optional[str]:
    """A refreshed access token, or None once the sign-in has ended.

    While the gateway can't be reached, a token that hasn't expired is kept,
    since it works once the gateway answers; after that, GatewayUnreachable.
    """
    try:
        refreshed = refresh_access_token()
    except GatewayUnreachable:
        if expires_at > datetime.utcnow():
            return access_token
        raise
    if refreshed:
        tokens = load_tokens()
        return tokens.get("access_token") if tokens else None
    print(
        "Warning: Token refresh failed. Please run 'gravitino-mcp login' to re-authenticate."
    )
    return None


def refresh_access_token() -> bool:
    """
    Refresh the access token using refresh token via generic OIDC flow

    Uses gateway's refresh proxy endpoint to handle OIDC provider-specific details.
    This works with any OIDC provider (Azure AD, Okta, Auth0, Keycloak, etc.)
    """
    tokens = load_tokens()
    if not tokens or not tokens.get("refresh_token"):
        return False

    gateway_url = tokens.get("gateway_url")
    if not gateway_url:
        return False

    try:
        # Call gateway's generic refresh endpoint (provider-agnostic)
        response = requests.post(
            f"{gateway_url}/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            timeout=10,
        )

        if response.status_code == 200:
            token_data = response.json()
            # Update stored tokens with refreshed values
            save_tokens(
                token_data["access_token"],
                token_data.get(
                    "refresh_token", tokens["refresh_token"]
                ),  # Keep old if not returned
                gateway_url,
                token_data.get("expires_in", 3600),
            )
            return True
        print(
            f"Warning: Token refresh failed: {response.status_code} - {response.text}"
        )
        return False

    except (requests.ConnectionError, requests.Timeout) as e:
        raise GatewayUnreachable(gateway_url) from e
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Warning: Token refresh error: {e}")
        return False


def logout():
    """Remove stored tokens"""
    if TOKEN_FILE.exists():
        TOKEN_FILE.unlink()
        print("Logged out successfully")
    else:
        print("Not currently logged in")
