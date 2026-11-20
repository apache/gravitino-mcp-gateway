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

"""``gravitino-mcp setup`` — one idempotent command to onboard any machine.

Orchestrates: login → configure every installed AI client → install the
always-on proxy service → ensure the proxy is up. Safe to re-run any time.
"""

from __future__ import annotations

import time
from typing import Callable

from . import auth as auth_module
from . import autostart as autostart_module
from . import clients as clients_module
from . import proxy as proxy_module
from .constants import MCP_SERVERS


def _wait_for_proxy(timeout: float = 15.0, interval: float = 0.5) -> bool:
    """Poll the proxy health endpoint until it responds or timeout elapses."""
    waited = 0.0
    while waited < timeout:
        if proxy_module.is_proxy_running():
            return True
        time.sleep(interval)
        waited += interval
    return proxy_module.is_proxy_running()


def _ensure_proxy_running(echo: Callable[[str], None], supervised: bool) -> bool:
    """Make sure exactly one proxy is up.

    When ``supervised`` is True the OS service already started the proxy, so we
    only wait/verify — we must NOT spawn a second detached instance (both would
    race for port 8001 and clobber proxy.pid). When unsupervised, start it
    ourselves (but only if it isn't already running).
    """
    if supervised:
        if _wait_for_proxy():
            echo("Proxy is running (managed by the auto-start service)")
            return True
        echo(
            "Warning: The service hasn't brought the proxy up yet. "
            "Check: gravitino-mcp proxy logs  (or: gravitino-mcp doctor)"
        )
        return False

    if proxy_module.is_proxy_running():
        echo("Proxy is already running")
        return True
    return proxy_module.start_proxy()


def run_setup(
    gateway_url: str = None,
    do_login: bool = True,
    enable_autostart: bool = True,
    echo: Callable[[str], None] = print,
) -> bool:
    """Run the full onboarding flow. Returns True on success."""
    echo("MCP Gateway Setup")
    echo("=" * 60)

    # 1. Authentication ----------------------------------------------------- #
    # A saved sign-in for another gateway isn't refreshed, since it may be down.
    other_gateway = gateway_url and gateway_url != (
        auth_module.load_tokens() or {}
    ).get("gateway_url")
    try:
        needs_login = do_login and (other_gateway or not auth_module.get_access_token())
    except auth_module.GatewayUnreachable as exc:
        echo(str(exc))
        return False
    if needs_login:
        echo("\nLogging in...")
        target = gateway_url or auth_module.get_gateway_url()
        if not auth_module.device_flow_login(target):
            echo("Login failed. Re-run: gravitino-mcp setup")
            return False
    else:
        echo("Already authenticated")

    # 2. Configure AI clients ---------------------------------------------- #
    echo("\nConfiguring AI clients...")
    any_configured = False
    marks = {
        clients_module.STATUS_CONFIGURED: "OK  ",
        clients_module.STATUS_SKIPPED: "--  ",
    }
    for result in clients_module.configure_all(MCP_SERVERS):
        any_configured |= result.status == clients_module.STATUS_CONFIGURED
        echo(f"   {marks.get(result.status, 'FAIL')} {result.name}: {result.detail}")
    if not any_configured:
        echo(
            "   Warning: No AI clients detected. Install one, then re-run: gravitino-mcp setup"
        )

    # 3. Always-on proxy service ------------------------------------------- #
    supervised = False
    if enable_autostart:
        echo("\nInstalling always-on proxy service...")
        result = autostart_module.enable()
        if result.status == autostart_module.STATUS_ENABLED:
            echo(f"   Auto-start enabled ({result.path})")
            supervised = True  # the service is now responsible for the proxy
        elif result.status == autostart_module.STATUS_UNSUPPORTED:
            echo(f"   {result.detail}")
        else:
            echo(f"   Warning: Could not enable auto-start: {result.detail}")

    # 4. Make sure the proxy is up right now -------------------------------- #
    echo("\nEnsuring proxy is running...")
    _ensure_proxy_running(echo, supervised=supervised)

    echo("\n" + "=" * 60)
    echo("Setup complete. If anything misbehaves, run: gravitino-mcp doctor")
    return True
