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

"""``gravitino-mcp doctor``: one command that explains why MCP isn't working.

Every check prints what to do about it. Returns False if any hard check fails,
so scripts and CI can gate on it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, List

import requests

from . import auth as auth_module
from . import autostart as autostart_module
from . import proxy as proxy_module

SEVERITY_FAIL = "fail"
SEVERITY_WARN = "warn"


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    message: str
    severity: str = SEVERITY_FAIL  # only matters when ok is False


def check_auth() -> Check:
    tokens = auth_module.load_tokens()
    if not tokens:
        return Check("Authentication", False, "Not logged in. Run: gravitino-mcp login")

    created_at = tokens.get("created_at")
    expires_in = tokens.get("expires_in", 3600)
    if created_at:
        try:
            expires_at = datetime.fromisoformat(created_at) + timedelta(
                seconds=expires_in
            )
            if expires_at < datetime.utcnow():
                return Check(
                    "Authentication",
                    False,
                    "Access token expired; it will auto-refresh on next use. "
                    "If calls fail, run: gravitino-mcp login",
                    severity=SEVERITY_WARN,
                )
        except ValueError:
            pass
    gateway = tokens.get("gateway_url", "(unknown)")
    return Check("Authentication", True, f"Logged in (gateway: {gateway})")


def check_gateway(get: Callable = requests.get) -> Check:
    gateway = auth_module.get_gateway_url()
    try:
        resp = get(f"{gateway}/health", timeout=5)
        if resp.status_code < 500:
            return Check("Gateway reachable", True, gateway)
        return Check(
            "Gateway reachable",
            False,
            f"{gateway} returned HTTP {resp.status_code}",
            severity=SEVERITY_WARN,
        )
    except requests.exceptions.RequestException:
        return Check(
            "Gateway reachable",
            False,
            f"Cannot reach {gateway}. Check the URL and that your network can reach it.",
        )


def check_proxy() -> Check:
    if proxy_module.is_proxy_running():
        return Check("Local proxy", True, f"running on port {proxy_module.PROXY_PORT}")
    return Check(
        "Local proxy",
        False,
        "Proxy not running. Run: gravitino-mcp proxy start  (or: gravitino-mcp setup)",
    )


def check_autostart() -> Check:
    result = autostart_module.status()
    if result.status == autostart_module.STATUS_ENABLED:
        return Check("Auto-start service", True, result.path or "enabled")
    if result.status == autostart_module.STATUS_UNSUPPORTED:
        return Check("Auto-start service", True, "not supported on this OS (skipped)")
    return Check(
        "Auto-start service",
        False,
        "Not installed. Run: gravitino-mcp setup  (or: gravitino-mcp autostart enable)",
        severity=SEVERITY_WARN,
    )


def run_doctor(echo: Callable[[str], None] = print) -> bool:
    """Run all checks, print results, and return True if none hard-failed."""
    checks: List[Check] = [
        check_auth(),
        check_gateway(),
        check_proxy(),
        check_autostart(),
    ]

    echo("\nMCP Gateway Doctor\n" + "=" * 60)
    has_fail = False
    for c in checks:
        if c.ok:
            icon = "OK  "
        elif c.severity == SEVERITY_WARN:
            icon = "WARN"
        else:
            icon = "FAIL"
            has_fail = True
        echo(f"{icon} {c.name}: {c.message}")

    echo("=" * 60)
    if has_fail:
        echo(
            "Some checks failed. Follow the remediation above, then re-run: gravitino-mcp doctor"
        )
    else:
        echo("All good.")
    return not has_fail
