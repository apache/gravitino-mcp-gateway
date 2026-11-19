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

"""Install the MCP Gateway proxy as an always-on OS service.

An OS service (launchd on macOS, systemd --user on Linux) with restart-on-exit
satisfies both onboarding requirements at once:

  • starts on login/startup            -> RunAtLoad / WantedBy=default.target
  • restarted if it fails               -> KeepAlive / Restart=on-failure

Pure generators (``generate_launchd_plist`` / ``generate_systemd_unit``) are
separated from side effects so they can be unit-tested directly.
"""

from __future__ import annotations

import platform
import plistlib
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from .constants import SERVICE_LABEL

STATUS_ENABLED = "enabled"
STATUS_DISABLED = "disabled"
STATUS_UNSUPPORTED = "unsupported"
STATUS_ERROR = "error"

_LOG_PATH = Path.home() / ".gravitino-mcp" / "proxy.log"
_SYSTEMD_UNIT_NAME = "gravitino-mcp-proxy.service"


@dataclass(frozen=True)
class AutostartResult:
    platform: str
    status: str
    detail: str = ""
    path: Optional[str] = None


def proxy_program_arguments() -> List[str]:
    """argv that runs the proxy in the foreground under a supervisor.

    Uses ``python -m`` (not the ``gravitino-mcp`` script) so it does not depend on
    the console-script being on the service's PATH.
    """
    return [sys.executable, "-m", "mcp_gateway_cli.cli", "proxy", "run"]


# --------------------------------------------------------------------------- #
# Pure generators
# --------------------------------------------------------------------------- #
def generate_launchd_plist(program_args: List[str], log_path: Path) -> bytes:
    plist = {
        "Label": SERVICE_LABEL,
        "ProgramArguments": list(program_args),
        "RunAtLoad": True,  # start on login/startup
        # Restart only on a crash (non-zero exit). A clean exit — e.g. the
        # proxy giving up cleanly when unauthenticated — must NOT be respawned,
        # otherwise an unauthenticated machine crash-loops the service.
        "KeepAlive": {"SuccessfulExit": False},
        # Back off between respawns (default is 10s; widen it as a safety net).
        "ThrottleInterval": 30,
        "StandardOutPath": str(log_path),
        "StandardErrorPath": str(log_path),
        "ProcessType": "Background",
        "WorkingDirectory": str(Path.home()),
    }
    return plistlib.dumps(plist)


def generate_systemd_unit(program_args: List[str], log_path: Path) -> str:
    exec_start = shlex.join(program_args)
    return (
        "[Unit]\n"
        "Description=MCP Gateway local auth proxy\n"
        "After=network-online.target\n"
        # Give up after too many rapid restarts so an unauthenticated /
        # misconfigured proxy can't crash-loop forever.
        "StartLimitIntervalSec=300\n"
        "StartLimitBurst=5\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={exec_start}\n"
        # Restart only on failure (non-zero exit). The proxy exits 0 when it
        # gives up cleanly while unauthenticated, so that won't trigger a restart.
        "Restart=on-failure\n"
        "RestartSec=5\n"
        f"StandardOutput=append:{log_path}\n"
        f"StandardError=append:{log_path}\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


# --------------------------------------------------------------------------- #
# Path helpers
# --------------------------------------------------------------------------- #
def launchd_plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{SERVICE_LABEL}.plist"


def systemd_unit_path() -> Path:
    return Path.home() / ".config" / "systemd" / "user" / _SYSTEMD_UNIT_NAME


# --------------------------------------------------------------------------- #
# Platform dispatch
# --------------------------------------------------------------------------- #
def enable(
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    plist_path: Optional[Path] = None,
    unit_path: Optional[Path] = None,
) -> AutostartResult:
    system = platform.system()
    if system == "Darwin":
        return _enable_launchd(runner, plist_path or launchd_plist_path())
    if system == "Linux":
        return _enable_systemd(runner, unit_path or systemd_unit_path())
    return AutostartResult(
        system, STATUS_UNSUPPORTED, "auto-start service not supported on this OS"
    )


def disable(
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    plist_path: Optional[Path] = None,
    unit_path: Optional[Path] = None,
) -> AutostartResult:
    system = platform.system()
    if system == "Darwin":
        return _disable_launchd(runner, plist_path or launchd_plist_path())
    if system == "Linux":
        return _disable_systemd(runner, unit_path or systemd_unit_path())
    return AutostartResult(system, STATUS_UNSUPPORTED, "nothing to disable")


def status(
    plist_path: Optional[Path] = None, unit_path: Optional[Path] = None
) -> AutostartResult:
    system = platform.system()
    if system == "Darwin":
        p = plist_path or launchd_plist_path()
        return AutostartResult(
            system, STATUS_ENABLED if p.exists() else STATUS_DISABLED, path=str(p)
        )
    if system == "Linux":
        u = unit_path or systemd_unit_path()
        return AutostartResult(
            system, STATUS_ENABLED if u.exists() else STATUS_DISABLED, path=str(u)
        )
    return AutostartResult(system, STATUS_UNSUPPORTED)


# --------------------------------------------------------------------------- #
# macOS launchd
# --------------------------------------------------------------------------- #
def _enable_launchd(runner, plist_path: Path) -> AutostartResult:
    try:
        _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        plist_path.parent.mkdir(parents=True, exist_ok=True)
        plist_path.write_bytes(
            generate_launchd_plist(proxy_program_arguments(), _LOG_PATH)
        )
        # Reload: unload any prior version, then load fresh.
        runner(
            ["launchctl", "unload", str(plist_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        result = runner(
            ["launchctl", "load", "-w", str(plist_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            stderr = (getattr(result, "stderr", "") or "").strip()
            return AutostartResult(
                "Darwin",
                STATUS_ERROR,
                f"launchctl load failed: {stderr}",
                str(plist_path),
            )
        return AutostartResult(
            "Darwin", STATUS_ENABLED, "LaunchAgent loaded", str(plist_path)
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # Surface any file system or launchctl failure.
        return AutostartResult("Darwin", STATUS_ERROR, str(exc), str(plist_path))


def _disable_launchd(runner, plist_path: Path) -> AutostartResult:
    try:
        if plist_path.exists():
            runner(
                ["launchctl", "unload", str(plist_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            plist_path.unlink()
        return AutostartResult(
            "Darwin", STATUS_DISABLED, "LaunchAgent removed", str(plist_path)
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return AutostartResult("Darwin", STATUS_ERROR, str(exc), str(plist_path))


# --------------------------------------------------------------------------- #
# Linux systemd (user)
# --------------------------------------------------------------------------- #
def _enable_systemd(runner, unit_path: Path) -> AutostartResult:
    try:
        _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        unit_path.parent.mkdir(parents=True, exist_ok=True)
        unit_path.write_text(
            generate_systemd_unit(proxy_program_arguments(), _LOG_PATH)
        )
        runner(
            ["systemctl", "--user", "daemon-reload"],
            capture_output=True,
            text=True,
            check=False,
        )
        result = runner(
            ["systemctl", "--user", "enable", "--now", _SYSTEMD_UNIT_NAME],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            stderr = (getattr(result, "stderr", "") or "").strip()
            return AutostartResult(
                "Linux",
                STATUS_ERROR,
                f"systemctl enable failed: {stderr}",
                str(unit_path),
            )
        return AutostartResult(
            "Linux", STATUS_ENABLED, "systemd user unit enabled", str(unit_path)
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return AutostartResult("Linux", STATUS_ERROR, str(exc), str(unit_path))


def _disable_systemd(runner, unit_path: Path) -> AutostartResult:
    try:
        runner(
            ["systemctl", "--user", "disable", "--now", _SYSTEMD_UNIT_NAME],
            capture_output=True,
            text=True,
            check=False,
        )
        if unit_path.exists():
            unit_path.unlink()
        runner(
            ["systemctl", "--user", "daemon-reload"],
            capture_output=True,
            text=True,
            check=False,
        )
        return AutostartResult(
            "Linux", STATUS_DISABLED, "systemd user unit removed", str(unit_path)
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return AutostartResult("Linux", STATUS_ERROR, str(exc), str(unit_path))
