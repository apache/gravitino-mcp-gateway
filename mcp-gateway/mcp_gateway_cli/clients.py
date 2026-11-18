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

"""Detect and configure AI clients to use the MCP Gateway proxy.

Each client stores MCP servers in its own file/format. We write the *same*
canonical endpoints (see :mod:`constants`) into every installed client and,
for Claude Code, actively de-duplicate conflicting scope registrations — the
single most common cause of the "needs authentication" failure.

Design notes:
  • File writers are idempotent and merge-only: existing unrelated servers are
    preserved, a ``.bak`` is written before the first change.
  • Functions accept explicit ``path`` / ``runner`` overrides so they can be
    unit-tested without touching the real home directory or shelling out.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

# Status values for a single client configuration attempt.
STATUS_CONFIGURED = "configured"
STATUS_SKIPPED = "skipped"
STATUS_ERROR = "error"

# headersHelper tells Claude Code to skip its built-in OAuth discovery and let
# the proxy inject the Bearer token. Without it Claude Code shows
# "needs authentication". ``echo {}`` returns an empty header set.
_HEADERS_HELPER = "echo '{}'"


@dataclass(frozen=True)
class ClientResult:
    """Outcome of configuring one client."""

    name: str
    status: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == STATUS_CONFIGURED


# --------------------------------------------------------------------------- #
# Platform-specific config locations
# --------------------------------------------------------------------------- #
def _home() -> Path:
    return Path.home()


def vscode_config_path() -> Path:
    """User-level VS Code MCP config (applies to every workspace)."""
    system = platform.system()
    if system == "Darwin":
        return (
            _home() / "Library" / "Application Support" / "Code" / "User" / "mcp.json"
        )
    if system == "Windows":
        base = os.getenv("APPDATA", str(_home() / "AppData" / "Roaming"))
        return Path(base) / "Code" / "User" / "mcp.json"
    return _home() / ".config" / "Code" / "User" / "mcp.json"


def cursor_config_path() -> Path:
    return _home() / ".cursor" / "mcp.json"


def opencode_config_path() -> Path:
    """Global OpenCode config (project-level files are out of scope)."""
    return _home() / ".config" / "opencode" / "opencode.json"


# --------------------------------------------------------------------------- #
# Generic JSON merge (immutable: builds a new document, never mutates in place)
# --------------------------------------------------------------------------- #
def merge_servers(existing: Dict, top_key: str, entries: Dict[str, Dict]) -> Dict:
    """Return a new config dict with ``entries`` merged under ``top_key``."""
    new_doc = dict(existing)
    servers = dict(new_doc.get(top_key) or {})
    for name, entry in entries.items():
        servers[name] = dict(entry)
    new_doc[top_key] = servers
    return new_doc


def _write_json_config(path: Path, top_key: str, entries: Dict[str, Dict]) -> None:
    """Read-merge-write ``entries`` into ``path`` with a one-time ``.bak``."""
    path.parent.mkdir(parents=True, exist_ok=True)

    existing: Dict = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text() or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path} contains invalid JSON: {exc}") from exc
        # Back up the original once, before our first edit.
        backup = path.with_suffix(path.suffix + ".bak")
        if not backup.exists():
            backup.write_text(path.read_text())

    merged = merge_servers(existing, top_key, entries)
    path.write_text(json.dumps(merged, indent=2) + "\n")


# --------------------------------------------------------------------------- #
# Claude Code (via the `claude` CLI — handles scope de-duplication)
# --------------------------------------------------------------------------- #
def _which(name: str) -> Optional[str]:
    """Where ``name`` is on PATH; tests replace this so they never run the real CLI."""
    return shutil.which(name)


def configure_claude_code(
    servers: Dict[str, str],
    runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
    which: Optional[Callable[[str], Optional[str]]] = None,
) -> ClientResult:
    """Register each server at user scope, replacing an earlier user-scope entry.

    Other scopes belong to the project in the current directory, so they are
    left alone.
    """
    runner = runner or subprocess.run
    which = which or _which
    if not which("claude"):
        return ClientResult(
            "Claude Code", STATUS_SKIPPED, "claude CLI not found on PATH"
        )

    configured: List[str] = []
    try:
        for name, url in servers.items():
            # Replace an earlier registration; "not found" is fine.
            runner(
                ["claude", "mcp", "remove", name, "-s", "user"],
                capture_output=True,
                text=True,
                check=False,
            )
            server_json = json.dumps(
                {"type": "http", "url": url, "headersHelper": _HEADERS_HELPER}
            )
            result = runner(
                ["claude", "mcp", "add-json", name, server_json, "--scope", "user"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                stderr = (getattr(result, "stderr", "") or "").strip()
                return ClientResult(
                    "Claude Code",
                    STATUS_ERROR,
                    f"failed to add '{name}': {stderr or 'unknown error'}",
                )
            configured.append(name)
    except FileNotFoundError:
        return ClientResult(
            "Claude Code", STATUS_SKIPPED, "claude CLI not found on PATH"
        )

    return ClientResult(
        "Claude Code",
        STATUS_CONFIGURED,
        f"user scope: {', '.join(configured)}",
    )


# --------------------------------------------------------------------------- #
# File-based clients
# --------------------------------------------------------------------------- #
def configure_vscode(
    servers: Dict[str, str], path: Optional[Path] = None
) -> ClientResult:
    path = path or vscode_config_path()
    # Only configure VS Code if its user profile directory exists.
    if not path.parent.exists() and not shutil.which("code"):
        return ClientResult("VS Code", STATUS_SKIPPED, "VS Code not detected")
    entries = {name: {"url": url, "type": "http"} for name, url in servers.items()}
    try:
        _write_json_config(path, "servers", entries)
    except ValueError as exc:
        return ClientResult("VS Code", STATUS_ERROR, str(exc))
    return ClientResult("VS Code", STATUS_CONFIGURED, str(path))


def configure_cursor(
    servers: Dict[str, str], path: Optional[Path] = None
) -> ClientResult:
    path = path or cursor_config_path()
    if not path.parent.exists() and not (_home() / ".cursor").exists():
        return ClientResult("Cursor", STATUS_SKIPPED, "Cursor not detected")
    entries = {name: {"url": url} for name, url in servers.items()}
    try:
        _write_json_config(path, "mcpServers", entries)
    except ValueError as exc:
        return ClientResult("Cursor", STATUS_ERROR, str(exc))
    return ClientResult("Cursor", STATUS_CONFIGURED, str(path))


def configure_opencode(
    servers: Dict[str, str], path: Optional[Path] = None
) -> ClientResult:
    path = path or opencode_config_path()
    if not path.exists() and not path.parent.exists():
        return ClientResult("OpenCode", STATUS_SKIPPED, "opencode config not detected")
    entries = {
        name: {"type": "remote", "url": url, "enabled": True}
        for name, url in servers.items()
    }
    try:
        _write_json_config(path, "mcp", entries)
    except ValueError as exc:
        return ClientResult("OpenCode", STATUS_ERROR, str(exc))
    return ClientResult("OpenCode", STATUS_CONFIGURED, str(path))


def configure_all(servers: Dict[str, str]) -> List[ClientResult]:
    """Configure every detected client. Absent clients are skipped, not failed."""
    return [
        configure_claude_code(servers),
        configure_vscode(servers),
        configure_cursor(servers),
        configure_opencode(servers),
    ]
