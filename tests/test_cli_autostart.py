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

"""Unit tests for mcp_gateway_cli.autostart (launchd / systemd)."""

import plistlib
from subprocess import CompletedProcess

import pytest

from mcp_gateway_cli import autostart
from mcp_gateway_cli.constants import SERVICE_LABEL

PROGRAM = ["/usr/bin/python3", "-m", "mcp_gateway_cli.cli", "proxy", "run"]
PLATFORMS = pytest.mark.parametrize(
    "system,path_arg,start",
    [
        ("Darwin", "plist_path", ["launchctl", "load", "-w"]),
        ("Linux", "unit_path", ["systemctl", "--user", "enable", "--now"]),
    ],
)


def _runner(failing=None):
    calls = []

    def runner(args, **kwargs):
        calls.append(args)
        code = 1 if failing and args[: len(failing)] == failing else 0
        return CompletedProcess(args, code, stdout="", stderr="nope")

    return runner, calls


def test_launchd_restarts_the_proxy_only_after_a_crash(tmp_path):
    plist = plistlib.loads(
        autostart.generate_launchd_plist(PROGRAM, tmp_path / "proxy.log")
    )

    assert plist["Label"] == SERVICE_LABEL
    assert plist["ProgramArguments"] == PROGRAM
    assert plist["RunAtLoad"] is True
    # Clean exits must not respawn (prevents unauthenticated crash-loop).
    assert plist["KeepAlive"] == {"SuccessfulExit": False}
    assert plist["ThrottleInterval"] == 30


def test_systemd_restarts_the_proxy_after_a_failure_with_backoff():
    unit = autostart.generate_systemd_unit(PROGRAM, "/tmp/proxy.log")

    for line in (
        "Restart=on-failure",
        "StartLimitBurst=5",
        "StartLimitIntervalSec=300",
        "WantedBy=default.target",
    ):
        assert line in unit
    assert "proxy run" in unit


@PLATFORMS
def test_enabling_installs_and_starts_the_service_and_disabling_removes_it(
    tmp_path, monkeypatch, system, path_arg, start
):
    monkeypatch.setattr(autostart.platform, "system", lambda: system)
    monkeypatch.setattr(autostart, "systemd_available", lambda: True)
    runner, calls = _runner()
    service = {path_arg: tmp_path / "service"}

    enabled = autostart.enable(runner=runner, **service)
    running = autostart.status(**service)
    disabled = autostart.disable(runner=runner, **service)

    assert (enabled.status, running.status) == (autostart.STATUS_ENABLED,) * 2
    assert any(call[: len(start)] == start for call in calls)
    assert disabled.status == autostart.STATUS_DISABLED
    assert not (tmp_path / "service").exists()
    assert autostart.status(**service).status == autostart.STATUS_DISABLED


@PLATFORMS
def test_enabling_reports_a_service_manager_that_fails_to_start_it(
    tmp_path, monkeypatch, system, path_arg, start
):
    monkeypatch.setattr(autostart.platform, "system", lambda: system)
    monkeypatch.setattr(autostart, "systemd_available", lambda: True)
    runner, _ = _runner(failing=start)

    result = autostart.enable(runner=runner, **{path_arg: tmp_path / "service"})

    assert result.status == autostart.STATUS_ERROR
    assert "nope" in result.detail
    # Left behind, the file would make status report the service as enabled.
    assert not (tmp_path / "service").exists()


def test_another_os_has_no_auto_start(monkeypatch):
    monkeypatch.setattr(autostart.platform, "system", lambda: "SunOS")

    for action in (autostart.enable, autostart.disable, autostart.status):
        assert action().status == autostart.STATUS_UNSUPPORTED


def test_linux_without_systemd_has_no_auto_start(tmp_path, monkeypatch):
    """Containers and minimal installs have no systemd, so nothing is written."""
    monkeypatch.setattr(autostart.platform, "system", lambda: "Linux")
    monkeypatch.setattr(autostart, "systemd_available", lambda: False)
    runner, calls = _runner()
    unit = tmp_path / "service"

    result = autostart.enable(runner=runner, unit_path=unit)

    assert result.status == autostart.STATUS_UNSUPPORTED
    assert "systemd" in result.detail
    assert not unit.exists()
    assert autostart.status(unit_path=unit).status == autostart.STATUS_UNSUPPORTED
    disabled = autostart.disable(runner=runner, unit_path=unit)
    assert disabled.status == autostart.STATUS_UNSUPPORTED
    assert not calls
