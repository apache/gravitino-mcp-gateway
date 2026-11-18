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

"""Unit tests for mcp_gateway_cli.setup_cmd and proxy.run_proxy_foreground."""

import pytest

from mcp_gateway_cli import autostart, clients, proxy, setup_cmd


@pytest.mark.parametrize(
    "configured,reported",
    [
        (
            [clients.ClientResult("Claude Code", clients.STATUS_CONFIGURED, "")],
            "Claude Code",
        ),
        ([], "No AI clients detected"),
    ],
)
def test_setup_configures_clients_and_leaves_starting_the_proxy_to_the_service(
    monkeypatch, configured, reported
):
    """A second, unsupervised proxy would race the service's for the port."""
    monkeypatch.setattr(setup_cmd.auth_module, "get_access_token", lambda: "tok")
    monkeypatch.setattr(
        setup_cmd.clients_module, "configure_all", lambda servers: configured
    )
    monkeypatch.setattr(
        setup_cmd.autostart_module,
        "enable",
        lambda: autostart.AutostartResult(
            "Darwin", autostart.STATUS_ENABLED, "ok", "/p"
        ),
    )
    monkeypatch.setattr(setup_cmd.proxy_module, "is_proxy_running", lambda: True)

    def fail_start():
        raise AssertionError("start_proxy must not be called when supervised")

    monkeypatch.setattr(setup_cmd.proxy_module, "start_proxy", fail_start)
    lines = []

    assert setup_cmd.run_setup(echo=lines.append) is True

    assert "Setup complete" in lines[-1]
    assert reported in "\n".join(lines)


def test_setup_stops_when_login_fails(monkeypatch):
    monkeypatch.setattr(setup_cmd.auth_module, "get_access_token", lambda: None)
    monkeypatch.setattr(setup_cmd.auth_module, "get_gateway_url", lambda: "https://gw")
    monkeypatch.setattr(setup_cmd.auth_module, "device_flow_login", lambda url: False)

    assert setup_cmd.run_setup(echo=lambda *_: None) is False


def test_the_proxy_exits_cleanly_when_no_one_is_signed_in(monkeypatch, tmp_path):
    """A clean exit (0), not a crash, so the supervisor doesn't restart it in a loop."""
    monkeypatch.setattr(proxy, "TOKEN_FILE", tmp_path / "tokens")

    assert proxy.run_proxy_foreground(wait_seconds=0) == 0
