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

"""Unit tests for mcp_gateway_cli.doctor."""

from datetime import datetime, timedelta

import requests

from mcp_gateway_cli import doctor


def test_check_auth_not_logged_in(monkeypatch):
    monkeypatch.setattr(doctor.auth_module, "load_tokens", lambda: None)
    check = doctor.check_auth()
    assert not check.ok
    assert "gravitino-mcp login" in check.message


def test_check_auth_valid(monkeypatch):
    monkeypatch.setattr(
        doctor.auth_module,
        "load_tokens",
        lambda: {
            "created_at": datetime.utcnow().isoformat(),
            "expires_in": 3600,
            "gateway_url": "https://gw",
        },
    )
    assert doctor.check_auth().ok


def test_check_auth_expired_is_warning(monkeypatch):
    monkeypatch.setattr(
        doctor.auth_module,
        "load_tokens",
        lambda: {
            "created_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
            "expires_in": 3600,
        },
    )
    check = doctor.check_auth()
    assert not check.ok
    assert check.severity == doctor.SEVERITY_WARN


def test_check_gateway_unreachable_says_what_to_check(monkeypatch):
    monkeypatch.setattr(doctor.auth_module, "get_gateway_url", lambda: "https://gw")

    def boom(*a, **k):
        raise requests.exceptions.ConnectionError()

    check = doctor.check_gateway(get=boom)
    assert not check.ok
    assert "Cannot reach https://gw" in check.message


def test_check_gateway_ok(monkeypatch):
    monkeypatch.setattr(doctor.auth_module, "get_gateway_url", lambda: "https://gw")

    class Resp:
        status_code = 200

    assert doctor.check_gateway(get=lambda *a, **k: Resp()).ok


def test_check_proxy(monkeypatch):
    monkeypatch.setattr(doctor.proxy_module, "is_proxy_running", lambda: True)
    assert doctor.check_proxy().ok
    monkeypatch.setattr(doctor.proxy_module, "is_proxy_running", lambda: False)
    assert not doctor.check_proxy().ok


def test_run_doctor_returns_false_on_failure(monkeypatch):
    monkeypatch.setattr(doctor, "check_auth", lambda: doctor.Check("Auth", False, "x"))
    monkeypatch.setattr(doctor, "check_gateway", lambda: doctor.Check("GW", True, "ok"))
    monkeypatch.setattr(
        doctor, "check_proxy", lambda: doctor.Check("Proxy", True, "ok")
    )
    monkeypatch.setattr(
        doctor, "check_autostart", lambda: doctor.Check("AS", True, "ok")
    )

    lines = []
    assert doctor.run_doctor(echo=lines.append) is False
    assert any(line.startswith("FAIL") for line in lines)
