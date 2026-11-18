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

"""Tests for mcp_gateway.log_filter: secrets are redacted from every log line."""

import io
import logging

import pytest
from uvicorn.logging import AccessFormatter

from mcp_gateway.log_filter import SensitiveDataFilter, install_sensitive_data_filter


def _record(msg, *args, name="test"):
    return logging.LogRecord(name, logging.INFO, __file__, 1, msg, args, None)


@pytest.mark.parametrize(
    "line,secret",
    [
        ("Authorization: Bearer eyJabc.eyJdef.sigXYZ123", "sigXYZ123"),
        ("raw eyJhbGc.eyJzdWI.signature", "eyJzdWI"),
        ('headers={"Authorization": "Bearer abc.def.ghi"}', "abc.def.ghi"),
        ("Authorization: Bearer%20eyJhbGc.eyJzdWI.sig-in-a-url", "sig-in-a-url"),
        ("client_secret=supersecret&keep=1", "supersecret"),
        ("basic_auth_password=hunter2", "hunter2"),
        ("GET /auth/oauth/callback?code=abc123&state=s", "abc123"),
        ("POST /token access_token=at-secret&x=1", "at-secret"),
        ("refresh_token=rt-secret", "rt-secret"),
        ("id_token=idt-secret", "idt-secret"),
        ("GET /x?token=opaque-secret", "opaque-secret"),
        ("POST https://hooks.slack.com/services/T01/B02/hook-secret", "hook-secret"),
        ("GET https://mcp.example.com/mcp?api_key=key-secret", "key-secret"),
        ("GET https://blob.example.com/x?sig=sig-secret&se=1", "sig-secret"),
        # Whoever polls with a device code first gets the person's tokens.
        ("DeviceCodeData(device_code='dev-secret', user_code='AB-12')", "dev-secret"),
        ("POST /api/device/token device_code=dev-secret&grant_type=x", "dev-secret"),
        ('{"device_code": "dev-secret", "user_code": "AB-12"}', "dev-secret"),
    ],
)
def test_secrets_in_headers_urls_and_forms_are_redacted(line, secret):
    rec = _record(line)

    assert SensitiveDataFilter().filter(rec) is True

    assert secret not in rec.getMessage()
    assert "REDACTED" in rec.getMessage()


@pytest.mark.parametrize(
    "line",
    ["status code=503 from upstream", "token_type=Bearer", "error_code=7", "keep=1"],
)
def test_ordinary_values_are_left_alone(line):
    rec = _record(line)

    SensitiveDataFilter().filter(rec)

    assert rec.getMessage() == line


class _Unprintable:
    def __str__(self):
        raise RuntimeError("no string for this")


@pytest.mark.parametrize(
    "msg, args",
    [
        ("token %s for %s", ("eyJhbGc.eyJzdWI.sig-secret",)),
        ("token %(missing)s", ({"token": "eyJhbGc.eyJzdWI.sig-secret"},)),
        ("token %s for %s eyJhbGc.eyJzdWI.sig-secret", (_Unprintable(),)),
    ],
    ids=["too-few-args", "mapping", "unprintable-arg"],
)
def test_a_record_that_cannot_be_formatted_is_logged_redacted(msg, args):
    """Logging prints such a record's arguments as they are."""
    rec = _record(msg, *args)

    assert SensitiveDataFilter().filter(rec) is True
    assert "sig-secret" not in f"{rec.msg} {rec.args}"


def test_access_log_records_stay_formattable_by_uvicorn():
    rec = _record(
        '%s - "%s %s HTTP/%s" %d',
        "127.0.0.1:5000",
        "GET",
        "/auth/callback?code=c&client_secret=supersecret",
        "1.1",
        200,
        name="uvicorn.access",
    )

    SensitiveDataFilter().filter(rec)
    line = AccessFormatter("%(request_line)s %(status_code)s").format(rec)

    assert "supersecret" not in line
    assert "client_secret=[REDACTED]" in line
    assert "GET /auth/callback" in line


@pytest.fixture(name="root_output")
def fixture_root_output():
    """A handler on the root logger, as logging.basicConfig adds at startup."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    root = logging.getLogger()
    root.addHandler(handler)
    yield stream
    root.removeHandler(handler)


def test_the_installed_filter_redacts_the_apps_and_uvicorns_records(root_output):
    install_sensitive_data_filter()

    # Module loggers' records reach the root handler by propagation.
    logging.getLogger("mcp_gateway.routes.example").warning(
        "token=%s", "eyJhbGc.eyJzdWI.signature"
    )

    assert "eyJzdWI" not in root_output.getvalue()
    assert "[JWT_REDACTED]" in root_output.getvalue()
    # uvicorn's access log does not propagate, so it has a filter of its own.
    assert any(
        isinstance(f, SensitiveDataFilter)
        for f in logging.getLogger("uvicorn.access").filters
    )
