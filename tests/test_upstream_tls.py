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

# pylint: disable=protected-access

"""TLS certificate checks on the gateway's calls to MCP servers."""

import importlib
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import certifi
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from mcp_gateway.config import Settings, settings
from mcp_gateway.routes import mcp_server


@pytest.fixture(name="client_verify")
def fixture_client_verify(monkeypatch):
    """Build the shared proxy client and return what it checks certificates with."""
    factory = MagicMock()
    monkeypatch.setattr(mcp_server.httpx, "AsyncClient", factory)
    monkeypatch.setattr(mcp_server, "_mcp_http_client", None)

    def build():
        mcp_server._get_mcp_http_client()
        return factory.call_args.kwargs["verify"]

    return build


def _ca_bundle(tmp_path):
    """A file holding one self-signed CA certificate, as a private CA would issue."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Private Test CA")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "private-ca.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


@pytest.mark.parametrize(
    "value, verify",
    [("true", True), ("TRUE", True), ("1", True), ("", True)]
    + [("false", False), ("False", False), ("0", False)],
)
def test_certificate_checks_are_on_unless_turned_off_explicitly(
    monkeypatch, client_verify, value, verify
):
    """Debug mode, which developers turn on, must not turn them off."""
    monkeypatch.setattr(settings, "DEBUG", True)
    monkeypatch.setattr(settings, "UPSTREAM_TLS_VERIFY", value)

    assert client_verify() is verify


def test_a_ca_bundle_is_trusted_on_top_of_the_default_roots(
    monkeypatch, client_verify, tmp_path
):
    """Servers with public certificates, such as SaaS sign-in, must keep working.

    The default roots are the ones httpx trusts with verification on, which
    are certifi's, not the system's; some systems have none.
    """
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    monkeypatch.setattr(settings, "UPSTREAM_TLS_VERIFY", str(_ca_bundle(tmp_path)))
    certifi_roots = ssl.create_default_context(cafile=certifi.where())

    verify = client_verify()

    assert verify.verify_mode == ssl.CERT_REQUIRED
    assert (
        verify.cert_store_stats()["x509_ca"]
        == certifi_roots.cert_store_stats()["x509_ca"] + 1
    )


@pytest.mark.parametrize(
    "module",
    [
        "mcp_gateway.oauth.mcp_oauth_discovery",
        "mcp_gateway.routes.mcp_oauth",
        "mcp_gateway.oauth.token_manager",
    ],
)
def test_oauth_calls_for_mcp_servers_follow_the_setting_too(module):
    """Private-CA servers usually have private-CA authorization servers too."""
    source = Path(importlib.import_module(module).__file__).read_text(encoding="utf-8")

    assert source.count("httpx.AsyncClient(") == source.count(
        "verify=settings.upstream_tls_verify"
    )


@pytest.mark.parametrize(
    "value",
    ["/no/such/ca.pem", "off", "{tmp}", "{tmp}/empty.pem", "{tmp}/junk.pem"],
)
def test_a_ca_bundle_without_certificates_stops_the_gateway_starting(tmp_path, value):
    """Otherwise every call to an MCP server fails instead."""
    (tmp_path / "empty.pem").write_bytes(b"")
    (tmp_path / "junk.pem").write_bytes(b"not a certificate\n")

    with pytest.raises(ValidationError, match="UPSTREAM_TLS_VERIFY"):
        Settings(UPSTREAM_TLS_VERIFY=value.format(tmp=tmp_path))
