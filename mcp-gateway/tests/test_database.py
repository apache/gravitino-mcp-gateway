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

"""Tests for how mcp_gateway.database connects to MySQL."""

import datetime
import ssl

import pymysql
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pymysql.constants import CLIENT

from mcp_gateway.database import Base, _mysql_tls_args, _with_utf8mb4

URL = "mysql+pymysql://user:pw@host/db"


@pytest.mark.parametrize(
    "url,expected",
    [
        (URL, f"{URL}?charset=utf8mb4"),
        (f"{URL}?connect_timeout=10", f"{URL}?connect_timeout=10&charset=utf8mb4"),
        (f"{URL}?charset=utf8mb4", f"{URL}?charset=utf8mb4"),
    ],
)
def test_the_mysql_url_asks_for_utf8mb4_once(url, expected):
    assert _with_utf8mb4(url) == expected


def test_every_table_keeps_the_mysql_charset():
    """A model's own table arguments would otherwise replace the base's."""
    for table in Base.metadata.sorted_tables:
        assert table.kwargs.get("mysql_charset") == "utf8mb4", table.name


def _pymysql_connection(tls_args: dict) -> pymysql.connections.Connection:
    return pymysql.connect(
        host="db.invalid", user="gateway", defer_connect=True, **tls_args
    )


def test_disabled_never_uses_tls():
    assert not _pymysql_connection(_mysql_tls_args("DISABLED", None)).ssl


def test_preferred_falls_back_to_plain_text():
    connection = _pymysql_connection(_mysql_tls_args("PREFERRED", None))

    assert connection.ssl
    assert not connection.client_flag & CLIENT.SSL


@pytest.mark.parametrize(
    "ssl_mode, verify_mode, check_hostname",
    [
        ("REQUIRED", ssl.CERT_NONE, False),
        ("VERIFY_CA", ssl.CERT_REQUIRED, False),
        ("VERIFY_IDENTITY", ssl.CERT_REQUIRED, True),
    ],
)
def test_tls_is_required_and_its_certificate_checks_follow_the_mode(
    ssl_mode, verify_mode, check_hostname
):
    tls_args = _mysql_tls_args(ssl_mode, None)

    assert _pymysql_connection(tls_args).client_flag & CLIENT.SSL
    assert tls_args["ssl"].verify_mode == verify_mode
    assert tls_args["ssl"].check_hostname is check_hostname


def test_the_configured_ca_is_trusted(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test MySQL CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    context = _mysql_tls_args("VERIFY_IDENTITY", str(ca_file))["ssl"]

    subjects = [cert["subject"] for cert in context.get_ca_certs()]
    assert subjects == [((("commonName", "Test MySQL CA"),),)]
