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

"""Tests for mcp_gateway_sdk.aws_token (EKS in-cluster TokenRequest)."""

import json
from unittest.mock import MagicMock, patch

import jwt
import pytest

from mcp_gateway_sdk import aws_token
from mcp_gateway_sdk.aws_token import (
    GatewayAwsTokenError,
    get_aws_identity_token,
    read_namespace_from_filesystem,
    service_account_name_from_token,
)
from mcp_gateway_sdk.sa_token import get_gateway_sa_token

AUDIENCE = "gravitino-mcp-gateway"
GATEWAY = "https://mcp-gateway.example.com"


def _token(claims: dict) -> str:
    return jwt.encode(claims, "a-test-secret-of-at-least-32-bytes", algorithm="HS256")


def _response(ok=True, status=201, body=None, text=""):
    resp = MagicMock(ok=ok, status_code=status, text=text)
    resp.json.return_value = body
    return resp


def _minted(token):
    return _response(body={"status": {"token": token}})


@pytest.fixture(name="in_cluster")
def fixture_in_cluster(tmp_path, monkeypatch):
    """The pod's ServiceAccount mount: namespace, bound token and cluster CA."""
    files = {
        "namespace": "example-ns",
        "token": _token(
            {
                "kubernetes.io": {
                    "namespace": "example-ns",
                    "serviceaccount": {"name": "example-sa"},
                }
            }
        ),
        "ca.crt": "dummy-ca-for-mock",
    }
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    monkeypatch.setattr(aws_token, "_DEFAULT_BOUND_TOKEN_PATH", tmp_path / "token")
    monkeypatch.setattr(aws_token, "_DEFAULT_NAMESPACE_PATH", tmp_path / "namespace")
    monkeypatch.setattr(aws_token, "_DEFAULT_CA_CERT_PATH", tmp_path / "ca.crt")
    return tmp_path


def test_the_service_account_name_comes_from_the_kubernetes_claims():
    token = _token(
        {
            "kubernetes.io": {"serviceaccount": {"name": "from-nested", "uid": "abc"}},
            "sub": "system:serviceaccount:ns:other",
        }
    )

    assert service_account_name_from_token(token) == "from-nested"


@pytest.mark.parametrize(
    "claims",
    [{"sub": "system:serviceaccount:example-ns:example-sa"}, {"iss": "https://x"}],
)
def test_a_token_without_the_kubernetes_claims_names_no_service_account(claims):
    with pytest.raises(GatewayAwsTokenError, match="Could not derive"):
        service_account_name_from_token(_token(claims))


def test_the_namespace_is_read_from_its_file(tmp_path):
    path = tmp_path / "namespace"
    path.write_text("example-ns\n", encoding="utf-8")

    assert read_namespace_from_filesystem(path) == "example-ns"


def test_an_empty_namespace_file_is_an_error(tmp_path):
    path = tmp_path / "namespace"
    path.write_text("  \n", encoding="utf-8")

    with pytest.raises(GatewayAwsTokenError, match="empty"):
        read_namespace_from_filesystem(path)


def test_a_token_for_a_named_audience_is_minted_for_the_pods_service_account(
    in_cluster,
):
    with patch.object(aws_token.requests, "post", return_value=_minted("t")) as post:
        token = get_gateway_sa_token(GATEWAY, source="aws", audience=AUDIENCE)

    assert token == "t"
    (url,), kwargs = post.call_args
    assert url.endswith(
        "/api/v1/namespaces/example-ns/serviceaccounts/example-sa/token"
    )
    assert (kwargs["verify"], kwargs["timeout"]) == (str(in_cluster / "ca.crt"), 10.0)
    spec = json.loads(kwargs["data"])["spec"]
    assert spec == {"audiences": [AUDIENCE], "expirationSeconds": 3600}


def test_the_token_is_for_the_gateways_url_without_asking_the_gateway(in_cluster):
    """Whoever answers the gateway's discovery documents must not choose the audience."""
    with patch.object(
        aws_token.requests, "post", return_value=_minted("t")
    ) as post, patch("mcp_gateway_sdk.sa_token.requests.get") as get:
        assert get_gateway_sa_token(f"{GATEWAY}/", source="aws") == "t"

    get.assert_not_called()
    assert json.loads(post.call_args.kwargs["data"])["spec"]["audiences"] == [GATEWAY]


@pytest.mark.parametrize(
    "response,error",
    [
        (_response(ok=False, status=403, text="forbidden"), "403"),
        (_response(body={"status": {}}), "missing status.token"),
    ],
)
def test_a_refused_or_empty_token_request_is_an_error(in_cluster, response, error):
    with patch.object(aws_token.requests, "post", return_value=response):
        with pytest.raises(GatewayAwsTokenError, match=error):
            get_aws_identity_token(audience=AUDIENCE)
