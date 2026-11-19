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
"""Tokens the gateway signs for passthrough servers name the person uniquely."""

import jwt

from mcp_gateway.gateway_keys import mint_gateway_jwt
from mcp_gateway.models import User


def test_the_subject_is_the_persons_gateway_username():
    """The email prefix used to be the subject, so bob@a and bob@b collided."""
    user = User(username="bob@a.example", email="bob@a.example", full_name="Bob")

    claims = jwt.decode(
        mint_gateway_jwt(user, "trino"), options={"verify_signature": False}
    )

    assert claims["sub"] == "bob@a.example"
    assert claims["preferred_username"] == "bob@a.example"
    assert claims["email"] == "bob@a.example"


def test_a_service_account_named_like_a_person_is_told_apart():
    """An admin names service accounts, so a name alone could pass for a person's."""
    person = User(username="alice@corp.example", email="alice@corp.example")
    account = User(
        username="alice@corp.example",
        email="alice@corp.example",
        is_service_account=True,
    )

    kinds = [
        jwt.decode(mint_gateway_jwt(u, "trino"), options={"verify_signature": False})[
            "principal_type"
        ]
        for u in (person, account)
    ]

    assert kinds == ["person", "service_account"]
