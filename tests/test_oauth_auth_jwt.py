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

# pylint: disable=too-many-lines

"""Bearer-token authentication, with real RS256 signatures rather than mocked decodes.

The tokens are signed with genuine RSA keys and ``jwt.decode`` runs for real, so
the signature, audience, issuer and expiry checks are exercised, not stubbed.
"""

import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from jwt.exceptions import PyJWKClientConnectionError
from sqlalchemy.orm import sessionmaker

from mcp_gateway.config import settings
from mcp_gateway.models import ServiceAccountCredentials, User
from mcp_gateway.oauth import oidc_client
from mcp_gateway.oauth_auth import (
    _aws_service_account_identities,
    _discover_jwks_uri,
    _extract_eks_iss_id,
    _get_jwks_client,
    _get_signing_key_with_retry,
    _jwks_clients,
    _jwks_uri_cache,
    _lookup_aws_service_account,
    _require_service_account_workload_headers,
    _username_for,
    _validate_oidc_jwt,
    get_user_from_bearer_token,
    get_workload_forward_headers,
    sync_person,
)
from tests.request_utils import make_starlette_request

ISSUER = "https://login.example.com/tenant/v2.0"
EKS_ISSUER = "https://oidc.eks.us-west-2.amazonaws.com/id/ABC123"
OTHER_EKS_ISSUER = "https://oidc.eks.us-east-1.amazonaws.com/id/OTHER"
SA_EMAIL = "svc-test@example.iam.gserviceaccount.com"
WORKLOAD_HEADERS = {"team": "data", "namespace": "prod"}
OTHER_CLIENT = "11111111-2222-3333-4444-555555555555"
# The emails of conftest's regular_user and admin_user.
REGULAR_EMAIL = "testuser@example.com"
ADMIN_EMAIL = "admin@example.com"
PINNED_ELSEWHERE = {"additional_config": {"iss": "https://the-real-issuer"}}
HMAC_SECRET = "a-shared-secret-of-at-least-32-bytes"


def _keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_pem, key.public_key()


# Generating RSA keys is slow; one trusted pair and one impostor pair suffice.
TRUSTED_PRIVATE, TRUSTED_PUBLIC = _keypair()
IMPOSTOR_PRIVATE, _IMPOSTOR_PUBLIC = _keypair()


def _sign(claims, *, key=TRUSTED_PRIVATE, ttl=3600, algorithm="RS256"):
    """A token with the claims every path requires; a claim set to None is left out."""
    now = datetime.now(timezone.utc)
    payload = {
        "iss": ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": now,
        "exp": now + timedelta(seconds=ttl),
        **claims,
    }
    return pyjwt.encode(
        {name: value for name, value in payload.items() if value is not None},
        key,
        algorithm=algorithm,
    )


def _human_claims(**claims):
    return {"azp": settings.GATEWAY_OAUTH_CLIENT_ID, "email_verified": True, **claims}


def _sa_claims(**claims):
    return {"azp": "sa-client", "email": SA_EMAIL, "email_verified": True, **claims}


def _eks_claims(**claims):
    return {
        "iss": EKS_ISSUER,
        "sub": "system:serviceaccount:prod:etl",
        "kubernetes.io": {"namespace": "prod", "serviceaccount": {"name": "etl"}},
        **claims,
    }


def _eks_registration(name, iss=EKS_ISSUER):
    return {
        "provider": "aws",
        "service_account_name": name,
        "additional_config": {"iss": iss} if iss else None,
    }


@pytest.fixture(autouse=True, name="_isolated_caches")
def fixture_isolated_caches():
    """The JWKS caches are module globals and would leak between tests."""
    _jwks_uri_cache.clear()
    _jwks_clients.clear()
    yield
    _jwks_uri_cache.clear()
    _jwks_clients.clear()


@pytest.fixture(name="trusted_jwks")
def fixture_trusted_jwks(monkeypatch):
    """Serve the trusted public key from any key endpoint; returns the endpoints used."""
    used = []
    monkeypatch.setattr(
        "mcp_gateway.oauth_auth._discover_jwks_uri",
        AsyncMock(return_value="https://jwks.example.com/keys"),
    )
    monkeypatch.setattr(
        "mcp_gateway.oauth_auth._get_jwks_client",
        lambda uri: used.append(uri)
        or SimpleNamespace(
            get_signing_key_from_jwt=lambda token: SimpleNamespace(key=TRUSTED_PUBLIC)
        ),
    )
    return used


@pytest.fixture(name="no_keys")
def fixture_no_keys(monkeypatch):
    """A provider whose keys can't be found; returns the discovery and fetch mocks."""
    discover = AsyncMock(return_value=None)
    fetch = MagicMock()
    monkeypatch.setattr("mcp_gateway.oauth_auth._discover_jwks_uri", discover)
    monkeypatch.setattr("mcp_gateway.oauth_auth._get_jwks_client", fetch)
    return discover, fetch


@pytest.fixture(name="authenticate")
def fixture_authenticate(db_session):
    """Whom a token names, as the bearer check finds them, or None."""

    async def _authenticate(token, headers=None):
        return await _validate_oidc_jwt(
            token, db_session, make_starlette_request(headers)
        )

    return _authenticate


@pytest.fixture(name="sa_credentials")
def fixture_sa_credentials(db_session, service_account):
    def _make(**overrides):
        fields = {
            "service_account_id": service_account.id,
            "provider": "google",
            "service_account_name": SA_EMAIL,
            "allowed_services": ["trino"],
            "created_by": service_account.id,
            **overrides,
        }
        cred = ServiceAccountCredentials(**fields)
        db_session.add(cred)
        db_session.commit()
        return cred

    return _make


@pytest.fixture(name="additional_clients")
def fixture_additional_clients(monkeypatch):
    monkeypatch.setattr(
        settings, "GATEWAY_OAUTH_ADDITIONAL_CLIENT_IDS", f"{OTHER_CLIENT},  "
    )


@pytest.fixture(name="any_client")
def fixture_any_client(monkeypatch):
    monkeypatch.setattr(settings, "GATEWAY_OAUTH_ACCEPT_ANY_CLIENT", True)


# --- the Authorization header ---------------------------------------------------


@pytest.mark.parametrize(
    "authorization, detail",
    [
        (None, "Authorization header required"),
        ("Basic dXNlcjpwYXNz", "Use: Bearer <token>"),
        ("Bearer   ", "Token is empty"),
        ("Bearer sk-live-opaque-key", "gravitino-mcp login"),
        ("Bearer ey.not-a-jwt", "gravitino-mcp login"),
    ],
    ids=["missing", "basic credentials", "empty", "opaque api key", "malformed jwt"],
)
async def test_an_authorization_header_without_a_valid_jwt_is_refused(
    db_session, authorization, detail
):
    with pytest.raises(HTTPException) as exc:
        await get_user_from_bearer_token(
            authorization, make_starlette_request(), db_session
        )

    assert exc.value.status_code == 401
    assert detail in exc.value.detail


async def test_a_persons_token_names_them_and_is_kept_for_token_exchange(
    db_session, regular_user, trusted_jwks
):
    """Token exchange re-presents the token; a person's workload headers aren't forwarded."""
    token = _sign(_human_claims(email=regular_user.email))
    request = make_starlette_request(WORKLOAD_HEADERS)

    user = await get_user_from_bearer_token(f"Bearer {token}", request, db_session)

    assert user.id == regular_user.id
    assert request.state.bearer_token == token
    assert not get_workload_forward_headers(request)


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": None, "azp": "x"},
        {"email": "someone@example.com", "email_verified": True},
        _eks_claims(sub=None),
    ],
    ids=["no issuer", "no client", "an eks token without a subject"],
)
async def test_a_token_naming_no_issuer_or_client_names_no_one(
    authenticate, trusted_jwks, claims
):
    assert await authenticate(_sign(claims), WORKLOAD_HEADERS) is None


# --- people's tokens --------------------------------------------------------------


@pytest.mark.parametrize(
    "claims, signing",
    [
        pytest.param({}, {"key": IMPOSTOR_PRIVATE}, id="another key"),
        pytest.param(
            {"email": "x@evil.example"}, {"key": IMPOSTOR_PRIVATE}, id="forged"
        ),
        pytest.param({"aud": "some-other-api"}, {}, id="another audience"),
        # People's tokens go on to Gravitino, which expects JWT_AUDIENCE.
        pytest.param({"aud": settings.oauth_resource}, {}, id="the gateway's url"),
        pytest.param({}, {"ttl": -60}, id="expired"),
        pytest.param({"exp": None}, {}, id="no expiry"),
        pytest.param({"azp": "unapproved-client"}, {}, id="unapproved client"),
        pytest.param({"azp": OTHER_CLIENT, "aud": "x"}, {}, id="approved, audience"),
        pytest.param(
            {"azp": OTHER_CLIENT}, {"key": IMPOSTOR_PRIVATE}, id="approved, key"
        ),
        pytest.param({"azp": OTHER_CLIENT}, {"ttl": -60}, id="approved, expired"),
    ],
)
async def test_a_persons_token_that_fails_a_check_names_no_one(
    authenticate,
    db_session,
    regular_user,
    trusted_jwks,
    additional_clients,
    claims,
    signing,
):
    token = _sign({**_human_claims(email=regular_user.email), **claims}, **signing)

    assert await authenticate(token) is None
    assert db_session.query(User).count() == 1


@pytest.mark.parametrize(
    "claims, full_name",
    [
        ({"name": "New Comer"}, "New Comer"),
        ({"given_name": "New"}, "New"),
        ({}, "newcomer"),
    ],
)
async def test_a_first_time_caller_is_provisioned_under_their_lowercase_email(
    authenticate, trusted_jwks, claims, full_name
):
    user = await authenticate(
        _sign(_human_claims(email="NewComer@Example.com", **claims))
    )

    assert user.email == user.username == "newcomer@example.com"
    assert user.full_name == full_name
    assert user.is_service_account is False


@pytest.mark.parametrize(
    "provider, claims",
    [
        ("generic", {"email": REGULAR_EMAIL}),
        ("generic", {"email": REGULAR_EMAIL, "email_verified": "true"}),
        ("generic", {"email": REGULAR_EMAIL, "email_verified": "TRUE"}),
        ("generic", {"email": REGULAR_EMAIL.upper()}),
        ("azure", {"email": REGULAR_EMAIL, "email_verified": None}),
        ("azure", {"preferred_username": REGULAR_EMAIL}),
        ("azure", {"upn": REGULAR_EMAIL}),
        ("azure", {"unique_name": REGULAR_EMAIL}),
    ],
)
async def test_a_trusted_identity_claim_names_the_person(
    authenticate, db_session, regular_user, trusted_jwks, monkeypatch, provider, claims
):
    """Entra ID's tokens carry no email_verified, and often no email; its tenant sets the rest."""
    monkeypatch.setattr(settings, "OIDC_PROVIDER", provider)

    user = await authenticate(_sign(_human_claims(**claims)))

    assert user.id == regular_user.id
    assert db_session.query(User).count() == 1


@pytest.mark.parametrize(
    "claims",
    [
        {},
        {"email": ADMIN_EMAIL, "email_verified": False},
        {"email": ADMIN_EMAIL, "email_verified": "false"},
        {"email": ADMIN_EMAIL, "email_verified": 0},
        {"email": ADMIN_EMAIL, "email_verified": "no"},
        {"email": ADMIN_EMAIL, "email_verified": None},
        {"preferred_username": ADMIN_EMAIL},
        {"upn": ADMIN_EMAIL},
        {"unique_name": ADMIN_EMAIL},
    ],
)
async def test_outside_entra_only_a_verified_email_names_a_person(
    authenticate, db_session, admin_user, trusted_jwks, claims
):
    """People can make their email read unverified, or set another name claim to an admin's email."""
    assert await authenticate(_sign(_human_claims(**claims))) is None
    assert db_session.query(User).count() == 1


async def test_a_deactivated_person_is_refused(
    authenticate, db_session, regular_user, trusted_jwks
):
    regular_user.is_active = False
    db_session.commit()

    assert await authenticate(_sign(_human_claims(email=regular_user.email))) is None


async def test_a_person_cannot_sign_in_as_a_service_account(
    authenticate, db_session, service_account, trusted_jwks, monkeypatch
):
    """Its row, name and audit trail must not become a person's."""
    monkeypatch.setattr(settings, "ADMIN_EMAILS", service_account.email)
    token = _sign(_human_claims(email=service_account.email, name="Mallory"))

    assert await authenticate(token) is None
    db_session.refresh(service_account)
    assert service_account.username == "svc-test"
    assert not service_account.is_admin


@pytest.mark.parametrize(
    "provider, claims",
    [
        ("generic", {"email": "boss@example.com"}),
        ("azure", {"upn": "boss@example.com"}),
    ],
)
async def test_a_listed_admin_is_an_admin_from_their_first_token(
    authenticate, trusted_jwks, monkeypatch, provider, claims
):
    """People who use only tokens, as in Gravitino's web UI, never sign in to the gateway."""
    monkeypatch.setattr(settings, "ADMIN_EMAILS", "other@example.com, Boss@example.com")
    monkeypatch.setattr(settings, "OIDC_PROVIDER", provider)

    user = await authenticate(_sign(_human_claims(**claims)))

    assert user.is_admin is True


async def test_an_admin_removed_from_the_list_loses_admin_rights(
    authenticate, db_session, admin_user, trusted_jwks, monkeypatch
):
    monkeypatch.setattr(settings, "ADMIN_EMAILS", "other@example.com")

    await authenticate(_sign(_human_claims(email=admin_user.email)))

    db_session.refresh(admin_user)
    assert admin_user.is_admin is False


@pytest.mark.parametrize(
    "others, claimed, email, username",
    [
        ([], "Alice.Smith@Corp.com", "alice.smith@example.org", "Alice.Smith@Corp.com"),
        ([("ace", "a@example.com")], "ace", "b@example.com", "b@example.com"),
        (
            [("b@x.example", "a@x.example")],
            "b@x.example",
            "b@x.example",
            "b@x.example#2",
        ),
    ],
    ids=["as claimed, in its case", "taken: the email", "taken, with the email"],
)
async def test_the_user_id_claim_names_a_person_unless_another_account_has_the_name(
    db_session, monkeypatch, others, claimed, email, username
):
    """Gravitino reads the claim as it is; a name someone else holds stays theirs."""
    monkeypatch.setattr(settings, "USER_ID_CLAIM", "preferred_username")
    for other_name, other_email in others:
        db_session.add(
            User(username=other_name, email=other_email, is_service_account=False)
        )
    db_session.commit()

    user = await sync_person(db_session, {"preferred_username": claimed}, email)

    assert (user.email, user.username) == (email, username)


async def test_changing_the_user_id_claim_renames_people_as_they_return(
    authenticate, regular_user, trusted_jwks, monkeypatch
):
    monkeypatch.setattr(settings, "USER_ID_CLAIM", "preferred_username")
    token = _sign(_human_claims(email=regular_user.email, preferred_username="renamed"))

    user = await authenticate(token)

    assert (user.id, user.username) == (regular_user.id, "renamed")


async def test_a_token_without_the_claim_keeps_the_persons_name(
    db_session, monkeypatch
):
    """ID tokens and access tokens can carry different claims."""
    monkeypatch.setattr(settings, "USER_ID_CLAIM", "preferred_username")
    await sync_person(db_session, {"preferred_username": "alice"}, "alice@example.com")

    user = await sync_person(db_session, {}, "alice@example.com")

    assert user.username == "alice"


async def test_people_whose_emails_share_a_prefix_are_different_users(db_session):
    first = await sync_person(db_session, {}, "bob@a.example")
    second = await sync_person(db_session, {}, "bob@b.example")

    assert first.id != second.id
    assert {first.username, second.username} == {"bob@a.example", "bob@b.example"}


class _Race:
    """Commits ``competitor`` from another session the next time a name is chosen.

    That is what a concurrent sign-in does between the gateway's check of a
    name and its commit.
    """

    def __init__(self, db_engine, competitor):
        self._db_engine = db_engine
        self._competitor = competitor

    def username_for(self, db, claims, email, user):
        """Stands in for ``_username_for``, racing it once."""
        if self._competitor is not None:
            other = sessionmaker(bind=self._db_engine)()
            other.add(self._competitor)
            other.commit()
            other.close()
            self._competitor = None
        return _username_for(db, claims, email, user)


async def test_a_concurrent_first_sign_in_uses_the_account_it_created(
    db_session, db_engine
):
    """Two first requests can race; the loser must not fail with a 500."""
    racer = "racer@example.com"
    race = _Race(db_engine, User(username=racer, email=racer, is_service_account=False))

    with patch("mcp_gateway.oauth_auth._username_for", race.username_for):
        user = await sync_person(db_session, {}, racer)

    assert user.email == racer
    assert db_session.query(User).filter_by(email=racer).count() == 1


async def test_a_name_taken_while_renaming_falls_back_to_the_email(
    db_session, db_engine, regular_user, monkeypatch
):
    monkeypatch.setattr(settings, "USER_ID_CLAIM", "preferred_username")
    race = _Race(
        db_engine,
        User(username="ace", email="other@example.com", is_service_account=False),
    )

    with patch("mcp_gateway.oauth_auth._username_for", race.username_for):
        user = await sync_person(
            db_session, {"preferred_username": "ace"}, regular_user.email
        )

    assert user.username == regular_user.email


@pytest.mark.parametrize(
    "claims, configured",
    [
        pytest.param(_human_claims(email=REGULAR_EMAIL), {}, id="person"),
        pytest.param(_sa_claims(), {"jwks_uri": "https://configured/keys"}, id="sa"),
    ],
)
async def test_a_configured_key_endpoint_is_used_instead_of_discovery(
    authenticate,
    regular_user,
    sa_credentials,
    trusted_jwks,
    monkeypatch,
    claims,
    configured,
):
    """People's comes from OIDC_JWKS_URI, a service account's from its registration."""
    monkeypatch.setattr(settings, "OIDC_JWKS_URI", "https://configured/keys")
    sa_credentials(additional_config=configured)

    await authenticate(_sign(claims), WORKLOAD_HEADERS)

    assert trusted_jwks == ["https://configured/keys"]


@pytest.mark.parametrize("document", [{}, {"issuer": ISSUER}])
async def test_without_oidc_issuer_only_the_discovered_issuer_names_people(
    authenticate, regular_user, trusted_jwks, monkeypatch, document
):
    monkeypatch.setattr(settings, "OIDC_ISSUER", None)
    monkeypatch.setattr(settings, "OIDC_DISCOVERY_URL", f"{ISSUER}/.well-known/x")
    monkeypatch.setattr(oidc_client, "_get_discovery_document", lambda url: document)

    user = await authenticate(_sign(_human_claims(email=regular_user.email)))

    assert (user is not None) == bool(document)


# --- approved calling clients ------------------------------------------------------


@pytest.mark.parametrize(
    "raw, extra",
    [
        ("", []),
        (f"{OTHER_CLIENT},  ", [OTHER_CLIENT]),
        (f"{OTHER_CLIENT}, other-client", [OTHER_CLIENT, "other-client"]),
    ],
    ids=["none", "one, with a trailing comma", "several"],
)
def test_additional_clients_are_approved_after_the_primary(monkeypatch, raw, extra):
    monkeypatch.setattr(settings, "GATEWAY_OAUTH_ADDITIONAL_CLIENT_IDS", raw)

    assert settings.gateway_oauth_client_ids == [
        settings.GATEWAY_OAUTH_CLIENT_ID,
        *extra,
    ]


@pytest.mark.parametrize(
    "approved, client_id",
    [
        pytest.param({}, settings.GATEWAY_OAUTH_CLIENT_ID, id="primary"),
        pytest.param({"ADDITIONAL_CLIENT_IDS": OTHER_CLIENT}, OTHER_CLIENT, id="extra"),
        # MCP clients that register themselves (RFC 7591) each get a new client id.
        pytest.param({"ACCEPT_ANY_CLIENT": True}, "registered", id="any"),
    ],
)
async def test_an_approved_client_authenticates_its_user(
    db_session, regular_user, trusted_jwks, monkeypatch, approved, client_id
):
    for name, value in approved.items():
        monkeypatch.setattr(settings, f"GATEWAY_OAUTH_{name}", value)
    token = _sign(_human_claims(email=regular_user.email, azp=client_id))
    request = make_starlette_request()

    user = await _validate_oidc_jwt(token, db_session, request)

    assert user.id == regular_user.id


@pytest.mark.parametrize(
    "claims",
    [
        {
            "azp": "some-gcp-project",
            "email": "anything@attacker-project.iam.gserviceaccount.com",
        },
        {"azp": "registered-on-the-fly", "email": "someone@example.com", "aud": "x"},
        {
            "azp": "registered-on-the-fly",
            "email": "someone@example.com",
            "iss": "https://accounts.google.com",
        },
    ],
    ids=["a google service account", "another audience", "another issuer"],
)
async def test_with_any_client_accepted_these_tokens_still_name_no_one(
    authenticate, db_session, trusted_jwks, any_client, claims
):
    """Any Google service account can get a token for the gateway's audience."""
    assert await authenticate(_sign(_human_claims(**claims)), WORKLOAD_HEADERS) is None
    assert db_session.query(User).count() == 0


async def test_with_any_client_accepted_a_registered_service_account_keeps_its_path(
    authenticate, db_session, sa_credentials, trusted_jwks, any_client
):
    """Otherwise a workload could skip registration and its workload headers."""
    sa_credentials()

    with pytest.raises(HTTPException) as exc:
        await authenticate(_sign(_sa_claims()))

    assert exc.value.status_code == 401
    assert not db_session.query(User).filter(User.email == SA_EMAIL).first()


# --- service accounts' tokens ------------------------------------------------------


@pytest.mark.parametrize(
    "registration, claims",
    [
        pytest.param({}, {}, id="registered"),
        pytest.param({}, {"aud": settings.oauth_resource}, id="for the gateway's url"),
        pytest.param({}, {"email": SA_EMAIL.upper()}, id="email in another case"),
        pytest.param({"additional_config": {"iss": ISSUER}}, {}, id="pinned issuer"),
    ],
)
async def test_a_registered_service_account_is_authenticated(
    db_session, service_account, sa_credentials, trusted_jwks, registration, claims
):
    """The SDK asks for a token for the gateway's URL, which its metadata names."""
    sa_credentials(**registration)
    request = make_starlette_request(
        {**WORKLOAD_HEADERS, "pipeline": "etl", "x-unlisted": "x"}
    )

    user = await _validate_oidc_jwt(_sign(_sa_claims(**claims)), db_session, request)

    assert user.id == service_account.id
    assert request.state.is_service_account is True
    assert get_workload_forward_headers(request) == {
        **WORKLOAD_HEADERS,
        "pipeline": "etl",
    }


@pytest.mark.parametrize(
    "registration, claims, signing",
    [
        pytest.param({}, {"aud": "some-other-api"}, {}, id="another audience"),
        pytest.param({}, {"email": "stranger@example.com"}, {}, id="unregistered"),
        pytest.param(PINNED_ELSEWHERE, {}, {}, id="issuer not the pinned one"),
        pytest.param({}, {}, {"key": HMAC_SECRET, "algorithm": "HS256"}, id="hs256"),
        pytest.param({}, {}, {"ttl": -60}, id="expired"),
        pytest.param({}, {"exp": None}, {}, id="no expiry"),
        pytest.param({}, {"email_verified": False}, {}, id="email unverified"),
        pytest.param({}, {"email_verified": None}, {}, id="verification left out"),
        pytest.param({}, {"email": "   "}, {}, id="blank email"),
        pytest.param({}, {"email": 12345}, {}, id="email not a string"),
    ],
)
async def test_a_service_account_token_that_fails_a_check_is_refused(
    authenticate, sa_credentials, trusted_jwks, registration, claims, signing
):
    """Registration is the only allowlist, and no standing pass: the token must check out."""
    sa_credentials(**registration)
    token = _sign(_sa_claims(**claims), **signing)

    assert await authenticate(token, WORKLOAD_HEADERS) is None


@pytest.mark.parametrize("gone", ["deactivated", "deleted"])
async def test_a_registration_without_an_active_account_authenticates_no_one(
    authenticate, db_session, service_account, sa_credentials, trusted_jwks, gone
):
    cred = sa_credentials()
    if gone == "deactivated":
        service_account.is_active = False
    else:
        cred.service_account_id = 999999
    db_session.commit()

    assert await authenticate(_sign(_sa_claims()), WORKLOAD_HEADERS) is None


@pytest.mark.parametrize(
    "headers, missing",
    [
        ({}, "team"),
        ({"team": "data"}, "namespace"),
        ({"team": "", "namespace": "prod"}, "team"),
    ],
    ids=["none", "no namespace", "blank team"],
)
async def test_a_service_account_without_its_workload_headers_is_refused(
    authenticate, sa_credentials, trusted_jwks, headers, missing
):
    """The headers attribute the call in the audit trail."""
    sa_credentials()

    with pytest.raises(HTTPException) as exc:
        await authenticate(_sign(_sa_claims()), headers)

    assert exc.value.status_code == 401
    assert missing in exc.value.detail


@pytest.mark.parametrize(
    "required, headers",
    [("", {}), (" Team ", {"team": "data"})],
    ids=["none configured", "names in any case"],
)
def test_only_the_configured_workload_headers_are_required(
    monkeypatch, required, headers
):
    monkeypatch.setattr(settings, "SERVICE_ACCOUNT_REQUIRED_HEADERS", required)

    _require_service_account_workload_headers(make_starlette_request(headers))


# --- both paths --------------------------------------------------------------------

BOTH_PATHS = pytest.mark.parametrize(
    "claims",
    [_human_claims(email=REGULAR_EMAIL), _sa_claims()],
    ids=["person", "service account"],
)


@pytest.mark.parametrize(
    "claims",
    [
        _human_claims(email=REGULAR_EMAIL, iss="https://evil.example/issuer"),
        _sa_claims(),
    ],
    ids=["person", "service account"],
)
async def test_a_token_from_an_untrusted_issuer_makes_no_network_call(
    authenticate, regular_user, sa_credentials, no_keys, monkeypatch, claims
):
    """Fetching keys for any issuer a token names would let anyone aim the gateway's requests."""
    monkeypatch.setattr(settings, "TRUSTED_ISSUERS", "")
    sa_credentials()

    assert await authenticate(_sign(claims), WORKLOAD_HEADERS) is None
    for mock in no_keys:
        mock.assert_not_called()


@BOTH_PATHS
async def test_a_provider_whose_keys_cant_be_found_authenticates_no_one(
    authenticate, regular_user, sa_credentials, no_keys, claims
):
    sa_credentials()

    assert await authenticate(_sign(claims), WORKLOAD_HEADERS) is None
    no_keys[1].assert_not_called()


@BOTH_PATHS
async def test_an_unexpected_failure_authenticates_no_one(
    authenticate, regular_user, sa_credentials, trusted_jwks, monkeypatch, claims
):
    """A broken key endpoint must fail closed rather than surface a 500."""
    sa_credentials()
    monkeypatch.setattr(
        "mcp_gateway.oauth_auth._get_jwks_client",
        MagicMock(side_effect=RuntimeError("key endpoint melted")),
    )

    assert await authenticate(_sign(claims), WORKLOAD_HEADERS) is None


# --- Amazon EKS workload identity ---------------------------------------------------


@pytest.mark.parametrize(
    "registration",
    [
        _eks_registration("prod::etl::abc123", iss=None),
        _eks_registration("prod::etl"),
    ],
    ids=["names its cluster", "pins its cluster's issuer"],
)
async def test_an_eks_workload_is_authenticated_by_its_kubernetes_identity(
    authenticate, service_account, sa_credentials, trusted_jwks, registration
):
    sa_credentials(**registration)

    user = await authenticate(_sign(_eks_claims()), WORKLOAD_HEADERS)

    assert user.id == service_account.id


@pytest.mark.parametrize(
    "registration, claims",
    [
        pytest.param(None, {}, id="unregistered"),
        pytest.param(
            _eks_registration("prod::etl", iss=None), {}, id="no cluster or issuer"
        ),
        pytest.param(
            _eks_registration("prod::etl::abc123", iss=OTHER_EKS_ISSUER),
            {},
            id="pinned to another cluster",
        ),
        pytest.param(
            None,
            {"kubernetes.io": {"namespace": "prod", "serviceaccount": {}}},
            id="incomplete kubernetes claims",
        ),
    ],
)
async def test_an_eks_workload_is_refused(
    authenticate, sa_credentials, trusted_jwks, registration, claims
):
    """namespace::name is the same in every cluster, so the issuer must say which."""
    if registration is not None:
        sa_credentials(**registration)

    assert await authenticate(_sign(_eks_claims(**claims)), WORKLOAD_HEADERS) is None


def test_a_cluster_specific_registration_wins_over_a_plain_one(
    db_session, sa_credentials
):
    for name in ("prod::etl", "prod::etl::abc123"):
        sa_credentials(**_eks_registration(name))

    cred = _lookup_aws_service_account(
        db_session, _aws_service_account_identities("prod", "etl", EKS_ISSUER)
    )

    assert cred.service_account_name == "prod::etl::abc123"


def test_a_workload_of_no_cluster_has_only_its_plain_name():
    assert _aws_service_account_identities("prod", "etl", "https://example.com") == [
        "prod::etl"
    ]


@pytest.mark.parametrize(
    "issuer, cluster",
    [
        (EKS_ISSUER, "abc123"),
        ("https://oidc.eks.cn-north-1.amazonaws.com.cn/id/ABC123", "abc123"),
        ("https://oidc.eks.us-east-1.amazonaws.com/id/", None),
        ("https://accounts.google.com", None),
        # Cognito's issuers are on amazonaws.com too, and name people.
        ("https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf", None),
        ("https://evil.example.com/oidc.eks.us-east-1.amazonaws.com/id/ABC123", None),
        ("https://oidc.eks.us-east-1.amazonaws.com.evil.example.com/id/ABC123", None),
        ("http://oidc.eks.us-east-1.amazonaws.com/id/ABC123", None),
    ],
)
def test_only_an_eks_issuer_names_a_cluster(issuer, cluster):
    assert _extract_eks_iss_id(issuer) == cluster


# --- finding a provider's keys -----------------------------------------------------


def _discovery_client(replies):
    """An httpx.AsyncClient stand-in. ``replies`` maps a URL's last segment to a
    key endpoint, a document, a status code or an exception; others answer 404."""

    async def _get(url):
        reply = replies.get(url.rsplit("/", 1)[-1], 404)
        if isinstance(reply, Exception):
            raise reply
        if isinstance(reply, int):
            return SimpleNamespace(status_code=reply)
        document = {"jwks_uri": reply} if isinstance(reply, str) else reply
        return SimpleNamespace(status_code=200, json=lambda: document)

    client = MagicMock()
    client.get = _get
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


OIDC_DOC = "openid-configuration"
OAUTH_DOC = "oauth-authorization-server"
ENTRA_ISSUER = "https://login.microsoftonline.com/tenant-abc/v2.0"


@pytest.mark.parametrize(
    "issuer, replies, expected",
    [
        pytest.param(ISSUER, {OIDC_DOC: "https://k/1"}, "https://k/1", id="openid"),
        pytest.param(ISSUER, {OAUTH_DOC: "https://k/2"}, "https://k/2", id="oauth"),
        pytest.param(
            ISSUER,
            {OIDC_DOC: OSError("refused"), OAUTH_DOC: "https://k/3"},
            "https://k/3",
            id="past a transport error",
        ),
        pytest.param(
            ISSUER,
            {OIDC_DOC: {"issuer": ISSUER}, OAUTH_DOC: "https://k/4"},
            "https://k/4",
            id="past a document without keys",
        ),
        pytest.param(ISSUER, {OIDC_DOC: 500}, None, id="undiscoverable"),
        pytest.param(
            ENTRA_ISSUER,
            {},
            "https://login.microsoftonline.com/tenant-abc/discovery/v2.0/keys",
            id="entra's known endpoint",
        ),
        pytest.param(
            OTHER_EKS_ISSUER, {}, f"{OTHER_EKS_ISSUER}/keys", id="eks's known endpoint"
        ),
    ],
)
async def test_a_trusted_issuers_key_endpoint_is_discovered(
    monkeypatch, issuer, replies, expected
):
    monkeypatch.setattr(
        "mcp_gateway.oauth_auth.httpx.AsyncClient",
        lambda **kw: _discovery_client(replies),
    )

    assert (
        await _discover_jwks_uri(issuer, allowed_issuers=frozenset({issuer}))
        == expected
    )


async def test_a_discovered_key_endpoint_is_cached_for_an_hour(monkeypatch):
    """Discovery runs on the authentication hot path; it must not probe every time."""
    probes = []

    def _client(**_kw):
        probes.append(1)
        return _discovery_client({OIDC_DOC: f"https://k/{len(probes)}"})

    monkeypatch.setattr("mcp_gateway.oauth_auth.httpx.AsyncClient", _client)
    allowed = frozenset({ISSUER})

    first = await _discover_jwks_uri(ISSUER, allowed_issuers=allowed)
    second = await _discover_jwks_uri(ISSUER, allowed_issuers=allowed)
    _jwks_uri_cache[ISSUER] = (first, time.monotonic() - 7200)
    third = await _discover_jwks_uri(ISSUER, allowed_issuers=allowed)

    assert (first, second, third) == ("https://k/1", "https://k/1", "https://k/2")


async def test_an_untrusted_issuer_is_not_discovered(monkeypatch):
    probes = []
    monkeypatch.setattr(
        "mcp_gateway.oauth_auth.httpx.AsyncClient",
        lambda **kw: probes.append(1) or _discovery_client({}),
    )

    assert await _discover_jwks_uri(ISSUER, allowed_issuers=frozenset()) is None
    assert not probes


def test_one_key_client_is_shared_per_key_endpoint():
    """A fresh client per request would discard the key cache every time."""
    first = _get_jwks_client("https://keys/a")

    assert _get_jwks_client("https://keys/a") is first
    assert _get_jwks_client("https://keys/b") is not first


def test_keys_are_not_cached_apart_from_the_key_set():
    """Such a cache never expires, so a withdrawn key would stay trusted."""
    client = _get_jwks_client("https://keys/a")

    assert not hasattr(client.get_signing_key, "cache_info")
    assert client.jwk_set_cache is not None


def test_a_key_fetch_is_tried_three_times_before_it_fails(monkeypatch):
    monkeypatch.setattr("mcp_gateway.oauth_auth._JWKS_FETCH_RETRY_DELAY", 0)
    flaky, down = MagicMock(), MagicMock()
    flaky.get_signing_key_from_jwt.side_effect = [
        PyJWKClientConnectionError("x"),
        "key",
    ]
    down.get_signing_key_from_jwt.side_effect = PyJWKClientConnectionError("down")

    assert _get_signing_key_with_retry(flaky, "token") == "key"
    with pytest.raises(PyJWKClientConnectionError):
        _get_signing_key_with_retry(down, "token")
    assert flaky.get_signing_key_from_jwt.call_count == 2
    assert down.get_signing_key_from_jwt.call_count == 3
