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

"""
Bearer token authentication for MCP Gateway: people's tokens from the
identity provider, and service accounts' workload identity tokens.
"""

import logging
import re
import threading
import time
from typing import Optional

import httpx
import jwt
from fastapi import Depends, Header, HTTPException, Request
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from .config import settings
from .database import get_db
from .gravitino_admins import is_gravitino_service_admin
from .models import ServiceAccountCredentials, User
from .oauth.oidc_client import get_configured_issuer

logger = logging.getLogger(__name__)

# https://oidc.eks.<region>.amazonaws.com/id/<cluster ID>, or .com.cn in China.
_EKS_ISSUER = re.compile(
    r"^https://oidc\.eks\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?/id/([0-9A-Za-z]+)/?$"
)
# How far apart the identity provider's clock and the gateway's may be.
JWT_LEEWAY_SECONDS = 60
# Google service accounts' emails.
_WORKLOAD_EMAIL_DOMAIN = ".gserviceaccount.com"
# https://login.microsoftonline.com/<tenant>/v2.0
_ENTRA_ISSUER = re.compile(r"^https://login\.microsoftonline\.com/([^/]+)/v2\.0/?$")

# One PyJWKClient per key endpoint, so its cached key set is shared. The set is
# fetched again after 5 minutes, and at most every 30 seconds for an unknown
# key ID. Keys aren't cached apart from the set: such a cache never expires,
# so a key the provider withdrew would stay trusted.
_jwks_clients: dict[str, PyJWKClient] = {}
_jwks_clients_lock = threading.Lock()

_JWKS_FETCH_MAX_RETRIES = 2
_JWKS_FETCH_RETRY_DELAY = 0.5  # seconds


def _get_jwks_client(jwks_uri: str) -> PyJWKClient:
    """Return a cached PyJWKClient for the given JWKS URI."""
    client = _jwks_clients.get(jwks_uri)
    if client is not None:
        return client
    with _jwks_clients_lock:
        # Double-check after acquiring lock
        client = _jwks_clients.get(jwks_uri)
        if client is None:
            client = PyJWKClient(
                jwks_uri,
                cache_keys=False,
                lifespan=300,
                timeout=settings.OIDC_HTTP_TIMEOUT,  # bound the blocking JWKS fetch
            )
            _jwks_clients[jwks_uri] = client
        return client


def _get_signing_key_with_retry(jwks_client: PyJWKClient, token: str):
    """Fetch the signing key, retrying on transient connection errors."""
    last_exc = None
    for attempt in range(_JWKS_FETCH_MAX_RETRIES + 1):
        try:
            return jwks_client.get_signing_key_from_jwt(token)
        except PyJWKClientConnectionError as exc:
            last_exc = exc
            if attempt < _JWKS_FETCH_MAX_RETRIES:
                logger.warning(
                    "JWKS fetch failed (attempt %d/%d), retrying: %s",
                    attempt + 1,
                    _JWKS_FETCH_MAX_RETRIES + 1,
                    exc,
                )
                time.sleep(_JWKS_FETCH_RETRY_DELAY * (attempt + 1))
    raise last_exc


def _service_account_trusted_issuers(
    sa_cred: ServiceAccountCredentials,
) -> frozenset[str]:
    """Issuers accepted for this service account before JWKS fetch or discovery."""
    if sa_cred.additional_config:
        pinned_iss = sa_cred.additional_config.get("iss")
        if isinstance(pinned_iss, str) and pinned_iss.strip():
            return frozenset({pinned_iss.strip()})
    return settings.trusted_issuer_set()


def _resolve_service_account_trusted_issuer(
    token_iss: str, sa_cred: ServiceAccountCredentials
) -> Optional[str]:
    """Return token_iss when it matches configured or registration-pinned issuers."""
    if not token_iss or not isinstance(token_iss, str):
        return None
    trusted = _service_account_trusted_issuers(sa_cred)
    if token_iss not in trusted:
        return None
    return token_iss


def _require_service_account_workload_headers(
    request: Request,
) -> None:
    """Reject a service-account request without a SERVICE_ACCOUNT_REQUIRED_HEADERS header."""
    for header in settings.service_account_required_headers:
        # Blank values aren't forwarded, so they don't count.
        if not (request.headers.get(header) or "").strip():
            raise HTTPException(
                status_code=401,
                detail=f"{header} header is required for service account authentication.",
            )


def get_workload_forward_headers(request: Request) -> dict[str, str]:
    """Return SA workload headers to forward to downstream MCP backends.

    Only service-account requests forward the configured workload headers.
    Human requests return an empty dict, so callers can do unconditional
    ``**get_workload_forward_headers(request)`` without forwarding (or auditing)
    workload attribution spoofed from arbitrary human-supplied headers.
    """
    if not getattr(request.state, "is_service_account", False):
        return {}
    out: dict[str, str] = {}
    for key in (
        settings.service_account_required_headers
        + settings.service_account_optional_headers
    ):
        v = request.headers.get(key)
        if v and v.strip():
            out[key] = v.strip()
    return out


def get_passthrough_forward_headers(request: Request) -> dict[str, str]:
    """Return the caller's MCP_FORWARD_HEADERS headers to forward to the upstream MCP.

    Only the configured headers are forwarded, so arbitrary client headers
    can't be smuggled to backends. Additive to, and never overriding, the
    OAuth/auth headers MCP Gateway sets for the backend request.
    """
    out: dict[str, str] = {}
    for name in settings.mcp_forward_headers:
        v = request.headers.get(name)
        if v and v.strip():
            out[name] = v.strip()
    return out


def email_from_claims(claims: dict) -> Optional[str]:
    """A person's email from ID or access token claims, or None.

    Only a verified email claim identifies someone. Some providers, Keycloak
    among them, let people change their own email, which then reads
    unverified; a provider that leaves email_verified out may not check at all.
    Microsoft Entra ID's tokens carry no email_verified, and often no email,
    so there the email, UPN and username the tenant assigns stand in;
    elsewhere those claims can hold a name the person picked, such as an
    admin's email.
    """
    email = claims.get("email")  # Standard OIDC
    if email:
        verified = claims.get("email_verified")
        if verified is None and settings.OIDC_PROVIDER == "azure":
            return email
        if _is_true(verified):
            return email
        if verified is None:
            logger.warning(
                "A token for %s has no email_verified claim; the gateway trusts "
                "only verified emails, so add it to the provider's tokens",
                email,
            )
        return None
    if settings.OIDC_PROVIDER != "azure":
        return None
    return (
        claims.get("preferred_username")  # Azure AD
        or claims.get("upn")  # Azure AD (UPN)
        or claims.get("unique_name")  # Azure AD (legacy)
    )


async def sync_person(
    db: Session, claims: dict, email: str, token: Optional[str] = None
) -> Optional[User]:
    """Find or create the person ``email`` names, and update their name and admin flag.

    People are found by their verified email. Their username comes from
    USER_ID_CLAIM, so the gateway can name people the way Gravitino does.
    Admins are the people in ADMIN_EMAILS and, with GRAVITINO_URI set,
    Gravitino's service admins, checked with ``token``. Returns None for an
    email that a service account is registered under, or a deactivated account.
    """
    try:
        return await _sync_person(db, claims, email, token)
    except IntegrityError:
        # A concurrent sign-in created this person or took the name; start again.
        db.rollback()
        return await _sync_person(db, claims, email, token)


async def _sync_person(
    db: Session, claims: dict, email: str, token: Optional[str]
) -> Optional[User]:
    user = db.query(User).filter(User.email == email).first()
    if user is not None and user.email != email:
        # MySQL's collation finds an email that differs in case or accents;
        # creating the person then fails on the unique email, so no one signs in.
        user = None
    if user is not None and user.is_service_account:
        # A person must not take over a service account's row, name or rights.
        logger.warning("Refused a sign-in as %s, a service account", email)
        return None
    if user is not None and not user.is_active:
        return None
    username = _username_for(db, claims, email, user)
    if user is None:
        user = User(
            username=username,
            email=email,
            full_name=claims.get("name")
            or claims.get("given_name")
            or email.split("@")[0],
            is_admin=email in settings.admin_emails,
            is_service_account=False,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info("Created user %s", email)

    is_admin = email in settings.admin_emails or await is_gravitino_service_admin(
        db, user, token
    )
    if user.username == username and user.is_admin == is_admin:
        return user
    if user.is_admin != is_admin:
        logger.info("Set is_admin=%s for %s", is_admin, email)
    user.username = username
    user.is_admin = is_admin
    db.commit()
    return user


def _username_for(db: Session, claims: dict, email: str, user: Optional[User]) -> str:
    """The person's username: the USER_ID_CLAIM value, unique among accounts.

    A token without the claim keeps the current name, since ID tokens and
    access tokens can carry different claims. A name another account holds
    falls back to the email, and then to the email with a number.
    """
    claimed = claims.get(settings.USER_ID_CLAIM)
    if isinstance(claimed, str) and claimed.strip():
        # Other claims keep their case, as Gravitino reads them.
        wanted = claimed.strip()
        if settings.USER_ID_CLAIM == "email":
            wanted = wanted.lower()
    elif user is not None:
        return user.username
    else:
        wanted = email
    if not _username_taken(db, wanted, email):
        return wanted
    candidate, number = email, 2
    while _username_taken(db, candidate, email):
        candidate, number = f"{email}#{number}", number + 1
    if user is None or user.username != candidate:
        logger.warning(
            "%s %r of %s belongs to another account; naming them %r",
            settings.USER_ID_CLAIM,
            wanted,
            email,
            candidate,
        )
    return candidate


def _username_taken(db: Session, username: str, email: str) -> bool:
    """Whether an account other than ``email``'s has ``username``."""
    return (
        db.query(User.id).filter(User.username == username, User.email != email).first()
        is not None
    )


async def get_user_from_bearer_token(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    request: Request = None,
    db: Session = Depends(get_db),
) -> User:
    """
    The caller a bearer token names: a person, with a token from the gateway's
    identity provider, or a registered service account, with its workload
    identity token and the headers in SERVICE_ACCOUNT_REQUIRED_HEADERS.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header format. Use: Bearer <token>",
        )

    token = authorization.replace("Bearer ", "").strip()

    if not token:
        raise HTTPException(status_code=401, detail="Token is empty")

    # Validate OIDC JWT (handles both human users and service accounts)
    if token.startswith("ey"):  # JWT tokens start with "ey"
        user = await _validate_oidc_jwt(token, db, request)
        if user:
            return user

    raise HTTPException(
        status_code=401,
        detail="Invalid or expired token. Please run: gravitino-mcp login",
    )


async def require_admin(user: User = Depends(get_user_from_bearer_token)) -> User:
    """The caller of an admin endpoint, who must be a gateway admin.

    Like the rest of the API, admin endpoints take only bearer tokens; the
    session cookie is for the gateway's own pages.
    """
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


def _extract_eks_iss_id(issuer: str) -> Optional[str]:
    """The cluster ID of an Amazon EKS OIDC issuer, in lower case, or None."""
    match = _EKS_ISSUER.match(issuer or "")
    return match.group(1).lower() if match else None


def _aws_service_account_identities(
    namespace: str, sa_name: str, issuer: str
) -> list[str]:
    """Candidate service_account_name values, most specific first."""
    legacy = f"{namespace}::{sa_name}"
    iss_id = _extract_eks_iss_id(issuer)
    if iss_id:
        return [f"{namespace}::{sa_name}::{iss_id}", legacy]
    return [legacy]


def _lookup_aws_service_account(
    db: Session, identities: list[str]
) -> Optional[ServiceAccountCredentials]:
    """The registration of the first identity that has one, or None.

    Every cluster has the same namespaces, so a ``namespace::name``
    registration counts only with ``additional_config.iss`` pinning one."""
    for identity in identities:
        identity_norm = identity.strip().lower()
        sa_cred = (
            db.query(ServiceAccountCredentials)
            .filter(
                func.lower(ServiceAccountCredentials.service_account_name)
                == identity_norm
            )
            .first()
        )
        if not sa_cred:
            continue
        pinned = (sa_cred.additional_config or {}).get("iss")
        if identity.count("::") == 1 and not (
            isinstance(pinned, str) and pinned.strip()
        ):
            logger.warning(
                "Service account %s names no cluster and pins no issuer", identity
            )
            return None
        return sa_cred
    return None


def _is_registered_service_account(db: Session, email_claim) -> bool:
    """Whether a token's email claim names a registered service account."""
    if not isinstance(email_claim, str) or not email_claim.strip():
        return False
    return (
        db.query(ServiceAccountCredentials.id)
        .filter(
            func.lower(ServiceAccountCredentials.service_account_name)
            == email_claim.strip().lower()
        )
        .first()
        is not None
    )


async def _is_human_token(
    db: Session, client_id: str, issuer: str, unverified_claims: dict
) -> bool:
    """Whether a token takes the human path rather than the service-account path."""
    if client_id in settings.gateway_oauth_client_ids:
        return True
    if not settings.GATEWAY_OAUTH_ACCEPT_ANY_CLIENT:
        return False
    if issuer != await run_in_threadpool(get_configured_issuer):
        return False
    # Workload identities can come from the same provider (for example Google),
    # so a registered service account keeps the service-account path.
    return not _is_registered_service_account(db, unverified_claims.get("email"))


async def _validate_oidc_jwt(
    token: str, db: Session, request: Request
) -> Optional[User]:
    """The person or service account a token names, or None if it names no one.

    The claims are read unverified only to choose a path; each path verifies the
    token's signature, issuer, audience and expiry before it trusts any claim.
    Every refusal looks the same to the caller, so tokens can't be used to find
    out which service accounts are registered.
    """
    triage = _triage(token)
    if triage is None:
        return None
    claims, issuer, cluster_id, client_id = triage
    try:
        if await _is_human_token(db, client_id, issuer, claims):
            return await _validate_human_user_jwt(token, issuer, db, request)
        return await _validate_service_account_jwt(
            token, claims, issuer, cluster_id, db, request
        )
    except HTTPException:
        raise
    except jwt.PyJWTError as e:
        # Including keys the issuer doesn't publish: anyone can send such a token.
        logger.info("Refused a token: %s", e)
        return None
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("Error validating a token")
        return None


def _triage(token: str) -> Optional[tuple]:
    """A token's unverified claims, issuer, EKS cluster ID and client, or None."""
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.InvalidTokenError:
        return None
    issuer = claims.get("iss")
    if not isinstance(issuer, str) or not issuer:
        return None
    cluster_id = _extract_eks_iss_id(issuer)
    # EKS tokens name the workload in sub; other providers name the client.
    client_id = (
        claims.get("sub")
        if cluster_id
        else (
            claims.get("appid")  # Entra ID
            or claims.get("azp")
            or claims.get("client_id")
            or claims.get("cid")  # Okta
        )
    )
    if not client_id:
        return None
    return claims, issuer, cluster_id, client_id


async def _validate_service_account_jwt(  # pylint: disable=too-many-arguments
    token: str,
    claims: dict,
    issuer: str,
    cluster_id: Optional[str],
    db: Session,
    request: Request,
) -> Optional[User]:
    """The registered service account a workload identity token names, or None."""
    sa_cred = _service_account_registration(db, claims, cluster_id)
    if sa_cred is None or not _resolve_service_account_trusted_issuer(issuer, sa_cred):
        return None
    jwks_uri = await _service_account_jwks_uri(sa_cred, issuer)
    if not jwks_uri:
        logger.error("Could not find the signing keys of issuer %s", issuer)
        return None
    decoded = await _verified_claims(
        token,
        jwks_uri,
        algorithms=["RS256", "RS384", "RS512"],
        issuer=issuer,
        audience=settings.service_account_audiences,
    )
    # A registration matches the email, which must be one the issuer checked.
    if cluster_id is None and not _is_true(decoded.get("email_verified")):
        return None

    service_account = (
        db.query(User)
        .filter(User.id == sa_cred.service_account_id, User.is_active.is_(True))
        .first()
    )
    if service_account is None or request is None:
        return None

    _require_service_account_workload_headers(request)
    # Its workload headers are forwarded to MCP servers and written to the audit log.
    request.state.is_service_account = True
    logger.info("Service account %s authenticated", service_account.username)
    return service_account


def _service_account_registration(
    db: Session, claims: dict, cluster_id: Optional[str]
) -> Optional[ServiceAccountCredentials]:
    """The registration that an unverified token's identity claims name, or None.

    GCP tokens name the service account's email; EKS tokens name the
    Kubernetes service account and, in the issuer, the cluster.
    """
    email = claims.get("email")
    if isinstance(email, str) and email.strip():
        return (
            db.query(ServiceAccountCredentials)
            .filter(
                func.lower(ServiceAccountCredentials.service_account_name)
                == email.strip().lower()
            )
            .first()
        )
    kubernetes = claims.get("kubernetes.io")
    if cluster_id is None or not isinstance(kubernetes, dict):
        return None
    account = kubernetes.get("serviceaccount")
    namespace = kubernetes.get("namespace")
    name = account.get("name") if isinstance(account, dict) else None
    if not isinstance(namespace, str) or not isinstance(name, str):
        return None
    return _lookup_aws_service_account(
        db, _aws_service_account_identities(namespace, name, claims["iss"])
    )


async def _service_account_jwks_uri(
    sa_cred: ServiceAccountCredentials, issuer: str
) -> Optional[str]:
    """Where the signing keys of a service account's issuer are."""
    pinned = (sa_cred.additional_config or {}).get("jwks_uri")
    if pinned:
        return pinned
    return settings.trusted_issuer_jwks_map().get(issuer) or await _discover_jwks_uri(
        issuer, allowed_issuers=_service_account_trusted_issuers(sa_cred)
    )


async def _verified_claims(
    token: str, jwks_uri: str, *, algorithms: list, issuer: str, audience
) -> dict:
    """The claims of ``token`` once its signature, issuer, audience and expiry check out."""
    # The key fetch is synchronous, so it runs in a worker thread.
    signing_key = await run_in_threadpool(
        _get_signing_key_with_retry, _get_jwks_client(jwks_uri), token
    )
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=algorithms,
        issuer=issuer,
        audience=audience,
        # Without an expiry a stolen token would work for ever.
        options={"require": ["exp"]},
        # The provider's clock and the gateway's may differ by a little.
        leeway=JWT_LEEWAY_SECONDS,
    )


def _is_true(value) -> bool:
    return value is True or str(value).lower() == "true"


# Each issuer's JWKS URI, from its discovery document: issuer -> (uri, when).
_jwks_uri_cache: dict[str, tuple[str, float]] = {}


def _eks_oidc_jwks_uri(issuer: str) -> Optional[str]:
    """Return the public JWKS URL for an Amazon EKS cluster OIDC issuer."""
    if _extract_eks_iss_id(issuer) is None:
        return None
    return f"{issuer.rstrip('/')}/keys"


async def _discover_jwks_uri(  # pylint: disable=too-many-locals
    issuer: str, *, allowed_issuers: frozenset[str]
) -> Optional[str]:
    """
    Discover JWKS URI from an already-trusted issuer's discovery document.

    ``issuer`` must be present in ``allowed_issuers``; untrusted issuers are
    rejected without making a network request.
    """
    if issuer not in allowed_issuers:
        logger.warning("Refusing JWKS discovery for untrusted issuer: %s", issuer)
        return None

    now = time.monotonic()

    cached = _jwks_uri_cache.get(issuer)
    if cached:
        uri, ts = cached
        if now - ts < settings.OIDC_DISCOVERY_CACHE_TTL:
            return uri

    discovery_urls = [
        f"{issuer.rstrip('/')}/.well-known/openid-configuration",
        f"{issuer.rstrip('/')}/.well-known/oauth-authorization-server",
    ]

    async with httpx.AsyncClient(timeout=settings.OIDC_HTTP_TIMEOUT) as client:
        for url in discovery_urls:
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    config = response.json()
                    jwks_uri = config.get("jwks_uri")
                    if jwks_uri:
                        logger.info("Discovered JWKS URI from %s: %s", url, jwks_uri)
                        _jwks_uri_cache[issuer] = (jwks_uri, now)
                        return jwks_uri
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.debug("Failed to fetch discovery from %s: %s", url, e)
                continue

    # Entra ID and EKS publish their keys at known places.
    known = _ENTRA_ISSUER.match(issuer)
    jwks_uri = (
        f"https://login.microsoftonline.com/{known.group(1)}/discovery/v2.0/keys"
        if known
        else _eks_oidc_jwks_uri(issuer)
    )
    if jwks_uri:
        logger.info("Using the known key endpoint of %s: %s", issuer, jwks_uri)
        _jwks_uri_cache[issuer] = (jwks_uri, now)
        return jwks_uri

    logger.warning("Could not discover JWKS URI for issuer: %s", issuer)
    return None


async def _validate_human_user_jwt(
    token: str,
    issuer: str,
    db: Session,
    request: Request,
) -> Optional[User]:
    """The person a token from the gateway's identity provider names, or None."""
    # The issuer may come from the discovery document, whose first fetch
    # blocks, so it is resolved in a worker thread.
    configured_issuer = await run_in_threadpool(get_configured_issuer)
    if not configured_issuer:
        logger.error("Signing people in needs OIDC_ISSUER or OIDC_DISCOVERY_URL")
        return None
    if issuer != configured_issuer:
        return None

    jwks_uri = (settings.OIDC_JWKS_URI or "").strip() or await _discover_jwks_uri(
        configured_issuer, allowed_issuers=frozenset({configured_issuer})
    )
    if not jwks_uri:
        logger.error("Could not find the signing keys of issuer %s", configured_issuer)
        return None
    decoded = await _verified_claims(
        token,
        jwks_uri,
        algorithms=["RS256"],
        issuer=configured_issuer,
        audience=settings.JWT_AUDIENCE,
    )

    email = _person_email(decoded)
    user = await sync_person(db, decoded, email, token) if email else None
    if user is None:
        return None

    if request:
        request.state.bearer_token = token  # For token exchange.
    logger.debug("%s authenticated", user.email)
    return user


def _person_email(claims: dict) -> Optional[str]:
    """The email, in lower case, of the person verified claims name, or None."""
    email = email_from_claims(claims)
    if not email:
        logger.warning(
            "A token has no verified email or account name (tried: email, "
            "preferred_username, upn, unique_name)"
        )
        return None
    if email.lower().endswith(_WORKLOAD_EMAIL_DOMAIN):
        # Any Google service account can get a token for any audience, so one
        # that isn't registered must not become a person.
        logger.warning("Refused a person's sign-in as the workload %s", email)
        return None
    return email.lower()
