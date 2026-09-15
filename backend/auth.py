import hashlib
import hmac
import os
import time
from urllib.parse import urlparse

import jwt
import requests
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import get_db

load_dotenv()

NEON_AUTH_URL = os.environ["NEON_AUTH_URL"]
INGEST_API_KEY = os.environ.get("INGEST_API_KEY")
_AUTH_ORIGIN = urlparse(NEON_AUTH_URL)
AUTH_ISSUER = f"{_AUTH_ORIGIN.scheme}://{_AUTH_ORIGIN.netloc}"
JWKS_URL = f"{NEON_AUTH_URL}/.well-known/jwks.json"

_jwks_cache: dict = {"keys": {}, "fetched_at": 0.0}
JWKS_TTL_SECONDS = 300


def _get_signing_key(kid: str):
    now = time.time()
    if kid not in _jwks_cache["keys"] or now - _jwks_cache["fetched_at"] > JWKS_TTL_SECONDS:
        resp = requests.get(JWKS_URL, timeout=5)
        resp.raise_for_status()
        client = jwt.PyJWKClient(JWKS_URL)
        _jwks_cache["client"] = client
        _jwks_cache["fetched_at"] = now
        _jwks_cache["keys"] = {k["kid"]: True for k in resp.json()["keys"]}

    if kid not in _jwks_cache["keys"]:
        raise HTTPException(status_code=401, detail="Unknown signing key")
    return _jwks_cache["client"].get_signing_key(kid)


class CurrentUser:
    def __init__(self, id: str, email: str, role: str):
        self.id = id
        self.email = email
        self.role = role


def get_current_user(request: Request, db: Session = Depends(get_db)) -> CurrentUser:
    authorization = request.headers.get("authorization", "")
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1]

    try:
        unverified_header = jwt.get_unverified_header(token)
        signing_key = _get_signing_key(unverified_header["kid"])
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["EdDSA"],
            issuer=AUTH_ISSUER,
            audience=AUTH_ISSUER,
        )
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    user_id = payload["sub"]
    row = db.execute(
        text('SELECT email, role, banned FROM neon_auth."user" WHERE id = :id'),
        {"id": user_id},
    ).first()
    if row is None:
        raise HTTPException(status_code=401, detail="User not found")
    if row.banned:
        # Enforced here rather than relying solely on Neon Auth's own ban
        # plugin (unconfirmed whether it's active for this project) — a
        # suspended user's existing, still-valid JWT must stop working
        # against our API regardless of what Neon Auth itself does with it.
        raise HTTPException(status_code=403, detail="This account has been suspended")

    return CurrentUser(id=user_id, email=row.email, role=row.role)


def resolve_org_for_api_key(db: Session, raw_key: str) -> str | None:
    """Hashes a raw per-org API key and resolves it to an organization id —
    shared by require_ingest_key (HTTP) and the syslog listener's optional
    embedded-key routing (backend/syslog_server.py), so both ingest paths
    trust the exact same real, hashed-at-rest key store (models.ApiKey).
    Returns None for an unknown key; raises 401 for a *revoked* one, since a
    revoked key was once valid and its holder should get an explicit signal
    rather than silent misrouting — callers that want silent fallback (the
    syslog path, which can't 401 a UDP sender) should catch that themselves."""
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    row = db.execute(
        text("SELECT organization_id, revoked FROM api_keys WHERE key_hash = :h"),
        {"h": key_hash},
    ).first()
    if row is None:
        return None
    if row.revoked:
        raise HTTPException(status_code=401, detail="This API key has been revoked")
    db.execute(text("UPDATE api_keys SET last_used_at = now() WHERE key_hash = :h"), {"h": key_hash})
    db.commit()
    return str(row.organization_id)


def require_ingest_key(request: Request, db: Session = Depends(get_db)) -> str:
    """Authenticates POST /events/ingest and resolves which organization the
    ingested event belongs to. Real per-org keys (backend/scripts or the
    Settings > Organization > API Keys UI, hashed at rest — see models.ApiKey)
    take priority; INGEST_API_KEY is kept only as a legacy single shared key
    for whoever set one up before per-org keys existed, and always resolves
    to the bootstrap default org."""
    provided = request.headers.get("x-api-key", "")
    if not provided:
        raise HTTPException(status_code=401, detail="Missing X-API-Key")

    org_id = resolve_org_for_api_key(db, provided)
    if org_id is not None:
        return org_id

    if INGEST_API_KEY and hmac.compare_digest(provided, INGEST_API_KEY):
        org_row = db.execute(text("SELECT id FROM neon_auth.organization WHERE slug = 'default'")).first()
        if org_row is None:
            raise HTTPException(
                status_code=503,
                detail="No default organization provisioned — run `python scripts/migrate_to_organizations.py`.",
            )
        return str(org_row.id)

    raise HTTPException(status_code=401, detail="Invalid X-API-Key")


def require_role(*roles: str):
    def dependency(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return dependency


class OrgMember:
    """The caller's identity plus which organization they're acting in and
    their role within it. Org membership lives in Neon Auth's own tables
    (neon_auth.member, provisioned by Better Auth's real `organization`
    plugin) — we only read it here, all writes (create org, invite, accept,
    setActive) happen client-side through the real Better Auth client."""

    def __init__(self, user: CurrentUser, org_id: str, org_role: str):
        self.user = user
        self.org_id = org_id
        self.org_role = org_role


def require_org_member(
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> OrgMember:
    org_id = request.headers.get("x-organization-id")
    if not org_id:
        raise HTTPException(status_code=400, detail="Missing X-Organization-Id header")

    row = db.execute(
        text('SELECT role FROM neon_auth.member WHERE "organizationId" = :org_id AND "userId" = :user_id'),
        {"org_id": org_id, "user_id": user.id},
    ).first()
    if row is None:
        raise HTTPException(status_code=403, detail="Not a member of this organization")

    return OrgMember(user=user, org_id=org_id, org_role=row.role)


def require_org_role(*org_roles: str):
    def dependency(member: OrgMember = Depends(require_org_member)) -> OrgMember:
        if member.org_role not in org_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions within this organization")
        return member

    return dependency
