"""
API key authentication middleware and key management.
"""

import hashlib
import logging
import os
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .db import get_db, ApiKey

logger = logging.getLogger(__name__)

# In-memory TTL cache for API key lookups
_key_cache: dict[str, tuple[float, dict]] = {}
_cache_ttl: int = 60  # seconds


def _hash_key(api_key: str) -> str:
    """SHA-256 hash an API key."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def _cache_get(key_hash: str) -> Optional[dict]:
    """Get a cached key lookup result."""
    entry = _key_cache.get(key_hash)
    if entry and (time.time() - entry[0]) < _cache_ttl:
        return entry[1]
    if entry:
        del _key_cache[key_hash]
    return None


def _cache_set(key_hash: str, data: dict):
    """Cache a key lookup result."""
    # Evict old entries if cache grows too large
    if len(_key_cache) > 256:
        cutoff = time.time() - _cache_ttl
        to_delete = [k for k, (t, _) in _key_cache.items() if t < cutoff]
        for k in to_delete:
            del _key_cache[k]
    _key_cache[key_hash] = (time.time(), data)


# Paths that skip authentication
SKIP_AUTH_PATHS = {"/", "/health", "/docs", "/openapi.json", "/redoc"}


async def auth_middleware(request: Request, call_next):
    """Validate API key on every request except health/docs."""
    from .config import get_config
    config = get_config()

    # Check if auth is enabled
    if not config.auth_enabled:
        request.state.team_name = "anonymous"
        request.state.api_key_id = None
        return await call_next(request)

    # Skip auth for exempt paths
    if request.url.path in SKIP_AUTH_PATHS:
        return await call_next(request)

    # Read API key from header
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return JSONResponse(
            status_code=401,
            content={"error": "Missing API key", "hint": "Set X-API-Key header"},
        )

    key_hash = _hash_key(api_key)

    # Check cache first
    cached = _cache_get(key_hash)
    if cached:
        if not cached.get("valid"):
            return JSONResponse(
                status_code=403,
                content={"error": "Invalid or expired API key"},
            )
        request.state.team_name = cached["team_name"]
        request.state.api_key_id = cached["id"]
        return await call_next(request)

    # Look up in database
    from .db.session import get_session_factory
    db = get_session_factory()()
    try:
        db_key = db.query(ApiKey).filter(ApiKey.key_hash == key_hash).first()

        if not db_key or not db_key.is_active:
            _cache_set(key_hash, {"valid": False})
            return JSONResponse(
                status_code=403,
                content={"error": "Invalid or expired API key"},
            )

        if db_key.expires_at and db_key.expires_at < datetime.utcnow():
            _cache_set(key_hash, {"valid": False})
            return JSONResponse(
                status_code=403,
                content={"error": "API key has expired"},
            )

        # Update last_used_at (non-blocking, best effort)
        db_key.last_used_at = datetime.utcnow()
        db.commit()

        _cache_set(key_hash, {
            "valid": True,
            "id": db_key.id,
            "team_name": db_key.team_name,
            "is_admin": db_key.is_admin,
        })

        request.state.team_name = db_key.team_name
        request.state.api_key_id = db_key.id
    finally:
        db.close()

    return await call_next(request)


def require_admin(request: Request):
    """FastAPI dependency that requires an admin API key."""
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    key_hash = _hash_key(api_key)
    cached = _cache_get(key_hash)
    if cached and cached.get("valid") and cached.get("is_admin"):
        return cached

    raise HTTPException(status_code=403, detail="Admin API key required")


def seed_admin_key(db: Session, admin_key: Optional[str] = None):
    """Seed an admin API key if none exists."""
    existing = db.query(ApiKey).filter(ApiKey.is_admin == True).first()
    if existing:
        logger.info(f"Admin key already exists (prefix: {existing.key_prefix}...)")
        return

    if not admin_key:
        admin_key = os.environ.get("SYFTER_ADMIN_API_KEY")

    if not admin_key:
        admin_key = secrets.token_hex(32)
        logger.warning(f"No SYFTER_ADMIN_API_KEY set. Generated admin key: {admin_key}")
        logger.warning("Save this key — it will not be shown again.")

    key_hash = _hash_key(admin_key)
    db_key = ApiKey(
        key_hash=key_hash,
        key_prefix=admin_key[:8],
        team_name="admin",
        description="Auto-generated admin key",
        is_admin=True,
    )
    db.add(db_key)
    db.commit()
    logger.info(f"Admin API key seeded (prefix: {admin_key[:8]}...)")


# --- Admin API key management endpoints ---

router = APIRouter(prefix="/admin/keys", tags=["admin"])


class ApiKeyCreateRequest(BaseModel):
    team_name: str = Field(..., description="Team name this key belongs to")
    description: Optional[str] = Field(default=None, description="Key description")
    expires_in_days: Optional[int] = Field(default=None, description="Days until expiration")


class ApiKeyResponse(BaseModel):
    id: int
    key_prefix: str
    team_name: str
    description: Optional[str]
    is_active: bool
    is_admin: bool
    created_at: datetime
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]

    class Config:
        from_attributes = True


class ApiKeyCreatedResponse(ApiKeyResponse):
    api_key: str  # Only returned once on creation


@router.post("/", response_model=ApiKeyCreatedResponse, status_code=201)
def create_api_key(
    body: ApiKeyCreateRequest,
    request: Request,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Create a new API key. Returns the plaintext key exactly once."""
    api_key = secrets.token_hex(32)
    key_hash = _hash_key(api_key)

    expires_at = None
    if body.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=body.expires_in_days)

    db_key = ApiKey(
        key_hash=key_hash,
        key_prefix=api_key[:8],
        team_name=body.team_name,
        description=body.description,
        expires_at=expires_at,
    )
    db.add(db_key)
    db.commit()
    db.refresh(db_key)

    return ApiKeyCreatedResponse(
        id=db_key.id,
        key_prefix=db_key.key_prefix,
        team_name=db_key.team_name,
        description=db_key.description,
        is_active=db_key.is_active,
        is_admin=db_key.is_admin,
        created_at=db_key.created_at,
        last_used_at=db_key.last_used_at,
        expires_at=db_key.expires_at,
        api_key=api_key,
    )


@router.get("/", response_model=list[ApiKeyResponse])
def list_api_keys(
    request: Request,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    """List all API keys (metadata only, no plaintext)."""
    keys = db.query(ApiKey).order_by(ApiKey.created_at).all()
    return [
        ApiKeyResponse(
            id=k.id,
            key_prefix=k.key_prefix,
            team_name=k.team_name,
            description=k.description,
            is_active=k.is_active,
            is_admin=k.is_admin,
            created_at=k.created_at,
            last_used_at=k.last_used_at,
            expires_at=k.expires_at,
        )
        for k in keys
    ]


@router.delete("/{key_id}", status_code=204)
def revoke_api_key(
    key_id: int,
    request: Request,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Revoke (deactivate) an API key."""
    db_key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not db_key:
        raise HTTPException(status_code=404, detail="API key not found")

    db_key.is_active = False
    db.commit()

    # Invalidate cache
    _key_cache.clear()
