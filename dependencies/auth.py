# dependencies/auth.py

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from db.mongo import get_tokens_collection

logger = logging.getLogger(__name__)

_bearer_scheme = HTTPBearer(auto_error=True, description="API token (ethikey_...)")


async def validate_api_token(token_string: str) -> Optional[dict]:
    """
    Direct token lookup against the shared api_tokens collection.
    Mirrors the agent backend's dependencies/auth.py exactly.
    """
    if not token_string:
        return None

    try:
        collection = get_tokens_collection()
        token_doc = await collection.find_one({"tokenId": token_string}, {"_id": 0})

        if not token_doc:
            return None
        if not token_doc.get("isActive", False):
            return None

        expires_at_str = token_doc.get("expiresAt")
        if expires_at_str:
            expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expires_at:
                await collection.update_one(
                    {"tokenId": token_string},
                    {"$set": {"isActive": False}},
                )
                return None

        return token_doc

    except Exception as e:
        logger.error(f"Token validation error: {e}", exc_info=True)
        return None


async def get_current_user_id(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
) -> str:
    """
    FastAPI dependency. This is the ONLY source of userId in the entire
    service. Request bodies and path params are never trusted for identity.
    """
    token_doc = await validate_api_token(credentials.credentials)

    if not token_doc:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = token_doc.get("userId")
    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scopes = token_doc.get("scopes") or []
    if "aida:blocked" in scopes or token_doc.get("status") == "blocked":
        raise HTTPException(status_code=403, detail="Account suspended.")

    return user_id