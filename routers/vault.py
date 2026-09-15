# routers/vault.py

import base64
import binascii
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator, model_validator

from apis.vault_maintenance import (
    expire_reservation,
    release_pending_bytes,
    sweep_expired_reservations_for_user,
    utc_now_iso,
)
from apis.vault_storage import get_vault_storage
from db.mongo import (
    get_vault_profiles_collection,
    get_vault_reservations_collection,
    get_vault_usage_collection,
)
from dependencies.auth import get_current_user_id
from dependencies.rate_limit import (
    SlidingWindowRateLimiter,
    commit_limiter,
    presign_limiter,
)

router = APIRouter()
logger = logging.getLogger(__name__)

# ────────────────────────────── Config ──────────────────────────────

DEFAULT_QUOTA_BYTES = int(os.getenv("VAULT_DEFAULT_QUOTA_BYTES", str(500 * 1024 * 1024)))
MAX_SNAPSHOT_BYTES = int(os.getenv("VAULT_MAX_SNAPSHOT_BYTES", str(50 * 1024 * 1024)))
# CHANGED: The frontend treats one appId as one vault. The backend still
# supports multiple profiles in general, but only one per (user, appId).
MAX_PROFILES_PER_USER = int(os.getenv("VAULT_MAX_PROFILES_PER_USER", "10"))
PRESIGN_TTL_SECONDS = int(os.getenv("VAULT_PRESIGN_TTL_SECONDS", "900"))
RESERVATION_TTL_MINUTES = int(os.getenv("VAULT_RESERVATION_TTL_MINUTES", "15"))
SNAPSHOT_HISTORY_KEEP = int(os.getenv("VAULT_SNAPSHOT_HISTORY_KEEP", "2"))
ALLOWED_KDF_ALGOS = {"PBKDF2-SHA256", "ARGON2ID"}

poll_limiter = SlidingWindowRateLimiter(
    int(os.getenv("VAULT_RATE_LIMIT_POLL_PER_HOUR", "360")), 3600
)

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


# ────────────────────────────── Schemas ─────────────────────────────

def _validate_b64(value: str) -> str:
    try:
        base64.b64decode(value.encode("utf-8"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        raise ValueError("must be valid base64")
    return value


class KdfParams(BaseModel):
    algo: str = Field(min_length=1, max_length=64)
    iterations: int = Field(ge=10_000, le=5_000_000)
    salt: str = Field(min_length=8, max_length=128)

    @field_validator("algo")
    @classmethod
    def _algo_allowed(cls, v):
        if v not in ALLOWED_KDF_ALGOS:
            raise ValueError(f"algo must be one of {sorted(ALLOWED_KDF_ALGOS)}")
        return v

    @field_validator("salt")
    @classmethod
    def _salt_b64(cls, v):
        return _validate_b64(v)


class ProfileCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    appId: str = Field(default="fractant", min_length=1, max_length=64)
    kdf: KdfParams
    wrappedDek: str = Field(min_length=16, max_length=4096)
    wrappedDekRecovery: Optional[str] = Field(default=None, min_length=16, max_length=4096)
    verifier: str = Field(min_length=16, max_length=4096)

    @field_validator("wrappedDek", "verifier")
    @classmethod
    def _b64_fields(cls, v):
        return _validate_b64(v)

    @field_validator("wrappedDekRecovery")
    @classmethod
    def _b64_optional(cls, v):
        return _validate_b64(v) if v is not None else v

    @field_validator("appId")
    @classmethod
    def _appid_safe(cls, v):
        if not re.fullmatch(r"[a-z0-9-]+", v):
            raise ValueError("appId must be lowercase alphanumeric with dashes")
        return v


class ProfileUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    kdf: Optional[KdfParams] = None
    wrappedDek: Optional[str] = Field(default=None, min_length=16, max_length=4096)
    wrappedDekRecovery: Optional[str] = Field(default=None, min_length=16, max_length=4096)
    verifier: Optional[str] = Field(default=None, min_length=16, max_length=4096)

    @field_validator("wrappedDek", "wrappedDekRecovery", "verifier")
    @classmethod
    def _b64_fields(cls, v):
        return _validate_b64(v) if v is not None else v

    @model_validator(mode="after")
    def _rotation_fields_together(self):
        rotation = [self.kdf, self.wrappedDek, self.verifier]
        if any(f is not None for f in rotation) and not all(f is not None for f in rotation):
            raise ValueError(
                "kdf, wrappedDek and verifier must be provided together for a password change"
            )
        return self


class PresignRequest(BaseModel):
    sizeBytes: int = Field(ge=1)
    baseVersion: int = Field(ge=0)


class CommitRequest(BaseModel):
    reservationId: str = Field(min_length=1, max_length=128)
    baseVersion: int = Field(ge=0)
    deviceLabel: Optional[str] = Field(default=None, max_length=120)


# ────────────────────────────── Helpers ─────────────────────────────

async def _get_owned_profile(profile_id: str, user_id: str) -> dict:
    if not _ID_RE.match(profile_id):
        raise HTTPException(status_code=404, detail="Profile not found")

    profile = await get_vault_profiles_collection().find_one(
        {"profileId": profile_id, "userId": user_id},
        {"_id": 0},
    )
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


async def _get_or_create_usage(user_id: str) -> dict:
    usage = get_vault_usage_collection()
    doc = await usage.find_one({"userId": user_id})
    if doc:
        return doc

    now = utc_now_iso()
    new_doc = {
        "userId": user_id,
        "usedBytes": 0,
        "pendingBytes": 0,
        "quotaBytes": DEFAULT_QUOTA_BYTES,
        "createdAt": now,
        "updatedAt": now,
    }
    try:
        await usage.insert_one(new_doc)
        return new_doc
    except Exception:
        doc = await usage.find_one({"userId": user_id})
        if doc:
            return doc
        raise


async def _cancel_reservation(reservation: dict, user_id: str) -> None:
    reservations = get_vault_reservations_collection()
    result = await reservations.update_one(
        {"reservationId": reservation["reservationId"], "status": "pending"},
        {"$set": {"status": "cancelled", "cancelledAt": utc_now_iso()}},
    )
    if result.modified_count == 1:
        await release_pending_bytes(user_id, int(reservation.get("sizeBytes", 0)))
        try:
            await get_vault_storage().delete_object(reservation["blobKey"])
        except Exception:
            pass


# ────────────────────────── Profile registry ────────────────────────

@router.post("/profiles", status_code=201)
async def create_profile(
    body: ProfileCreateRequest,
    user_id: str = Depends(get_current_user_id),
):
    profiles = get_vault_profiles_collection()

    # CHANGED: Enforce one vault per (user, appId). The frontend sends
    # appId="aida" and expects a single vault. If one already exists,
    # return 409 so the frontend can adopt it instead of creating a second.
    existing = await profiles.find_one(
        {"userId": user_id, "appId": body.appId},
        {"_id": 0, "profileId": 1},
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "vault_already_exists",
                "profileId": existing["profileId"],
            },
        )

    count = await profiles.count_documents({"userId": user_id})
    if count >= MAX_PROFILES_PER_USER:
        raise HTTPException(
            status_code=403,
            detail={"error": "profile_limit_reached", "maxProfiles": MAX_PROFILES_PER_USER},
        )

    now = utc_now_iso()
    doc = {
        "profileId": "prof_" + uuid.uuid4().hex,
        "userId": user_id,
        "appId": body.appId,
        "name": body.name,
        "kdf": body.kdf.model_dump(),
        "wrappedDek": body.wrappedDek,
        "wrappedDekRecovery": body.wrappedDekRecovery,
        "verifier": body.verifier,
        "snapshot": {"version": 0, "sizeBytes": 0, "updatedAt": None, "blobKey": None, "deviceLabel": None},
        "snapshotHistory": [],
        "createdAt": now,
        "updatedAt": now,
    }
    await profiles.insert_one(doc)
    doc.pop("_id", None)
    return {"success": True, "data": doc}


@router.get("/profiles")
async def list_profiles(
    appId: Optional[str] = None,
    user_id: str = Depends(get_current_user_id),
):
    query: dict = {"userId": user_id}
    if appId:
        query["appId"] = appId

    cursor = get_vault_profiles_collection().find(query, {"_id": 0})
    items = [doc async for doc in cursor]
    items.sort(key=lambda d: d.get("createdAt") or "")
    return {"success": True, "data": items, "count": len(items)}


@router.get("/profiles/{profile_id}")
async def get_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
):
    profile = await _get_owned_profile(profile_id, user_id)
    return {"success": True, "data": profile}


@router.patch("/profiles/{profile_id}")
async def update_profile(
    profile_id: str,
    body: ProfileUpdateRequest,
    user_id: str = Depends(get_current_user_id),
):
    await _get_owned_profile(profile_id, user_id)

    updates: dict = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.kdf is not None:
        updates["kdf"] = body.kdf.model_dump()
        updates["wrappedDek"] = body.wrappedDek
        updates["verifier"] = body.verifier
    # CHANGED: Only update wrappedDekRecovery when it is explicitly sent.
    # The frontend password-change flow does not rotate the recovery key,
    # so sending kdf+wrappedDek+verifier must not erase it.
    if body.wrappedDekRecovery is not None:
        updates["wrappedDekRecovery"] = body.wrappedDekRecovery

    if not updates:
        raise HTTPException(status_code=400, detail="No valid fields to update")

    updates["updatedAt"] = utc_now_iso()
    await get_vault_profiles_collection().update_one(
        {"profileId": profile_id, "userId": user_id},
        {"$set": updates},
    )
    fresh = await _get_owned_profile(profile_id, user_id)
    return {"success": True, "data": fresh}


@router.delete("/profiles/{profile_id}")
async def delete_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
):
    profile = await _get_owned_profile(profile_id, user_id)
    snapshot = profile.get("snapshot") or {}
    history = profile.get("snapshotHistory") or []

    storage = get_vault_storage()
    total_bytes = int(snapshot.get("sizeBytes", 0) or 0)

    if snapshot.get("blobKey"):
        await storage.delete_object(snapshot["blobKey"])
    for entry in history:
        total_bytes += int(entry.get("sizeBytes", 0) or 0)
        if entry.get("blobKey"):
            await storage.delete_object(entry["blobKey"])

    reservations = get_vault_reservations_collection()
    pending_cursor = reservations.find(
        {"profileId": profile_id, "userId": user_id, "status": "pending"}
    )
    async for r in pending_cursor:
        await _cancel_reservation(r, user_id)

    await get_vault_profiles_collection().delete_one(
        {"profileId": profile_id, "userId": user_id}
    )

    if total_bytes > 0:
        usage = get_vault_usage_collection()
        await usage.update_one(
            {"userId": user_id},
            {"$inc": {"usedBytes": -total_bytes}, "$set": {"updatedAt": utc_now_iso()}},
        )
        await usage.update_one(
            {"userId": user_id, "usedBytes": {"$lt": 0}},
            {"$set": {"usedBytes": 0}},
        )

    return {"success": True, "message": "Profile deleted"}


# ────────────────────────── Snapshot sync ───────────────────────────

@router.get("/profiles/{profile_id}/snapshot/meta")
async def get_snapshot_meta(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
):
    poll_limiter.check(user_id)
    profile = await _get_owned_profile(profile_id, user_id)
    s = profile.get("snapshot") or {}
    return {
        "success": True,
        "data": {
            "profileId": profile_id,
            "version": int(s.get("version", 0)),
            "sizeBytes": int(s.get("sizeBytes", 0) or 0),
            "updatedAt": s.get("updatedAt"),
            "deviceLabel": s.get("deviceLabel"),
        },
    }


@router.post("/profiles/{profile_id}/snapshot/presign")
async def presign_snapshot_upload(
    profile_id: str,
    body: PresignRequest,
    user_id: str = Depends(get_current_user_id),
):
    presign_limiter.check(user_id)
    profile = await _get_owned_profile(profile_id, user_id)

    if body.sizeBytes > MAX_SNAPSHOT_BYTES:
        raise HTTPException(
            status_code=413,
            detail={"error": "snapshot_too_large", "maxSnapshotBytes": MAX_SNAPSHOT_BYTES},
        )

    snapshot = profile.get("snapshot") or {}
    current_version = int(snapshot.get("version", 0))
    old_size = int(snapshot.get("sizeBytes", 0) or 0)

    if body.baseVersion != current_version:
        raise HTTPException(
            status_code=409,
            detail={"error": "version_conflict", "currentVersion": current_version},
        )

    await sweep_expired_reservations_for_user(user_id)

    usage_doc = await _get_or_create_usage(user_id)
    used = int(usage_doc.get("usedBytes", 0))
    pending = int(usage_doc.get("pendingBytes", 0))
    quota = int(usage_doc.get("quotaBytes", DEFAULT_QUOTA_BYTES))

    projected = used - old_size + pending + body.sizeBytes
    if projected > quota:
        raise HTTPException(
            status_code=413,
            detail={
                "error": "quota_exceeded",
                "usedBytes": used,
                "pendingBytes": pending,
                "quotaBytes": quota,
            },
        )

    storage = get_vault_storage()
    reservation_id = "rsv_" + uuid.uuid4().hex
    blob_key = storage.build_blob_key(user_id, profile_id, reservation_id)
    now = utc_now_iso()
    expires_at = (
        datetime.now(timezone.utc) + timedelta(minutes=RESERVATION_TTL_MINUTES)
    ).isoformat()

    await get_vault_reservations_collection().insert_one(
        {
            "reservationId": reservation_id,
            "userId": user_id,
            "profileId": profile_id,
            "sizeBytes": body.sizeBytes,
            "blobKey": blob_key,
            "status": "pending",
            "createdAt": now,
            "expiresAt": expires_at,
        }
    )
    await get_vault_usage_collection().update_one(
        {"userId": user_id},
        {"$inc": {"pendingBytes": body.sizeBytes}, "$set": {"updatedAt": now}},
    )

    usage_after = await get_vault_usage_collection().find_one({"userId": user_id})
    if usage_after:
        projected_after = (
            int(usage_after.get("usedBytes", 0))
            - old_size
            + int(usage_after.get("pendingBytes", 0))
        )
        if projected_after > quota:
            await _cancel_reservation(
                {"reservationId": reservation_id, "sizeBytes": body.sizeBytes, "blobKey": blob_key},
                user_id,
            )
            raise HTTPException(
                status_code=413,
                detail={
                    "error": "quota_exceeded",
                    "usedBytes": used,
                    "pendingBytes": pending,
                    "quotaBytes": quota,
                },
            )

    upload_url = await storage.presign_put(blob_key, PRESIGN_TTL_SECONDS)

    return {
        "success": True,
        "data": {
            "reservationId": reservation_id,
            "uploadUrl": upload_url,
            "expiresAt": expires_at,
        },
    }


@router.post("/profiles/{profile_id}/snapshot/commit")
async def commit_snapshot_upload(
    profile_id: str,
    body: CommitRequest,
    user_id: str = Depends(get_current_user_id),
):
    commit_limiter.check(user_id)
    profile = await _get_owned_profile(profile_id, user_id)

    reservations = get_vault_reservations_collection()
    reservation = await reservations.find_one(
        {
            "reservationId": body.reservationId,
            "userId": user_id,
            "profileId": profile_id,
        }
    )
    if not reservation:
        raise HTTPException(status_code=404, detail="Reservation not found")

    now = utc_now_iso()

    if reservation.get("status") != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"Reservation is already {reservation.get('status')}",
        )

    if reservation.get("expiresAt", "") < now:
        released = await expire_reservation(reservation)
        await release_pending_bytes(user_id, released)
        raise HTTPException(
            status_code=410, detail="Upload reservation expired. Please retry."
        )

    snapshot = profile.get("snapshot") or {}
    current_version = int(snapshot.get("version", 0))
    old_size = int(snapshot.get("sizeBytes", 0) or 0)
    old_blob_key = snapshot.get("blobKey")

    if body.baseVersion != current_version:
        await _cancel_reservation(reservation, user_id)
        raise HTTPException(
            status_code=409,
            detail={"error": "version_conflict", "currentVersion": current_version},
        )

    storage = get_vault_storage()

    actual_size = await storage.head_object_size(reservation["blobKey"])
    if actual_size is None:
        raise HTTPException(
            status_code=400,
            detail="Snapshot blob not found in storage. Upload first, then commit.",
        )
    if actual_size != reservation["sizeBytes"]:
        raise HTTPException(
            status_code=400,
            detail="Uploaded size does not match the reserved size. Restart the sync.",
        )

    history = list(profile.get("snapshotHistory") or [])
    if old_blob_key:
        history.insert(
            0,
            {
                "version": current_version,
                "sizeBytes": old_size,
                "updatedAt": snapshot.get("updatedAt"),
                "blobKey": old_blob_key,
                "deviceLabel": snapshot.get("deviceLabel"),
            },
        )
    evicted = history[SNAPSHOT_HISTORY_KEEP:]
    history = history[:SNAPSHOT_HISTORY_KEEP]
    evicted_bytes = sum(int(e.get("sizeBytes", 0) or 0) for e in evicted)

    new_version = current_version + 1
    result = await get_vault_profiles_collection().update_one(
        {
            "profileId": profile_id,
            "userId": user_id,
            "snapshot.version": current_version,
        },
        {
            "$set": {
                "snapshot.version": new_version,
                "snapshot.sizeBytes": reservation["sizeBytes"],
                "snapshot.updatedAt": now,
                "snapshot.blobKey": reservation["blobKey"],
                "snapshot.deviceLabel": body.deviceLabel,
                "snapshotHistory": history,
                "updatedAt": now,
            }
        },
    )
    if result.matched_count == 0:
        fresh = await _get_owned_profile(profile_id, user_id)
        raise HTTPException(
            status_code=409,
            detail={
                "error": "version_conflict",
                "currentVersion": int((fresh.get("snapshot") or {}).get("version", 0)),
            },
        )

    usage = get_vault_usage_collection()
    await usage.update_one(
        {"userId": user_id},
        {
            "$inc": {
                "pendingBytes": -reservation["sizeBytes"],
                "usedBytes": reservation["sizeBytes"] - evicted_bytes,
            },
            "$set": {"updatedAt": now},
        },
        upsert=True,
    )
    await usage.update_one(
        {"userId": user_id, "pendingBytes": {"$lt": 0}},
        {"$set": {"pendingBytes": 0}},
    )

    await reservations.update_one(
        {"reservationId": reservation["reservationId"]},
        {"$set": {"status": "committed", "committedAt": now}},
    )

    for entry in evicted:
        try:
            await storage.delete_object(entry["blobKey"])
        except Exception as e:
            logger.warning(f"Failed to delete evicted history blob: {e}")

    return {
        "success": True,
        "data": {
            "profileId": profile_id,
            "version": new_version,
            "sizeBytes": reservation["sizeBytes"],
            "updatedAt": now,
            "deviceLabel": body.deviceLabel,
        },
    }


@router.get("/profiles/{profile_id}/snapshot")
async def get_snapshot_download(
    profile_id: str,
    version: Optional[int] = None,
    user_id: str = Depends(get_current_user_id),
):
    profile = await _get_owned_profile(profile_id, user_id)
    snapshot = profile.get("snapshot") or {}
    current_version = int(snapshot.get("version", 0))

    if version is None or version == current_version:
        if not snapshot.get("blobKey"):
            raise HTTPException(status_code=404, detail="No snapshot uploaded yet")
        target = {
            "version": current_version,
            "sizeBytes": int(snapshot.get("sizeBytes", 0) or 0),
            "updatedAt": snapshot.get("updatedAt"),
            "blobKey": snapshot["blobKey"],
            "deviceLabel": snapshot.get("deviceLabel"),
        }
    else:
        history = profile.get("snapshotHistory") or []
        target = next((h for h in history if int(h.get("version", -1)) == version), None)
        if not target:
            raise HTTPException(
                status_code=404,
                detail="Requested version is no longer retained",
            )

    download_url = await get_vault_storage().presign_get(
        target["blobKey"], PRESIGN_TTL_SECONDS
    )
    return {
        "success": True,
        "data": {
            "profileId": profile_id,
            "version": target["version"],
            "sizeBytes": target["sizeBytes"],
            "updatedAt": target.get("updatedAt"),
            "deviceLabel": target.get("deviceLabel"),
            "downloadUrl": download_url,
            "expiresIn": PRESIGN_TTL_SECONDS,
        },
    }


# ────────────────────────────── Usage ───────────────────────────────

@router.get("/usage")
async def get_usage(user_id: str = Depends(get_current_user_id)):
    await sweep_expired_reservations_for_user(user_id)
    usage_doc = await _get_or_create_usage(user_id)

    cursor = get_vault_profiles_collection().find(
        {"userId": user_id},
        {
            "_id": 0,
            "profileId": 1,
            "name": 1,
            "appId": 1,
            "snapshot.sizeBytes": 1,
            "snapshotHistory.sizeBytes": 1,
        },
    )
    breakdown = []
    async for p in cursor:
        live = int((p.get("snapshot") or {}).get("sizeBytes", 0) or 0)
        hist = sum(
            int(h.get("sizeBytes", 0) or 0) for h in (p.get("snapshotHistory") or [])
        )
        breakdown.append(
            {
                "profileId": p["profileId"],
                "name": p.get("name"),
                "appId": p.get("appId"),
                "sizeBytes": live + hist,
            }
        )

    return {
        "success": True,
        "data": {
            "usedBytes": int(usage_doc.get("usedBytes", 0)),
            "pendingBytes": int(usage_doc.get("pendingBytes", 0)),
            "quotaBytes": int(usage_doc.get("quotaBytes", DEFAULT_QUOTA_BYTES)),
            "profiles": breakdown,
        },
    }