# apis/vault_maintenance.py

import logging
from datetime import datetime, timezone

from db.mongo import (
    get_vault_reservations_collection,
    get_vault_usage_collection,
)
from apis.vault_storage import get_vault_storage

logger = logging.getLogger(__name__)


def utc_now_iso() -> str:
    """All vault timestamps use this exact format so ISO string comparison stays valid."""
    return datetime.now(timezone.utc).isoformat()


async def release_pending_bytes(user_id: str, size_bytes: int) -> None:
    if size_bytes <= 0:
        return
    usage = get_vault_usage_collection()
    await usage.update_one(
        {"userId": user_id},
        {"$inc": {"pendingBytes": -size_bytes}, "$set": {"updatedAt": utc_now_iso()}},
    )
    # Clamp against drift. The reconciliation pass is the real fix, this is the guardrail.
    await usage.update_one(
        {"userId": user_id, "pendingBytes": {"$lt": 0}},
        {"$set": {"pendingBytes": 0}},
    )


async def expire_reservation(reservation: dict) -> int:
    """
    Atomically transitions a pending reservation to expired.
    Returns the number of pending bytes released (0 if another
    process already handled it).
    """
    reservations = get_vault_reservations_collection()
    result = await reservations.update_one(
        {"reservationId": reservation["reservationId"], "status": "pending"},
        {"$set": {"status": "expired", "expiredAt": utc_now_iso()}},
    )
    if result.modified_count != 1:
        return 0

    size = int(reservation.get("sizeBytes", 0))
    try:
        await get_vault_storage().delete_object(reservation["blobKey"])
    except Exception as e:
        logger.warning(f"Orphan blob cleanup failed for {reservation.get('blobKey')}: {e}")
    return size


async def sweep_expired_reservations_for_user(user_id: str) -> int:
    """Lazy per-user sweep, run before quota checks so stale reservations never block uploads."""
    now = utc_now_iso()
    reservations = get_vault_reservations_collection()
    cursor = reservations.find(
        {"userId": user_id, "status": "pending", "expiresAt": {"$lt": now}}
    )
    released = 0
    async for r in cursor:
        released += await expire_reservation(r)
    if released:
        await release_pending_bytes(user_id, released)
    return released


async def sweep_expired_reservations_globally(limit: int = 500) -> int:
    """Periodic global sweep for users who never come back to trigger the lazy one."""
    now = utc_now_iso()
    reservations = get_vault_reservations_collection()
    cursor = reservations.find(
        {"status": "pending", "expiresAt": {"$lt": now}}
    ).limit(limit)

    released_by_user: dict = {}
    async for r in cursor:
        size = await expire_reservation(r)
        if size:
            released_by_user[r["userId"]] = released_by_user.get(r["userId"], 0) + size

    for uid, size in released_by_user.items():
        await release_pending_bytes(uid, size)

    return sum(released_by_user.values())