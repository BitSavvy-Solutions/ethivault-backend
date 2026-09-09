# db/mongo.py

import os
import logging
from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection

logger = logging.getLogger(__name__)

_client: Optional[AsyncIOMotorClient] = None


def get_mongo_client() -> AsyncIOMotorClient:
    """
    Lazy singleton Motor client, reused for the lifetime of the process.
    Accepts MONGODB_CONNECTION_STRING (agent backend convention) and falls
    back to MONGODB_URI (Azure Functions convention) so either env layout works.
    """
    global _client
    if _client is None:
        conn_str = os.getenv("MONGODB_CONNECTION_STRING") or os.getenv("MONGODB_URI")
        if not conn_str:
            raise EnvironmentError(
                "MONGODB_CONNECTION_STRING is not set in environment variables."
            )
        _client = AsyncIOMotorClient(conn_str)
        logger.info("Motor MongoDB client initialized.")
    return _client


def _get_collection(name_env: str, default_name: str) -> AsyncIOMotorCollection:
    client = get_mongo_client()
    db_name = os.getenv("MONGODB_DB_NAME", "userdb")
    collection_name = os.getenv(name_env, default_name)
    return client[db_name][collection_name]


def get_tokens_collection() -> AsyncIOMotorCollection:
    """Shared auth collection, same one the agent backend reads."""
    return _get_collection("API_TOKENS_COLLECTION_NAME", "api_tokens")


def get_vault_profiles_collection() -> AsyncIOMotorCollection:
    return _get_collection("VAULT_PROFILES_COLLECTION_NAME", "vault_profiles")


def get_vault_usage_collection() -> AsyncIOMotorCollection:
    return _get_collection("VAULT_USAGE_COLLECTION_NAME", "vault_usage")


def get_vault_reservations_collection() -> AsyncIOMotorCollection:
    return _get_collection("VAULT_RESERVATIONS_COLLECTION_NAME", "vault_reservations")


async def ensure_indexes() -> None:
    """
    Creates indexes on startup. Each creation is wrapped so that a failure
    (e.g. Cosmos rejecting a unique index on a non-empty collection) logs a
    warning instead of killing the service.
    """
    index_plan = [
        (get_vault_profiles_collection(), [("profileId", 1)], {"unique": True}),
        (get_vault_profiles_collection(), [("userId", 1), ("appId", 1)], {}),
        (get_vault_usage_collection(), [("userId", 1)], {"unique": True}),
        (get_vault_reservations_collection(), [("reservationId", 1)], {"unique": True}),
        (get_vault_reservations_collection(), [("userId", 1), ("status", 1)], {}),
        (get_vault_reservations_collection(), [("status", 1), ("expiresAt", 1)], {}),
    ]
    for collection, keys, kwargs in index_plan:
        try:
            await collection.create_index(keys, **kwargs)
        except Exception as e:
            logger.warning(
                f"Index creation failed on {collection.name} for {keys}: {e}"
            )