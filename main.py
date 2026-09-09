# main.py

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from routers import vault
from db.mongo import ensure_indexes, get_mongo_client
from apis.vault_maintenance import sweep_expired_reservations_globally

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SWEEP_INTERVAL_SECONDS = int(os.getenv("VAULT_SWEEP_INTERVAL_SECONDS", "600"))


def _allowed_origins() -> list:
    raw = os.getenv(
        "ALLOWED_ORIGINS",
        "https://aida.iverse.space,http://localhost:5173",
    )
    return [o.strip() for o in raw.split(",") if o.strip()]


async def periodic_sweep():
    """Background reservation sweeper, same pattern as models.periodic_refresh_cache."""
    while True:
        try:
            released = await sweep_expired_reservations_globally()
            if released:
                logger.info(f"Vault sweep released {released} pending bytes.")
        except Exception as e:
            logger.error(f"Vault sweep failed: {e}")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        client = get_mongo_client()
        await client.admin.command("ping")
        logger.info("MongoDB connection verified on startup.")
        await ensure_indexes()
    except Exception as e:
        logger.error(f"MongoDB startup check failed: {e}.")

    sweep_task = asyncio.create_task(periodic_sweep())
    yield
    sweep_task.cancel()
    try:
        await sweep_task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="AIDA Vault", version="1.0.0", lifespan=lifespan)

# Explicit origin list, not a wildcard. This service handles user data.
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


app.include_router(vault.router, prefix="/api/vault")


@app.get("/")
async def health_check():
    return {"status": "running", "service": "aida-vault"}