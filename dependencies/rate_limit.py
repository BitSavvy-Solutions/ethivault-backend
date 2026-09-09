# dependencies/rate_limit.py

import os
import time
from collections import defaultdict, deque

from fastapi import HTTPException


class SlidingWindowRateLimiter:
    """
    Simple in-memory sliding window limiter. Per instance, so with multiple
    replicas the effective limit is limit x replicas. Swap for Redis when
    you scale past one instance.
    """

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window = window_seconds
        self._hits: dict = defaultdict(deque)

    def check(self, key: str) -> None:
        now = time.monotonic()
        q = self._hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.max_requests:
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Please try again later.",
            )
        q.append(now)


presign_limiter = SlidingWindowRateLimiter(
    int(os.getenv("VAULT_RATE_LIMIT_PRESIGN_PER_HOUR", "60")), 3600
)
commit_limiter = SlidingWindowRateLimiter(
    int(os.getenv("VAULT_RATE_LIMIT_COMMIT_PER_HOUR", "120")), 3600
)