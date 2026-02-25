"""
Simple in-memory token bucket rate limiter per client IP.
Config: RATE_LIMIT_RPM requests per minute (default 60).
"""
from __future__ import annotations
import os
import time
import logging
from collections import defaultdict
from fastapi import Request, HTTPException

logger = logging.getLogger(__name__)

RATE_LIMIT_RPM: int = int(os.getenv("RATE_LIMIT_RPM", "60"))
WINDOW_SECONDS: float = 60.0

# {ip: [timestamp, ...]}  – sliding window approach
_request_log: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(request: Request) -> None:
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    window_start = now - WINDOW_SECONDS

    # Prune old entries
    timestamps = _request_log[ip]
    _request_log[ip] = [t for t in timestamps if t > window_start]

    if len(_request_log[ip]) >= RATE_LIMIT_RPM:
        logger.warning("Rate limit exceeded for IP %s", ip)
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: max {RATE_LIMIT_RPM} requests/minute",
        )

    _request_log[ip].append(now)
