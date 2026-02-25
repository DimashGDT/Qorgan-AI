from __future__ import annotations
import hashlib
import json
import time
from urllib.parse import urlparse


def make_trace_id(url: str) -> str:
    """Deterministic trace_id: sha256(url + unix_second)."""
    ts = str(int(time.time()))
    raw = f"{url}:{ts}"
    return hashlib.sha256(raw.encode()).hexdigest()


def url_hash(url: str) -> str:
    """sha256 of the full URL – stored instead of the raw URL."""
    return hashlib.sha256(url.encode()).hexdigest()


def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        return (parsed.hostname or "")[:253]
    except Exception:
        return ""


def truncate_features_json(features: dict, max_bytes: int = 2048) -> str:
    """Serialize features dict to JSON, truncating if needed."""
    raw = json.dumps(features, default=str)
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    return raw
