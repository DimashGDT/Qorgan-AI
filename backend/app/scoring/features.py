"""Feature extraction helpers used by the rules engine."""
from __future__ import annotations
import re
from urllib.parse import urlparse
from app.schemas import FeaturesInput


SUSPICIOUS_KEYWORDS = {
    "login", "verify", "account", "update", "secure", "banking",
    "paypal", "amazon", "apple", "microsoft", "support", "confirm",
    "password", "signin", "wallet", "crypto", "free", "prize", "winner",
    "urgent", "alert", "suspended", "unusual", "activity",
}

CARD_KEYWORDS = {
    "credit card", "card number", "cvv", "expiry", "billing",
    "payment", "checkout", "buy now",
}


def extract_from_url(url: str) -> dict:
    """Extract domain-level features from the URL string."""
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
    except Exception:
        return {}

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # Punycode detection
    has_punycode = "xn--" in hostname.lower()

    # Hyphen count in domain (not counting subdomains separator dots)
    hyphen_count = hostname.count("-")

    # Subdomain count
    parts = hostname.split(".")
    subdomain_count = max(0, len(parts) - 2)

    # Domain length (just the registered domain part)
    domain_length = len(hostname)

    # Path depth
    path_depth = len([p for p in path.split("/") if p])

    # Protocol
    is_https = parsed.scheme == "https"

    # Suspicious words in hostname
    lower_host = hostname.lower()
    suspicious_words_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower_host)

    return {
        "has_punycode": has_punycode,
        "hyphen_count": hyphen_count,
        "subdomain_count": subdomain_count,
        "domain_length": domain_length,
        "path_depth": path_depth,
        "is_https": is_https,
        "suspicious_words_count_url": suspicious_words_count,
        "hostname": hostname,
    }


def merge_features(url_features: dict, client_features: FeaturesInput) -> dict:
    """Merge URL-derived features with client-reported features."""
    merged = {
        "domain_length": client_features.domain_length or url_features.get("domain_length", 0),
        "redirect_count": client_features.redirect_count,
        "has_password_input": client_features.has_password_input,
        "has_card_keywords": client_features.has_card_keywords,
        "suspicious_words_count": max(
            client_features.suspicious_words_count,
            url_features.get("suspicious_words_count_url", 0),
        ),
        "gambling_keywords_count": client_features.gambling_keywords_count,
        "adult_keywords_count": client_features.adult_keywords_count,
        "drug_keywords_count": client_features.drug_keywords_count,
        "subdomain_count": client_features.subdomain_count or url_features.get("subdomain_count", 0),
        "has_punycode": client_features.has_punycode or url_features.get("has_punycode", False),
        "hyphen_count": client_features.hyphen_count or url_features.get("hyphen_count", 0),
        "path_depth": client_features.path_depth or url_features.get("path_depth", 0),
        "is_https": client_features.is_https and url_features.get("is_https", True),
        "hostname": url_features.get("hostname", ""),
    }
    return merged
