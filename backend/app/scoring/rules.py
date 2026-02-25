"""Rules-based scoring engine."""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple

GAMBLING_DOMAINS = {
    "1xbet", "1xbet.kz", "bet365", "betway", "stake", "betsafe",
    "casumo", "jackpot", "pokerstars", "888casino", "vulkan",
    "spinbet", "mostbet", "melbet", "parimatch", "fonbet",
    "leonbets", "olimpbet", "winline", "betcity", "1win",
    "pin-up", "pinup", "joycasino", "slotocash", "fastpay",
    "bcgame", "rollbit", "roobet", "csgoempire", "thunderpick",
}

# These domains are always considered safe regardless of page content
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "wikipedia.org", "github.com",
    "stackoverflow.com", "reddit.com", "twitter.com", "x.com",
    "facebook.com", "instagram.com", "linkedin.com", "apple.com",
    "microsoft.com", "amazon.com", "netflix.com", "spotify.com",
    "telegram.org", "whatsapp.com", "discord.com", "twitch.tv",
    "tiktok.com", "pinterest.com", "yahoo.com", "bing.com",
    "dropbox.com", "notion.so", "figma.com", "canva.com",
    "anthropic.com", "openai.com", "cloudflare.com",
}

GAMBLING_KEYWORDS_PAGE = {
    "place a bet", "live betting", "sports betting", "casino bonus",
    "free spins", "slot machine", "jackpot", "roulette", "blackjack",
    "poker chips", "odds", "handicap bet", "accumulator",
    "депозит бонус", "ставки на спорт", "игровые автоматы",
    "букмекер", "тотализатор", "коэффициент",
}

RISKY_TLDS = {
    ".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".buzz", ".icu", ".cyou", ".cfd", ".monster",
    ".loan", ".win", ".bid", ".trade", ".stream", ".download",
}


@dataclass
class RuleResult:
    score_delta: int
    reason: str


def apply_rules(features: dict) -> Tuple[int, List[str]]:
    """
    Apply heuristic rules to features dict.
    Returns (total_score 0..100, list_of_human_readable_reasons).
    """
    results: List[RuleResult] = []

    # Check if hostname is a trusted domain — return immediately as SAFE
    hostname = features.get("hostname", "").lower()
    is_trusted = any(
        hostname == d or hostname.endswith("." + d)
        for d in TRUSTED_DOMAINS
    )
    if is_trusted:
        return 0, ["Domain is a well-known trusted site"]

    # 0. Gambling / casino site detection
    is_known_gambling = any(
        hostname == d or hostname.endswith("." + d) or d in hostname
        for d in GAMBLING_DOMAINS
    )
    if is_known_gambling:
        results.append(RuleResult(70, "Site is a known gambling / betting platform"))

    gambling_kw_count = features.get("gambling_keywords_count", 0)
    if gambling_kw_count >= 6 and not is_known_gambling:
        results.append(RuleResult(60, f"Page contains {gambling_kw_count} gambling-related keywords (betting, casino, slots)"))
    elif gambling_kw_count >= 4 and not is_known_gambling:
        results.append(RuleResult(30, "Page contains several gambling-related keywords"))

    # Adult content detection
    adult_kw = features.get("adult_keywords_count", 0)
    if adult_kw >= 3:
        results.append(RuleResult(70, "Page contains explicit adult content keywords"))
    elif adult_kw >= 1:
        results.append(RuleResult(40, "Page contains adult content keywords"))

    # Drug / dangerous content detection
    drug_kw = features.get("drug_keywords_count", 0)
    if drug_kw >= 2:
        results.append(RuleResult(75, "Page contains drug-related or dangerous content keywords"))
    elif drug_kw >= 1:
        results.append(RuleResult(40, "Page contains suspicious drug-related keywords"))

    # Risky TLD
    for tld in RISKY_TLDS:
        if hostname.endswith(tld):
            results.append(RuleResult(20, f"Domain uses a high-risk TLD ({tld})"))
            break

    # 1. Punycode domain (IDN homograph attack vector)
    if features.get("has_punycode"):
        results.append(RuleResult(30, "Domain uses Punycode encoding (possible homograph attack)"))

    # 2. Excessive hyphens in domain
    hyphens = features.get("hyphen_count", 0)
    if hyphens >= 3:
        results.append(RuleResult(20, f"Domain contains {hyphens} hyphens (common in phishing domains)"))
    elif hyphens == 2:
        results.append(RuleResult(10, "Domain contains multiple hyphens"))

    # 3. Suspicious keywords in domain/URL
    sw = features.get("suspicious_words_count", 0)
    if sw >= 3:
        results.append(RuleResult(25, f"Domain/URL contains {sw} suspicious keywords (e.g. login, verify, secure)"))
    elif sw >= 1:
        results.append(RuleResult(10, f"Domain/URL contains {sw} suspicious keyword(s)"))

    # 4. Redirect chain
    rc = features.get("redirect_count", 0)
    if rc >= 3:
        results.append(RuleResult(20, f"Page triggered {rc} redirects before loading"))
    elif rc >= 1:
        results.append(RuleResult(8, f"Page triggered {rc} redirect(s)"))

    # 5. Password input on non-HTTPS page
    if features.get("has_password_input") and not features.get("is_https", True):
        results.append(RuleResult(35, "Password input field detected on an insecure (HTTP) page"))

    # 6. Credit card keywords
    if features.get("has_card_keywords"):
        results.append(RuleResult(15, "Page contains credit card / payment keywords"))

    # 7. Very long domain
    dl = features.get("domain_length", 0)
    if dl > 40:
        results.append(RuleResult(15, f"Unusually long domain name ({dl} characters)"))
    elif dl > 25:
        results.append(RuleResult(5, f"Long domain name ({dl} characters)"))

    # 8. Many subdomains
    sc = features.get("subdomain_count", 0)
    if sc >= 3:
        results.append(RuleResult(15, f"Domain has {sc} subdomains (unusual for legitimate sites)"))
    elif sc == 2:
        results.append(RuleResult(5, "Domain has 2 subdomains"))

    # 9. No HTTPS
    if not features.get("is_https", True):
        results.append(RuleResult(20, "Site does not use HTTPS"))

    # 10. Deep path
    pd = features.get("path_depth", 0)
    if pd >= 5:
        results.append(RuleResult(5, f"Deep URL path ({pd} levels)"))

    total = sum(r.score_delta for r in results)
    total = min(total, 100)

    # Pick top 6 reasons by score_delta
    top_reasons = [
        r.reason for r in sorted(results, key=lambda x: x.score_delta, reverse=True)[:6]
    ]

    return total, top_reasons


def score_to_verdict(score: int) -> str:
    if score >= 60:
        return "SCAM"
    if score >= 30:
        return "SUSPICIOUS"
    return "SAFE"
