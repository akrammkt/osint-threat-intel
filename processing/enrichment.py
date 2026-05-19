"""
processing/enrichment.py
-------------------------
Second half of the processing stage: ENRICHMENT.

A normalised domain on its own is just a string. Enrichment adds the context
the scoring stage needs to judge how dangerous it is:

  1. domain_age_days  - how recently the domain was registered (via WHOIS).
                        Phishing domains are typically very young; legitimate
                        businesses usually have domains years old.

  2. brand_similarity - how visually/textually close the domain is to the
                        protected brand (0.0 = unrelated, 1.0 = identical).
                        A high score means the domain is a convincing
                        look-alike designed to deceive victims.

  3. typo_technique   - if the domain came from dnstwist, which typosquatting
                        method produced it (homoglyph, omission, ...).
"""

from datetime import datetime, timezone

import Levenshtein
import whois

from config import PROTECTED_BRAND


# ---------------------------------------------------------------------------
# 1. WHOIS domain age
# ---------------------------------------------------------------------------
def get_domain_age_days(domain: str):
    """
    Return the age of a domain in days from its WHOIS creation date.
    Returns None if WHOIS data is unavailable (common for privacy-protected
    or very new domains) - the scoring stage handles that case explicitly.
    """
    try:
        record = whois.whois(domain)
        created = record.creation_date
        # WHOIS sometimes returns a list of dates - take the earliest
        if isinstance(created, list):
            created = created[0]
        if not isinstance(created, datetime):
            return None
        # make both datetimes timezone-aware for a safe subtraction
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - created
        return max(age.days, 0)
    except Exception:
        # any WHOIS failure (rate limit, no record, parse error) -> unknown
        return None


# ---------------------------------------------------------------------------
# 2. Brand similarity
# ---------------------------------------------------------------------------
def brand_similarity(domain: str) -> float:
    """
    Score how closely a domain resembles the protected brand, from 0.0 to 1.0.

    The brand keyword appearing literally in the domain (paypal-secure.com)
    is the strongest signal, so that scores at the top. Otherwise we use the
    Levenshtein similarity ratio against the brand to catch near-misses like
    'paypa1' or 'payqal'.
    """
    # strip the TLD - compare only the meaningful part of the domain
    name = domain.split(".")[0]

    if PROTECTED_BRAND in name:
        # brand contained verbatim: score 0.90-1.00 depending on extra noise
        extra = len(name) - len(PROTECTED_BRAND)
        return round(max(1.0 - extra * 0.02, 0.90), 3)

    # otherwise: textual closeness to the brand (homoglyphs, typos)
    return round(Levenshtein.ratio(name, PROTECTED_BRAND), 3)


# ---------------------------------------------------------------------------
# Enrich a single indicator
# ---------------------------------------------------------------------------
def enrich(indicator):
    """
    Enrich one indicator in place: add domain age, brand similarity, and the
    typosquatting technique. Advances its status to 'enriched'.
    """
    age = get_domain_age_days(indicator.value)

    indicator.enrichment = {
        "domain_age_days": age,
        "age_known": age is not None,
        "brand_similarity": brand_similarity(indicator.value),
        "typo_technique": indicator.raw.get("fuzzer", "n/a"),
        "source_count": len(indicator.source.split(",")),
    }
    indicator.status = "enriched"
    return indicator