"""
processing/enrichment.py
-------------------------
Second half of the processing stage: ENRICHMENT.

A normalised domain on its own is just a string. Enrichment adds the context
the scoring and correlation stages need:

  1. domain_age_days   - how recently the domain was registered (via WHOIS).
                         Phishing domains are typically very young.

  2. brand_similarity  - how visually/textually close the domain is to the
                         protected brand (0.0 = unrelated, 1.0 = identical).

  3. whois_registrant  - the organisation/name that registered the domain.
                         The correlation stage uses this to group domains
                         registered by the same entity into one campaign.

  4. typo_technique    - if the domain came from dnstwist, which typosquatting
                         method produced it (homoglyph, omission, ...).
"""

from datetime import datetime, timezone

import Levenshtein
import whois

from config import PROTECTED_BRAND


# ---------------------------------------------------------------------------
# WHOIS lookup - age and registrant in a single query
# ---------------------------------------------------------------------------
def get_whois_info(domain: str) -> dict:
    """
    Look up a domain's WHOIS record once and return both its age in days and
    its registrant. Either value may be None if WHOIS does not provide it
    (common for privacy-protected or very new domains).
    """
    info = {"age_days": None, "registrant": None}
    try:
        record = whois.whois(domain)

        # --- creation date -> age in days ---
        created = record.creation_date
        if isinstance(created, list):
            created = created[0]
        if isinstance(created, datetime):
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            info["age_days"] = max((datetime.now(timezone.utc) - created).days, 0)

        # --- registrant: prefer the organisation, fall back to the name ---
        registrant = record.org or record.name
        if isinstance(registrant, list):
            registrant = registrant[0]
        if registrant and str(registrant).strip():
            info["registrant"] = str(registrant).strip()

    except Exception:
        # any WHOIS failure (rate limit, no record, parse error) -> leave None
        pass

    return info


# ---------------------------------------------------------------------------
# Brand similarity
# ---------------------------------------------------------------------------
def brand_similarity(domain: str) -> float:
    """
    Score how closely a domain resembles the protected brand, from 0.0 to 1.0.

    The brand keyword appearing literally in the domain (paypal-secure.com)
    is the strongest signal, so that scores at the top. Otherwise we use the
    Levenshtein similarity ratio against the brand to catch near-misses like
    'paypa1' or 'payqal'.
    """
    name = domain.split(".")[0]   # compare only the meaningful part

    if PROTECTED_BRAND in name:
        extra = len(name) - len(PROTECTED_BRAND)
        return round(max(1.0 - extra * 0.02, 0.90), 3)

    return round(Levenshtein.ratio(name, PROTECTED_BRAND), 3)


# ---------------------------------------------------------------------------
# Enrich a single indicator
# ---------------------------------------------------------------------------
def enrich(indicator):
    """
    Enrich one indicator in place: WHOIS age + registrant, brand similarity,
    and the typosquatting technique. Advances its status to 'enriched'.
    """
    whois_info = get_whois_info(indicator.value)
    age = whois_info["age_days"]

    indicator.enrichment = {
        "domain_age_days": age,
        "age_known": age is not None,
        "whois_registrant": whois_info["registrant"],
        "brand_similarity": brand_similarity(indicator.value),
        "typo_technique": indicator.raw.get("fuzzer", "n/a"),
        "source_count": len(indicator.source.split(",")),
    }
    indicator.status = "enriched"
    return indicator