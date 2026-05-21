"""
processing/enrichment.py
-------------------------
Second half of the processing stage: ENRICHMENT.

Adds the context the scoring stage needs:
  - domain_age_days   : WHOIS-derived domain age
  - whois_registrant  : WHOIS-derived registrant (used by campaign correlator)
  - brand_similarity  : how closely the domain resembles the protected brand
  - typo_technique    : which dnstwist permutation produced it (if any)

The brand the indicator is being compared against is passed in explicitly,
so this module is now brand-agnostic - the same enrichment code works for
any brand the pipeline is monitoring.
"""

from datetime import datetime, timezone

import Levenshtein
import whois


def get_whois_info(domain: str) -> dict:
    """
    Single WHOIS lookup returning both the domain's age in days and the
    registrant organisation/name. Either may be None if WHOIS does not
    provide them (privacy services, rate limits, parse errors).
    """
    info = {"age_days": None, "registrant": None}
    try:
        record = whois.whois(domain)

        created = record.creation_date
        if isinstance(created, list):
            created = created[0]
        if isinstance(created, datetime):
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            info["age_days"] = max((datetime.now(timezone.utc) - created).days, 0)

        registrant = record.org or record.name
        if isinstance(registrant, list):
            registrant = registrant[0]
        if registrant and str(registrant).strip():
            info["registrant"] = str(registrant).strip()

    except Exception:
        pass

    return info


def brand_similarity(domain: str, brand: str) -> float:
    """
    Score how closely a domain resembles the protected brand, from 0.0 to 1.0.
    Verbatim brand-as-substring scores high (0.90-1.00); otherwise fall back to
    the Levenshtein similarity ratio against the brand name.
    """
    name = domain.split(".")[0]   # compare only the main label

    if brand in name:
        extra = len(name) - len(brand)
        return round(max(1.0 - extra * 0.02, 0.90), 3)

    return round(Levenshtein.ratio(name, brand), 3)


def enrich(indicator, brand: str):
    """
    Enrich one indicator in place against the given brand name.
    Advances its status to 'enriched'.
    """
    whois_info = get_whois_info(indicator.value)
    age = whois_info["age_days"]

    indicator.enrichment = {
        "domain_age_days": age,
        "age_known": age is not None,
        "whois_registrant": whois_info["registrant"],
        "brand_similarity": brand_similarity(indicator.value, brand),
        "typo_technique": indicator.raw.get("fuzzer", "n/a"),
        "source_count": len(indicator.source.split(",")),
    }
    indicator.status = "enriched"
    return indicator
