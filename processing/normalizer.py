"""
processing/normalizer.py
-------------------------
First half of the processing stage: NORMALISATION.

Collectors produce raw indicators that are noisy - the crt.sh collector in
particular returns many subdomains of the same registered domain
(developer.paypalworld.com, login.paypalworld.com, api.paypalworld.com ...).
For threat analysis we care about the REGISTERED DOMAIN, because that is the
unit an attacker actually buys and controls.

This module collapses every indicator to its registered domain and merges
duplicates, so 15 subdomains of paypalworld.com become a single indicator.
"""

import tldextract
from core.schema import Indicator, make_id

# Build the registered domain offline from a bundled snapshot. The snapshot is
# refreshed automatically the first time; we never depend on a live download.
_extract = tldextract.TLDExtract()


def registered_domain(hostname: str) -> str:
    """
    Reduce a hostname to its registered domain.
    'developer.paypalworld.com' -> 'paypalworld.com'
    'a.b.paypal.co.uk'          -> 'paypal.co.uk'
    """
    parts = _extract(hostname)
    return parts.top_domain_under_public_suffix or hostname


def normalize(indicators: list) -> list:
    """
    Collapse a list of indicators to their registered domains and merge
    duplicates. Returns one indicator per unique registered domain.

    When several indicators collapse together, their data is merged:
      - sources are unioned        (crt.sh + dnstwist -> "crt.sh,dnstwist")
      - the earliest first_seen is kept
      - the count of collapsed subdomains is recorded for context
    """
    merged = {}

    for ind in indicators:
        domain = registered_domain(ind.value)

        if domain not in merged:
            # start a fresh indicator keyed on the registered domain
            new = Indicator(
                value=domain,
                source=ind.source,
                first_seen=ind.first_seen,
                collected_at=ind.collected_at,
                raw=dict(ind.raw),
            )
            new.raw["subdomains_seen"] = 1
            new.raw["original_hostnames"] = [ind.value]
            new.status = "normalized"
            merged[domain] = new
        else:
            existing = merged[domain]
            # union the sources
            sources = set(existing.source.split(",")) | set(ind.source.split(","))
            existing.source = ",".join(sorted(sources))
            # keep the earliest first_seen date
            if ind.first_seen < existing.first_seen:
                existing.first_seen = ind.first_seen
            # merge raw data and track how many hostnames collapsed in
            for key, value in ind.raw.items():
                existing.raw.setdefault(key, value)
            existing.raw["subdomains_seen"] += 1
            existing.raw["original_hostnames"].append(ind.value)

    # ids were generated from the old value - regenerate from the new one
    for ind in merged.values():
        ind.id = make_id(ind.value)

    return list(merged.values())