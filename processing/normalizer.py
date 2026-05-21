"""
processing/normalizer.py
-------------------------
First half of the processing stage: NORMALISATION.

Collapses every indicator to its registered domain (via the Public Suffix List)
and merges duplicates. The merged indicator inherits the brand of its inputs,
so each brand's data is normalised independently.
"""

import tldextract
from core.schema import Indicator, make_id

_extract = tldextract.TLDExtract()


def registered_domain(hostname: str) -> str:
    """Reduce a hostname to its registered domain."""
    parts = _extract(hostname)
    return parts.top_domain_under_public_suffix or hostname


def normalize(indicators: list) -> list:
    """Collapse a list of indicators to their registered domains, merging duplicates."""
    merged = {}

    for ind in indicators:
        domain = registered_domain(ind.value)

        if domain not in merged:
            new = Indicator(
                value=domain,
                source=ind.source,
                brand=ind.brand,
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
            sources = set(existing.source.split(",")) | set(ind.source.split(","))
            existing.source = ",".join(sorted(sources))
            if ind.first_seen < existing.first_seen:
                existing.first_seen = ind.first_seen
            for key, value in ind.raw.items():
                existing.raw.setdefault(key, value)
            existing.raw["subdomains_seen"] += 1
            existing.raw["original_hostnames"].append(ind.value)

    # Regenerate ids from the new (collapsed) value, scoped to the brand.
    for ind in merged.values():
        ind.id = make_id(ind.value, ind.brand)

    return list(merged.values())
