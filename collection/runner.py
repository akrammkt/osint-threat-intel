"""
collection/runner.py
---------------------
Runs every OSINT collector for a given BrandProfile and saves the discovered
indicators to the database. When two collectors find the same domain, their
findings are merged into a single indicator with the union of sources.
"""

from core.database import init_db, save_many
from core.schema import BrandProfile
from collection import crtsh_collector, dnstwist_collector

# Every collector module must expose a collect(profile) -> list[Indicator] function.
COLLECTORS = [crtsh_collector, dnstwist_collector]


def run_collection(profile: BrandProfile) -> int:
    """Run all collectors for the brand, merge their results, save them."""
    init_db()
    merged = {}

    for collector in COLLECTORS:
        for ind in collector.collect(profile):
            if ind.value in merged:
                existing = merged[ind.value]
                sources = set(existing.source.split(",")) | set(ind.source.split(","))
                existing.source = ",".join(sorted(sources))
                existing.raw.update(ind.raw)
            else:
                merged[ind.value] = ind

    save_many(list(merged.values()))

    corroborated = sum(1 for i in merged.values() if "," in i.source)
    print(f"\nCollection complete: {len(merged)} unique indicators saved "
          f"({corroborated} corroborated by multiple sources).")
    return len(merged)
