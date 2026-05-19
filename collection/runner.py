"""
collection/runner.py
---------------------
Runs every OSINT collector, then saves the discovered indicators to the database.

When two collectors find the SAME domain, their findings are MERGED rather than
overwritten: the `source` field becomes a comma-separated list of every source
that flagged the domain (e.g. "crt.sh,dnstwist"). This cross-source
corroboration is a key threat signal used later by the scoring stage.
"""

from core.database import init_db, save_many
from collection import crtsh_collector, dnstwist_collector

# Every collector module must expose a collect() -> list[Indicator] function.
COLLECTORS = [crtsh_collector, dnstwist_collector]


def run_collection() -> int:
    """Run all collectors, merge their results, and store them. Returns the count saved."""
    init_db()
    merged = {}

    for collector in COLLECTORS:
        for ind in collector.collect():
            if ind.value in merged:
                # same domain found by another source -> merge, do not overwrite
                existing = merged[ind.value]
                sources = set(existing.source.split(",")) | {ind.source}
                existing.source = ",".join(sorted(sources))
                existing.raw.update(ind.raw)
            else:
                merged[ind.value] = ind

    save_many(list(merged.values()))

    corroborated = sum(1 for i in merged.values() if "," in i.source)
    print(f"\nCollection complete: {len(merged)} unique indicators saved "
          f"({corroborated} corroborated by multiple sources).")
    return len(merged)