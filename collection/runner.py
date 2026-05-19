"""
collection/runner.py
---------------------
Runs every OSINT collector, then saves the discovered indicators to the database.

Adding a new collector later takes one line: import it and add it to COLLECTORS.
"""

from core.database import init_db, save_many
from collection import crtsh_collector

# Every collector module must expose a collect() -> list[Indicator] function.
COLLECTORS = [crtsh_collector]


def run_collection() -> int:
    """Run all collectors and store the results. Returns the number of indicators saved."""
    init_db()
    all_indicators = {}

    for collector in COLLECTORS:
        for ind in collector.collect():
            all_indicators[ind.value] = ind   # de-dup across collectors by domain

    save_many(list(all_indicators.values()))
    print(f"\nCollection complete: {len(all_indicators)} unique indicators saved.")
    return len(all_indicators)