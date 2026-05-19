"""
processing/runner.py
---------------------
Orchestrates the full processing stage.

  collected indicators  ->  NORMALISE  ->  ENRICH  ->  enriched indicators

It reads every 'collected' indicator from the database, collapses them to
registered domains, enriches each one (WHOIS age + brand similarity), and
saves the results back. The scoring stage then picks up the 'enriched' ones.
"""

from concurrent.futures import ThreadPoolExecutor

from core.database import get_indicators, save_many
from processing.normalizer import normalize
from processing.enrichment import enrich

# WHOIS lookups are network-bound and slow, so run several in parallel.
ENRICH_THREADS = 20


def run_processing() -> int:
    """Normalise and enrich all collected indicators. Returns the enriched count."""
    raw = get_indicators(status="collected")
    print(f"  [processing] {len(raw)} raw indicators read from the database")

    # 1. Normalise: collapse subdomains, merge duplicates.
    normalized = normalize(raw)
    print(f"  [processing] normalised to {len(normalized)} unique registered domains")

    # 2. Enrich: WHOIS age + brand similarity, in parallel.
    print(f"  [processing] enriching {len(normalized)} domains (WHOIS lookups) ...")
    with ThreadPoolExecutor(max_workers=ENRICH_THREADS) as pool:
        enriched = list(pool.map(enrich, normalized))

    # 3. Save the enriched indicators back to the database.
    save_many(enriched)

    known = sum(1 for i in enriched if i.enrichment["age_known"])
    print(f"\nProcessing complete: {len(enriched)} indicators enriched "
          f"({known} with a known WHOIS age).")
    return len(enriched)