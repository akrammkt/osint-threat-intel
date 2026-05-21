"""
processing/runner.py
---------------------
Orchestrates the processing stage for a single brand:

  collected (brand=B)  ->  NORMALISE  ->  ENRICH  ->  enriched (brand=B)
"""

from concurrent.futures import ThreadPoolExecutor

from core.database import get_indicators, save_many
from core.schema import BrandProfile
from processing.normalizer import normalize
from processing.enrichment import enrich

ENRICH_THREADS = 20


def run_processing(profile: BrandProfile) -> int:
    """Normalise and enrich all collected indicators for the given brand."""
    raw = get_indicators(status="collected", brand=profile.name)
    print(f"  [processing] {len(raw)} raw indicators read from the database")

    normalized = normalize(raw)
    print(f"  [processing] normalised to {len(normalized)} unique registered domains")

    print(f"  [processing] enriching {len(normalized)} domains (WHOIS lookups) ...")
    with ThreadPoolExecutor(max_workers=ENRICH_THREADS) as pool:
        enriched = list(pool.map(lambda ind: enrich(ind, profile.name), normalized))

    save_many(enriched)

    known = sum(1 for i in enriched if i.enrichment["age_known"])
    print(f"\nProcessing complete: {len(enriched)} indicators enriched "
          f"({known} with a known WHOIS age).")
    return len(enriched)
