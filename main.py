"""
main.py
--------
Pipeline orchestrator.

  python main.py                  # uses DEFAULT_BRAND from config (paypal.com)
  python main.py paypal.com       # monitor PayPal (uses the curated profile)
  python main.py uir.ac.ma        # monitor any other brand (auto-derived profile)

Each run clears existing data for THAT brand before re-collecting, so the
result is reproducible. Other brands' historical data is preserved.
"""

import sys

from core.database import init_db, clear_brand
from core.schema import BrandProfile
from config import DEFAULT_BRAND, KNOWN_PROFILES
from collection.runner import run_collection
from processing.runner import run_processing
from scoring.runner import run_scoring


def resolve_brand_profile(domain: str) -> BrandProfile:
    """Curated profile for known brands, auto-derived profile for everything else."""
    domain = domain.strip().lower()
    if domain in KNOWN_PROFILES:
        return KNOWN_PROFILES[domain]
    return BrandProfile.from_domain(domain)


def run_pipeline(brand_input: str):
    """Run every stage for one brand on a freshly cleared per-brand dataset."""
    profile = resolve_brand_profile(brand_input)

    init_db()
    deleted = clear_brand(profile.name)

    print("=" * 60)
    print("OSINT THREAT-INTELLIGENCE PIPELINE")
    print(f"  brand    : {profile.name}")
    print(f"  domain   : {profile.domain}")
    print(f"  keywords : {', '.join(profile.keywords)}")
    if deleted:
        print(f"  cleared  : {deleted} previous indicator(s) for this brand")
    print("=" * 60)

    print("\n[STAGE 1/3] COLLECTION")
    run_collection(profile)

    print("\n[STAGE 2/3] PROCESSING & ENRICHMENT")
    run_processing(profile)

    print("\n[STAGE 3/3] SCORING & CORRELATION")
    run_scoring(profile)

    print("\n" + "=" * 60)
    print("PIPELINE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    brand = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BRAND
    run_pipeline(brand)
