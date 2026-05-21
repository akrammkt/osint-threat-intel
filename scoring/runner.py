"""
scoring/runner.py
------------------
Orchestrates the scoring stage for a single brand.

  enriched (brand=B)  ->  SCORE each  ->  CORRELATE into campaigns
                      ->  scored (brand=B)
"""

from core.database import get_indicators, save_many
from core.schema import BrandProfile
from scoring.scorer import score_indicator
from scoring.correlator import correlate


def run_scoring(profile: BrandProfile) -> int:
    """Score and correlate all enriched indicators for the given brand."""
    enriched = get_indicators(status="enriched", brand=profile.name)
    print(f"  [scoring] {len(enriched)} enriched indicators read from the database")

    scored = [score_indicator(ind) for ind in enriched]
    print(f"  [scoring] {len(scored)} indicators scored")

    campaigns = correlate(scored)
    print(f"  [scoring] {campaigns} campaign(s) identified")

    save_many(scored)

    bands = {}
    for ind in scored:
        level = ind.enrichment.get("risk_level", "LOW")
        bands[level] = bands.get(level, 0) + 1
    summary = ", ".join(f"{bands.get(b,0)} {b}"
                        for b in ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    print(f"\nScoring complete: {summary}.")
    return len(scored)
