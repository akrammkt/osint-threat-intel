"""
scoring/runner.py
------------------
Orchestrates the scoring stage.

  enriched indicators  ->  SCORE each one  ->  CORRELATE into campaigns
                       ->  scored indicators

Reads every 'enriched' indicator, assigns a 0-100 early-warning score,
clusters the high-scoring ones into campaigns, and saves everything back
with status 'scored'. This is the last stage before the dashboard.
"""

from core.database import get_indicators, save_many
from scoring.scorer import score_indicator
from scoring.correlator import correlate


def run_scoring() -> int:
    """Score and correlate all enriched indicators. Returns the scored count."""
    enriched = get_indicators(status="enriched")
    print(f"  [scoring] {len(enriched)} enriched indicators read from the database")

    # 1. Score every indicator.
    scored = [score_indicator(ind) for ind in enriched]
    print(f"  [scoring] {len(scored)} indicators scored")

    # 2. Cluster the high-scoring ones into campaigns.
    campaigns = correlate(scored)
    print(f"  [scoring] {campaigns} campaign(s) identified")

    # 3. Save everything back to the database.
    save_many(scored)

    # quick risk-band summary
    bands = {}
    for ind in scored:
        level = ind.enrichment.get("risk_level", "LOW")
        bands[level] = bands.get(level, 0) + 1
    summary = ", ".join(f"{bands.get(b,0)} {b}"
                        for b in ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    print(f"\nScoring complete: {summary}.")
    return len(scored)