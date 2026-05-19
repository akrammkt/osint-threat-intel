"""
check_scoring.py - run the scoring stage and show the ranked threat list.
Run from the project root with:  python check_scoring.py
"""

from scoring.runner import run_scoring
from core.database import get_indicators

run_scoring()

scored = get_indicators(status="scored")
scored.sort(key=lambda i: i.score, reverse=True)

print(f"\nTop 20 ranked threats (of {len(scored)} scored):")
print(f"  {'domain':<30} {'score':<7} {'risk':<10} {'age':<10} {'campaign'}")
print("  " + "-" * 72)
for ind in scored[:20]:
    age = ind.enrichment.get("domain_age_days")
    age_str = f"{age}d" if age is not None else "unknown"
    print(f"  {ind.value:<30} {ind.score:<7} "
          f"{ind.enrichment['risk_level']:<10} {age_str:<10} {ind.campaign_id or '-'}")

# Show any campaigns found.
campaigns = {}
for ind in scored:
    if ind.campaign_id:
        campaigns.setdefault(ind.campaign_id, []).append(ind.value)
if campaigns:
    print(f"\nCampaigns identified: {len(campaigns)}")
    for cid, domains in campaigns.items():
        print(f"  {cid}: {len(domains)} domains -> {', '.join(domains[:5])}"
              + (" ..." if len(domains) > 5 else ""))