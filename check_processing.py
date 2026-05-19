"""
check_processing.py - run the processing stage and show enriched results.
Run from the project root with:  python check_processing.py
"""

from processing.runner import run_processing
from core.database import get_indicators

run_processing()

enriched = get_indicators(status="enriched")
print(f"\nTotal enriched indicators: {len(enriched)}")

# Sort by brand similarity so the most convincing look-alikes show first.
enriched.sort(key=lambda i: i.enrichment["brand_similarity"], reverse=True)

print("\nTop 20 most brand-similar domains:")
print(f"  {'domain':<32} {'similarity':<11} {'age (days)':<12} {'sources'}")
print("  " + "-" * 70)
for ind in enriched[:20]:
    age = ind.enrichment["domain_age_days"]
    age_str = str(age) if age is not None else "unknown"
    print(f"  {ind.value:<32} {ind.enrichment['brand_similarity']:<11} "
          f"{age_str:<12} {ind.source}")