"""
check_collection.py - run the collection stage and show what it found.
Run from the project root with:  python check_collection.py
"""

from collection.runner import run_collection
from core.database import get_indicators

# Run every collector and store the results in the database.
run_collection()

collected = get_indicators(status="collected")
print(f"\nTotal indicators with status 'collected': {len(collected)}")

# Highlight any domains corroborated by more than one source.
corroborated = [i for i in collected if "," in i.source]
if corroborated:
    print(f"\nDomains flagged by MULTIPLE sources ({len(corroborated)}):")
    for ind in corroborated:
        print(f"  - {ind.value:<40} sources: {ind.source}")

print("\nSample of suspicious domains found:")
for ind in collected[:15]:
    print(f"  - {ind.value:<45} [{ind.source}]")