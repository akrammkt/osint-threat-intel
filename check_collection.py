"""
check_collection.py - run the collection stage and show what it found.
Run from the project root with:  python check_collection.py
"""

from collection.runner import run_collection
from core.database import get_indicators

# Run every collector and store the results in the database.
run_collection()

# Show a sample of what was collected.
collected = get_indicators(status="collected")
print(f"\nTotal indicators with status 'collected': {len(collected)}")
print("\nSample of suspicious look-alike domains found:")
for ind in collected[:15]:
    print(f"  - {ind.value:<45} (first seen {ind.first_seen[:10]})")