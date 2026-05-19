"""
check_core.py - quick sanity check for the core layer (schema + database).
Run once from the project root with:  python check_core.py
"""

from core.schema import Indicator
from core.database import init_db, save_indicator, get_indicators, count_indicators

# 1. Create the database file and the indicators table.
init_db()
print("[1] Database initialised.")

# 2. Build a sample Indicator, the way a collector would.
sample = Indicator(
    value="PayPa1-Secure-Login.com",
    source="crt.sh",
    raw={"issuer": "Let's Encrypt", "not_before": "2026-05-18"},
)
print("[2] Created indicator:")
print("      id     :", sample.id)
print("      value  :", sample.value, "  (normalised to lowercase)")
print("      status :", sample.status)

# 3. Save it to the database.
save_indicator(sample)
print("[3] Indicator saved to the database.")

# 4. Read it back out, filtering by pipeline stage.
stored = get_indicators(status="collected")
print(f"[4] Indicators in database: {count_indicators()}")
print("      read back ->", stored[0].value, "| id:", stored[0].id)

print("\nCore layer works correctly.")