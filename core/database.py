"""
core/database.py
-----------------
SQLite persistence layer.

The indicators table now carries a `brand` column so multiple brands can
coexist in the same database. Indicators are uniquely keyed on (value, brand)
- the same domain can appear under two brands if both happen to monitor it.
"""

import sqlite3
import json
from pathlib import Path
from core.schema import Indicator

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "indicators.db"


def get_connection() -> sqlite3.Connection:
    """Open a connection to the SQLite database (creates the file if needed)."""
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the indicators table if it does not already exist."""
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS indicators (
            id             TEXT PRIMARY KEY,
            value          TEXT,
            brand          TEXT,
            source         TEXT,
            indicator_type TEXT,
            first_seen     TEXT,
            collected_at   TEXT,
            raw            TEXT,
            enrichment     TEXT,
            score          REAL,
            campaign_id    TEXT,
            status         TEXT,
            UNIQUE(value, brand)
        )
    """)
    conn.commit()
    conn.close()


def _row_to_indicator(row: sqlite3.Row) -> Indicator:
    """Convert a database row back into an Indicator object."""
    data = dict(row)
    data["raw"] = json.loads(data["raw"]) if data["raw"] else {}
    data["enrichment"] = json.loads(data["enrichment"]) if data["enrichment"] else {}
    return Indicator.from_dict(data)


def save_indicator(indicator: Indicator) -> None:
    """Insert or replace one indicator (keyed on (value, brand))."""
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO indicators
        (id, value, brand, source, indicator_type, first_seen, collected_at,
         raw, enrichment, score, campaign_id, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        indicator.id, indicator.value, indicator.brand,
        indicator.source, indicator.indicator_type,
        indicator.first_seen, indicator.collected_at,
        json.dumps(indicator.raw), json.dumps(indicator.enrichment),
        indicator.score, indicator.campaign_id, indicator.status,
    ))
    conn.commit()
    conn.close()


def save_many(indicators: list) -> int:
    """Save a list of indicators. Returns the count."""
    for ind in indicators:
        save_indicator(ind)
    return len(indicators)


def get_indicators(status: str = None, brand: str = None) -> list:
    """
    Fetch indicators, optionally filtered by status and/or brand.
    Both filters can be combined.
    """
    conn = get_connection()
    query = "SELECT * FROM indicators WHERE 1=1"
    params = []
    if status:
        query += " AND status = ?"
        params.append(status)
    if brand:
        query += " AND brand = ?"
        params.append(brand)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [_row_to_indicator(r) for r in rows]


def count_indicators(brand: str = None) -> int:
    """Total indicators in the database (or for one brand if given)."""
    conn = get_connection()
    if brand:
        n = conn.execute("SELECT COUNT(*) FROM indicators WHERE brand = ?",
                         (brand,)).fetchone()[0]
    else:
        n = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    conn.close()
    return n


def clear_brand(brand: str) -> int:
    """
    Delete every indicator for a given brand. Used at the start of a pipeline
    run so the brand's data is rebuilt from scratch while other brands'
    historical data is preserved.
    """
    conn = get_connection()
    cur = conn.execute("DELETE FROM indicators WHERE brand = ?", (brand,))
    conn.commit()
    deleted = cur.rowcount
    conn.close()
    return deleted


def list_brands() -> list:
    """
    Return the distinct brands present in the database, newest first.
    Each entry is a dict with keys: brand, last_seen, n.
    """
    conn = get_connection()
    rows = conn.execute(
        "SELECT brand, MAX(collected_at) AS last_seen, COUNT(*) AS n "
        "FROM indicators WHERE brand != '' "
        "GROUP BY brand ORDER BY last_seen DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
