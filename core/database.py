"""
core/database.py
-----------------
SQLite persistence layer for the OSINT threat-intelligence pipeline.

Every pipeline stage talks to the same SQLite database file through these
functions. Complex fields (raw, enrichment) are stored as JSON text.
"""

import sqlite3
import json
from pathlib import Path
from core.schema import Indicator

# The database file lives in the project's data/ folder.
DB_PATH = Path(__file__).resolve().parent.parent / "data" / "indicators.db"


def get_connection() -> sqlite3.Connection:
    """Open a connection to the SQLite database (creates the file if needed)."""
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row   # lets us access columns by name
    return conn


def init_db() -> None:
    """Create the indicators table if it does not already exist."""
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS indicators (
            id             TEXT PRIMARY KEY,
            value          TEXT UNIQUE,
            source         TEXT,
            indicator_type TEXT,
            first_seen     TEXT,
            collected_at   TEXT,
            raw            TEXT,
            enrichment     TEXT,
            score          REAL,
            campaign_id    TEXT,
            status         TEXT
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
    """
    Insert an indicator, or replace it if one with the same id already exists.
    Because the id is derived from the domain, this doubles as an update:
    the processing and scoring stages just re-save the same indicator.
    """
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO indicators
        (id, value, source, indicator_type, first_seen, collected_at,
         raw, enrichment, score, campaign_id, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        indicator.id, indicator.value, indicator.source, indicator.indicator_type,
        indicator.first_seen, indicator.collected_at,
        json.dumps(indicator.raw), json.dumps(indicator.enrichment),
        indicator.score, indicator.campaign_id, indicator.status,
    ))
    conn.commit()
    conn.close()


def save_many(indicators: list) -> int:
    """Save a list of indicators. Returns how many were processed."""
    for ind in indicators:
        save_indicator(ind)
    return len(indicators)


def get_indicators(status: str = None) -> list:
    """
    Fetch indicators from the database.
    If `status` is given, only indicators at that stage are returned
    (e.g. "collected", "enriched", "scored").
    """
    conn = get_connection()
    if status:
        rows = conn.execute(
            "SELECT * FROM indicators WHERE status = ?", (status,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM indicators").fetchall()
    conn.close()
    return [_row_to_indicator(r) for r in rows]


def count_indicators() -> int:
    """Return the total number of indicators stored."""
    conn = get_connection()
    n = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    conn.close()
    return n