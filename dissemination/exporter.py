"""
dissemination/exporter.py
--------------------------
IOC (Indicator of Compromise) report exporter.

The final step of the threat-intelligence lifecycle is DISSEMINATION:
delivering the findings in a form other systems and people can act on.
This module exports the high-confidence indicators as:

  - CSV  : for analysts and spreadsheets
  - JSON : for ingestion by other security tools (SIEM, blocklists)

Only indicators at or above EXPORT_MIN_SCORE are exported - the report is a
curated threat feed, not a raw dump.
"""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

EXPORT_MIN_SCORE = 50   # only HIGH and CRITICAL indicators go in the report
EXPORT_DIR = Path(__file__).resolve().parent.parent / "exports"


def _exportable(indicators: list) -> list:
    """Filter and sort the indicators that belong in the IOC report."""
    rows = [i for i in indicators if i.score >= EXPORT_MIN_SCORE]
    rows.sort(key=lambda i: i.score, reverse=True)
    return rows


def export_csv(indicators: list) -> Path:
    """Write the IOC report as a CSV file. Returns the file path."""
    EXPORT_DIR.mkdir(exist_ok=True)
    rows = _exportable(indicators)
    path = EXPORT_DIR / "ioc_report.csv"

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["domain", "score", "risk_level", "campaign",
                         "domain_age_days", "brand_similarity", "sources",
                         "first_seen"])
        for i in rows:
            e = i.enrichment
            writer.writerow([i.value, i.score, e.get("risk_level", ""),
                             i.campaign_id or "", e.get("domain_age_days", ""),
                             e.get("brand_similarity", ""), i.source,
                             i.first_seen])
    return path


def export_json(indicators: list) -> Path:
    """Write the IOC report as a JSON file. Returns the file path."""
    EXPORT_DIR.mkdir(exist_ok=True)
    rows = _exportable(indicators)
    path = EXPORT_DIR / "ioc_report.json"

    report = {
        "report_type": "OSINT phishing-campaign IOC report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "indicator_count": len(rows),
        "indicators": [
            {
                "domain": i.value,
                "score": i.score,
                "risk_level": i.enrichment.get("risk_level", ""),
                "campaign": i.campaign_id or None,
                "domain_age_days": i.enrichment.get("domain_age_days"),
                "brand_similarity": i.enrichment.get("brand_similarity"),
                "sources": i.source.split(","),
                "first_seen": i.first_seen,
            }
            for i in rows
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return path