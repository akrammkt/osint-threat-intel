"""
dissemination/alerting.py
--------------------------
Threshold alerting.

The pipeline produces a scored list, but an analyst should not have to read
200 rows to find the dangerous ones. The alerting layer applies a simple
rule - "any indicator scoring at or above ALERT_THRESHOLD is an alert" - and
writes those alerts to a log file so there is a persistent, timestamped
record of every early warning the system raised.
"""

from datetime import datetime
from pathlib import Path

# An indicator at or above this score triggers an alert.
ALERT_THRESHOLD = 75

# Alerts are appended here, one line per alert, newest run last.
ALERT_LOG = Path(__file__).resolve().parent.parent / "data" / "alerts.log"


def get_alerts(indicators: list) -> list:
    """Return the indicators whose score is at or above the alert threshold."""
    alerts = [i for i in indicators if i.score >= ALERT_THRESHOLD]
    alerts.sort(key=lambda i: i.score, reverse=True)
    return alerts


def write_alert_log(indicators: list) -> int:
    """
    Append every current alert to the alert log file with a timestamp.
    Returns the number of alerts written.
    """
    alerts = get_alerts(indicators)
    ALERT_LOG.parent.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(ALERT_LOG, "a", encoding="utf-8") as fh:
        for ind in alerts:
            level = ind.enrichment.get("risk_level", "?")
            fh.write(f"[{stamp}] ALERT {level} score={ind.score} "
                     f"domain={ind.value} campaign={ind.campaign_id or '-'}\n")

    return len(alerts)