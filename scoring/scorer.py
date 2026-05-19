"""
scoring/scorer.py
------------------
The early-warning risk scoring engine - the analytical core of the pipeline.

Every enriched indicator carries several independent signals. On their own,
none is conclusive: a brand-similar domain might be 20 years old and harmless;
a brand-new domain might be unrelated to the brand. The scorer COMBINES the
signals into a single 0-100 score so that genuine emerging threats rise to
the top and noise sinks to the bottom.

Scoring model (weighted sum, capped at 100):

  brand similarity      0-35 pts   how convincingly the domain imitates the brand
  domain youth          0-35 pts   how recently it was registered (newest = highest)
  source corroboration  0-20 pts   flagged by more than one OSINT source
  active discovery      0-10 pts   dnstwist confirmed it is a registered typosquat

Domain youth carries the most weight alongside similarity, because newly
registered look-alike domains are the strongest early indicator of a phishing
campaign being staged.
"""

# --- Tunable weights (each is the maximum points that signal can contribute) ---
W_SIMILARITY    = 35
W_YOUTH         = 35
W_CORROBORATION = 20
W_DISCOVERY     = 10

# A domain older than this many days is treated as not a fresh threat.
YOUTH_HORIZON_DAYS = 365

# Score bands for human-readable risk levels.
RISK_BANDS = [(75, "CRITICAL"), (50, "HIGH"), (25, "MEDIUM"), (0, "LOW")]


def _similarity_points(enrichment: dict) -> float:
    """0-35 points scaled directly from the 0.0-1.0 brand similarity."""
    return enrichment.get("brand_similarity", 0.0) * W_SIMILARITY


def _youth_points(enrichment: dict) -> float:
    """
    0-35 points based on how young the domain is.
    A domain registered today scores the full 35; the score falls linearly
    to 0 at YOUTH_HORIZON_DAYS (one year) and stays 0 beyond that.

    If the WHOIS age is unknown, award a partial score: unknown age is mildly
    suspicious (phishing domains often hide WHOIS data) but not conclusive.
    """
    age = enrichment.get("domain_age_days")
    if age is None:
        return W_YOUTH * 0.4          # unknown age -> moderate, not full
    if age >= YOUTH_HORIZON_DAYS:
        return 0.0
    return W_YOUTH * (1 - age / YOUTH_HORIZON_DAYS)


def _corroboration_points(enrichment: dict) -> float:
    """0 or 20 points - full points if more than one source flagged the domain."""
    return W_CORROBORATION if enrichment.get("source_count", 1) > 1 else 0.0


def _discovery_points(enrichment: dict) -> float:
    """0 or 10 points - awarded if dnstwist confirmed a registered typosquat."""
    return W_DISCOVERY if enrichment.get("typo_technique", "n/a") != "n/a" else 0.0


def risk_level(score: float) -> str:
    """Map a numeric score to a human-readable risk band."""
    for threshold, label in RISK_BANDS:
        if score >= threshold:
            return label
    return "LOW"


def score_indicator(indicator):
    """
    Compute the 0-100 early-warning score for one enriched indicator.
    Stores the score, a per-signal breakdown, and the risk level, then
    advances the indicator's status to 'scored'.
    """
    e = indicator.enrichment

    breakdown = {
        "similarity":    round(_similarity_points(e), 1),
        "youth":         round(_youth_points(e), 1),
        "corroboration": round(_corroboration_points(e), 1),
        "discovery":     round(_discovery_points(e), 1),
    }
    total = min(sum(breakdown.values()), 100.0)

    indicator.score = round(total, 1)
    indicator.enrichment["score_breakdown"] = breakdown
    indicator.enrichment["risk_level"] = risk_level(total)
    indicator.status = "scored"
    return indicator