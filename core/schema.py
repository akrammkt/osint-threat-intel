"""
core/schema.py
----------------
The Indicator schema - the shared contract every pipeline stage reads and writes.

An Indicator represents one piece of open-source intelligence: a suspicious domain
discovered by a collector, then progressively enriched and scored as it moves
through the pipeline.

Pipeline status flow:
    collected  ->  enriched  ->  scored
    (collection)   (processing)   (scoring)
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import hashlib


def _utc_now() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def make_id(value: str) -> str:
    """
    Build a stable, deterministic ID from an indicator's value.
    The same domain always produces the same ID, which makes
    deduplication across collectors automatic.
    """
    return hashlib.sha1(value.strip().lower().encode()).hexdigest()[:12]


@dataclass
class Indicator:
    # --- Core fields (set by the COLLECTION stage) ---
    value: str                                            # the suspicious domain
    source: str                                           # which collector found it
    indicator_type: str = "domain"                        # kind of indicator
    first_seen: str = field(default_factory=_utc_now)     # when the domain first appeared
    collected_at: str = field(default_factory=_utc_now)   # when our collector picked it up
    raw: dict = field(default_factory=dict)               # original source payload

    # --- Enrichment fields (set by the PROCESSING stage) ---
    enrichment: dict = field(default_factory=dict)        # domain_age_days, brand_similarity...

    # --- Analysis fields (set by the SCORING stage) ---
    score: float = 0.0                                    # early-warning risk score, 0-100
    campaign_id: str = ""                                 # cluster this indicator belongs to

    # --- Pipeline bookkeeping ---
    id: str = ""                                          # stable unique id (auto-filled)
    status: str = "collected"                             # collected -> enriched -> scored

    def __post_init__(self):
        # Normalise the domain and auto-generate the id if not provided.
        self.value = self.value.strip().lower()
        if not self.id:
            self.id = make_id(self.value)

    def to_dict(self) -> dict:
        """Return a plain dict - used for JSON export and database storage."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Indicator":
        """Rebuild an Indicator from a plain dict (loaded from JSON or the database)."""
        return cls(**data)