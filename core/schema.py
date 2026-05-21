"""
core/schema.py
----------------
Shared data types used by every stage of the pipeline.

  - Indicator     : one observed suspicious domain.
  - BrandProfile  : the asset profile a pipeline run is protecting.

Both are dataclasses so they can be serialised to/from the database trivially.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import hashlib

import tldextract


def _utc_now() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def make_id(value: str, brand: str = "") -> str:
    """
    Stable, deterministic ID derived from (brand, domain).
    Including the brand means the same domain monitored under two different
    brands gets two distinct ids and never accidentally merges.
    """
    key = f"{brand.lower()}|{value.strip().lower()}"
    return hashlib.sha1(key.encode()).hexdigest()[:12]


@dataclass
class Indicator:
    # --- Core fields (set by COLLECTION) ---
    value: str                                            # the suspicious domain
    source: str                                           # which collector found it
    brand: str = ""                                       # which brand this indicator protects
    indicator_type: str = "domain"
    first_seen: str = field(default_factory=_utc_now)
    collected_at: str = field(default_factory=_utc_now)
    raw: dict = field(default_factory=dict)

    # --- Enrichment fields (set by PROCESSING) ---
    enrichment: dict = field(default_factory=dict)

    # --- Analysis fields (set by SCORING) ---
    score: float = 0.0
    campaign_id: str = ""

    # --- Pipeline bookkeeping ---
    id: str = ""
    status: str = "collected"

    def __post_init__(self):
        self.value = self.value.strip().lower()
        if not self.id:
            self.id = make_id(self.value, self.brand)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Indicator":
        return cls(**data)


# Suffix-list extractor reused by BrandProfile derivation.
_extract = tldextract.TLDExtract()


@dataclass
class BrandProfile:
    """
    The asset profile a single pipeline run is protecting.

    For a fully-curated deployment this lists every legitimate domain the brand
    owns (preventing the pipeline from flagging the brand's own infrastructure).
    For the search-bar case we auto-derive a minimal profile from a single input
    domain via BrandProfile.from_domain(...).
    """
    name: str                                # short identifier, used in similarity scoring
    domain: str                              # canonical domain used by dnstwist generation
    keywords: list = field(default_factory=list)
    legitimate_domains: list = field(default_factory=list)

    @classmethod
    def from_domain(cls, raw: str) -> "BrandProfile":
        """
        Build a BrandProfile from a single domain.
            'paypal.com'  -> name='paypal', domain='paypal.com', keywords=['paypal']
            'uir.ac.ma'   -> name='uir',    domain='uir.ac.ma',  keywords=['uir']
        """
        clean = raw.strip().lower()
        parts = _extract(clean)
        name = parts.domain or clean.split(".")[0]
        canonical = parts.top_domain_under_public_suffix or clean
        return cls(
            name=name,
            domain=canonical,
            keywords=[name],
            legitimate_domains=[canonical],
        )
