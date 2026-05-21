"""
collection/crtsh_collector.py
-------------------------------
Collector for Certificate Transparency logs via the crt.sh public API.

Now parameterised by a BrandProfile: collect(profile) runs the search using
the profile's keywords and filters out the profile's legitimate domains.
"""

import re
import time
import requests

from core.schema import Indicator, BrandProfile
from config import CRTSH_MAX_RESULTS, CRTSH_TIMEOUT

CRTSH_URL = "https://crt.sh/"
SOURCE_NAME = "crt.sh"

CRTSH_RETRIES = 4
CRTSH_RETRY_DELAY = 5

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$")


def _query_crtsh(keyword: str) -> list:
    """Query the crt.sh JSON API for certificates whose domain matches a keyword."""
    params = {"q": keyword, "output": "json", "exclude": "expired"}
    headers = {"User-Agent": "OSINT-ThreatIntel-Project/1.0"}
    for attempt in range(1, CRTSH_RETRIES + 1):
        try:
            response = requests.get(CRTSH_URL, params=params,
                                    headers=headers, timeout=CRTSH_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as e:
            print(f"  [crt.sh] attempt {attempt}/{CRTSH_RETRIES} failed: {e}")
            if attempt < CRTSH_RETRIES:
                wait = CRTSH_RETRY_DELAY * attempt
                print(f"  [crt.sh] retrying in {wait}s ...")
                time.sleep(wait)
    print(f"  [crt.sh] all attempts failed for '{keyword}' - skipping")
    return []


def _extract_domains(cert_record: dict) -> set:
    """Pull all usable domain names from one crt.sh certificate record."""
    domains = set()
    for name in cert_record.get("name_value", "").splitlines():
        name = name.strip().lower()
        if not name or name.startswith("*"):
            continue
        if name.startswith("www."):
            name = name[4:]
        if not DOMAIN_RE.match(name):
            continue
        domains.add(name)
    return domains


def _is_legitimate(domain: str, profile: BrandProfile) -> bool:
    """True if the domain is one of the profile's legitimate domains."""
    return any(domain == legit or domain.endswith("." + legit)
               for legit in profile.legitimate_domains)


def collect(profile: BrandProfile) -> list:
    """
    Run the crt.sh collector for every keyword in the given profile.
    Returns a list of Indicator objects for suspicious look-alike domains.
    """
    indicators = {}

    for keyword in profile.keywords:
        print(f"  [crt.sh] searching certificate logs for '{keyword}' ...")
        records = _query_crtsh(keyword)
        print(f"  [crt.sh] received {len(records)} certificate records")

        records.sort(
            key=lambda r: r.get("entry_timestamp") or r.get("not_before") or "",
            reverse=True,
        )

        for record in records[:CRTSH_MAX_RESULTS]:
            for domain in _extract_domains(record):
                if _is_legitimate(domain, profile):
                    continue
                if keyword not in domain:
                    continue
                if domain in indicators:
                    continue

                fields = dict(
                    value=domain,
                    source=SOURCE_NAME,
                    brand=profile.name,
                    raw={
                        "issuer": record.get("issuer_name", ""),
                        "not_before": record.get("not_before", ""),
                        "not_after": record.get("not_after", ""),
                        "crtsh_id": record.get("id", ""),
                        "matched_keyword": keyword,
                    },
                )
                not_before = record.get("not_before")
                if not_before:
                    fields["first_seen"] = not_before

                indicators[domain] = Indicator(**fields)

    return list(indicators.values())
