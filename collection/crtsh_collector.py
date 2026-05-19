"""
collection/crtsh_collector.py
-------------------------------
Collector for Certificate Transparency (CT) logs via the crt.sh public API.

Every TLS certificate issued for a domain is recorded publicly in CT logs.
When attackers prepare a phishing campaign, they register a look-alike domain
and obtain a certificate for it - often days before sending any emails.
By searching CT logs for our brand keyword, we catch those look-alike domains
during the staging phase, before the attack goes live. That is the "early
detection" at the heart of this project.
"""

import re
import time
import requests
from core.schema import Indicator
from config import BRAND_KEYWORDS, LEGITIMATE_DOMAINS, CRTSH_MAX_RESULTS, CRTSH_TIMEOUT

CRTSH_URL = "https://crt.sh/"
SOURCE_NAME = "crt.sh"

# crt.sh is a free, frequently-overloaded service that intermittently returns
# 404/502 errors or times out. Those failures are transient, so we retry.
CRTSH_RETRIES = 4          # how many times to try before giving up
CRTSH_RETRY_DELAY = 5      # base seconds between retries (grows each attempt)

# A valid domain: dot-separated labels, ending in a real TLD. Rejects junk
# like "paypal, inc." that crt.sh sometimes returns from certificate subjects.
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$")


def _query_crtsh(keyword: str) -> list:
    """
    Query the crt.sh JSON API for certificates whose domain matches a keyword.
    Retries transient failures (crt.sh is unreliable) with a growing delay.
    """
    params = {"q": keyword, "output": "json", "exclude": "expired"}
    headers = {"User-Agent": "OSINT-ThreatIntel-Project/1.0"}

    for attempt in range(1, CRTSH_RETRIES + 1):
        try:
            response = requests.get(
                CRTSH_URL, params=params, headers=headers, timeout=CRTSH_TIMEOUT
            )
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
    # name_value can hold several domains separated by newlines (the cert SANs)
    for name in cert_record.get("name_value", "").splitlines():
        name = name.strip().lower()
        if not name or name.startswith("*"):   # skip blanks and wildcard certs
            continue
        if name.startswith("www."):            # treat www.x.com and x.com as one
            name = name[4:]
        if not DOMAIN_RE.match(name):          # reject non-domain junk
            continue
        domains.add(name)
    return domains


def _is_legitimate(domain: str) -> bool:
    """True if the domain is one of our own legitimate domains (not a threat)."""
    return any(domain == legit or domain.endswith("." + legit)
               for legit in LEGITIMATE_DOMAINS)


def collect() -> list:
    """
    Run the crt.sh collector for every brand keyword.
    Returns a list of Indicator objects for the suspicious look-alike domains.
    """
    indicators = {}

    for keyword in BRAND_KEYWORDS:
        print(f"  [crt.sh] searching certificate logs for '{keyword}' ...")
        records = _query_crtsh(keyword)
        print(f"  [crt.sh] received {len(records)} certificate records")

        # newest certificates first, so we focus on the freshest registrations
        records.sort(
            key=lambda r: r.get("entry_timestamp") or r.get("not_before") or "",
            reverse=True,
        )

        for record in records[:CRTSH_MAX_RESULTS]:
            for domain in _extract_domains(record):
                if _is_legitimate(domain):       # ignore our own domains
                    continue
                if keyword not in domain:        # must actually contain the brand
                    continue
                if domain in indicators:         # already captured this domain
                    continue

                fields = dict(
                    value=domain,
                    source=SOURCE_NAME,
                    raw={
                        "issuer": record.get("issuer_name", ""),
                        "not_before": record.get("not_before", ""),
                        "not_after": record.get("not_after", ""),
                        "crtsh_id": record.get("id", ""),
                        "matched_keyword": keyword,
                    },
                )
                # use the certificate's not_before date as the "first seen" time
                not_before = record.get("not_before")
                if not_before:
                    fields["first_seen"] = not_before

                indicators[domain] = Indicator(**fields)

    return list(indicators.values())