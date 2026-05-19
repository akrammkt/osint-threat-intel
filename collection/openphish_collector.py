"""
collection/openphish_collector.py
-----------------------------------
Collector for the OpenPhish community feed - a public list of URLs that have
been CONFIRMED as active phishing pages.

While the crt.sh collector finds domains that are merely *suspicious* (a
look-alike certificate was issued), OpenPhish provides domains that are
*confirmed malicious*. This gives the pipeline two things:

  1. Corroboration - if a domain appears in both crt.sh and OpenPhish, our
     confidence that it belongs to a real campaign is much higher.
  2. A confirmed-phishing signal that the scoring stage weights heavily.

The feed is plain text: one phishing URL per line. We keep only the URLs
whose hostname impersonates our protected brand.
"""

import re
import time
import requests
from urllib.parse import urlparse
from core.schema import Indicator
from config import BRAND_KEYWORDS, LEGITIMATE_DOMAINS, OPENPHISH_TIMEOUT, OPENPHISH_RETRIES

OPENPHISH_URL = "https://openphish.com/feed.txt"
SOURCE_NAME = "openphish"
RETRY_DELAY = 4   # seconds between retries

# Same domain-validity check used by the crt.sh collector.
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$")


def _fetch_feed() -> list:
    """Download the OpenPhish community feed as a list of URL strings."""
    headers = {"User-Agent": "OSINT-ThreatIntel-Project/1.0"}
    for attempt in range(1, OPENPHISH_RETRIES + 1):
        try:
            response = requests.get(
                OPENPHISH_URL, headers=headers, timeout=OPENPHISH_TIMEOUT
            )
            response.raise_for_status()
            return response.text.splitlines()
        except requests.RequestException as e:
            print(f"  [openphish] attempt {attempt}/{OPENPHISH_RETRIES} failed: {e}")
            if attempt < OPENPHISH_RETRIES:
                time.sleep(RETRY_DELAY)
    print("  [openphish] feed unavailable - skipping this source")
    return []


def _hostname(url: str) -> str:
    """Extract the lowercase hostname from a URL (drops port and a leading 'www.')."""
    host = (urlparse(url).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _is_legitimate(domain: str) -> bool:
    """True if the domain is one of our own legitimate domains (not a threat)."""
    return any(domain == legit or domain.endswith("." + legit)
               for legit in LEGITIMATE_DOMAINS)


def collect() -> list:
    """
    Run the OpenPhish collector.
    Returns Indicator objects for confirmed phishing domains that impersonate
    our protected brand.
    """
    print("  [openphish] downloading community phishing feed ...")
    urls = _fetch_feed()
    print(f"  [openphish] feed contains {len(urls)} phishing URLs")

    indicators = {}
    matched = 0

    for url in urls:
        url = url.strip()
        if not url:
            continue
        host = _hostname(url)
        if not host or not DOMAIN_RE.match(host):
            continue
        # keep only phishing domains that impersonate our protected brand
        if not any(keyword in host for keyword in BRAND_KEYWORDS):
            continue
        if _is_legitimate(host):
            continue

        matched += 1
        if host in indicators:        # same domain, several phishing URLs
            continue
        indicators[host] = Indicator(
            value=host,
            source=SOURCE_NAME,
            raw={"phishing_url": url, "feed": "openphish_community"},
        )

    print(f"  [openphish] {matched} URLs impersonate the brand "
          f"-> {len(indicators)} unique phishing domains")
    return list(indicators.values())