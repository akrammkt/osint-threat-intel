"""
collection/dnstwist_collector.py
----------------------------------
Active-discovery collector built on dnstwist.

The crt.sh collector is PASSIVE - it waits for a look-alike domain to appear
in an external data source. This collector is ACTIVE: using dnstwist, it
generates every plausible typosquatting variation of the protected brand's
domain - character omissions, insertions, homoglyphs, hyphenation, TLD swaps,
bitsquatting, and more - then checks which of those candidate domains are
actually REGISTERED (i.e. resolve in DNS).

A registered look-alike domain is exactly the infrastructure an attacker
prepares before launching a phishing campaign, so this surfaces threats that
no external feed has reported yet.
"""

import socket
from concurrent.futures import ThreadPoolExecutor

import dnstwist

from core.schema import Indicator
from config import LEGITIMATE_DOMAINS, DNSTWIST_DOMAIN, DNSTWIST_THREADS

SOURCE_NAME = "dnstwist"
DNS_TIMEOUT = 5   # seconds before giving up on a single DNS lookup


def _is_legitimate(domain: str) -> bool:
    """True if the domain is one of our own legitimate domains (not a threat)."""
    return any(domain == legit or domain.endswith("." + legit)
               for legit in LEGITIMATE_DOMAINS)


def _resolve(domain: str):
    """
    Return the IPv4 address a domain resolves to, or None if it does not
    resolve. A domain that resolves is registered and has live infrastructure.
    """
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, socket.timeout, UnicodeError, OSError):
        return None


def collect() -> list:
    """
    Generate typosquatting permutations of the protected brand domain and
    return Indicator objects for the ones that are actually registered.
    """
    # 1. Generate the candidate look-alike domains (offline, instant).
    print(f"  [dnstwist] generating look-alike domains for '{DNSTWIST_DOMAIN}' ...")
    fuzzer = dnstwist.Fuzzer(DNSTWIST_DOMAIN)
    fuzzer.generate()
    permutations = fuzzer.permutations()

    # drop the original brand domain itself (its fuzzer is tagged "*original")
    candidates = [p for p in permutations if not p["fuzzer"].startswith("*")]
    print(f"  [dnstwist] {len(candidates)} candidate domains generated")

    # 2. Check which candidates are actually registered (DNS resolves).
    print("  [dnstwist] checking which are registered (this can take 1-3 min) ...")
    socket.setdefaulttimeout(DNS_TIMEOUT)
    domains = [p["domain"] for p in candidates]
    with ThreadPoolExecutor(max_workers=DNSTWIST_THREADS) as pool:
        ip_addresses = list(pool.map(_resolve, domains))

    # 3. Build an Indicator for every registered look-alike domain.
    indicators = {}
    for perm, ip in zip(candidates, ip_addresses):
        domain = perm["domain"].strip().lower()
        if ip is None:                    # not registered - skip
            continue
        if _is_legitimate(domain):        # ignore our own domains
            continue
        if domain in indicators:
            continue
        indicators[domain] = Indicator(
            value=domain,
            source=SOURCE_NAME,
            raw={
                "fuzzer": perm["fuzzer"],     # the typosquatting technique used
                "resolved_ip": ip,
                "discovery": "dnstwist_permutation",
            },
        )

    print(f"  [dnstwist] {len(indicators)} registered look-alike domains found")
    return list(indicators.values())