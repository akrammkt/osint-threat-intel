"""
collection/dnstwist_collector.py
----------------------------------
Active-discovery collector built on dnstwist.

Now parameterised by a BrandProfile: dnstwist generates look-alikes of the
profile's canonical domain, the resolver checks which are registered, and the
profile's legitimate domains are filtered out of the result.
"""

import socket
from concurrent.futures import ThreadPoolExecutor

import dnstwist

from core.schema import Indicator, BrandProfile
from config import DNSTWIST_THREADS

SOURCE_NAME = "dnstwist"
DNS_TIMEOUT = 5


def _is_legitimate(domain: str, profile: BrandProfile) -> bool:
    """True if the domain is one of the profile's legitimate domains."""
    return any(domain == legit or domain.endswith("." + legit)
               for legit in profile.legitimate_domains)


def _resolve(domain: str):
    """Return the IPv4 address a domain resolves to, or None if it does not resolve."""
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, socket.timeout, UnicodeError, OSError):
        return None


def collect(profile: BrandProfile) -> list:
    """
    Generate typosquatting permutations of the profile's brand domain and
    return Indicator objects for those that are actually registered.
    """
    print(f"  [dnstwist] generating look-alike domains for '{profile.domain}' ...")
    fuzzer = dnstwist.Fuzzer(profile.domain)
    fuzzer.generate()
    permutations = fuzzer.permutations()

    candidates = [p for p in permutations if not p["fuzzer"].startswith("*")]
    print(f"  [dnstwist] {len(candidates)} candidate domains generated")

    print("  [dnstwist] checking which are registered (this can take 1-3 min) ...")
    socket.setdefaulttimeout(DNS_TIMEOUT)
    domains = [p["domain"] for p in candidates]
    with ThreadPoolExecutor(max_workers=DNSTWIST_THREADS) as pool:
        ip_addresses = list(pool.map(_resolve, domains))

    indicators = {}
    for perm, ip in zip(candidates, ip_addresses):
        domain = perm["domain"].strip().lower()
        if ip is None:
            continue
        if _is_legitimate(domain, profile):
            continue
        if domain in indicators:
            continue
        indicators[domain] = Indicator(
            value=domain,
            source=SOURCE_NAME,
            brand=profile.name,
            raw={
                "fuzzer": perm["fuzzer"],
                "resolved_ip": ip,
                "discovery": "dnstwist_permutation",
            },
        )

    print(f"  [dnstwist] {len(indicators)} registered look-alike domains found")
    return list(indicators.values())
