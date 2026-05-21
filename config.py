"""
config.py
----------
Pipeline-wide settings, independent of any specific protected brand.

Brand-specific settings (the protected domain, keywords, legitimate variants)
now live in core.schema.BrandProfile. Build a profile from a single domain
with BrandProfile.from_domain('paypal.com'). For well-known brands where we
have curated lists of legitimate domains, see KNOWN_PROFILES below.
"""

from core.schema import BrandProfile

# Default brand monitored when no domain is given on the command line.
DEFAULT_BRAND = "paypal.com"

# Curated profiles for well-known brands. Each entry overrides the auto-derived
# profile with hand-picked legitimate domain lists, so PayPal's own
# corporate and international sites are never flagged as look-alikes.
# Add new entries here to give other brands the same level of polish.
KNOWN_PROFILES = {
    "paypal.com": BrandProfile(
        name="paypal",
        domain="paypal.com",
        keywords=["paypal"],
        legitimate_domains=[
            "paypal.com", "paypal.me", "paypal.co.uk", "paypal.de",
            "paypal.fr", "paypal.es", "paypal.it", "paypal.nl", "paypal.ca",
            "paypalcorp.com", "paypalinc.com", "paypalcredit.com",
            "paypal-engineering.com", "paypalobjects.com", "paypal-prod.com",
        ],
    ),
}

# --- crt.sh collector settings ---
CRTSH_MAX_RESULTS = 200
CRTSH_TIMEOUT = 60

# --- dnstwist collector settings ---
DNSTWIST_THREADS = 50
