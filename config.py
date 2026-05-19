"""
config.py
----------
Central configuration for the OSINT threat-intelligence pipeline.

The "asset profile" describes the organisation we are protecting: the brand
attackers are likely to impersonate, its legitimate domains, and the keywords
we monitor across OSINT sources.
"""

# --- Protected asset profile ---
# The brand we are defending. Attackers register look-alike domains of this
# brand to run phishing campaigns. Change this to monitor a different brand.
PROTECTED_BRAND = "paypal"

# The real, legitimate domains owned by the brand. These are never flagged
# as threats - they are the baseline we compare suspicious domains against.
LEGITIMATE_DOMAINS = [
    "paypal.com", "paypal.me", "paypal.co.uk", "paypal.de",
    "paypal.fr", "paypal.es", "paypal.it", "paypal.nl", "paypal.ca",
    "paypalcorp.com", "paypalinc.com", "paypalcredit.com",
    "paypal-engineering.com", "paypalobjects.com", "paypal-prod.com",
]

# Keywords the collectors search for across OSINT sources.
BRAND_KEYWORDS = ["paypal"]

# --- Collection settings ---
CRTSH_MAX_RESULTS = 200      # max certificates processed per crt.sh query
CRTSH_TIMEOUT = 60           # seconds to wait for a crt.sh response

# --- dnstwist collector settings ---
DNSTWIST_DOMAIN = "paypal.com"   # the brand domain whose look-alikes we generate
DNSTWIST_THREADS = 50            # parallel DNS lookups (higher = faster)