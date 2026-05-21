"""
scoring/correlator.py
----------------------
Campaign correlation - groups related indicators into "campaigns".

A single attacker rarely registers just one domain. They register a batch of
look-alikes and frequently host them on shared infrastructure. Reporting 200
isolated domains is noise; reporting "3 campaigns" is intelligence. This
module clusters indicators that share STRONG, evidence-based signals so an
analyst sees coordinated activity rather than a flat list.

Design note - why the rules are strict:
Earlier we tried correlating on "same typosquatting technique + similar
first-seen date". That over-clustered badly: most domains share the common
'homoglyph' technique, and domains with no WHOIS date share a default
first-seen timestamp, so dozens of unrelated domains collapsed into one giant
fake campaign. A real campaign needs HARD evidence of shared control, so we
correlate only on concrete infrastructure overlap:

  - shared resolved IP address      (same hosting server), OR
  - shared WHOIS registrant         (registered by the same entity)

These cannot happen by coincidence the way a shared technique can.
"""


def _campaign_keys(indicator) -> set:
    """
    Return the set of 'infrastructure keys' for an indicator. Two indicators
    that share any key are part of the same campaign.
    """
    keys = set()

    ip = indicator.raw.get("resolved_ip")
    if ip:
        keys.add(f"ip:{ip}")

    registrant = indicator.enrichment.get("whois_registrant")
    if registrant and registrant.lower() not in ("", "unknown", "n/a"):
        keys.add(f"reg:{registrant.lower()}")

    return keys


def correlate(indicators: list, min_score: int = 50) -> int:
    """
    Cluster scored indicators into campaigns by shared infrastructure.
    Writes a campaign_id onto each clustered indicator and returns the number
    of distinct campaigns found.

    Only indicators scoring >= min_score are eligible: low-score noise is
    never clustered. A campaign must contain at least 2 domains.
    """
    candidates = [i for i in indicators if i.score >= min_score]

    # union-find over the candidate list
    parent = list(range(len(candidates)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        parent[find(x)] = find(y)

    # map each infrastructure key to the candidates that have it
    key_to_indices = {}
    for idx, ind in enumerate(candidates):
        for key in _campaign_keys(ind):
            key_to_indices.setdefault(key, []).append(idx)

    # any candidates sharing a key belong to the same campaign
    for indices in key_to_indices.values():
        for other in indices[1:]:
            union(indices[0], other)

    # collect groups
    clusters = {}
    for idx in range(len(candidates)):
        clusters.setdefault(find(idx), []).append(idx)

    # assign campaign ids to groups of 2 or more
    campaign_number = 0
    for members in clusters.values():
        if len(members) >= 2:
            campaign_number += 1
            campaign_id = f"CAMP-{campaign_number:03d}"
            for idx in members:
                candidates[idx].campaign_id = campaign_id

    return campaign_number
