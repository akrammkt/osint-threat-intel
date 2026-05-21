"""
dashboard.py
-------------
Streamlit dashboard with on-demand pipeline scanning.

A search bar at the top lets the user enter any domain and run the full
threat-intelligence pipeline against it without touching the terminal.
Past scans are preserved per-brand in the database; the sidebar selector
switches between every brand that has been scanned.

Run from the project root with:  streamlit run dashboard.py
"""

import re
import pandas as pd
import plotly.express as px
import streamlit as st

from core.database import (
    get_indicators, list_brands, init_db, clear_brand,
)
from core.schema import BrandProfile
from config import KNOWN_PROFILES
from collection.runner import run_collection
from processing.runner import run_processing
from scoring.runner import run_scoring
from dissemination.alerting import get_alerts, write_alert_log, ALERT_THRESHOLD
from dissemination.exporter import export_csv, export_json


st.set_page_config(page_title="OSINT Threat Intelligence", layout="wide")


# --------------------------------------------------------------------------
# Input handling and pipeline orchestration
# --------------------------------------------------------------------------
_INPUT_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$")


def normalize_input(raw: str) -> str:
    """
    Clean and validate a user-supplied brand domain.

    Accepts URLs ('https://www.paypal.com/'), bare domains ('uir.ac.ma'),
    and trailing-slash variants. Returns the normalised domain or raises
    ValueError if it does not look like a real domain.
    """
    s = raw.strip().lower()
    for scheme in ("https://", "http://", "ftp://"):
        if s.startswith(scheme):
            s = s[len(scheme):]
    if s.startswith("www."):
        s = s[4:]
    s = s.split("/")[0]
    if not _INPUT_DOMAIN_RE.match(s):
        raise ValueError(
            f"'{raw}' does not look like a valid domain. "
            "Try something like 'paypal.com' or 'uir.ac.ma'."
        )
    return s


def resolve_brand_profile(domain: str) -> BrandProfile:
    """Use the curated profile for known brands, otherwise auto-derive one."""
    domain = domain.strip().lower()
    if domain in KNOWN_PROFILES:
        return KNOWN_PROFILES[domain]
    return BrandProfile.from_domain(domain)


def run_pipeline_with_status(domain_input: str):
    """Run all three pipeline stages and stream progress into an st.status panel."""
    init_db()
    profile = resolve_brand_profile(domain_input)
    deleted = clear_brand(profile.name)

    with st.status(f"Scanning '{profile.domain}'...", expanded=True) as status:
        st.write(f"Brand resolved: **{profile.name}** (canonical domain "
                 f"`{profile.domain}`)")
        if deleted:
            st.write(f"Cleared {deleted} previous indicator(s) for this brand")

        st.write("**Stage 1/3 — Collection** (typically 1–3 minutes)")
        st.write("Querying crt.sh and generating dnstwist look-alikes...")
        n_collected = run_collection(profile)
        st.write(f"✓ Collected **{n_collected}** unique indicators")

        st.write("**Stage 2/3 — Processing & enrichment** (typically 1–3 minutes)")
        st.write("Normalising, deduplicating, and looking up WHOIS data...")
        n_enriched = run_processing(profile)
        st.write(f"✓ Enriched **{n_enriched}** unique registered domains")

        st.write("**Stage 3/3 — Scoring & correlation** (seconds)")
        n_scored = run_scoring(profile)
        st.write(f"✓ Scored **{n_scored}** indicators")

        status.update(label=f"Scan complete: {profile.domain}",
                      state="complete", expanded=False)

    st.cache_data.clear()
    st.session_state["selected_brand"] = profile.name


# --------------------------------------------------------------------------
# Header + search bar
# --------------------------------------------------------------------------
st.title("OSINT-Based Threat Intelligence")
st.caption("Early detection of phishing campaigns by monitoring open-source intelligence")

with st.container(border=True):
    st.subheader("Monitor a brand")
    st.markdown(
        "Enter a domain to scan for look-alike registrations and potential "
        "phishing infrastructure. A full scan takes 3–6 minutes."
    )

    col_input, col_btn = st.columns([5, 1])
    with col_input:
        user_input = st.text_input(
            "Brand domain",
            placeholder="e.g. paypal.com, uir.ac.ma, your-bank.com",
            label_visibility="collapsed",
        )
    with col_btn:
        scan_clicked = st.button("Scan", type="primary", width="stretch")

    if scan_clicked:
        if not user_input.strip():
            st.error("Please enter a domain.")
        else:
            try:
                cleaned = normalize_input(user_input)
            except ValueError as e:
                st.error(str(e))
            else:
                try:
                    run_pipeline_with_status(cleaned)
                    st.rerun()
                except Exception as e:
                    st.error(f"Pipeline failed: {e}")


# --------------------------------------------------------------------------
# Brand selector (sidebar)
# --------------------------------------------------------------------------
brands = list_brands()
if not brands:
    st.info("No scan results yet. Enter a domain above to start monitoring.")
    st.stop()

brand_names = [b["brand"] for b in brands]
default_idx = 0
preselected = st.session_state.get("selected_brand")
if preselected and preselected in brand_names:
    default_idx = brand_names.index(preselected)

st.sidebar.header("Brand")
current_brand = st.sidebar.selectbox(
    "Brand to display",
    options=brand_names,
    index=default_idx,
)
st.sidebar.caption(f"{len(brands)} brand(s) scanned so far")


# --------------------------------------------------------------------------
# Load data for the selected brand
# --------------------------------------------------------------------------
@st.cache_data
def load_data(brand: str) -> pd.DataFrame:
    # observation stage advances status from 'scored' to 'observed', so include both
    indicators = get_indicators(status="scored") + get_indicators(status="observed")
    rows = []
    for i in indicators:
        e = i.enrichment
        obs = i.observation or {}
        rows.append({
            "domain": i.value,
            "score": i.score,
            "risk_level": e.get("risk_level", "LOW"),
            "campaign": i.campaign_id or "",
            "stage": obs.get("stage", "—"),
            "stage_confidence": obs.get("confidence", 0.0),
            "scheme": obs.get("scheme", ""),
            "status_code": obs.get("status_code"),
            "favicon_hash": obs.get("favicon_hash", ""),
            "domain_age_days": e.get("domain_age_days"),
            "brand_similarity": e.get("brand_similarity", 0.0),
            "typo_technique": e.get("typo_technique", "n/a"),
            "sources": i.source,
            "first_seen": i.first_seen[:10],
            "observation_signals": ", ".join(obs.get("signals", [])),
        })
    return pd.DataFrame(rows)


df = load_data(current_brand)
if df.empty:
    st.warning(f"No scored indicators for '{current_brand}'.")
    st.stop()

scored_indicators = get_indicators(status="scored", brand=current_brand)

st.subheader(f"Results for: `{current_brand}`")


# --------------------------------------------------------------------------
# Summary metrics
# --------------------------------------------------------------------------
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total indicators", len(df))
col2.metric("Critical", int((df.risk_level == "CRITICAL").sum()))
col3.metric("High", int((df.risk_level == "HIGH").sum()))
col4.metric("Campaigns", df[df.campaign != ""].campaign.nunique())
col5.metric("Alerts", int((df.score >= ALERT_THRESHOLD).sum()))

# Prominent banner for confirmed phishing pages
phishing_rows = df[df.stage.isin(["likely_phishing", "live_phishing"])]
if not phishing_rows.empty:
    n = len(phishing_rows)
    with st.container(border=True):
        st.markdown(f"### 🚨 {n} confirmed phishing page{'s' if n != 1 else ''} detected")
        st.caption("These domains were observed serving brand-impersonating "
                   "content with password fields. Treat as live threats.")
        for _, row in phishing_rows.iterrows():
            signals = []
            if row.get("has_password", False):
                signals.append("password field")
            if row.get("brand_on_page", False):
                signals.append("brand on page")
            if row.get("page_title"):
                signals.append(f'"{row.page_title[:60]}"')
            sig_str = " · ".join(signals) if signals else "see Observation tab"
            st.error(f"**`{row.domain}`** — score **{row.score}** — "
                     f"campaign {row.campaign or '–'} — {sig_str}")

st.divider()


# --------------------------------------------------------------------------
# Sidebar filters
# --------------------------------------------------------------------------
st.sidebar.header("Filters")
levels = st.sidebar.multiselect(
    "Risk level",
    options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    default=["CRITICAL", "HIGH"],
)
min_score = st.sidebar.slider("Minimum score", 0, 100, 0)
search = st.sidebar.text_input("Search domain")

view = df.copy()
if levels:
    view = view[view.risk_level.isin(levels)]
view = view[view.score >= min_score]
if search:
    view = view[view.domain.str.contains(search, case=False, na=False)]
view = view.sort_values("score", ascending=False)



# Pipeline architecture explainer
with st.expander("ℹ️ How this tool works", expanded=False):
    st.markdown("""
    The pipeline runs **four sequential stages** against any monitored brand:

    1. **Collection** — gathers candidate domains from two complementary OSINT sources:
       Certificate Transparency logs (passive, via crt.sh) and active typosquatting
       discovery (dnstwist generates ~1,370 look-alikes, DNS confirms which are registered).

    2. **Processing** — collapses subdomains to their registered domain (Public Suffix List),
       deduplicates across sources, and enriches each with WHOIS data (age, registrant) and
       a brand-similarity score (Levenshtein + substring matching).

    3. **Scoring** — combines four signals into a 0–100 early-warning score:
       brand similarity (35 pts), domain youth (35 pts), source corroboration (20 pts),
       active discovery (10 pts). High-scoring domains are clustered into **campaigns** by
       shared infrastructure (IP, registrant).

    4. **Observation** — fetches the homepage of each HIGH/CRITICAL domain, extracts content
       features (page title, password fields, brand mentions), hashes the favicon, and
       classifies what the domain is **currently being used for**.

    *Total scan time: 4–8 minutes per brand. All data is stored locally in SQLite.*
    """)

# --------------------------------------------------------------------------
# Tabs
# --------------------------------------------------------------------------
tab1, tab2, tab3, tab4, tab5 = st.tabs(
    ["Threat list", "Campaigns", "Observation", "Analytics", "Alerts & export"]
)

with tab1:
    st.subheader(f"Ranked threats ({len(view)} shown)")
    event = st.dataframe(
    view[cols],
    width="stretch",
    hide_index=True,
    on_select="rerun",
    selection_mode="single-row",
    key="threat_table_select",
)

# Detail view for the selected row
if event and event.selection and event.selection.rows:
    sel = view.iloc[event.selection.rows[0]]
    with st.container(border=True):
        st.subheader(f"Details: `{sel.domain}`")
        c1, c2, c3 = st.columns(3)
        c1.metric("Score", sel.score)
        c2.metric("Risk", sel.risk_level)
        c3.metric("Stage", sel.get("stage") or "not observed")

        st.write(f"**Sources:** {sel.sources}")
        st.write(f"**First seen:** {sel.first_seen}")
        age = sel.get("domain_age_days")
        st.write(f"**Domain age:** {int(age)} days" if pd.notna(age) else "**Domain age:** unknown")
        st.write(f"**Brand similarity:** {sel.brand_similarity:.2f}")
        st.write(f"**Campaign:** {sel.campaign or '—'}")
        if sel.get("page_title"):
            st.write(f"**Page title:** {sel.page_title}")
        if sel.get("final_url"):
            st.write(f"**Final URL:** `{sel.final_url}`")
        if sel.get("favicon_hash"):
            st.write(f"**Favicon hash:** `{sel.favicon_hash}`")

with tab2:
    campaigns = df[df.campaign != ""]
    if campaigns.empty:
        st.info("No multi-domain campaigns identified in this run.")
    else:
        st.subheader(f"{campaigns.campaign.nunique()} campaign(s) identified")
        for cid in sorted(campaigns.campaign.unique()):
            members = campaigns[campaigns.campaign == cid].sort_values(
                "score", ascending=False)
            with st.expander(f"{cid} - {len(members)} domains "
                             f"(top score {members.score.max()})"):
                st.dataframe(
                    members[["domain", "score", "risk_level",
                             "domain_age_days", "sources"]],
                    width="stretch", hide_index=True,
                )

# --- Tab 3: observation (what suspicious domains are being used for) ---
with tab3:
    observed = view[view.stage != "—"]
    st.subheader(f"Live observation of {len(observed)} high-scoring domains")
    if observed.empty:
        st.info("No observations yet. Run the pipeline (`python main.py <brand>`) "
                "and the observation stage will fetch each high-scoring domain.")
    else:
        # Stage-by-stage breakdown
        stage_colors = {
            "live_phishing":      "🔴 LIVE PHISHING",
            "parked":             "🟡 parked",
            "under_construction": "🟠 under construction",
            "redirect":           "🔁 redirect",
            "live":               "🟢 live (unrelated)",
            "error":              "⚠️ http error",
            "no_response":        "⚫ no response",
        }
        stage_counts = observed.stage.value_counts()
        cols = st.columns(min(len(stage_counts), 5) or 1)
        for idx, (stage, count) in enumerate(stage_counts.items()):
            cols[idx % len(cols)].metric(stage_colors.get(stage, stage), count)

        st.divider()
        st.dataframe(
            observed[["domain", "stage", "score", "risk_level", "scheme",
                      "status_code", "observation_signals"]],
            use_container_width=True, hide_index=True,
        )


with tab4:
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Risk level distribution")
        counts = (df.risk_level.value_counts()
                  .reindex(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
                  .fillna(0).reset_index())
        counts.columns = ["risk_level", "count"]
        fig = px.bar(counts, x="risk_level", y="count",
                     color="risk_level",
                     color_discrete_map={"CRITICAL": "#c0392b",
                                         "HIGH": "#e67e22",
                                         "MEDIUM": "#f1c40f",
                                         "LOW": "#27ae60"})
        st.plotly_chart(fig, width="stretch")
    with c2:
        st.subheader("Score distribution")
        fig2 = px.histogram(df, x="score", nbins=20)
        st.plotly_chart(fig2, width="stretch")

    st.subheader("Detections over time (by first seen)")
    timeline = df.groupby("first_seen").size().reset_index(name="count")
    fig3 = px.line(timeline, x="first_seen", y="count", markers=True)
    st.plotly_chart(fig3, width="stretch")

with tab5:
    st.subheader(f"Active alerts (score >= {ALERT_THRESHOLD})")
    alerts = get_alerts(scored_indicators)
    if alerts:
        for a in alerts:
            st.error(f"**{a.value}** - score {a.score} "
                     f"[{a.enrichment.get('risk_level')}] "
                     f"- campaign {a.campaign_id or 'none'}")
    else:
        st.success("No indicators currently exceed the alert threshold.")

    st.divider()
    st.subheader("Export IOC report")
    st.write("Export the HIGH and CRITICAL indicators as a threat-intel "
             "report for analysts or other security tools.")

    cexp1, cexp2, cexp3 = st.columns(3)
    if cexp1.button("Export CSV"):
        path = export_csv(scored_indicators)
        st.success(f"CSV report written to: {path}")
    if cexp2.button("Export JSON"):
        path = export_json(scored_indicators)
        st.success(f"JSON report written to: {path}")
    if cexp3.button("Write alert log"):
        n = write_alert_log(scored_indicators)
        st.success(f"{n} alerts written to the alert log.")
