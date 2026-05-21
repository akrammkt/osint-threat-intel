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
    indicators = get_indicators(status="scored", brand=brand)
    rows = []
    for i in indicators:
        e = i.enrichment
        rows.append({
            "domain": i.value,
            "score": i.score,
            "risk_level": e.get("risk_level", "LOW"),
            "campaign": i.campaign_id or "",
            "domain_age_days": e.get("domain_age_days"),
            "brand_similarity": e.get("brand_similarity", 0.0),
            "typo_technique": e.get("typo_technique", "n/a"),
            "sources": i.source,
            "first_seen": i.first_seen[:10],
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


# --------------------------------------------------------------------------
# Tabs
# --------------------------------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs(
    ["Threat list", "Campaigns", "Analytics", "Alerts & export"]
)

with tab1:
    st.subheader(f"Ranked threats ({len(view)} shown)")
    st.dataframe(
        view[["domain", "score", "risk_level", "campaign",
              "domain_age_days", "brand_similarity", "sources", "first_seen"]],
        width="stretch",
        hide_index=True,
    )

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

with tab3:
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

with tab4:
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
