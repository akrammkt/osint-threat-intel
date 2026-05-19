"""
dashboard.py
-------------
Streamlit dashboard - the dissemination layer's visual interface.

Presents the scored indicators from the database as an interactive threat
console: summary metrics, filters, a ranked threat table, the campaign view,
charts, an alert panel, and IOC report export.

Run from the project root with:  streamlit run dashboard.py
"""

import pandas as pd
import plotly.express as px
import streamlit as st

from core.database import get_indicators, count_indicators
from config import PROTECTED_BRAND
from dissemination.alerting import get_alerts, write_alert_log, ALERT_THRESHOLD
from dissemination.exporter import export_csv, export_json


# --------------------------------------------------------------------------
# Page setup
# --------------------------------------------------------------------------
st.set_page_config(page_title="OSINT Threat Intelligence", layout="wide")


@st.cache_data
def load_data() -> pd.DataFrame:
    """Load scored indicators from the database into a DataFrame."""
    indicators = get_indicators(status="scored")
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


# --------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------
st.title("OSINT-Based Threat Intelligence")
st.caption(f"Early detection of phishing campaigns impersonating "
           f"'{PROTECTED_BRAND}'")

df = load_data()

if df.empty:
    st.warning("No scored indicators found. Run `python main.py` first to "
               "populate the database, then refresh this page.")
    st.stop()

# Keep the original objects around for alerting and export.
scored_indicators = get_indicators(status="scored")


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

# --- Tab 1: ranked threat table -------------------------------------------
with tab1:
    st.subheader(f"Ranked threats ({len(view)} shown)")
    st.dataframe(
        view[["domain", "score", "risk_level", "campaign",
              "domain_age_days", "brand_similarity", "sources", "first_seen"]],
        width="stretch",
        hide_index=True,
    )

# --- Tab 2: campaign view -------------------------------------------------
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

# --- Tab 3: analytics charts ----------------------------------------------
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

# --- Tab 4: alerts and export ---------------------------------------------
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