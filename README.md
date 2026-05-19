# OSINT-Based Threat Intelligence for Early Detection of Cyber Threat Campaigns

A modular Python pipeline that monitors open-source intelligence sources to detect
phishing and brand-impersonation campaigns in their early staging phase.

4th-year Cybersecurity Engineering project — Université Internationale de Rabat.

## Pipeline stages
1. Collection — gathers suspicious domain indicators from OSINT sources.
2. Processing & enrichment — normalizes, deduplicates, enriches with WHOIS and
   typosquatting-similarity scoring.
3. Analysis & scoring — early-warning risk score and campaign correlation.
4. Dissemination — Streamlit dashboard, alerting, and IOC report export.

## Team
Akram Mokhtari, Omar, Asmae, Hajar.