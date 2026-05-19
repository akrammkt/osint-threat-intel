# OSINT-Based Threat Intelligence for Early Detection of Cyber Threat Campaigns

A modular Python pipeline that monitors open-source intelligence (OSINT)
sources to detect phishing and brand-impersonation campaigns during their
staging phase — before the attack goes live.

4th-year Cybersecurity Engineering project — Université Internationale de Rabat.

## Concept

Attackers preparing a phishing campaign register look-alike domains and obtain
TLS certificates for them days before sending any emails. Those actions are
publicly observable. This tool collects that public evidence, scores how
dangerous each domain is, groups related domains into campaigns, and raises
early-warning alerts — implementing the threat-intelligence lifecycle:
collection, processing, analysis, and dissemination.

## Pipeline stages

1. **Collection** — gathers suspicious domains from two OSINT sources:
   Certificate Transparency logs (crt.sh) and active typosquatting discovery
   (dnstwist).
2. **Processing & enrichment** — normalizes domains, removes duplicates, and
   enriches each with WHOIS data and a brand-similarity score.
3. **Analysis & scoring** — computes a 0–100 early-warning risk score and
   clusters related domains into campaigns by shared infrastructure.
4. **Dissemination** — a Streamlit dashboard, threshold alerting, and IOC
   report export (CSV / JSON).

## Project structure

- `core/` — shared Indicator schema and SQLite database layer
- `collection/` — OSINT collectors and their runner
- `processing/` — normalization and enrichment
- `scoring/` — risk scoring and campaign correlation
- `dissemination/` — alerting and IOC export
- `config.py` — protected-brand asset profile and settings
- `main.py` — runs the full pipeline end to end
- `dashboard.py` — the Streamlit threat console

## Setup

    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt

## Usage

Run the full pipeline (collection → processing → scoring):

    python main.py

Launch the dashboard:

    streamlit run dashboard.py

## Team

Akram Mokhtari, Omar Errai, Asmae Hritine Hajar Zeyni.