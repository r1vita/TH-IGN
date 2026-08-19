# TH-IGN

Python script that scrapes CVE databases and known exploits, compares them against local assets, and exports CSV reports.

## Setup

### Linux / macOS

```bash
git clone https://github.com/r1vita/TH-IGN.git
cd TH-IGN
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
git clone https://github.com/r1vita/TH-IGN.git
cd TH-IGN
python -m venv venv
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Running

```bash
python3 main.py
```

This opens the interactive menu:

```
  [1] Fetch & Update Threat Feeds
  [2] Scan Local Assets Against Threat Database
  [3] Search Vulnerability by Keyword/Vendor
  [4] Export Threat Report to CSV
  [5] Exit
```

Type `a` from the main prompt for the Tools menu (add/remove assets, view all CVEs).

### Demo mode

```bash
python3 main.py --demo
```

Runs through all milestones and prints sample output.

### Tests

```bash
python3 -m pytest tests/ -v
```

## Overview

**Scraping**: Fetches from CISA KEV (JSON), NVD API (last 7 days), and CISA Advisories (XML). Each source is tried independently — if one fails you still get data from the others.

**Asset matching**: Your monitored assets (in `data/monitored_assets.json`) are matched against CVE vendor/product fields. Names are normalized so "node_js" matches "Node.js", "open-ssl" matches "OpenSSL", etc.

**Risk levels**: Matched threats are flagged as HIGH or CRITICAL based on the original severity. MEDIUM/LOW are not flagged as active risks.

**Storage**: Fetched CVEs go into `data/vulnerabilities.json`. Running fetch again won't create duplicates. CSV export goes wherever you choose.
