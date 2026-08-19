# TH-IGN — ThreatIntel Engine

A Python tool that scrapes CVE databases and known exploit feeds, matches them against your monitored assets, and exports structured CSV reports.

## Project Structure

```
TH-IGN/
├── main.py                     # CLI entry point and demonstrations
├── requirements.txt            # Python dependencies
├── README.md
├── .gitignore
├── data/
│   ├── monitored_assets.json   # List of monitored software assets
│   ├── vulnerabilities.json    # Stored CVE database (generated)
│   └── matched_vulnerabilities.json  # Last scan results (generated)
├── models/
│   └── vulnerability.py        # Vulnerability data class
├── scrapers/
│   └── threat_scraper.py       # CVE feed scrapers (CISA KEV, NVD, CISA Advisories)
├── utils/
│   ├── asset_matcher.py        # Asset-to-vulnerability matching logic
│   ├── report_generator.py     # CSV report generation
│   └── storage.py              # JSON file storage and duplicate handling
├── tests/
│   ├── test_vulnerability.py   # Vulnerability model tests
│   ├── test_threat_scraper.py  # Scraper parsing tests
│   ├── test_storage.py         # Storage and merge tests
│   ├── test_asset_matcher.py   # Asset matching tests
│   └── test_report_generator.py # CSV export tests
└── screenshots/
    ├── ss1.png
    ├── ss2.png
    └── ss3.png
```

## Module Overview

- **models/vulnerability.py** — `Vulnerability` class with severity normalization, CVE ID validation, and serialization.
- **scrapers/threat_scraper.py** — `ThreatScraper` fetches from CISA KEV, NVD (recent 7 days), and CISA Advisories. Reports per-source success/failure.
- **utils/asset_matcher.py** — `AssetMatcher` normalizes names (spaces, hyphens, underscores, aliases) and matches vulnerabilities to monitored assets. Risk is set to HIGH or CRITICAL only.
- **utils/storage.py** — `Storage` handles JSON read/write with atomic saves, corruption recovery, and duplicate-prevention during merge.
- **utils/report_generator.py** — `ReportGenerator` exports matched, full, or search results to CSV with proper headers.
- **main.py** — Interactive CLI with menu `[1]`–`[5]` and a `--demo` mode for milestone demonstrations.

## Step 1 — Installation & Setup

### Linux / macOS

```bash
git clone https://github.com/r1vita/TH-IGN.git
cd TH-IGN
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
git clone https://github.com/r1vita/TH-IGN.git
cd TH-IGN
python -m venv venv
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Step 2 — Run

### Interactive Mode

```bash
python3 main.py
```

### Milestone Demonstrations

```bash
python3 main.py --demo
```

### Run Tests

```bash
python3 -m pytest tests/ -v
```

## CLI Menu

```
  Main Menu

  > [1] Fetch & Update Threat Feeds
      Download latest CVE data

    [2] Scan Local Assets Against Threat Database
        Match assets against known CVEs

    [3] Search Vulnerability by Keyword/Vendor
        Find vulnerabilities

    [4] Export Threat Report to CSV
        Save data to a CSV file

    [5] Exit
        Close ThreatIntel Engine
```

Type `a`, `r`, `v`, or `t` from the main prompt for the Tools menu (Add Asset, Remove Asset, View All CVEs).

## Threat Intelligence Sources

| Source | URL | Type |
|--------|-----|------|
| CISA Known Exploited Vulnerabilities | `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | JSON |
| NVD CVE API 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0` | JSON (last 7 days) |
| CISA Advisories | `cisa.gov/cybersecurity-advisories/all.xml` | XML (HTML fallback) |

## How Asset Matching Works

1. Each monitored asset name is normalized (lowercased, whitespace standardized) and expanded using known aliases (e.g., "Chrome" matches "google chrome", "chromium").
2. Vulnerability vendor, product, and description fields are normalized the same way.
3. A match occurs when an asset alias is a substring of (or equals) any vulnerability field.
4. Matched threats are assigned risk levels: only CRITICAL and HIGH severity vulns are flagged; all others are marked UNKNOWN.

## How Risk Levels Are Determined

Risk comes from the vulnerability's original severity as reported by the source (CISA KEV estimate or NVD CVSS score). Matched threats inherit the severity but risk is capped: only CRITICAL and HIGH severities are reported as risks. MEDIUM, LOW, and UNKNOWN severities are not flagged as active risks.

## Generated Files

| File | Location | Description |
|------|----------|-------------|
| `vulnerabilities.json` | `data/` | All fetched CVE records |
| `matched_vulnerabilities.json` | `data/` | Results of last asset scan |
| `threat_report.csv` | user-chosen path | Exported CSV report |

## Monitored Assets

Default assets in `data/monitored_assets.json`:

```json
["Chrome", "Apache", "Python", "Windows Server", "OpenSSL", "Nginx", "Firefox", "PostgreSQL"]
```

Add or remove assets via the Tools menu or by editing the JSON file directly.

## Screenshots

| Main Interface | Asset Overview | Report/Export Action |
| :---: | :---: | :---: |
| <img src="screenshots/ss1.png" width="300" alt="Main Interface"> | <img src="screenshots/ss2.png" width="300" alt="Asset Selection"> | <img src="screenshots/ss3.png" width="300" alt="Report Export"> |
