## Install

```bash
git clone https://github.com/r1vita/TH-IGN.git
cd TH-IGN
pip install -r requirements.txt
```

## Run

```bash
python3 main.py
```

## Monitored Assets

Add/Remove Assets directly from the CLI or edit `data/monitored_assets.json` with your desired content :

```json
EXAMPLE : ["Chrome", "Apache", "Python", "Windows Server"]
```

## Project Structure

```
main.py                      # CLI interface
models/vulnerability.py      # Vulnerability data 
scrapers/threat_scraper.py   # CVE Scraper
utils/storage.py             # JSON file read/write
utils/asset_matcher.py       # Matches CVEs to assets
utils/report_generator.py    # CSV export
data/monitored_assets.json   # Your desired assets list
data/vulnerabilities.json    # Stored CVE database (auto-generated)
data/threat_report.csv       # Exported report (auto-generated)
data/settings.json           # App settings (auto-generated)
```
