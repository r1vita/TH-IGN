# TH-IGN

Simple Python script that scrapes CVE databases and compares to a local dabatase Assets and exports structured `.csv` reports.

## Screenshots
![CLI Interface Overview](screenshots/ss1.png)
![Asset Management View](screenshots/ss2.png)
![Report Export Action](screenshots/ss3.png)

## Step 1 - Installation & Setup

### Linux / macOS
```bash
git clone https://github.com
cd TH-IGN
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Windows
```powershell
git clone https://github.com
cd TH-IGN
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

## Step 2 - Run the .py file
```bash
python3 main.py
```
