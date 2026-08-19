import re
import warnings
from datetime import datetime, timedelta, timezone

import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

from models.vulnerability import Vulnerability

KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_HTML_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_ADVISORIES_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

HIGH_IMPACT_VENDORS = {
    "microsoft", "adobe", "oracle", "vmware", "citrix", "fortinet",
    "palo alto", "cisco", "apple", "solarwinds", "ivanti", "progress", "google",
}

CRITICAL_HINTS = (
    "remote code execution", "unauthenticated", "arbitrary code",
    "privilege escalation", "full compromise", "ransomware",
)


class FetchResult:
    def __init__(self, source, vulns=None, error=None):
        self.source = source
        self.vulns = vulns or []
        self.error = error
        self.success = error is None
        self.partial = error is not None and len(self.vulns) > 0


class ThreatScraper:

    def __init__(self, timeout=25, user_agent="ThreatIntelEngine/1.0"):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

    def scrape_all(self):
        all_vulns = []
        results = []
        sources = [
            ("CISA KEV", self.scrape_kev_catalog),
            ("NVD Recent", self.scrape_nvd),
            ("CISA Advisories", self.scrape_cisa_advisories),
        ]
        for name, func in sources:
            try:
                vulns = func()
                all_vulns.extend(vulns)
                results.append(FetchResult(name, vulns=vulns))
            except requests.exceptions.ConnectionError as e:
                results.append(FetchResult(name, error=f"Connection failed: {e}"))
            except requests.exceptions.Timeout as e:
                results.append(FetchResult(name, error=f"Request timed out: {e}"))
            except requests.exceptions.RequestException as e:
                results.append(FetchResult(name, error=f"Network error: {e}"))
            except Exception as e:
                results.append(FetchResult(name, error=f"Parse error: {e}"))

        deduped = self._deduplicate(all_vulns)
        return deduped, results

    def _deduplicate(self, vulns):
        seen = {}
        for v in vulns:
            key = v.cve_id.upper()
            if key and key not in seen:
                seen[key] = v
        return list(seen.values())

    def scrape_kev_catalog(self):
        try:
            r = self.session.get(KEV_JSON_URL, timeout=self.timeout)
            r.raise_for_status()
            return self._parse_kev_json(r.json())
        except Exception:
            return self.scrape_html_feed(KEV_HTML_URL)

    def _parse_kev_json(self, data):
        vulns = []
        for e in data.get("vulnerabilities", []):
            cve_id = e.get("cveID", "")
            if not cve_id:
                continue
            cve_match = CVE_RE.search(cve_id)
            if cve_match:
                cve_id = cve_match.group(0)
            else:
                continue
            vulns.append(Vulnerability(
                cve_id=cve_id,
                vendor=e.get("vendorProject", ""),
                product=e.get("product", ""),
                vulnerability_name=e.get("vulnerabilityName", ""),
                date_added=e.get("dateAdded", ""),
                severity=self._estimate_severity(
                    e.get("vendorProject", ""),
                    e.get("shortDescription", ""),
                ),
            ))
        return vulns

    def scrape_html_feed(self, url):
        r = self.session.get(url, timeout=self.timeout)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        vulns = []
        for table in soup.find_all("table"):
            vulns.extend(self._parse_table(table))
        return vulns

    def _parse_table(self, table):
        headers = [th.get_text(" ", strip=True).lower() for th in table.find_all("th")]
        if not headers:
            return []
        vulns = []
        for row in table.find_all("tr"):
            cells = [td.get_text(" ", strip=True) for td in row.find_all("td")]
            if not cells:
                continue
            rec = dict(zip(headers, cells))
            cve = self._find_cve(rec)
            if not cve:
                continue
            cve_match = CVE_RE.search(cve)
            if cve_match:
                cve = cve_match.group(0)
            else:
                continue
            vulns.append(Vulnerability(
                cve_id=cve,
                vendor=self._find_column(rec, "vendor"),
                product=self._find_column(rec, "product"),
                vulnerability_name=self._find_column(rec, "name", "title"),
                date_added=self._find_column(rec, "date"),
                severity=self._estimate_severity(
                    self._find_column(rec, "vendor"),
                    self._find_column(rec, "name", "title"),
                ),
            ))
        return vulns

    def scrape_nvd(self):
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=7)
        params = {
            "resultsPerPage": 100,
            "startIndex": 0,
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        }
        r = self.session.get(NVD_API_URL, params=params, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        return self._parse_nvd_response(data)

    def _parse_nvd_response(self, data):
        vulns = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            descs = cve.get("descriptions", [])
            desc = ""
            for d in descs:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            severity = self._nvd_severity(cve.get("metrics", {}))
            vendor, product = self._nvd_vendor_product(cve)
            published = cve.get("published", "")[:10]
            vulns.append(Vulnerability(
                cve_id=cve_id,
                vendor=vendor,
                product=product,
                vulnerability_name=desc[:120] if desc else "",
                date_added=published,
                severity=severity,
            ))
        return vulns

    def _nvd_severity(self, metrics):
        for key in ("cvssMetricV31", "cvssMetricV30"):
            list_ = metrics.get(key, [])
            if not list_:
                continue
            cvss = list_[0].get("cvssData", {})
            sev = cvss.get("baseSeverity", "")
            if sev:
                return sev.upper()
            score = cvss.get("baseScore", 0)
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            return "LOW"

        v2_list = metrics.get("cvssMetricV2", [])
        if v2_list:
            v2_data = v2_list[0]
            sev = v2_data.get("baseSeverity", "")
            if sev:
                return sev.upper()
            cvss = v2_data.get("cvssData", {})
            score = cvss.get("baseScore", 0)
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            return "LOW"

        return "UNKNOWN"

    def _nvd_vendor_product(self, cve):
        configs = cve.get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        return parts[3].capitalize(), parts[4]
        return "", ""

    def scrape_cisa_advisories(self):
        r = self.session.get(CISA_ADVISORIES_URL, timeout=self.timeout)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        vulns = []
        for item in soup.find_all("item"):
            title = item.find("title")
            link = item.find("link")
            pub = item.find("pubDate")
            cve_id = ""
            if title:
                text = title.get_text()
                match = CVE_RE.search(text)
                if match:
                    cve_id = match.group(0)
            if not cve_id:
                desc_tag = item.find("description")
                if desc_tag:
                    text = desc_tag.get_text()
                    match = CVE_RE.search(text)
                    if match:
                        cve_id = match.group(0)
            if not cve_id:
                continue
            name = title.get_text().strip() if title else ""
            date_str = ""
            if pub:
                from email.utils import parsedate_to_datetime
                try:
                    date_str = parsedate_to_datetime(pub.get_text()).strftime("%Y-%m-%d")
                except Exception:
                    date_str = pub.get_text()[:10]
            vulns.append(Vulnerability(
                cve_id=cve_id,
                vendor="",
                product="",
                vulnerability_name=name[:120],
                date_added=date_str,
                severity="HIGH",
            ))
        return vulns

    @staticmethod
    def _find_cve(record):
        for key, value in record.items():
            if "cve" in key:
                match = CVE_RE.search(value)
                if match:
                    return match.group(0)
        for value in record.values():
            match = CVE_RE.search(str(value))
            if match:
                return match.group(0)
        return ""

    @staticmethod
    def _find_column(record, *names):
        for name in names:
            for key, value in record.items():
                if name in key:
                    return value
        return ""

    @staticmethod
    def _estimate_severity(vendor, description):
        v = (vendor or "").lower()
        d = (description or "").lower()
        if v in HIGH_IMPACT_VENDORS:
            return "CRITICAL"
        if any(h in d for h in CRITICAL_HINTS):
            return "CRITICAL"
        return "HIGH"
