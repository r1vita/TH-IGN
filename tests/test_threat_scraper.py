import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scrapers.threat_scraper import ThreatScraper, FetchResult
from models.vulnerability import Vulnerability


def test_fetch_result_success():
    r = FetchResult("TestSource", vulns=[1, 2, 3])
    assert r.success is True
    assert r.partial is False


def test_fetch_result_error():
    r = FetchResult("TestSource", error="Connection failed")
    assert r.success is False


def test_parse_nvd_basic():
    scraper = ThreatScraper()
    data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-12345",
                    "descriptions": [{"lang": "en", "value": "Test vuln description"}],
                    "metrics": {},
                    "configurations": [],
                    "published": "2024-01-15T10:00:00",
                }
            }
        ]
    }
    vulns = scraper._parse_nvd_response(data)
    assert len(vulns) == 1
    assert vulns[0].cve_id == "CVE-2024-12345"


def test_parse_nvd_with_cpe():
    scraper = ThreatScraper()
    data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-99999",
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": {},
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {"criteria": "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"}
                                    ]
                                }
                            ]
                        }
                    ],
                    "published": "2024-02-01T00:00:00",
                }
            }
        ]
    }
    vulns = scraper._parse_nvd_response(data)
    assert vulns[0].vendor == "Apache"
    assert vulns[0].product == "http_server"


def test_nvd_severity_v31():
    scraper = ThreatScraper()
    metrics = {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL", "baseScore": 9.8}}]}
    assert scraper._nvd_severity(metrics) == "CRITICAL"


def test_nvd_severity_v2():
    # v2 severity is at metric level, not in cvssData
    scraper = ThreatScraper()
    metrics = {"cvssMetricV2": [{"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}]}
    assert scraper._nvd_severity(metrics) == "HIGH"


def test_nvd_severity_unknown():
    scraper = ThreatScraper()
    assert scraper._nvd_severity({}) == "UNKNOWN"


def test_parse_kev():
    scraper = ThreatScraper()
    data = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1234",
                "vendorProject": "TestVendor",
                "product": "TestProduct",
                "vulnerabilityName": "Test Vuln",
                "dateAdded": "2024-01-01",
                "shortDescription": "Remote code execution vulnerability",
            }
        ]
    }
    vulns = scraper._parse_kev_json(data)
    assert len(vulns) == 1
    assert vulns[0].cve_id == "CVE-2024-1234"
    assert vulns[0].vendor == "TestVendor"


def test_estimate_severity():
    assert ThreatScraper._estimate_severity("Microsoft", "something") == "CRITICAL"
    assert ThreatScraper._estimate_severity("Unknown", "remote code execution in app") == "CRITICAL"
    assert ThreatScraper._estimate_severity("AcmeCorp", "minor bug") == "HIGH"


def test_find_cve():
    record = {"cve id": "CVE-2024-1234"}
    assert ThreatScraper._find_cve(record) == "CVE-2024-1234"


def test_find_cve_in_value():
    record = {"info": "Details about CVE-2024-5678"}
    assert ThreatScraper._find_cve(record) == "CVE-2024-5678"


def test_deduplication():
    scraper = ThreatScraper()
    vulns = [
        Vulnerability("CVE-2024-1", "V", "P", "N1", "2024-01-01", "HIGH"),
        Vulnerability("CVE-2024-1", "V2", "P2", "N2", "2024-01-02", "LOW"),
        Vulnerability("CVE-2024-2", "V", "P", "N3", "2024-01-03", "CRITICAL"),
    ]
    result = scraper._deduplicate(vulns)
    assert len(result) == 2
    assert result[0].cve_id == "CVE-2024-1"
