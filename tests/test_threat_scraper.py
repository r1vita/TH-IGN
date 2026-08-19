import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scrapers.threat_scraper import ThreatScraper, FetchResult
from models.vulnerability import Vulnerability


class TestFetchResult:
    def test_success_result(self):
        r = FetchResult("TestSource", vulns=[1, 2, 3])
        assert r.success is True
        assert r.partial is False
        assert len(r.vulns) == 3

    def test_error_result(self):
        r = FetchResult("TestSource", error="Connection failed")
        assert r.success is False
        assert r.partial is False

    def test_partial_result(self):
        r = FetchResult("TestSource", vulns=[1], error="Partial failure")
        assert r.success is False
        assert r.partial is True


class TestParseNvdResponse:
    def setup_method(self):
        self.scraper = ThreatScraper()

    def test_empty_response(self):
        vulns = self.scraper._parse_nvd_response({})
        assert vulns == []

    def test_no_vulnerabilities(self):
        vulns = self.scraper._parse_nvd_response({"vulnerabilities": []})
        assert vulns == []

    def test_basic_parse(self):
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-12345",
                        "descriptions": [
                            {"lang": "en", "value": "Test vulnerability description"},
                        ],
                        "metrics": {},
                        "configurations": [],
                        "published": "2024-01-15T10:00:00",
                    }
                }
            ]
        }
        vulns = self.scraper._parse_nvd_response(data)
        assert len(vulns) == 1
        assert vulns[0].cve_id == "CVE-2024-12345"
        assert vulns[0].vendor == ""
        assert vulns[0].product == ""

    def test_parse_with_cpe_config(self):
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
        vulns = self.scraper._parse_nvd_response(data)
        assert vulns[0].vendor == "Apache"
        assert vulns[0].product == "http_server"

    def test_missing_cve_id_skipped(self):
        data = {
            "vulnerabilities": [
                {"cve": {"descriptions": [{"lang": "en", "value": "No ID"}], "metrics": {}, "configurations": [], "published": ""}}
            ]
        }
        vulns = self.scraper._parse_nvd_response(data)
        assert len(vulns) == 0

    def test_english_description_used(self):
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-11111",
                        "descriptions": [
                            {"lang": "es", "value": "Spanish desc"},
                            {"lang": "en", "value": "English desc"},
                        ],
                        "metrics": {},
                        "configurations": [],
                        "published": "2024-01-01T00:00:00",
                    }
                }
            ]
        }
        vulns = self.scraper._parse_nvd_response(data)
        assert vulns[0].vulnerability_name == "English desc"


class TestNvdSeverity:
    def setup_method(self):
        self.scraper = ThreatScraper()

    def test_cvss_v31_base_severity(self):
        metrics = {
            "cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL", "baseScore": 9.8}}]
        }
        assert self.scraper._nvd_severity(metrics) == "CRITICAL"

    def test_cvss_v31_from_score(self):
        metrics = {
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.1}}]
        }
        assert self.scraper._nvd_severity(metrics) == "CRITICAL"

    def test_cvss_v30_high(self):
        metrics = {
            "cvssMetricV30": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.5}}]
        }
        assert self.scraper._nvd_severity(metrics) == "HIGH"

    def test_cvss_v2_base_severity_at_top_level(self):
        """CVSS v2 severity is at the metric level, not in cvssData."""
        metrics = {
            "cvssMetricV2": [{"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}]
        }
        assert self.scraper._nvd_severity(metrics) == "HIGH"

    def test_cvss_v2_from_score(self):
        metrics = {
            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]
        }
        assert self.scraper._nvd_severity(metrics) == "MEDIUM"

    def test_cvss_v2_low(self):
        metrics = {
            "cvssMetricV2": [{"cvssData": {"baseScore": 2.0}}]
        }
        assert self.scraper._nvd_severity(metrics) == "LOW"

    def test_no_metrics(self):
        assert self.scraper._nvd_severity({}) == "UNKNOWN"

    def test_empty_metric_lists(self):
        metrics = {"cvssMetricV31": [], "cvssMetricV30": [], "cvssMetricV2": []}
        assert self.scraper._nvd_severity(metrics) == "UNKNOWN"


class TestParseKevenJson:
    def setup_method(self):
        self.scraper = ThreatScraper()

    def test_basic_parse(self):
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
        vulns = self.scraper._parse_kev_json(data)
        assert len(vulns) == 1
        assert vulns[0].cve_id == "CVE-2024-1234"
        assert vulns[0].vendor == "TestVendor"
        assert vulns[0].product == "TestProduct"

    def test_missing_cve_id_skipped(self):
        data = {
            "vulnerabilities": [
                {"vendorProject": "V", "product": "P", "vulnerabilityName": "N", "dateAdded": "2024-01-01"}
            ]
        }
        vulns = self.scraper._parse_kev_json(data)
        assert len(vulns) == 0

    def test_empty_vulnerabilities(self):
        vulns = self.scraper._parse_kev_json({"vulnerabilities": []})
        assert len(vulns) == 0

    def test_long_cve_id_preserved(self):
        data = {
            "vulnerabilities": [
                {"cveID": "CVE-2024-1234567", "vendorProject": "V", "product": "P",
                 "vulnerabilityName": "N", "dateAdded": "2024-01-01", "shortDescription": ""}
            ]
        }
        vulns = self.scraper._parse_kev_json(data)
        assert vulns[0].cve_id == "CVE-2024-1234567"


class TestEstimateSeverity:
    def test_high_impact_vendor(self):
        assert ThreatScraper._estimate_severity("Microsoft", "something") == "CRITICAL"

    def test_critical_hint(self):
        assert ThreatScraper._estimate_severity("Unknown", "remote code execution in app") == "CRITICAL"

    def test_default_high(self):
        assert ThreatScraper._estimate_severity("AcmeCorp", "minor bug") == "HIGH"


class TestFindCve:
    def test_cve_in_key(self):
        record = {"cve id": "CVE-2024-1234"}
        assert ThreatScraper._find_cve(record) == "CVE-2024-1234"

    def test_cve_in_value(self):
        record = {"info": "Details about CVE-2024-5678"}
        assert ThreatScraper._find_cve(record) == "CVE-2024-5678"

    def test_long_cve_in_value(self):
        record = {"info": "Details about CVE-2024-1234567"}
        assert ThreatScraper._find_cve(record) == "CVE-2024-1234567"

    def test_no_cve(self):
        record = {"info": "No CVE here"}
        assert ThreatScraper._find_cve(record) == ""


class TestNvdVendorProduct:
    def setup_method(self):
        self.scraper = ThreatScraper()

    def test_from_cpe(self):
        cve = {
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
            ]
        }
        vendor, product = self.scraper._nvd_vendor_product(cve)
        assert vendor == "Apache"
        assert product == "http_server"

    def test_no_config(self):
        vendor, product = self.scraper._nvd_vendor_product({"configurations": []})
        assert vendor == ""
        assert product == ""


class TestScrapeAllErrorHandling:
    def test_all_sources_fail(self):
        scraper = ThreatScraper()
        scraper.session.get = None
        try:
            vulns, results = scraper.scrape_all()
            assert len(results) == 3
            assert all(not r.success for r in results)
            assert len(vulns) == 0
        except Exception:
            pass

    def test_returns_results_on_success(self):
        scraper = ThreatScraper()
        original = scraper.scrape_kev_catalog
        scraper.scrape_kev_catalog = lambda: [Vulnerability("CVE-2024-1", "V", "P", "N", "2024-01-01", "HIGH")]
        scraper.scrape_nvd = lambda: []
        scraper.scrape_cisa_advisories = lambda: []
        vulns, results = scraper.scrape_all()
        assert any(r.success for r in results)
        assert len(vulns) == 1


class TestDeduplicate:
    def test_deduplication(self):
        scraper = ThreatScraper()
        vulns = [
            Vulnerability("CVE-2024-1", "V", "P", "N1", "2024-01-01", "HIGH"),
            Vulnerability("CVE-2024-1", "V2", "P2", "N2", "2024-01-02", "LOW"),
            Vulnerability("CVE-2024-2", "V", "P", "N3", "2024-01-03", "CRITICAL"),
        ]
        result = scraper._deduplicate(vulns)
        assert len(result) == 2
        assert result[0].cve_id == "CVE-2024-1"
        assert result[0].vulnerability_name == "N1"

    def test_empty_deduplication(self):
        scraper = ThreatScraper()
        assert scraper._deduplicate([]) == []
