import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.asset_matcher import AssetMatcher, normalize_name, aliases_for
from utils.storage import Storage
from models.vulnerability import Vulnerability


class TestNormalizeName:
    def test_lowercase(self):
        assert normalize_name("Google Chrome") == "google chrome"

    def test_strip_whitespace(self):
        assert normalize_name("  Apache  ") == "apache"

    def test_underscores(self):
        assert normalize_name("node_js") == "node js"

    def test_hyphens(self):
        assert normalize_name("my-product") == "my product"

    def test_multiple_spaces(self):
        assert normalize_name("windows   server") == "windows server"

    def test_empty(self):
        assert normalize_name("") == ""

    def test_none(self):
        assert normalize_name(None) == ""


class TestAliasesFor:
    def test_known_alias(self):
        aliases = aliases_for("Chrome")
        assert "google chrome" in aliases
        assert "chromium" in aliases

    def test_unknown_asset(self):
        aliases = aliases_for("SomeUnknownSoftware")
        assert len(aliases) == 1

    def test_apache_aliases(self):
        aliases = aliases_for("Apache")
        normalized = [normalize_name(a) for a in aliases]
        assert "apache" in normalized
        assert "apache http server" in normalized
        assert "apache tomcat" in normalized


class TestAssetMatcherMatch:
    def setup_method(self):
        self.storage = Storage()

    def test_exact_vendor_match(self):
        matcher = AssetMatcher(self.storage)
        vulns = [
            Vulnerability("CVE-2024-1", "Chrome", "browser", "Chrome Vuln", "2024-01-01", "HIGH"),
        ]
        matches = matcher.match(vulns, ["Chrome"])
        assert len(matches) == 1
        assert matches[0]["asset"] == "Chrome"

    def test_product_match(self):
        matcher = AssetMatcher(self.storage)
        vulns = [
            Vulnerability("CVE-2024-1", "Google", "Chrome", "Browser vuln", "2024-01-01", "HIGH"),
        ]
        matches = matcher.match(vulns, ["Chrome"])
        assert len(matches) == 1

    def test_no_match(self):
        matcher = AssetMatcher(self.storage)
        vulns = [
            Vulnerability("CVE-2024-1", "Adobe", "Reader", "PDF vuln", "2024-01-01", "HIGH"),
        ]
        matches = matcher.match(vulns, ["Chrome"])
        assert len(matches) == 0

    def test_case_insensitive_match(self):
        matcher = AssetMatcher(self.storage)
        vulns = [
            Vulnerability("CVE-2024-1", "apache", "http_server", "Apache vuln", "2024-01-01", "HIGH"),
        ]
        matches = matcher.match(vulns, ["Apache"])
        assert len(matches) == 1

    def test_normalized_match_with_underscore(self):
        matcher = AssetMatcher(self.storage)
        vulns = [
            Vulnerability("CVE-2024-1", "nodejs", "node_js", "Node vuln", "2024-01-01", "HIGH"),
        ]
        matches = matcher.match(vulns, ["Node.js"])
        assert len(matches) == 1

    def test_normalized_match_with_hyphen(self):
        matcher = AssetMatcher(self.storage)
        vulns = [
            Vulnerability("CVE-2024-1", "", "open-ssl", "SSL vuln", "2024-01-01", "HIGH"),
        ]
        matches = matcher.match(vulns, ["OpenSSL"])
        assert len(matches) == 1

    def test_multiple_assets(self):
        matcher = AssetMatcher(self.storage)
        vulns = [
            Vulnerability("CVE-2024-1", "Chrome", "browser", "Vuln1", "2024-01-01", "HIGH"),
            Vulnerability("CVE-2024-2", "Apache", "httpd", "Vuln2", "2024-01-02", "LOW"),
        ]
        matches = matcher.match(vulns, ["Chrome", "Apache"])
        assert len(matches) == 2

    def test_empty_assets(self):
        matcher = AssetMatcher(self.storage)
        vulns = [Vulnerability("CVE-2024-1", "Chrome", "browser", "V", "2024-01-01", "HIGH")]
        matches = matcher.match(vulns, [])
        assert len(matches) == 0

    def test_empty_vulns(self):
        matcher = AssetMatcher(self.storage)
        matches = matcher.match([], ["Chrome"])
        assert len(matches) == 0


class TestRiskLevel:
    def test_critical_risk(self):
        v = Vulnerability("CVE-2024-1", "V", "P", "N", "2024-01-01", "CRITICAL")
        assert AssetMatcher._risk_level(v) == "CRITICAL"

    def test_high_risk(self):
        v = Vulnerability("CVE-2024-1", "V", "P", "N", "2024-01-01", "HIGH")
        assert AssetMatcher._risk_level(v) == "HIGH"

    def test_medium_risk_becomes_unknown(self):
        v = Vulnerability("CVE-2024-1", "V", "P", "N", "2024-01-01", "MEDIUM")
        assert AssetMatcher._risk_level(v) == "UNKNOWN"

    def test_low_risk_becomes_unknown(self):
        v = Vulnerability("CVE-2024-1", "V", "P", "N", "2024-01-01", "LOW")
        assert AssetMatcher._risk_level(v) == "UNKNOWN"

    def test_unknown_risk(self):
        v = Vulnerability("CVE-2024-1", "V", "P", "N", "2024-01-01", "UNKNOWN")
        assert AssetMatcher._risk_level(v) == "UNKNOWN"


class TestFalsePositiveReduction:
    def setup_method(self):
        self.storage = Storage()

    def test_no_match_for_unrelated_asset(self):
        matcher = AssetMatcher(self.storage)
        vulns = [
            Vulnerability("CVE-2024-1", "Cisco", "ios", "Network vuln", "2024-01-01", "CRITICAL"),
        ]
        matches = matcher.match(vulns, ["Chrome"])
        assert len(matches) == 0

    def test_generic_vendor_no_false_positive(self):
        matcher = AssetMatcher(self.storage)
        vulns = [
            Vulnerability("CVE-2024-1", "Microsoft", "office", "Office vuln", "2024-01-01", "HIGH"),
        ]
        matches = matcher.match(vulns, ["Apache"])
        assert len(matches) == 0

    def test_vulnerability_name_substring(self):
        matcher = AssetMatcher(self.storage)
        vulns = [
            Vulnerability("CVE-2024-1", "Other", "Other", "Chrome browser RCE", "2024-01-01", "HIGH"),
        ]
        matches = matcher.match(vulns, ["Chrome"])
        assert len(matches) == 1


class TestAssetSorting:
    def setup_method(self):
        self.storage = Storage()

    def test_sorted_by_risk(self):
        matcher = AssetMatcher(self.storage)
        vulns = [
            Vulnerability("CVE-2024-1", "Chrome", "P", "N", "2024-01-01", "LOW"),
            Vulnerability("CVE-2024-2", "Chrome", "P", "N", "2024-01-02", "CRITICAL"),
            Vulnerability("CVE-2024-3", "Chrome", "P", "N", "2024-01-03", "HIGH"),
        ]
        matches = matcher.match(vulns, ["Chrome"])
        risks = [m["risk_level"] for m in matches]
        assert risks[0] == "CRITICAL"
        assert risks[1] == "HIGH"
