import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.asset_matcher import AssetMatcher, normalize_name, aliases_for
from utils.storage import Storage
from models.vulnerability import Vulnerability


def test_normalize_lowercase():
    assert normalize_name("Google Chrome") == "google chrome"


def test_normalize_underscores():
    assert normalize_name("node_js") == "node js"


def test_normalize_hyphens():
    assert normalize_name("my-product") == "my product"


def test_normalize_empty():
    assert normalize_name("") == ""


def test_aliases():
    aliases = aliases_for("Chrome")
    assert "google chrome" in aliases
    assert "chromium" in aliases


def test_exact_vendor_match():
    storage = Storage()
    matcher = AssetMatcher(storage)
    vulns = [
        Vulnerability("CVE-2024-1", "Chrome", "browser", "Chrome Vuln", "2024-01-01", "HIGH"),
    ]
    matches = matcher.match(vulns, ["Chrome"])
    assert len(matches) == 1
    assert matches[0]["asset"] == "Chrome"


def test_no_match():
    storage = Storage()
    matcher = AssetMatcher(storage)
    vulns = [
        Vulnerability("CVE-2024-1", "Adobe", "Reader", "PDF vuln", "2024-01-01", "HIGH"),
    ]
    matches = matcher.match(vulns, ["Chrome"])
    assert len(matches) == 0


def test_case_insensitive_match():
    storage = Storage()
    matcher = AssetMatcher(storage)
    vulns = [
        Vulnerability("CVE-2024-1", "apache", "http_server", "Apache vuln", "2024-01-01", "HIGH"),
    ]
    matches = matcher.match(vulns, ["Apache"])
    assert len(matches) == 1


def test_normalized_match():
    storage = Storage()
    matcher = AssetMatcher(storage)
    vulns = [
        Vulnerability("CVE-2024-1", "nodejs", "node_js", "Node vuln", "2024-01-01", "HIGH"),
    ]
    matches = matcher.match(vulns, ["Node.js"])
    assert len(matches) == 1


def test_risk_level_critical():
    v = Vulnerability("CVE-2024-1", "V", "P", "N", "2024-01-01", "CRITICAL")
    assert AssetMatcher._risk_level(v) == "CRITICAL"


def test_risk_level_high():
    v = Vulnerability("CVE-2024-1", "V", "P", "N", "2024-01-01", "HIGH")
    assert AssetMatcher._risk_level(v) == "HIGH"


def test_risk_level_medium_becomes_unknown():
    v = Vulnerability("CVE-2024-1", "V", "P", "N", "2024-01-01", "MEDIUM")
    assert AssetMatcher._risk_level(v) == "UNKNOWN"


def test_no_false_positive():
    storage = Storage()
    matcher = AssetMatcher(storage)
    vulns = [
        Vulnerability("CVE-2024-1", "Microsoft", "office", "Office vuln", "2024-01-01", "HIGH"),
    ]
    matches = matcher.match(vulns, ["Apache"])
    assert len(matches) == 0
