import sys
import os
import csv
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.report_generator import ReportGenerator, MATCHED_HEADERS, FULL_HEADERS


def test_export_matched():
    report = ReportGenerator()
    rows = [
        {"cve_id": "CVE-2024-1", "vendor": "V", "product": "P", "risk_level": "HIGH", "date_detected": "2024-01-01"},
        {"cve_id": "CVE-2024-2", "vendor": "V2", "product": "P2", "risk_level": "CRITICAL", "date_detected": "2024-01-02"},
    ]
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        path = f.name
    try:
        result = report.export_matched_csv(rows, path)
        assert result == path
        with open(path) as f:
            reader = csv.DictReader(f)
            assert reader.fieldnames == MATCHED_HEADERS
            lines = list(reader)
            assert len(lines) == 2
            assert lines[0]["CVE_ID"] == "CVE-2024-1"
            assert lines[0]["Risk_Level"] == "HIGH"
    finally:
        os.unlink(path)


def test_export_full():
    report = ReportGenerator()
    rows = [
        {"cve_id": "CVE-2024-1", "vendor": "V", "product": "P",
         "vulnerability_name": "N", "severity": "HIGH", "date_added": "2024-01-01"},
    ]
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        path = f.name
    try:
        result = report.export_full_csv(rows, path)
        assert result == path
        with open(path) as f:
            reader = csv.DictReader(f)
            assert reader.fieldnames == FULL_HEADERS
            assert len(list(reader)) == 1
    finally:
        os.unlink(path)


def test_summarize():
    entries = [
        {"risk_level": "HIGH"},
        {"risk_level": "HIGH"},
        {"risk_level": "CRITICAL"},
    ]
    result = ReportGenerator.summarize(entries)
    assert result["HIGH"] == 2
    assert result["CRITICAL"] == 1


def test_summarize_empty():
    result = ReportGenerator.summarize([])
    assert result == {}
