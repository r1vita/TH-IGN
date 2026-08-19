import sys
import os
import csv
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.report_generator import ReportGenerator, MATCHED_HEADERS, FULL_HEADERS, SEARCH_HEADERS


class TestReportGeneratorMatched:
    def test_export_matched(self):
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

    def test_export_matched_empty(self):
        report = ReportGenerator()
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            report.export_matched_csv([], path)
            with open(path) as f:
                reader = csv.DictReader(f)
                assert reader.fieldnames == MATCHED_HEADERS
                assert len(list(reader)) == 0
        finally:
            os.unlink(path)


class TestReportGeneratorFull:
    def test_export_full(self):
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
                lines = list(reader)
                assert len(lines) == 1
        finally:
            os.unlink(path)

    def test_export_full_empty(self):
        report = ReportGenerator()
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            report.export_full_csv([], path)
            with open(path) as f:
                reader = csv.DictReader(f)
                assert reader.fieldnames == FULL_HEADERS
                assert len(list(reader)) == 0
        finally:
            os.unlink(path)


class TestReportGeneratorSearch:
    def test_export_search(self):
        report = ReportGenerator()
        rows = [
            {"cve_id": "CVE-2024-1", "vendor": "V", "product": "P", "severity": "HIGH", "date_added": "2024-01-01"},
            {"cve_id": "CVE-2024-2", "vendor": "V2", "product": "P2", "severity": "LOW", "date_added": "2024-01-02"},
        ]
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            result = report.export_search_csv(rows, path)
            assert result == path
            with open(path) as f:
                reader = csv.DictReader(f)
                assert reader.fieldnames == SEARCH_HEADERS
                assert len(list(reader)) == 2
        finally:
            os.unlink(path)


class TestReportGeneratorMissingKeys:
    def test_handles_missing_keys(self):
        report = ReportGenerator()
        rows = [{"cve_id": "CVE-2024-1"}]
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            report.export_full_csv(rows, path)
            with open(path) as f:
                reader = csv.DictReader(f)
                lines = list(reader)
                assert lines[0]["Vendor"] == ""
                assert lines[0]["Severity"] == ""
        finally:
            os.unlink(path)


class TestSummarize:
    def test_summarize(self):
        entries = [
            {"risk_level": "HIGH"},
            {"risk_level": "HIGH"},
            {"risk_level": "CRITICAL"},
            {"risk_level": "LOW"},
        ]
        result = ReportGenerator.summarize(entries)
        assert result["HIGH"] == 2
        assert result["CRITICAL"] == 1
        assert result["LOW"] == 1

    def test_summarize_empty(self):
        result = ReportGenerator.summarize([])
        assert result == {}


class TestEnsureDir:
    def test_creates_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "subdir", "report.csv")
            ReportGenerator._ensure_dir(filepath)
            assert os.path.isdir(os.path.join(tmpdir, "subdir"))
