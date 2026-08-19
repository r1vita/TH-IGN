import csv
from collections import Counter
from utils.storage import Storage

MATCHED_HEADERS = ["CVE_ID", "Asset", "Vendor", "Product", "Risk_Level", "Date_Detected"]
FULL_HEADERS = ["CVE_ID", "Vendor", "Product", "Vulnerability_Name", "Severity", "Date_Added"]
SEARCH_HEADERS = ["CVE_ID", "Vendor", "Product", "Severity", "Date_Added"]


class ReportGenerator:

    def __init__(self, storage=None):
        self.storage = storage or Storage()

    def export_matched_csv(self, matched_entries, filepath):
        self._ensure_dir(filepath)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=MATCHED_HEADERS)
            writer.writeheader()
            for entry in matched_entries:
                writer.writerow({
                    "CVE_ID": entry.get("cve_id", ""),
                    "Asset": entry.get("asset", ""),
                    "Vendor": entry.get("vendor", ""),
                    "Product": entry.get("product", ""),
                    "Risk_Level": entry.get("risk_level", ""),
                    "Date_Detected": entry.get("date_detected", entry.get("date_added", "")),
                })
        return filepath

    def export_full_csv(self, db_entries, filepath):
        self._ensure_dir(filepath)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FULL_HEADERS)
            writer.writeheader()
            for entry in db_entries:
                writer.writerow({
                    "CVE_ID": entry.get("cve_id", ""),
                    "Vendor": entry.get("vendor", ""),
                    "Product": entry.get("product", ""),
                    "Vulnerability_Name": entry.get("vulnerability_name", ""),
                    "Severity": entry.get("severity", ""),
                    "Date_Added": entry.get("date_added", ""),
                })
        return filepath

    def export_search_csv(self, search_entries, filepath):
        self._ensure_dir(filepath)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=SEARCH_HEADERS)
            writer.writeheader()
            for entry in search_entries:
                writer.writerow({
                    "CVE_ID": entry.get("cve_id", ""),
                    "Vendor": entry.get("vendor", ""),
                    "Product": entry.get("product", ""),
                    "Severity": entry.get("severity", ""),
                    "Date_Added": entry.get("date_added", ""),
                })
        return filepath

    @staticmethod
    def _ensure_dir(filepath):
        import os
        directory = os.path.dirname(filepath)
        if directory:
            os.makedirs(directory, exist_ok=True)

    @staticmethod
    def summarize(matched_entries):
        counts = Counter(entry.get("risk_level", "UNKNOWN") for entry in matched_entries)
        return dict(counts)
