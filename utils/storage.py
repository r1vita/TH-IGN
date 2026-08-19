import json
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DATA_DIR = os.path.join(PROJECT_ROOT, "data")

DEFAULT_SETTINGS = {
    "export_filename": "threat_report.csv",
    "export_dir": "data",
    "max_display": 50,
}


class Storage:

    def __init__(self, data_dir=DEFAULT_DATA_DIR):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)

    def _path(self, filename):
        return os.path.join(self.data_dir, filename)

    def path_for(self, filename):
        return self._path(filename)

    def load(self, filename, default=None):
        try:
            with open(self._path(filename), "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return default

    def save(self, filename, payload):
        path = self._path(filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return path

    def load_settings(self):
        settings = self.load("settings.json", default={})
        if not isinstance(settings, dict):
            settings = {}
        return {**DEFAULT_SETTINGS, **settings}

    def save_settings(self, settings):
        return self.save("settings.json", settings)

    def merge_vulnerabilities(self, vulnerabilities):
        existing = self.load("vulnerabilities.json", default=[])
        if not isinstance(existing, list):
            existing = []
        by_id = {item["cve_id"]: item for item in existing if item.get("cve_id")}
        added = 0
        for vuln in vulnerabilities:
            entry = vuln.to_dict()
            if entry["cve_id"] and entry["cve_id"] not in by_id:
                by_id[entry["cve_id"]] = entry
                added += 1
        merged = list(by_id.values())
        merged.sort(key=lambda item: item.get("date_added", ""), reverse=True)
        self.save("vulnerabilities.json", merged)
        return added, len(merged)
