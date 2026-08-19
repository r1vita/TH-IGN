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
        path = self._path(filename)
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return default
        except json.JSONDecodeError:
            return default
        except OSError:
            return default

    def save(self, filename, payload):
        path = self._path(filename)
        tmp_path = path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, path)
        except OSError:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise
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

        by_id = {}
        for item in existing:
            if isinstance(item, dict) and item.get("cve_id"):
                by_id[item["cve_id"]] = item

        added = 0
        duplicates = 0
        skipped = 0
        for vuln in vulnerabilities:
            entry = vuln.to_dict()
            cve_id = entry.get("cve_id", "")
            if not cve_id:
                skipped += 1
                continue
            if cve_id in by_id:
                duplicates += 1
                continue
            by_id[cve_id] = entry
            added += 1

        merged = list(by_id.values())
        merged.sort(key=lambda item: item.get("date_added", ""), reverse=True)
        self.save("vulnerabilities.json", merged)
        return {
            "added": added,
            "total": len(merged),
            "duplicates": duplicates,
            "skipped": skipped,
        }
