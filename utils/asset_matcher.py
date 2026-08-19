from datetime import date
from utils.storage import Storage

ASSET_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


class AssetMatcher:

    def __init__(self, storage=None):
        self.storage = storage or Storage()

    def load_assets(self, filename="monitored_assets.json"):
        data = self.storage.load(filename, default=[])
        if isinstance(data, dict):
            data = data.get("assets", [])
        if not isinstance(data, list):
            return []
        return [asset for asset in data if isinstance(asset, str) and asset.strip()]

    def match(self, vulnerabilities, assets):
        normalized_assets = [asset.strip().lower() for asset in assets]
        detected_on = date.today().isoformat()
        matches = []
        for vuln in vulnerabilities:
            hit = None
            for asset, norm in zip(assets, normalized_assets):
                if not norm:
                    continue
                fields = [
                    vuln.product.lower(),
                    vuln.vendor.lower(),
                    vuln.vulnerability_name.lower(),
                ]
                if any(norm in field or field in norm for field in fields if field):
                    hit = asset
                    break
            if hit is None:
                continue
            entry = vuln.to_dict()
            entry["asset"] = hit
            entry["risk_level"] = self._risk_level(vuln)
            entry["date_detected"] = detected_on
            matches.append(entry)
        matches.sort(
            key=lambda entry: (
                ASSET_ORDER.get(entry.get("risk_level", "UNKNOWN"), 4),
                entry.get("date_added", ""),
            )
        )
        return matches

    @staticmethod
    def _risk_level(vuln):
        #just maps severity to a risk level label
        if vuln.severity == "CRITICAL":
            return "CRITICAL"
        if vuln.severity == "HIGH":
            return "HIGH"
        if vuln.severity == "MEDIUM":
            return "MEDIUM"
        return "LOW"
