import re
from datetime import date
from utils.storage import Storage

ASSET_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

ASSET_ALIASES = {
    "chrome": ["google chrome", "chrome", "chromium"],
    "firefox": ["mozilla firefox", "firefox", "gecko"],
    "apache": ["apache", "apache http server", "apache httpd", "apache tomcat"],
    "nginx": ["nginx"],
    "python": ["python", "cpython"],
    "windows server": ["windows server", "microsoft windows server", "windows"],
    "windows": ["microsoft windows", "windows", "windows os"],
    "linux": ["linux", "linux kernel"],
    "openssl": ["openssl", "open ssl"],
    "postgresql": ["postgresql", "postgres"],
    "mysql": ["mysql", "mariadb"],
    "node.js": ["node.js", "nodejs", "node"],
    "java": ["java", "openjdk", "jdk", "jre"],
    "docker": ["docker", "docker engine"],
    "vmware": ["vmware", "vmware esxi", "vmware vcenter"],
    "cisco": ["cisco", "cisco ios", "cisco ios xe"],
    "fortinet": ["fortinet", "fortigate", "fortios"],
}

_WHITESPACE_RE = re.compile(r"[\s_\-]+")


def normalize_name(name):
    if not name:
        return ""
    n = name.lower().strip()
    n = _WHITESPACE_RE.sub(" ", n)
    return n


def aliases_for(asset_name):
    lower = asset_name.lower().strip()
    if lower in ASSET_ALIASES:
        return [normalize_name(a) for a in ASSET_ALIASES[lower]]
    return [normalize_name(asset_name)]


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
        asset_aliases = {}
        for asset in assets:
            asset_aliases[asset] = aliases_for(asset)

        detected_on = date.today().isoformat()
        matches = []
        for vuln in vulnerabilities:
            hit = self._find_match(vuln, asset_aliases)
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

    def _find_match(self, vuln, asset_aliases):
        vuln_fields = [
            normalize_name(vuln.product),
            normalize_name(vuln.vendor),
            normalize_name(vuln.vulnerability_name),
        ]
        vuln_text = " ".join(f for f in vuln_fields if f)

        for asset, aliases in asset_aliases.items():
            for alias in aliases:
                if not alias:
                    continue
                for field in vuln_fields:
                    if not field:
                        continue
                    if alias == field:
                        return asset
                    if alias in field or field in alias:
                        return asset
                if alias in vuln_text:
                    return asset
        return None

    @staticmethod
    def _risk_level(vuln):
        if vuln.severity in ("CRITICAL", "HIGH"):
            return vuln.severity
        return "UNKNOWN"
