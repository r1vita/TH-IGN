import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.storage import Storage
from models.vulnerability import Vulnerability


def test_load_existing():
    storage = Storage()
    path = storage.path_for("vulnerabilities.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump([{"cve_id": "CVE-2024-1"}], f)
    data = storage.load("vulnerabilities.json")
    assert isinstance(data, list)
    assert data[0]["cve_id"] == "CVE-2024-1"


def test_load_corrupted_json():
    storage = Storage()
    path = storage.path_for("corrupted.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("{invalid json content")
    data = storage.load("corrupted.json", default=[])
    assert data == []


def test_save_and_load():
    storage = Storage()
    payload = [{"cve_id": "CVE-2024-1"}, {"cve_id": "CVE-2024-2"}]
    storage.save("test_save.json", payload)
    loaded = storage.load("test_save.json")
    assert loaded == payload
    os.remove(storage.path_for("test_save.json"))


def test_merge_new():
    storage = Storage()
    path = storage.path_for("vulnerabilities.json")
    if os.path.exists(path):
        os.remove(path)
    vulns = [
        Vulnerability("CVE-2024-1", "V", "P", "N", "2024-01-01", "HIGH"),
        Vulnerability("CVE-2024-2", "V", "P", "N", "2024-01-02", "LOW"),
    ]
    result = storage.merge_vulnerabilities(vulns)
    assert result["added"] == 2
    assert result["total"] == 2
    assert result["duplicates"] == 0


def test_merge_duplicates():
    storage = Storage()
    path = storage.path_for("vulnerabilities.json")
    if os.path.exists(path):
        os.remove(path)
    vulns = [Vulnerability("CVE-2024-1", "V", "P", "N", "2024-01-01", "HIGH")]
    storage.merge_vulnerabilities(vulns)
    result = storage.merge_vulnerabilities(vulns)
    assert result["added"] == 0
    assert result["duplicates"] == 1
    assert result["total"] == 1


def test_duplicate_not_inserted_twice():
    storage = Storage()
    path = storage.path_for("vulnerabilities.json")
    if os.path.exists(path):
        os.remove(path)
    vuln = Vulnerability("CVE-2024-9999", "V", "P", "N", "2024-01-01", "CRITICAL")
    storage.merge_vulnerabilities([vuln])
    storage.merge_vulnerabilities([vuln])
    storage.merge_vulnerabilities([vuln])
    data = storage.load("vulnerabilities.json", default=[])
    count = sum(1 for d in data if d.get("cve_id") == "CVE-2024-9999")
    assert count == 1
