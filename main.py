import os
import sys

from models.vulnerability import Vulnerability
from scrapers.threat_scraper import ThreatScraper
from utils.asset_matcher import AssetMatcher
from utils.report_generator import ReportGenerator
from utils.storage import Storage

VERSION = "2.0"

BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
REVERSE = "\033[7m"


def colored(text, color):
    return f"{color}{text}{RESET}"


def risk_style(level):
    styles = {
        "CRITICAL": RED,
        "HIGH": YELLOW,
        "MEDIUM": CYAN,
        "LOW": GREEN,
        "UNKNOWN": DIM,
    }
    return styles.get(str(level).upper(), "")


def print_header(status):
    print()
    print(colored("=" * 58, CYAN))
    print(colored("         THREATINTEL ENGINE  v" + VERSION, BOLD + CYAN))
    print(colored("=" * 58, CYAN))
    print(f"  db: {BOLD}{status['database']}{RESET}   "
          f"assets: {BOLD}{status['assets']}{RESET}   "
          f"matched: {BOLD}{status['matches']}{RESET}")
    print(colored("-" * 58, CYAN))


def print_menu(selected=None):
    items = [
        ("1", "Fetch & Update Feeds", "Download latest CVE data"),
        ("2", "Scan Local Assets Against Threat Database", "Match assets against known CVEs"),
        ("3", "Search Vulnerability by Keyword/Vendor", "Find vulnerabilities"),
        ("4", "Export Threat Report to CSV", "Save data to a CSV file"),
        ("5", "Exit", "Close TH-IGN"),
    ]
    print()
    print(colored("  Main Menu", BOLD))
    print()
    for num, label, desc in items:
        marker = colored(">", CYAN) if num == selected else " "
        style = BOLD if num == selected else ""
        print(f"  {marker} {style}[{num}]{RESET} {label}")
        print(f"      {colored(desc, DIM)}")
    print()
    print(colored("-" * 58, CYAN))


def print_extras_menu():
    items = [
        ("a", "Add Asset", "Add asset to monitored list"),
        ("r", "Remove Asset", "Remove asset from monitored list"),
        ("v", "View All CVEs", "Browse every CVE in database"),
        ("b", "Back", "Return to main menu"),
    ]
    print()
    print(colored("  Tools Menu", BOLD))
    print()
    for num, label, desc in items:
        print(f"    [{num}] {label}")
        print(f"        {colored(desc, DIM)}")
    print()


def read_status(matcher, storage):
    db = storage.load("vulnerabilities.json", default=[])
    matches = storage.load("matched_vulnerabilities.json", default=[])
    return {
        "database": len(db) if isinstance(db, list) else 0,
        "assets": len(matcher.load_assets()),
        "matches": len(matches) if isinstance(matches, list) else 0,
    }


def do_fetch(scraper, storage):
    print()
    print(colored("  Downloading data...", YELLOW))
    print()
    vulns, results = scraper.scrape_all()

    for r in results:
        if r.success:
            print(colored(f"  [OK]    {r.source}: {len(r.vulns)} vulnerabilities", GREEN))
        else:
            print(colored(f"  [FAIL]  {r.source}: {r.error}", RED))

    merge = storage.merge_vulnerabilities(vulns)
    added = merge["added"]
    total = merge["total"]
    duplicates = merge["duplicates"]

    all_fail = all(not r.success for r in results)

    print()
    if all_fail:
        print(colored("  FAILED: All sources unreachable. No data downloaded.", RED))
        print(colored("  Check your internet connection and try again.", DIM))
    elif added > 0:
        print(colored(f"  {len(vulns)} vulnerabilities fetched ({added} new, {duplicates} duplicates)", GREEN))
        print(colored(f"  Database: {total} total entries", BOLD))
    else:
        print(colored(f"  {len(vulns)} vulnerabilities fetched, all duplicates", YELLOW))
        print(colored(f"  Database: {total} total entries (already up to date)", BOLD))
    print()


def do_scan(matcher, storage):
    assets = matcher.load_assets()
    if not assets:
        print(colored("  No assets found. Add assets via the Tools menu.", RED))
        return
    db = storage.load("vulnerabilities.json", default=[])
    if not isinstance(db, list) or not db:
        print(colored("  Database empty. Run Fetch first.", RED))
        return

    vulns = []
    for e in db:
        v = Vulnerability.from_dict(e)
        if v is not None:
            vulns.append(v)

    matches = matcher.match(vulns, assets)
    storage.save("matched_vulnerabilities.json", matches)

    if not matches:
        print(colored("  No risks found for your monitored assets.", GREEN))
        return

    print()
    print(colored(f"  {len(matches)} risks found:", BOLD))
    from collections import Counter
    counts = Counter(m.get("risk_level", "UNKNOWN") for m in matches)
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if counts[level] > 0:
            print(colored(f"    {level}: {counts[level]}", risk_style(level)))
    print()
    print(f"  {'CVE_ID':<18} {'Asset':<16} {'Product':<24} {'Risk':<10}")
    print(colored("  " + "-" * 68, DIM))
    for m in matches[:50]:
        cve = m.get("cve_id", "")[:17]
        asset = m.get("asset", "")[:15]
        product = m.get("product", "")[:23]
        risk = m.get("risk_level", "")
        print(f"  {cve:<18} {asset:<16} {product:<24} {colored(risk, risk_style(risk))}")
    if len(matches) > 50:
        print(colored(f"  ... and {len(matches) - 50} more", DIM))
    print()


def do_search(storage):
    db = storage.load("vulnerabilities.json", default=[])
    if not isinstance(db, list) or not db:
        print(colored("  Database empty. Run Fetch first.", RED))
        return

    keyword = input("  Search> ").strip()
    if not keyword:
        return

    needle = keyword.lower()
    results = [
        e for e in db
        if needle in e.get("cve_id", "").lower()
        or needle in e.get("vendor", "").lower()
        or needle in e.get("product", "").lower()
        or needle in e.get("vulnerability_name", "").lower()
    ]

    if not results:
        print(colored(f"  No results for '{keyword}'.", YELLOW))
        return

    print()
    print(colored(f"  {len(results)} result(s) for '{keyword}':", BOLD))
    print()
    print(f"  {'CVE_ID':<18} {'Vendor':<16} {'Product':<24} {'Severity':<10} {'Date':<12}")
    print(colored("  " + "-" * 80, DIM))
    for e in results[:50]:
        print(f"  {e.get('cve_id', '')[:17]:<18} "
              f"{e.get('vendor', '')[:15]:<16} "
              f"{e.get('product', '')[:23]:<24} "
              f"{colored(e.get('severity', ''), risk_style(e.get('severity', '')))}   "
              f"{e.get('date_added', '')[:11]}")
    if len(results) > 50:
        print(colored(f"  ... and {len(results) - 50} more", DIM))
    print()
    return results


def do_export(storage, matcher, report):
    db = storage.load("vulnerabilities.json", default=[])
    if not isinstance(db, list) or not db:
        print(colored("  Database empty. Run Fetch first.", RED))
        return

    print()
    print(colored("  Export options:", BOLD))
    print("    [1] Matched assets only")
    print("    [2] Full database (all CVEs)")
    print("    [3] Cancel")
    print()
    choice = input("  Choice> ").strip()

    if choice == "1":
        matches = storage.load("matched_vulnerabilities.json", default=[])
        if not isinstance(matches, list) or not matches:
            print(colored("  No matched assets. Run Scan first.", YELLOW))
            return
        rows = matches
        export_fn = report.export_matched_csv
    elif choice == "2":
        rows = db
        export_fn = report.export_full_csv
    else:
        return

    default_path = os.path.join("data", "threat_report.csv")
    filepath = input(f"  File path [{default_path}]> ").strip()
    if not filepath:
        filepath = default_path

    try:
        path = export_fn(rows, filepath)
        print(colored(f"  Exported {len(rows)} records to {path}", GREEN))
    except Exception as exc:
        print(colored(f"  Export failed: {exc}", RED))
    print()


def do_list_all(storage):
    db = storage.load("vulnerabilities.json", default=[])
    if not isinstance(db, list) or not db:
        print(colored("  Database empty. Run Fetch first.", RED))
        return

    print()
    print(colored(f"  {len(db)} total CVEs in database:", BOLD))
    print()
    print(f"  {'CVE_ID':<18} {'Vendor':<16} {'Product':<24} {'Severity':<10} {'Date':<12}")
    print(colored("  " + "-" * 80, DIM))
    for e in db[:50]:
        print(f"  {e.get('cve_id', '')[:17]:<18} "
              f"{e.get('vendor', '')[:15]:<16} "
              f"{e.get('product', '')[:23]:<24} "
              f"{colored(e.get('severity', ''), risk_style(e.get('severity', '')))}   "
              f"{e.get('date_added', '')[:11]}")
    if len(db) > 50:
        print(colored(f"  ... and {len(db) - 50} more", DIM))
    print()


def do_add_asset(matcher, storage):
    assets = matcher.load_assets()
    current = ", ".join(assets) if assets else "(none)"
    print()
    print(colored("  Current monitored assets:", BOLD))
    print(f"    {colored(current, CYAN)}")
    print()
    name = input("  Asset name> ").strip()
    if not name:
        return

    data = storage.load("monitored_assets.json", default=[])
    if not isinstance(data, list):
        data = []

    if name.lower() in [a.lower() for a in data]:
        print(colored(f"  '{name}' is already in your list.", YELLOW))
        return

    data.append(name)
    storage.save("monitored_assets.json", data)
    print(colored(f"  Added '{name}'.", GREEN))


def do_del_asset(matcher, storage):
    assets = matcher.load_assets()
    if not assets:
        print(colored("  No assets to remove.", YELLOW))
        return

    print()
    print(colored("  Monitored assets:", BOLD))
    for i, a in enumerate(assets):
        print(f"    {i + 1}. {a}")
    print()
    choice = input("  Remove which ? (#)> ").strip()

    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(assets):
            name = assets[idx]
            data = storage.load("monitored_assets.json", default=[])
            if not isinstance(data, list):
                data = []
            data = [a for a in data if a.lower() != name.lower()]
            storage.save("monitored_assets.json", data)
            print(colored(f"  Removed '{name}'.", GREEN))
            return
    print(colored("  Invalid selection.", RED))


def main():
    storage = Storage()
    scraper = ThreatScraper()
    matcher = AssetMatcher(storage)
    report = ReportGenerator(storage)

    print()
    print(colored("  TH-IGN v" + VERSION, BOLD + CYAN))
    print(colored("  Press Ctrl+C at any time to exit.", DIM))

    try:
        while True:
            status = read_status(matcher, storage)
            print_header(status)
            print_menu()

            choice = input("  ThreatIntel> ").strip()

            if choice == "1":
                do_fetch(scraper, storage)
            elif choice == "2":
                do_scan(matcher, storage)
            elif choice == "3":
                do_search(storage)
            elif choice == "4":
                do_export(storage, matcher, report)
            elif choice == "5":
                print(colored("  Goodbye.", CYAN))
                break
            elif choice.lower() in ("a", "add"):
                do_add_asset(matcher, storage)
            elif choice.lower() in ("r", "remove"):
                do_del_asset(matcher, storage)
            elif choice.lower() in ("v", "view"):
                do_list_all(storage)
            elif choice.lower() in ("t", "tools"):
                run_tools_menu(matcher, storage)
            elif choice.lower() in ("q", "quit", "exit"):
                print(colored("  Goodbye.", CYAN))
                break
            else:
                print(colored("  Invalid option. Choose 1-5.", YELLOW))
    except KeyboardInterrupt:
        print(colored("\n  Interrupted. Goodbye.", CYAN))
    except EOFError:
        print(colored("\n  Goodbye.", CYAN))


def run_tools_menu(matcher, storage):
    while True:
        print_extras_menu()
        choice = input("  Tools> ").strip().lower()
        if choice == "a":
            do_add_asset(matcher, storage)
        elif choice == "r":
            do_del_asset(matcher, storage)
        elif choice == "v":
            do_list_all(storage)
        elif choice in ("b", ""):
            break
        else:
            print(colored("  Invalid option.", YELLOW))


def run_demo_milestone1():
    scraper = ThreatScraper()
    print(colored("\n Milestone 1 Demonstration", BOLD + CYAN))
    print(colored("  Fetching live CVE data from multiple sources...\n", DIM))
    vulns, results = scraper.scrape_all()
    print(colored("  Source results:", BOLD))
    for r in results:
        if r.success:
            print(colored(f"    [OK] {r.source}: {len(r.vulns)} vulnerabilities", GREEN))
        else:
            print(colored(f"    [FAIL] {r.source}: {r.error}", RED))
    print()
    print(colored(f"  Total unique vulnerabilities: {len(vulns)}", BOLD))
    print()
    if vulns:
        print(colored("  First 10 parsed Vulnerability objects:", BOLD))
        print()
        for i, v in enumerate(vulns[:10], 1):
            print(f"  {i:>2}. {v}")
    print()
    return vulns


def run_demo_milestone2(vulns):
    storage = Storage()
    matcher = AssetMatcher(storage)
    assets = matcher.load_assets()
    print(colored("\n Milestone 2 Demonstration", BOLD + CYAN))
    print(colored(f"  Monitored assets: {', '.join(assets)}", BOLD))
    print()
    if not vulns:
        vulns_dicts = storage.load("vulnerabilities.json", default=[])
        vulns = []
        for e in vulns_dicts:
            v = Vulnerability.from_dict(e)
            if v:
                vulns.append(v)
    matches = matcher.match(vulns, assets)
    if matches:
        print(colored(f"  {len(matches)} matched threats found:", BOLD))
        print()
        for m in matches[:10]:
            print(f"    Asset: {colored(m['asset'], CYAN)}")
            print(f"    CVE: {m['cve_id']}   Vendor: {m['vendor']}   Product: {m['product']}")
            print(f"    Severity: {colored(m['severity'], risk_style(m['severity']))}"
                  f"   Risk: {colored(m['risk_level'], risk_style(m['risk_level']))}")
            print()
    else:
        print(colored("  No matches found.", YELLOW))
    print()
    return matches


def run_demo_milestone3(storage, matches=None):
    print(colored("\n Milestone 3 Demonstration", BOLD + CYAN))
    vulns_dicts = storage.load("vulnerabilities.json", default=[])
    print(colored(f"  Database contains {len(vulns_dicts)} vulnerabilities.", BOLD))
    print()
    report = ReportGenerator(storage)
    path = os.path.join("data", "demo_report.csv")
    if matches:
        report.export_matched_csv(matches, path)
        print(colored(f"  Exported {len(matches)} matched records to {path}", GREEN))
    else:
        report.export_full_csv(vulns_dicts, path)
        print(colored(f"  Exported {len(vulns_dicts)} records to {path}", GREEN))
    print()
    print(colored("  Running merge again to verify no duplicates:", DIM))
    vulns = []
    for e in vulns_dicts[:5]:
        v = Vulnerability.from_dict(e)
        if v:
            vulns.append(v)
    result = storage.merge_vulnerabilities(vulns)
    print(f"    Added: {result['added']}  Duplicates: {result['duplicates']}  "
          f"Total: {result['total']}")
    print()


if __name__ == "__main__":
    if "--demo" in sys.argv:
        vulns = run_demo_milestone1()
        matches = run_demo_milestone2(vulns)
        run_demo_milestone3(Storage(), matches)
        print(colored("  All demonstrations complete.", GREEN + BOLD))
        print()
    else:
        main()
