import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from models.vulnerability import Vulnerability
from scrapers.threat_scraper import ThreatScraper
from utils.asset_matcher import AssetMatcher
from utils.report_generator import ReportGenerator
from utils.storage import Storage

VERSION = "1.0"

ACCENT = "cyan"
OK = "green"
WARN = "yellow"
DANGER = "red"
MUTED = "bright_black"

RISK_STYLES = {
    "CRITICAL": "red",
    "HIGH": "yellow",
    "MEDIUM": "cyan",
    "LOW": "green",
    "UNKNOWN": "bright_black",
}

SCROLL_PAGE = 25  # how many rows show at once in scrollable views


def risk_color(level):
    return RISK_STYLES.get(str(level).upper(), "white")


def _truncate(text, max_len):
    text = str(text)
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


# terminal stuff

_SAVED_TERM_ATTRS = None


def enter_raw_mode():
    global _SAVED_TERM_ATTRS
    if os.name == "nt":
        # Windows doesn't need raw terminal setup for msvcrt
        return
    import termios, tty
    fd = sys.stdin.fileno()
    if _SAVED_TERM_ATTRS is None:
        _SAVED_TERM_ATTRS = termios.tcgetattr(fd)
        tty.setcbreak(fd)


def exit_raw_mode():
    global _SAVED_TERM_ATTRS
    if os.name == "nt":
        # Windows doesn't use termios to exit raw mode
        return
    import termios
    fd = sys.stdin.fileno()
    if _SAVED_TERM_ATTRS is not None:
        termios.tcsetattr(fd, termios.TCSADRAIN, _SAVED_TERM_ATTRS)
        _SAVED_TERM_ATTRS = None


def get_key():
    if os.name == "nt":
        return _get_key_windows()
    return _get_key_posix()


def _get_key_windows():
    import msvcrt
    ch = msvcrt.getwch()
    if ch in ("\x00", "\xe0"):
        arrow = msvcrt.getwch()
        return {"H": "up", "P": "down", "M": "right", "K": "left"}.get(arrow, arrow)
    if ch in ("\r", "\n"):
        return "enter"
    if ch == "\x03":
        return "ctrl-c"
    if ch == "\x1b":
        return "esc"
    if ch in ("\x7f", "\x08"):
        return "backspace"
    return ch


def _get_key_posix():
    fd = sys.stdin.fileno()
    os.set_blocking(fd, True)
    first = os.read(fd, 1)
    if not first:
        return ""
    if first == b"\x1b":
        tail = _read_available(fd, 2)
        combined = first + tail
        if combined == b"\x1b[64~":
            return "scroll_up"
        if combined == b"\x1b[65~":
            return "scroll_down"
        return _decode_key(combined)
    if first[0] >= 0x80:
        tail = _read_available(fd, 3)
        try:
            return (first + tail).decode("utf-8")
        except UnicodeDecodeError:
            return ""
    return _decode_key(first)


def _read_available(fd, limit):
    os.set_blocking(fd, False)
    data = b""
    try:
        while len(data) < limit:
            chunk = os.read(fd, 1)
            if not chunk:
                break
            data += chunk
    except BlockingIOError:
        pass
    finally:
        os.set_blocking(fd, True)
    return data


def _decode_key(data):
    if data == b"\x1b[A":
        return "up"
    if data == b"\x1b[B":
        return "down"
    if data == b"\x1b[C":
        return "right"
    if data == b"\x1b[D":
        return "left"
    if data in (b"\r", b"\n"):
        return "enter"
    if data in (b"\x7f", b"\x08"):
        return "backspace"
    if data == b"\x03":
        return "ctrl-c"
    if data == b"\x1b":
        return "esc"
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return ""


@dataclass
class MenuItem:
    key: str
    label: str
    description: str


@dataclass
class Status:
    database: int = 0
    assets: int = 0
    matches: int = 0


def _get_suggested_dirs():
    home = Path.home()
    dirs = []
    for name in ("Desktop", "Documents", "Downloads"):
        p = home / name
        if p.exists():
            dirs.append(str(p))
    # project own data folder coz easier
    project_data = str(Path(__file__).resolve().parent / "data")
    dirs.append(project_data)
    dirs.append(tempfile.gettempdir())
    return dirs


class ThreatIntelApp:

    def __init__(self, console=None):
        self.console = console or Console(force_terminal=True)
        self.storage = Storage()
        self.scraper = ThreatScraper()
        self.matcher = AssetMatcher(self.storage)
        self.report = ReportGenerator(self.storage)

        self.menu_items = [
            MenuItem("fetch", "Fetch Threat CVEs", "Download latest CVE data"),
            MenuItem("scan", "Scan Assets vs Threats", "Match your desired Assets against known CVEs"),
            MenuItem("search", "Search CVEs", "Find vulnerabilities by keyword or vendor"),
            MenuItem("list", "View All CVEs", "Browse every CVE"),
            MenuItem("add_asset", "Add Asset", "Add asset to your monitored list"),
            MenuItem("del_asset", "Remove Asset", "Remove asset from monitored list"),
            MenuItem("export", "Export to CSV", "Save data to a CSV file"),
            MenuItem("quit", "Exit", "Close ThreatIntel Engine"),
        ]
        self.selected = 0
        self.input_prompt = None
        self.input_buffer = ""
        self.output = self._idle_panel()
        self.live = None
        self.status = self._read_status()
        self.quit_requested = False

        # scrollable view state
        self._scroll_heading = Text("")
        self._scroll_entries = []
        self._scroll_columns = []
        self._scroll_offset = 0
        self._scroll_title = ""

        self._last_search_results = []

        # sub-menus for export
        self._export_active = False
        self._export_selected = 0
        self._export_options = [
            ("matched", "Matched assets only"),
            ("full", "Full database (all CVEs)"),
            ("search", "Last search results"),
        ]

        # path picker popup (need to fix something ?)
        self._path_popup_active = False
        self._path_popup_selected = 0
        self._path_popup_dirs = _get_suggested_dirs()
        self._path_popup_custom = ""
        self._path_popup_custom_mode = False
        self._path_popup_rows = []
        self._path_popup_export_type = ""
        self._path_popup_rows_data = []

    def _read_status(self):
        db = self.storage.load("vulnerabilities.json", default=[])
        matches = self.storage.load("matched_vulnerabilities.json", default=[])
        return Status(
            database=len(db) if isinstance(db, list) else 0,
            assets=len(self.matcher.load_assets()),
            matches=len(matches) if isinstance(matches, list) else 0,
        )

    def _refresh_status(self):
        self.status = self._read_status()

    # scrollable list render

    def _set_scrollable(self, heading, entries, columns, title=""):
        self._scroll_heading = heading
        self._scroll_entries = entries
        self._scroll_columns = columns
        self._scroll_title = title
        self._scroll_offset = 0
        self._render_scroll_window()

    def _render_scroll_window(self):
        entries = getattr(self, "_scroll_entries", [])
        columns = getattr(self, "_scroll_columns", [])
        heading = getattr(self, "_scroll_heading", Text(""))
        total = len(entries)
        if total == 0:
            self._set_output(Panel(heading, title=self._scroll_title))
            return

        max_offset = max(0, total - SCROLL_PAGE)
        self._scroll_offset = max(0, min(self._scroll_offset, max_offset))

        start = self._scroll_offset
        end = min(start + SCROLL_PAGE, total)
        page_entries = entries[start:end]

        table = Table(
            title=None, border_style=ACCENT, box=box.SIMPLE_HEAD,
            pad_edge=False, expand=True,
        )
        for col_header, _, width, _ in columns:
            table.add_column(
                col_header, header_style="bold", width=width,
                no_wrap=True, overflow="ellipsis",
            )
        for entry in page_entries:
            cells = []
            for _, key, width, style_fn in columns:
                val = _truncate(str(entry.get(key, "")), width - 1)
                style = style_fn(entry.get(key, "")) if style_fn else None
                cells.append(Text(val, style=style) if style else Text(val))
            table.add_row(*cells)

        pos = Text()
        pos.append(f"Showing {start + 1}-{end} of {total}", style="bold")
        if total > SCROLL_PAGE:
            pos.append("  (up/down to scroll, Esc to go back)", style=MUTED)

        content = Group(heading, Text(""), pos, table)
        if end < total:
            content = Group(content, Text(f"\n--- {total - end} more below ---", style=MUTED))

        self.output = Panel(
            content,
            title=f"[bold]{self._scroll_title}",
            border_style=ACCENT, box=box.HEAVY,
        )
        self._update()

    def _handle_scroll(self, key):
        if not getattr(self, "_scroll_entries", None):
            return False
        if key in ("up", "scroll_up"):
            self._scroll_offset -= 1
            self._render_scroll_window()
            return True
        if key in ("down", "scroll_down"):
            self._scroll_offset += 1
            self._render_scroll_window()
            return True
        return False

    # panels

    def _idle_panel(self):
        group = Group(
            Align.left(Text("ThreatIntel Engine", style=f"bold {ACCENT}")),
            Text(""),
            Text("Scrapes CVE and known exploits", style=MUTED),
            Text("Matches against your monitored Asset and exports CSV reports.", style=MUTED),
            Text(""),
            Text("Use  up / down  to move,  Enter  to select,  q  to quit.", style=MUTED),
        )
        return Panel(group, title="[bold]Dashboard", border_style=ACCENT, box=box.HEAVY)

    def render_header(self):
        status = self.status
        st = Text()
        st.append("db ", style=MUTED)
        st.append(str(status.database), style="bold")
        st.append("  assets ", style=MUTED)
        st.append(str(status.assets), style="bold")
        st.append("  matched ", style=MUTED)
        st.append(str(status.matches), style="bold")
        group = Group(
            Align.center(Text("THREATINTEL  ENGINE", style=f"bold {ACCENT}")), #could have chosen another name coz come on man
            Align.center(st),
        )
        return Panel(
            Align.center(group),
            title=f"[{ACCENT}]ThreatIntel[/]",
            subtitle=f"v{VERSION}",
            border_style=ACCENT,
            box=box.ROUNDED,
        )

    def render_menu(self):
        lines = Text()
        for index, item in enumerate(self.menu_items):
            cursor = ">" if index == self.selected else " "
            if index == self.selected:
                lines.append(f" {cursor} {item.label}\n", style="bold reverse")
            else:
                lines.append(f" {cursor} {item.label}\n")
            lines.append(f"   {item.description}\n", style=MUTED)
            lines.append("\n")
        return Panel(lines, title="[bold]Menu", border_style=ACCENT, box=box.HEAVY)

    def render_footer(self):
        if self._path_popup_active:
            if self._path_popup_custom_mode:
                content = Align.left(Text("type path   Enter confirm   Esc cancel", style=MUTED))
            else:
                content = Align.left(Text("up/down choose   Enter select   type to custom path   Esc cancel", style=MUTED))
        elif self.input_prompt is not None:
            prompt = Text()
            prompt.append(f"{self.input_prompt}> ", style=f"bold {ACCENT}")
            prompt.append(self.input_buffer, style="bold")
            prompt.append("_", style="blink")
            content = Align.left(prompt)
        elif self._export_active:
            content = Align.left(Text("up/down choose   Enter confirm   Esc cancel", style=MUTED))
        elif getattr(self, "_scroll_entries", None):
            content = Align.left(Text("up/down scroll   Esc back to menu", style=MUTED))
        else:
            content = Align.left(Text("up/down move   Enter select   q quit", style=MUTED))
        return Panel(content, border_style=ACCENT, box=box.HEAVY)

    def render(self):
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=6),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(self.render_menu(), name="menu", ratio=2),
            Layout(self.output, name="output", ratio=5),
        )
        layout["header"].update(self.render_header())
        layout["footer"].update(self.render_footer())
        return layout

    def _update(self):
        if self.live is not None:
            self.live.update(self.render(), refresh=True)

    def _set_output(self, renderable):
        self.output = renderable
        self._update()

    def _error_panel(self, message):
        return Panel(
            Text(f"Error: {message}", style=DANGER),
            title="[bold]Error", border_style=DANGER, box=box.HEAVY,
        )

    # sb-menu export 2

    def _export_sub_menu(self):
        lines = Text()
        lines.append("What do you want to export ?\n\n", style="bold")
        for i, (key, label) in enumerate(self._export_options):
            cursor = ">" if i == self._export_selected else " "
            style = "bold reverse" if i == self._export_selected else None
            lines.append(f"  {cursor} {label}\n", style=style)
            if key == "matched":
                lines.append(f"      ({self.status.matches} records)\n", style=MUTED)
            elif key == "full":
                lines.append(f"      ({self.status.database} records)\n", style=MUTED)
            elif key == "search":
                lines.append(f"      ({len(self._last_search_results)} records)\n", style=MUTED)
            lines.append("\n")
        lines.append("up/down choose, Enter confirm, Esc back", style=MUTED)
        return Panel(lines, title="[bold]Export to CSV", border_style=ACCENT, box=box.HEAVY)

    def _build_export_rows(self, export_type):
        if export_type == "search":
            return self._last_search_results
        if export_type == "full":
            db = self.storage.load("vulnerabilities.json", default=[])
            return db if isinstance(db, list) else []
        #matched only
        db = self.storage.load("vulnerabilities.json", default=[])
        if not isinstance(db, list) or not db:
            return []
        assets = self.matcher.load_assets()
        if not assets:
            return []
        vulns = [Vulnerability.from_dict(e) for e in db]
        return self.matcher.match(vulns, assets)

    #path picker

    def _build_path_popup(self):
        lines = Text()
        lines.append("Choose export location\n\n", style="bold")

        if self._path_popup_custom_mode:
            lines.append("  > ", style=f"bold {ACCENT}")
            lines.append(self._path_popup_custom, style="bold")
            lines.append("_", style="blink")
            lines.append("\n\n", style=MUTED)
            lines.append("Press Enter to confirm, Esc to cancel", style=MUTED)
        else:
            for i, d in enumerate(self._path_popup_dirs):
                cursor = ">" if i == self._path_popup_selected else " "
                style = "bold reverse" if i == self._path_popup_selected else None
                lines.append(f"  {cursor} {d}\n", style=style)
            lines.append("\n  > ", style=f"bold {ACCENT}")
            lines.append(self._path_popup_custom, style="bold")
            lines.append("_", style="blink")
            lines.append("\n\n", style=MUTED)
            lines.append("up/down select folder   type custom path   Enter confirm   Esc cancel", style=MUTED)

        label = dict(self._export_options).get(self._path_popup_export_type, "")
        return Panel(lines, title=f"[bold]Export: {label}", border_style=ACCENT, box=box.HEAVY)

    def _open_path_popup(self, export_type, rows):
        self._path_popup_active = True
        self._path_popup_selected = 0
        self._path_popup_custom = ""
        self._path_popup_custom_mode = False
        self._path_popup_export_type = export_type
        self._path_popup_rows = rows
        self._set_output(self._build_path_popup())

    def _close_path_popup(self):
        self._path_popup_active = False
        self._path_popup_custom_mode = False

    def _do_export_to_path(self, filepath):
        export_type = self._path_popup_export_type
        rows = self._path_popup_rows
        self._close_path_popup()
        try:
            if export_type == "full":
                path = self.report.export_full_csv(rows, filepath)
            elif export_type == "search":
                path = self.report.export_search_csv(rows, filepath)
            else:
                path = self.report.export_matched_csv(rows, filepath)
        except Exception as exc:
            self._set_output(self._error_panel(f"Export failed: {exc}"))
            return
        summary = Text()
        summary.append("Export done\n", style=OK)
        summary.append(f"  {len(rows)} records saved\n\n", style="bold")
        summary.append(f"  File: {path}", style=ACCENT)
        self._set_output(Panel(
            summary, title="[bold]Export to CSV", border_style=ACCENT, box=box.HEAVY,
        ))

    def _handle_path_popup(self, key):
        if not self._path_popup_active:
            return False

        if self._path_popup_custom_mode:
            if key == "enter":
                chosen = self._path_popup_custom.strip()
                if chosen:
                    self._do_export_to_path(chosen)
                else:
                    self._close_path_popup()
                return True
            if key == "esc":
                self._close_path_popup()
                self._set_output(self._idle_panel())
                return True
            if key == "backspace":
                self._path_popup_custom = self._path_popup_custom[:-1]
                self._set_output(self._build_path_popup())
                return True
            if isinstance(key, str) and len(key) == 1 and key.isprintable():
                self._path_popup_custom += key
                self._set_output(self._build_path_popup())
                return True
            return True

        if key == "up":
            self._path_popup_selected = (self._path_popup_selected - 1) % len(self._path_popup_dirs)
            self._set_output(self._build_path_popup())
            return True
        if key == "down":
            self._path_popup_selected = (self._path_popup_selected + 1) % len(self._path_popup_dirs)
            self._set_output(self._build_path_popup())
            return True
        if key == "enter":
            chosen_dir = self._path_popup_dirs[self._path_popup_selected]
            filename = self.storage.load_settings().get("export_filename", "threat_report.csv")
            filepath = os.path.join(chosen_dir, filename)
            self._do_export_to_path(filepath)
            return True
        if key == "esc":
            self._close_path_popup()
            self._set_output(self._idle_panel())
            return True
        if isinstance(key, str) and len(key) == 1 and key.isprintable():
            self._path_popup_custom_mode = True
            self._path_popup_custom = key
            self._set_output(self._build_path_popup())
            return True
        return True

    # actions
    def do_fetch(self):
        self._set_output(Panel(
            Group(
                Text("Downloading ...", style=WARN),
            ),
            title="[bold]Fetch Threat", border_style=ACCENT, box=box.HEAVY,
        ))
        try:
            vulns = self.scraper.scrape_all()
            added, total = self.storage.merge_vulnerabilities(vulns)
        except Exception as exc:
            self._set_output(self._error_panel(f"{exc} -- check your internet."))
            return

        criticals = sum(1 for v in vulns if v.is_critical())
        summary = Text()
        summary.append("Done\n", style=OK)
        summary.append(f"  {len(vulns)} vulnerabilities downloaded", style="bold")
        summary.append(f" ({criticals} critical, {len(vulns) - criticals} high)\n")
        if added:
            summary.append(f"  {added} new entries added\n", style=OK)
        else:
            summary.append("  Already up to date\n", style=WARN)
        summary.append(f"  Database: {total} total\n", style="bold")
        self._refresh_status()
        self._set_output(Panel(
            Group(summary, Text(""), Text("Use View All CVEs or Search to browse.", style=MUTED)),
            title="[bold]Fetch Threat Feeds", border_style=ACCENT, box=box.HEAVY,
        ))

    def do_scan(self):
        assets = self.matcher.load_assets()
        if not assets:
            self._set_output(self._error_panel("No assets found. Use Add Asset first."))
            return
        db = self.storage.load("vulnerabilities.json", default=[])
        if not isinstance(db, list) or not db:
            self._set_output(self._error_panel("Database empty. Run Fetch first."))
            return

        vulns = [Vulnerability.from_dict(e) for e in db]
        matches = self.matcher.match(vulns, assets)
        self.storage.save("matched_vulnerabilities.json", matches)

        if not matches:
            self._set_output(Panel(
                Text("No risks found for your monitored assets.", style=OK),
                title="[bold]Scan Assets", border_style=ACCENT, box=box.HEAVY,
            ))
            self._refresh_status()
            return

        summ = self.report.summarize(matches)
        heading = Text()
        heading.append(f"{len(matches)} risks found  ", style="bold")
        for level, count in summ.items():
            heading.append(f"{level}:{count}  ", style=risk_color(level))

        columns = [
            ("CVE_ID", "cve_id", 18, lambda s: "bold"),
            ("Asset", "asset", 14, None),
            ("Product", "product", 36, None),
            ("Risk", "risk_level", 10, risk_color),
            ("Detected", "date_detected", 12, None),
        ]

        self._refresh_status()
        self._set_scrollable(heading, matches, columns, "Scan Assets vs Threats")

    def do_search(self, keyword):
        db = self.storage.load("vulnerabilities.json", default=[])
        if not isinstance(db, list) or not db:
            self._set_output(self._error_panel("Database empty. Run Fetch first."))
            return

        needle = keyword.lower()
        results = [
            e for e in db
            if needle in e.get("cve_id", "").lower()
            or needle in e.get("vendor", "").lower()
            or needle in e.get("product", "").lower()
            or needle in e.get("vulnerability_name", "").lower()
        ]
        self._last_search_results = results

        if not results:
            self._set_output(Panel(
                Group(Text("No results for ", style="bold"), Text(repr(keyword), style=ACCENT)),
                title="[bold]Search", border_style=ACCENT, box=box.HEAVY,
            ))
            return

        heading = Text()
        heading.append(f"{len(results)} result(s) for ", style="bold")
        heading.append(repr(keyword), style=ACCENT)
        heading.append("\nAll results shown. Use Export > Last search results to save.", style=MUTED)

        columns = [
            ("CVE_ID", "cve_id", 18, lambda s: "bold"),
            ("Vendor", "vendor", 14, None),
            ("Product", "product", 36, None),
            ("Severity", "severity", 10, risk_color),
            ("Date", "date_added", 12, None),
        ]

        self._set_scrollable(heading, results, columns, "Search")

    def do_list_all(self):
        db = self.storage.load("vulnerabilities.json", default=[])
        if not isinstance(db, list) or not db:
            self._set_output(self._error_panel("Database empty. Run Fetch first."))
            return

        heading = Text(f"{len(db)} total CVEs in database", style="bold")

        columns = [
            ("CVE_ID", "cve_id", 18, lambda s: "bold"),
            ("Vendor", "vendor", 14, None),
            ("Product", "product", 36, None),
            ("Severity", "severity", 10, risk_color),
            ("Date", "date_added", 12, None),
        ]

        self._set_scrollable(heading, db, columns, "All CVEs")

    def do_add_asset(self):
        assets = self.matcher.load_assets()
        current = ", ".join(assets) if assets else "(none)"
        lines = Text()
        lines.append("Current monitored assets:\n\n", style="bold")
        lines.append(f"  {current}\n\n", style=ACCENT)
        lines.append("Type a new asset name and press Enter.\n", style=MUTED)
        lines.append("Press Esc to go back.\n", style=MUTED)
        self._set_output(Panel(
            lines, title="[bold]Add Asset", border_style=ACCENT, box=box.HEAVY,
        ))

        self.input_prompt = "Asset name"
        self.input_buffer = ""
        self._update()

        while True:
            self._update()
            key = get_key()
            if key == "enter":
                name = self.input_buffer.strip()
                self.input_prompt = None
                if name:
                    self._save_asset(name)
                return
            if key in ("esc", "ctrl-c"):
                self.input_prompt = None
                return
            if key == "backspace":
                self.input_buffer = self.input_buffer[:-1]
            elif isinstance(key, str) and len(key) == 1 and key.isprintable():
                self.input_buffer += key

    def _save_asset(self, name):
        filename = "monitored_assets.json"
        data = self.storage.load(filename, default=[])
        if not isinstance(data, list):
            data = []

        if name.lower() in [a.lower() for a in data]:
            self._set_output(Panel(
                Text(f"'{name}' is already in your list.", style=WARN),
                title="[bold]Add Asset", border_style=ACCENT, box=box.HEAVY,
            ))
            self._refresh_status()
            return

        data.append(name)
        self.storage.save(filename, data)
        self._refresh_status()

        updated = self.matcher.load_assets()
        lines = Text()
        lines.append(f"Added '{name}'.\n\n", style=OK)
        lines.append("Monitored assets:\n\n", style="bold")
        for a in updated:
            marker = " * " if a == name else "   "
            lines.append(f"{marker}{a}\n", style=ACCENT if a == name else "")
        self._set_output(Panel(
            lines, title="[bold]Add Asset", border_style=ACCENT, box=box.HEAVY,
        ))

    def do_del_asset(self):
        assets = self.matcher.load_assets()
        if not assets:
            self._set_output(Panel(
                Text("No assets to remove.", style=WARN),
                title="[bold]Remove Asset", border_style=ACCENT, box=box.HEAVY,
            ))
            return

        lines = Text()
        lines.append("Current monitored assets:\n\n", style="bold")
        for i, a in enumerate(assets):
            lines.append(f"  {i + 1}. {a}\n", style=ACCENT)
        lines.append("\nType the number of the asset to remove.\n", style=MUTED)
        lines.append("Press Esc to go back.\n", style=MUTED)
        self._set_output(Panel(
            lines, title="[bold]Remove Asset", border_style=ACCENT, box=box.HEAVY,
        ))

        self.input_prompt = "Asset #"
        self.input_buffer = ""
        self._update()

        while True:
            self._update()
            key = get_key()
            if key == "enter":
                choice = self.input_buffer.strip()
                self.input_prompt = None
                if choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(assets):
                        self._remove_asset(assets[idx])
                        return
                self._set_output(self._error_panel("Invalid number."))
                return
            if key in ("esc", "ctrl-c"):
                self.input_prompt = None
                return
            if key == "backspace":
                self.input_buffer = self.input_buffer[:-1]
            elif isinstance(key, str) and len(key) == 1 and key.isprintable():
                self.input_buffer += key

    def _remove_asset(self, name):
        filename = "monitored_assets.json"
        data = self.storage.load(filename, default=[])
        if not isinstance(data, list):
            data = []

        data = [a for a in data if a.lower() != name.lower()]
        self.storage.save(filename, data)
        self._refresh_status()

        updated = self.matcher.load_assets()
        lines = Text()
        lines.append(f"Removed '{name}'.\n\n", style=OK)
        if updated:
            lines.append("Remaining assets:\n\n", style="bold")
            for a in updated:
                lines.append(f"  {a}\n", style=ACCENT)
        else:
            lines.append("No assets left.\n", style=MUTED)
        self._set_output(Panel(
            lines, title="[bold]Remove Asset", border_style=ACCENT, box=box.HEAVY,
        ))

    def do_export(self):
        self._export_active = True
        self._export_selected = 0
        self._set_output(self._export_sub_menu())

    #def do_settings(self):
     #   settings = self.storage.load_settings()
      #  lines = Text()
       # lines.append("Current settings:\n\n", style="bold")
        #lines.append(f"  Export filename:  {settings.get('export_filename', 'threat_report.csv')}\n", style=ACCENT)
        #lines.append(f"  Export directory: {settings.get('export_dir', 'data')}\n", style=ACCENT)
        #lines.append("\nPress Enter to change export filename.", style=MUTED)
        #self._set_output(Panel(
         #   lines, title="[bold]Settings", border_style=ACCENT, box=box.HEAVY,
        #))

    def prompt_search(self):
        self.input_prompt = "Search"
        self.input_buffer = ""
        self._set_output(self._idle_panel())
        while True:
            self._update()
            key = get_key()
            if key == "enter":
                kw = self.input_buffer
                self.input_prompt = None
                if kw.strip():
                    self.do_search(kw)
                return
            if key in ("esc", "ctrl-c"):
                self.input_prompt = None
                return
            if key == "backspace":
                self.input_buffer = self.input_buffer[:-1]
            elif isinstance(key, str) and len(key) == 1 and key.isprintable():
                self.input_buffer += key

   # def prompt_settings(self):
    #    settings = self.storage.load_settings()
     #   current = settings.get("export_filename", "threat_report.csv")
      #  self.input_prompt = "Export filename"
      #  self.input_buffer = current
      #  self._set_output(self._idle_panel())
      #  while True:
       #     self._update()
        #    key = get_key()
         #   if key == "enter":
          #      new_name = self.input_buffer.strip()
           #     self.input_prompt = None
            #    if new_name:
             #       settings["export_filename"] = new_name
              #      self.storage.save_settings(settings)
               #     self._set_output(Panel(
                #        Text(f"Export filename set to: {new_name}", style=OK),
                 #       title="[bold]Settings", border_style=ACCENT, box=box.HEAVY,
                  #  ))
                #return
            #if key in ("esc", "ctrl-c"):
             #   self.input_prompt = None
              #  return
            #if key == "backspace":
             #   self.input_buffer = self.input_buffer[:-1]
            #elif isinstance(key, str) and len(key) == 1 and key.isprintable():
             #   self.input_buffer += key

    def activate(self):
        item = self.menu_items[self.selected]
        if item.key == "fetch":
            self.do_fetch()
        elif item.key == "scan":
            self.do_scan()
        elif item.key == "search":
            self.prompt_search()
        elif item.key == "list":
            self.do_list_all()
        elif item.key == "add_asset":
            self.do_add_asset()
        elif item.key == "del_asset":
            self.do_del_asset()
        elif item.key == "export":
            self.do_export()
        elif item.key == "settings":
            self.do_settings()
            self.prompt_settings()
        elif item.key == "quit":
            self.quit_requested = True

    def _handle_export_nav(self, key):
        if not self._export_active:
            return False
        if key == "up":
            self._export_selected = (self._export_selected - 1) % len(self._export_options)
            self._set_output(self._export_sub_menu())
            return True
        if key == "down":
            self._export_selected = (self._export_selected + 1) % len(self._export_options)
            self._set_output(self._export_sub_menu())
            return True
        if key == "enter":
            exp_type = self._export_options[self._export_selected][0]
            self._export_active = False
            rows = self._build_export_rows(exp_type)
            if not rows:
                self._set_output(self._error_panel("Nothing to export for this selection."))
                return True
            self._open_path_popup(exp_type, rows)
            return True
        if key == "esc":
            self._export_active = False
            self._set_output(self._idle_panel())
            return True
        return False

    def run_tui(self):
        try:
            enter_raw_mode()
            with Live(
                self.render(),
                console=self.console,
                screen=True,
                auto_refresh=False,
            ) as live:
                self.live = live
                while not self.quit_requested:
                    self._update()
                    key = get_key()
                    if key == "ctrl-c":
                        break
                    #q only works in menu state, not when browsing results etc
                    if key == "q" and self.input_prompt is None and not self._export_active and not self._path_popup_active and not getattr(self, "_scroll_entries", None):
                        break

                    if self.input_prompt is not None:
                        continue

                    if self._path_popup_active:
                        self._handle_path_popup(key)
                        continue

                    if self._export_active:
                        self._handle_export_nav(key)
                        continue

                    if getattr(self, "_scroll_entries", None):
                        if key == "esc":
                            self._scroll_entries = []
                            self._scroll_offset = 0
                            self._set_output(self._idle_panel())
                            continue
                        if self._handle_scroll(key):
                            continue

                    if key == "up":
                        self.selected = (self.selected - 1) % len(self.menu_items)
                    elif key == "down":
                        self.selected = (self.selected + 1) % len(self.menu_items)
                    elif key in ("enter", "right"):
                        self.activate()
        except KeyboardInterrupt:
            pass
        finally:
            exit_raw_mode()

    def run_line(self):
        self.console.print(self.render_header())
        while not self.quit_requested:
            self.console.print()
            for index, item in enumerate(self.menu_items):
                marker = ">" if index == self.selected else " "
                style = "bold " + ACCENT if index == self.selected else "default"
                self.console.print(f"  {marker} {index + 1}. {item.label}", style=style)
            try:
                choice = input("\n  ThreatIntel> ").strip()
            except (EOFError, KeyboardInterrupt):
                self.console.print("\n  Bye.")
                return
            if not choice.isdigit():
                continue
            index = int(choice) - 1
            if not 0 <= index < len(self.menu_items):
                continue
            self.selected = index
            item = self.menu_items[index]
            if item.key == "fetch":
                self.do_fetch()
            elif item.key == "scan":
                self.do_scan()
            elif item.key == "search":
                keyword = input("  Search> ").strip()
                self.do_search(keyword)
            elif item.key == "list":
                self.do_list_all()
            elif item.key == "add_asset":
                name = input("  Asset name> ").strip()
                if name:
                    self._save_asset(name)
            elif item.key == "del_asset":
                assets = self.matcher.load_assets()
                if not assets:
                    self.console.print("  No assets to remove.", style=WARN)
                else:
                    self.console.print("\n  Monitored assets:")
                    for i, a in enumerate(assets):
                        self.console.print(f"    {i+1}. {a}")
                    choice = input("  Remove which ? (# or name)> ").strip()
                    if choice.isdigit():
                        idx = int(choice) - 1
                        if 0 <= idx < len(assets):
                            self._remove_asset(assets[idx])
                        else:
                            self.console.print("  Invalid number.", style=WARN)
                    elif choice:
                        self._remove_asset(choice)
            elif item.key == "export":
                self.console.print("\n  What to export?")
                for i, (k, label) in enumerate(self._export_options):
                    self.console.print(f"    {i+1}. {label}")
                exp_choice = input("  Choice> ").strip()
                if exp_choice.isdigit() and 1 <= int(exp_choice) <= len(self._export_options):
                    exp_type = self._export_options[int(exp_choice) - 1][0]
                    rows = self._build_export_rows(exp_type)
                    if not rows:
                        self.console.print("  Nothing to export.", style=WARN)
                    else:
                        default_path = os.path.join("data", "threat_report.csv")
                        dirs = _get_suggested_dirs()
                        self.console.print("\n  Suggested directories:")
                        for i, d in enumerate(dirs):
                            self.console.print(f"    {i+1}. {d}")
                        loc = input(f"  Choose # or type path [{default_path}]> ").strip()
                        if loc.isdigit() and 1 <= int(loc) <= len(dirs):
                            filename = self.storage.load_settings().get("export_filename", "threat_report.csv")
                            filepath = os.path.join(dirs[int(loc) - 1], filename)
                        elif loc:
                            filepath = loc
                        else:
                            filepath = default_path
                        try:
                            if exp_type == "full":
                                path = self.report.export_full_csv(rows, filepath)
                            elif exp_type == "search":
                                path = self.report.export_search_csv(rows, filepath)
                            else:
                                path = self.report.export_matched_csv(rows, filepath)
                            self.console.print(f"  Exported {len(rows)} records to {path}", style=OK)
                        except Exception as exc:
                            self.console.print(f"  Export failed: {exc}", style=DANGER)
            elif item.key == "settings":
                self.do_settings()
                new_name = input("  Export filename> ").strip()
                if new_name:
                    settings = self.storage.load_settings()
                    settings["export_filename"] = new_name
                    self.storage.save_settings(settings)
                    self.console.print(f"  Export filename set to: {new_name}", style=OK)
            elif item.key == "quit":
                self.quit_requested = True
            self.console.print(self.output)

    def run(self):
        if sys.stdin.isatty():
            self.run_tui()
        else:
            self.run_line()


def main():
    app = ThreatIntelApp()
    try:
        app.run()
    except Exception as exc:
        app.console.print(f"[{DANGER}]Fatal:[/] {exc}")


if __name__ == "__main__":
    main()
