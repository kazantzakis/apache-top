#!/usr/bin/env python3
"""apache-top - an elegant live Apache server-status monitor.

Polls Apache's mod_status endpoints and renders a continuously refreshing,
top-style dashboard using `rich`.

Two endpoints are used per refresh:
  * <base>/server-status?auto  -> machine-readable summary metrics + scoreboard
  * <base>/server-status       -> HTML page, parsed for the per-connection table
                                  (requires `ExtendedStatus On`, default in 2.4)

Usage:
    apache-top web01.example.com
    apache-top https://host/server-status -i 1 --sort cpu
    apache-top localhost:8080 --once
"""

from __future__ import annotations

import argparse
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, Literal, Optional

import requests
from bs4 import BeautifulSoup
from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ---------------------------------------------------------------------------
# Constants & legends
# ---------------------------------------------------------------------------

# Apache scoreboard single-character slot states.
# Reference: https://httpd.apache.org/docs/2.4/mod/mod_status.html
SCOREBOARD_LEGEND: dict[str, str] = {
    "_": "Waiting",
    "S": "Starting",
    "R": "Reading",
    "W": "Sending",
    "K": "Keepalive",
    "D": "DNS",
    "C": "Closing",
    "L": "Logging",
    "G": "Graceful",
    "I": "Idle",
    ".": "Open",
}

# Short labels used in the compact Workers panel (folded scoreboard counts).
SCOREBOARD_SHORT: dict[str, str] = {
    "Waiting": "Wait",
    "Starting": "Start",
    "Reading": "Read",
    "Sending": "Send",
    "Keepalive": "Keep",
    "DNS": "DNS",
    "Closing": "Close",
    "Logging": "Log",
    "Graceful": "Grace",
    "Idle": "Idle",
    "Open": "Open",
}

# rich styles keyed by worker mode character (M column / scoreboard).
MODE_STYLES: dict[str, str] = {
    "_": "dim",
    "S": "magenta",
    "R": "cyan",
    "W": "green",
    "K": "blue",
    "D": "magenta",
    "C": "yellow",
    "L": "magenta",
    "G": "yellow",
    "I": "dim",
    ".": "dim",
}

SortKey = Literal["cpu", "ss", "req", "acc", "client"]
SORT_CHOICES: tuple[SortKey, ...] = ("cpu", "ss", "req", "acc", "client")


# ---------------------------------------------------------------------------
# Data contracts (typed dataclasses passed between layers)
# ---------------------------------------------------------------------------


@dataclass
class AppConfig:
    """Resolved runtime configuration derived from CLI arguments."""

    auto_url: str
    html_url: str
    display_url: str
    interval: float
    timeout: float
    auth: Optional[tuple[str, str]]
    verify_tls: bool
    once: bool
    iterations: Optional[int]
    show_all: bool
    sort_key: SortKey
    rows: Optional[int]


@dataclass
class AutoStatus:
    """Parsed values from the machine-readable `?auto` endpoint."""

    version: str = "Apache"
    mpm: str = "n/a"
    uptime_seconds: int = 0
    total_accesses: int = 0
    total_kbytes: float = 0.0
    req_per_sec: float = 0.0
    bytes_per_sec: float = 0.0
    bytes_per_req: float = 0.0
    cpu_load: float = 0.0
    busy: int = 0
    idle: int = 0
    scoreboard: str = ""


@dataclass
class WorkerRow:
    """A single row from the HTML server-status worker table."""

    srv: str = ""
    pid: str = ""
    acc: str = ""
    mode: str = ""
    cpu: float = 0.0
    ss: int = 0
    req: str = ""
    conn_kb: float = 0.0
    client: str = ""
    vhost: str = ""
    request: str = ""


@dataclass
class LiveMetrics:
    """Derived, delta-based metrics computed across refreshes."""

    live_req_s: Optional[float] = None
    live_bytes_s: Optional[float] = None
    utilization: float = 0.0


class FetchError(Exception):
    """Raised when an endpoint cannot be retrieved or returns a bad status."""

    def __init__(self, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.hint = hint


# ---------------------------------------------------------------------------
# CLI parsing & target normalization
# ---------------------------------------------------------------------------


def normalize_target(server: str) -> tuple[str, str, str]:
    """Turn a host / host:port / URL into (auto_url, html_url, display_url).

    Examples:
        web01                 -> http://web01/server-status(?auto)
        host:8080             -> http://host:8080/server-status(?auto)
        https://h/server-status -> kept, ?auto appended for the auto endpoint
    """
    target = server.strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    # If no explicit status path was given, append the conventional one.
    # We only look at the path portion after the scheme://host[:port].
    scheme_sep = target.find("://") + 3
    path_start = target.find("/", scheme_sep)
    has_path = path_start != -1 and target[path_start:].strip("/") != ""
    if not has_path:
        target = target.rstrip("/") + "/server-status"

    # Strip any existing query so we can build both variants cleanly.
    base = target.split("?", 1)[0]
    html_url = base
    auto_url = base + "?auto"
    return auto_url, html_url, html_url


def parse_args(argv: Optional[list[str]] = None) -> AppConfig:
    """Parse command-line arguments into an :class:`AppConfig`."""
    parser = argparse.ArgumentParser(
        prog="apache-top",
        description="Elegant live Apache server-status monitor.",
    )
    parser.add_argument(
        "server",
        help="Apache host, host:port, or full server-status URL.",
    )
    parser.add_argument("-i", "--interval", type=float, default=2.0,
                        help="Refresh interval in seconds (default: 2).")
    parser.add_argument("-t", "--timeout", type=float, default=5.0,
                        help="HTTP timeout in seconds (default: 5).")
    parser.add_argument("-u", "--user", help="HTTP Basic auth username.")
    parser.add_argument("-p", "--password", help="HTTP Basic auth password.")
    parser.add_argument("-k", "--insecure", action="store_true",
                        help="Skip TLS certificate verification.")
    parser.add_argument("--once", action="store_true",
                        help="Render a single snapshot and exit.")
    parser.add_argument("-n", "--iterations", type=int, default=None,
                        help="Exit after N refreshes (default: run forever).")
    parser.add_argument("--all", dest="show_all", action="store_true",
                        help="Include idle/open worker slots in the table.")
    parser.add_argument("--sort", dest="sort_key", choices=SORT_CHOICES,
                        default="ss", help="Sort key for requests (default: ss).")
    parser.add_argument("--rows", type=int, default=None,
                        help="Max request rows to show (default: auto-fit).")

    args = parser.parse_args(argv)

    auth: Optional[tuple[str, str]] = None
    if args.user is not None:
        auth = (args.user, args.password or "")

    auto_url, html_url, display_url = normalize_target(args.server)

    return AppConfig(
        auto_url=auto_url,
        html_url=html_url,
        display_url=display_url,
        interval=max(0.1, args.interval),
        timeout=max(0.1, args.timeout),
        auth=auth,
        verify_tls=not args.insecure,
        once=args.once,
        iterations=args.iterations,
        show_all=args.show_all,
        sort_key=args.sort_key,
        rows=args.rows,
    )


# ---------------------------------------------------------------------------
# Fetcher (the only layer that performs network I/O)
# ---------------------------------------------------------------------------


class StatusFetcher:
    """Retrieves the `?auto` text and HTML status pages over HTTP(S)."""

    def __init__(self, cfg: AppConfig) -> None:
        self._cfg = cfg
        self._session = requests.Session()
        if cfg.auth is not None:
            self._session.auth = cfg.auth
        self._session.verify = cfg.verify_tls

    def _get(self, url: str) -> str:
        try:
            resp = self._session.get(url, timeout=self._cfg.timeout)
        except requests.exceptions.SSLError as exc:
            raise FetchError(f"TLS error: {exc}",
                             "Use -k/--insecure to skip verification.") from exc
        except requests.exceptions.ConnectionError as exc:
            raise FetchError("Connection refused / host unreachable.",
                             "Is Apache running and reachable?") from exc
        except requests.exceptions.Timeout as exc:
            raise FetchError("Request timed out.",
                             "Increase --timeout or check the network.") from exc
        except requests.exceptions.RequestException as exc:
            raise FetchError(f"Request failed: {exc}") from exc

        if resp.status_code == 403:
            raise FetchError("403 Forbidden.",
                             "mod_status may be IP-restricted; allow your IP.")
        if resp.status_code == 404:
            raise FetchError("404 Not Found.",
                             "Is mod_status enabled at this path?")
        if resp.status_code != 200:
            raise FetchError(f"HTTP {resp.status_code} {resp.reason}.")
        return resp.text

    def fetch_auto(self) -> str:
        """Return the raw text of the `?auto` endpoint."""
        return self._get(self._cfg.auto_url)

    def fetch_html(self) -> str:
        """Return the raw HTML of the human status page."""
        return self._get(self._cfg.html_url)


# ---------------------------------------------------------------------------
# Parsers (pure functions - no I/O, easily testable)
# ---------------------------------------------------------------------------


def _to_int(value: str, default: int = 0) -> int:
    try:
        return int(float(value.strip()))
    except (ValueError, AttributeError):
        return default


def _to_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value.strip())
    except (ValueError, AttributeError):
        return default


def parse_auto(text: str) -> AutoStatus:
    """Parse the `key: value` lines of the `?auto` response.

    Raises FetchError if the body looks like HTML (i.e. `?auto` was ignored
    or the endpoint served the human page instead).
    """
    stripped = text.lstrip()
    if stripped.startswith("<"):
        raise FetchError("Endpoint returned HTML, not machine-readable data.",
                         "Ensure the URL ends with '?auto'.")

    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        fields[key.strip()] = val.strip()

    status = AutoStatus()
    status.version = fields.get("ServerVersion", "Apache")
    status.mpm = fields.get("ServerMPM", "n/a")
    status.uptime_seconds = _to_int(fields.get("ServerUptimeSeconds",
                                               fields.get("Uptime", "0")))
    status.total_accesses = _to_int(fields.get("Total Accesses", "0"))
    status.total_kbytes = _to_float(fields.get("Total kBytes", "0"))
    status.req_per_sec = _to_float(fields.get("ReqPerSec", "0"))
    status.bytes_per_sec = _to_float(fields.get("BytesPerSec", "0"))
    status.bytes_per_req = _to_float(fields.get("BytesPerReq", "0"))
    status.cpu_load = _to_float(fields.get("CPULoad", "0"))
    status.busy = _to_int(fields.get("BusyWorkers", "0"))
    status.idle = _to_int(fields.get("IdleWorkers", "0"))
    status.scoreboard = fields.get("Scoreboard", "")
    return status


def decode_scoreboard(scoreboard: str) -> dict[str, int]:
    """Count scoreboard slot characters into named states."""
    counts: dict[str, int] = {name: 0 for name in SCOREBOARD_LEGEND.values()}
    for char in scoreboard:
        name = SCOREBOARD_LEGEND.get(char)
        if name is not None:
            counts[name] += 1
    return counts


def parse_html_workers(html: str) -> list[WorkerRow]:
    """Extract the per-connection worker rows from the HTML status page.

    Apache renders a table whose header includes 'Srv' and 'Request'. Column
    order can vary slightly by version, so we map by header name.
    """
    soup = BeautifulSoup(html, "lxml")

    target = None
    for table in soup.find_all("table"):
        header_cells = table.find_all("th")
        headers = [th.get_text(strip=True) for th in header_cells]
        if "Srv" in headers and "Request" in headers:
            target = table
            headers_map = {name: idx for idx, name in enumerate(headers)}
            break
    if target is None:
        return []

    rows: list[WorkerRow] = []
    for tr in target.find_all("tr"):
        cells = tr.find_all("td")
        if not cells:
            continue
        values = [td.get_text(" ", strip=True) for td in cells]

        def col(name: str) -> str:
            idx = headers_map.get(name)
            if idx is None or idx >= len(values):
                return ""
            return values[idx]

        # Skip the summary/legend rows that lack a numeric Srv like "0-0".
        srv = col("Srv")
        if "-" not in srv:
            continue

        rows.append(WorkerRow(
            srv=srv,
            pid=col("PID"),
            acc=col("Acc"),
            mode=col("M"),
            cpu=_to_float(col("CPU")),
            ss=_to_int(col("SS")),
            req=col("Req"),
            conn_kb=_to_float(col("Conn")),
            client=col("Client"),
            vhost=col("VHost"),
            request=col("Request"),
        ))
    return rows


def detect_extended_status(rows: list[WorkerRow]) -> bool:
    """Heuristic: ExtendedStatus is on if any row exposes client/request data."""
    return any(r.client or r.request for r in rows)


# ---------------------------------------------------------------------------
# Metrics (holds cross-refresh state to compute live deltas)
# ---------------------------------------------------------------------------


class MetricsState:
    """Remembers the previous sample to derive live req/s and throughput."""

    def __init__(self) -> None:
        self._prev: Optional[AutoStatus] = None
        self._prev_ts: Optional[float] = None

    def update(self, status: AutoStatus) -> LiveMetrics:
        """Fold in a new sample and return derived live metrics."""
        now = time.monotonic()
        metrics = LiveMetrics()

        total = status.busy + status.idle
        metrics.utilization = (status.busy / total) if total else 0.0

        if self._prev is not None and self._prev_ts is not None:
            dt = now - self._prev_ts
            if dt > 0:
                d_acc = status.total_accesses - self._prev.total_accesses
                d_kb = status.total_kbytes - self._prev.total_kbytes
                # Guard against counter resets (server restart).
                if d_acc >= 0:
                    metrics.live_req_s = d_acc / dt
                if d_kb >= 0:
                    metrics.live_bytes_s = (d_kb * 1024.0) / dt

        self._prev = status
        self._prev_ts = now
        return metrics


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def human_bytes(num: float) -> str:
    """Format a byte count with binary-ish suffixes."""
    value = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(value) < 1024.0:
            return f"{value:.1f} {unit}" if unit != "B" else f"{value:.0f} {unit}"
        value /= 1024.0
    return f"{value:.1f} EB"


def human_int(num: int) -> str:
    """Group thousands with commas."""
    return f"{num:,}"


def human_duration(seconds: int) -> str:
    """Format seconds as e.g. '12d 04h 37m'."""
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours:02d}h {minutes:02d}m"
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def utilization_bar(fraction: float, width: int = 30) -> Text:
    """Render a colored utilization bar for a 0..1 fraction."""
    fraction = max(0.0, min(1.0, fraction))
    filled = int(round(fraction * width))
    if fraction < 0.60:
        color = "green"
    elif fraction < 0.85:
        color = "yellow"
    else:
        color = "red"
    bar = Text()
    bar.append("[", style="dim")
    bar.append("█" * filled, style=color)
    bar.append("░" * (width - filled), style="dim")
    bar.append("]", style="dim")
    bar.append(f" {fraction * 100:.0f}%", style=color)
    return bar


def _sort_rows(rows: list[WorkerRow], sort_key: SortKey) -> list[WorkerRow]:
    """Return rows sorted descending by the chosen key (client sorts asc)."""
    if sort_key == "cpu":
        return sorted(rows, key=lambda r: r.cpu, reverse=True)
    if sort_key == "ss":
        return sorted(rows, key=lambda r: r.ss, reverse=True)
    if sort_key == "req":
        return sorted(rows, key=lambda r: _to_int(r.req), reverse=True)
    if sort_key == "acc":
        return sorted(rows, key=lambda r: _to_int(r.acc.split("/")[-1]),
                      reverse=True)
    return sorted(rows, key=lambda r: r.client)


# ---------------------------------------------------------------------------
# Renderers (pure: model -> rich renderables)
# ---------------------------------------------------------------------------


def build_header(auto: AutoStatus, cfg: AppConfig, now: datetime,
                 extended: bool) -> Panel:
    """Top panel: version, MPM, URL, uptime, ExtendedStatus, clock."""
    line1 = Text()
    line1.append(auto.version, style="bold white")
    line1.append("   MPM: ", style="dim")
    line1.append(auto.mpm, style="bold cyan")
    line1.append("   ")
    line1.append(cfg.display_url, style="blue")

    line2 = Text()
    line2.append("Uptime: ", style="dim")
    line2.append(human_duration(auto.uptime_seconds), style="white")
    line2.append("    ExtendedStatus: ", style="dim")
    line2.append("on" if extended else "off",
                 style="green" if extended else "red")
    line2.append("    \u27f3 ", style="dim")
    line2.append(f"{cfg.interval:g}s", style="white")
    line2.append("   ")
    line2.append(now.strftime("%Y-%m-%d %H:%M:%S"), style="dim")

    return Panel(Group(line1, line2), title="apache-top",
                 border_style="cyan", padding=(0, 1))


def build_summary(auto: AutoStatus, live: LiveMetrics) -> Panel:
    """Left panel: lifetime + live traffic/request metrics."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim", justify="left")
    table.add_column(justify="left", style="white")

    live_req = (f"  (live {live.live_req_s:.1f})"
                if live.live_req_s is not None else "")
    live_bps = (human_bytes(live.live_bytes_s) + "/s"
                if live.live_bytes_s is not None
                else human_bytes(auto.bytes_per_sec) + "/s")

    table.add_row("Total Requests", human_int(auto.total_accesses))
    table.add_row("Total Traffic", human_bytes(auto.total_kbytes * 1024.0))
    table.add_row("Requests/sec", f"{auto.req_per_sec:.2f}{live_req}")
    table.add_row("Traffic/sec", live_bps)
    table.add_row("Bytes/request", human_bytes(auto.bytes_per_req))
    table.add_row("CPU Load", f"{auto.cpu_load:.2f} %")

    return Panel(table, title="Summary", border_style="cyan", padding=(0, 1))


def build_workers(auto: AutoStatus, counts: dict[str, int],
                  live: LiveMetrics) -> Panel:
    """Right panel: busy/idle totals, utilization bar, folded scoreboard."""
    total = auto.busy + auto.idle
    head = Text()
    head.append("Busy ", style="dim")
    head.append(str(auto.busy), style="bold green")
    head.append("   Idle ", style="dim")
    head.append(str(auto.idle), style="bold white")
    head.append("   Total ", style="dim")
    head.append(str(total), style="bold white")

    bar = utilization_bar(live.utilization)

    # Folded scoreboard counts, laid out in a compact grid.
    grid = Table.grid(padding=(0, 2))
    for _ in range(4):
        grid.add_column(justify="left")

    order = ["Sending", "Reading", "Keepalive", "Closing",
             "Waiting", "DNS", "Logging", "Open"]
    cells: list[Text] = []
    for name in order:
        short = SCOREBOARD_SHORT.get(name, name)
        cell = Text()
        cell.append(f"{short} ", style="dim")
        cell.append(str(counts.get(name, 0)), style="white")
        cells.append(cell)
    grid.add_row(*cells[0:4])
    grid.add_row(*cells[4:8])

    body = Group(head, Text(""), bar, Text(""), grid)
    return Panel(body, title="Workers", border_style="cyan", padding=(0, 1))


def build_requests(rows: list[WorkerRow], cfg: AppConfig,
                   max_rows: Optional[int]) -> Panel:
    """Bottom panel: sortable, filtered table of active worker connections."""
    visible = rows if cfg.show_all else [
        r for r in rows if r.mode not in ("_", ".", "")
    ]
    visible = _sort_rows(visible, cfg.sort_key)
    active_count = len(visible)
    if max_rows is not None and max_rows > 0:
        visible = visible[:max_rows]

    table = Table(expand=True, pad_edge=False, box=None, header_style="bold")
    table.add_column("Srv", style="dim", no_wrap=True)
    table.add_column("PID", style="dim", no_wrap=True)
    table.add_column("M", no_wrap=True, justify="center")
    table.add_column("CPU", justify="right", no_wrap=True)
    table.add_column("SS", justify="right", no_wrap=True)
    table.add_column("Req", justify="right", no_wrap=True)
    table.add_column("Conn", justify="right", no_wrap=True)
    table.add_column("Client", no_wrap=True)
    table.add_column("VHost", no_wrap=True)
    table.add_column("Request", no_wrap=True, overflow="ellipsis", ratio=1)

    for r in visible:
        style = MODE_STYLES.get(r.mode, "white")
        table.add_row(
            r.srv, r.pid,
            Text(r.mode, style=style),
            f"{r.cpu:.2f}",
            str(r.ss),
            r.req or "-",
            f"{r.conn_kb:.1f}",
            r.client,
            r.vhost,
            r.request or "",
        )

    title = f"Active Requests  ({active_count} active \u00b7 sort: {cfg.sort_key})"
    if not visible:
        body: object = Align.center(
            Text("No active requests.", style="dim"), vertical="middle")
    else:
        body = table
    return Panel(body, title=title, border_style="cyan", padding=(0, 1))


def build_footer(cfg: AppConfig) -> Text:
    """Bottom status line with key hints."""
    footer = Text(justify="center")
    footer.append(f"interval {cfg.interval:g}s", style="dim")
    footer.append("  \u00b7  ", style="dim")
    footer.append(f"sort {cfg.sort_key}", style="dim")
    footer.append("  \u00b7  ", style="dim")
    footer.append("--all for idle workers", style="dim")
    footer.append("  \u00b7  ", style="dim")
    footer.append("Ctrl-C to quit", style="dim")
    return footer


def build_error(err: FetchError, cfg: AppConfig) -> Panel:
    """Full-body red error panel shown when a fetch fails."""
    body = Text()
    body.append("\u26a0  ", style="bold red")
    body.append(str(err), style="red")
    body.append(f"\n     {cfg.display_url}\n", style="dim")
    if err.hint:
        body.append(f"\n     Hint: {err.hint}", style="yellow")
    if not cfg.once:
        body.append(f"\n\n     Retrying in {cfg.interval:g}s\u2026", style="dim")
    return Panel(body, title="apache-top", border_style="red", padding=(1, 1))


def compose_layout(auto: AutoStatus, rows: list[WorkerRow],
                   live: LiveMetrics, cfg: AppConfig,
                   console: Console) -> Layout:
    """Assemble all panels into the full-screen layout grid."""
    now = datetime.now()
    counts = decode_scoreboard(auto.scoreboard)
    extended = detect_extended_status(rows)

    # Reserve vertical space for header(4) + metrics(9) + footer(1) + borders.
    reserved = 4 + 9 + 1
    if cfg.rows is not None:
        max_rows = cfg.rows
    else:
        max_rows = max(1, console.size.height - reserved - 3)

    layout = Layout()
    layout.split_column(
        Layout(build_header(auto, cfg, now, extended), name="header", size=4),
        Layout(name="metrics", size=9),
        Layout(build_requests(rows, cfg, max_rows), name="requests"),
        Layout(build_footer(cfg), name="footer", size=1),
    )
    layout["metrics"].split_row(
        Layout(build_summary(auto, live), name="summary"),
        Layout(build_workers(auto, counts, live), name="workers"),
    )
    return layout


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _ticks(cfg: AppConfig) -> Iterator[int]:
    """Yield refresh indices honoring --once / --iterations."""
    if cfg.once:
        yield 0
        return
    count = 0
    while cfg.iterations is None or count < cfg.iterations:
        yield count
        count += 1


def run(cfg: AppConfig) -> int:
    """Main refresh loop. Returns a process exit code."""
    console = Console()
    fetcher = StatusFetcher(cfg)
    metrics = MetricsState()

    def render_once() -> object:
        try:
            auto = parse_auto(fetcher.fetch_auto())
        except FetchError as exc:
            return build_error(exc, cfg)
        # HTML table is best-effort; summary still renders if it fails.
        try:
            rows = parse_html_workers(fetcher.fetch_html())
        except FetchError:
            rows = []
        live = metrics.update(auto)
        return compose_layout(auto, rows, live, cfg, console)

    if cfg.once:
        console.print(render_once())
        return 0

    with Live(console=console, screen=True, transient=False,
              auto_refresh=False) as live_view:
        for tick in _ticks(cfg):
            live_view.update(render_once(), refresh=True)
            is_last = (cfg.iterations is not None
                       and tick >= cfg.iterations - 1)
            if not is_last:
                time.sleep(cfg.interval)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    """Entry point: parse args, install signal handling, run the loop."""
    cfg = parse_args(argv)
    # Ensure Ctrl-C raises KeyboardInterrupt even under rich's Live.
    signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        return run(cfg)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
