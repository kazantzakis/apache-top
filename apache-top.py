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
import ipaddress
import os
import queue
import select
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, Literal, Optional

import requests

# Optional POSIX-only terminal modules for interactive key handling.
# Guarded so the tool still imports on platforms without them (e.g. Windows).
try:
    import termios
    import tty
    _HAS_TERMIOS = True
except ImportError:  # pragma: no cover - platform dependent
    _HAS_TERMIOS = False
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

# Free ip-api.com batch endpoint (HTTP only on the free tier). Returns up to
# 100 results per request; ~45 requests/min limit. Reference:
# https://ip-api.com/docs/api:batch
IPAPI_BATCH_URL = "http://ip-api.com/batch"
IPAPI_FIELDS = "status,countryCode,country,query"
IPAPI_MAX_BATCH = 100

# Placeholder display strings for the Country column.
GEO_PENDING = "\u2026"    # resolution in progress
GEO_UNKNOWN = "?"          # public IP that could not be resolved
GEO_PRIVATE = "LAN"        # RFC1918 / unique-local address
GEO_RESERVED = "\u2014"    # loopback / link-local / reserved / multicast


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
    show_country: bool = False


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
    load1: Optional[float] = None
    load5: Optional[float] = None
    load15: Optional[float] = None
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
    parser.add_argument("--country", dest="show_country", action="store_true",
                        help="Start with the Country column shown (toggle: F2).")

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
        show_country=args.show_country,
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
# Geolocation (IP -> country) via the free ip-api.com batch endpoint
# ---------------------------------------------------------------------------


def classify_ip(ip: str) -> Optional[str]:
    """Return a local label for non-public addresses, else None.

    Private addresses become 'LAN'; loopback/link-local/reserved/multicast
    become the reserved dash. Public addresses return None (need a lookup).
    Unparseable input returns the unknown marker.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return GEO_UNKNOWN
    if addr.is_private and not addr.is_loopback and not addr.is_link_local:
        return GEO_PRIVATE
    if (addr.is_loopback or addr.is_link_local or addr.is_reserved
            or addr.is_multicast or addr.is_unspecified):
        return GEO_RESERVED
    return None


class GeoResolver:
    """Resolves client IPs to a 'CODE, Country' string, off the render path.

    Public IPs are resolved by a background worker that batches requests to
    ip-api.com and caches results. Private/reserved IPs are labelled locally
    without any network call. Lookups never block or raise into the UI: an
    unknown public IP returns a pending marker and is queued for resolution.
    """

    def __init__(self, timeout: float = 5.0, min_interval: float = 1.5) -> None:
        self._timeout = timeout
        # Throttle between batch calls to stay well under ~45 req/min.
        self._min_interval = min_interval
        self._cache: dict[str, str] = {}
        self._pending: set[str] = set()
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._lock = threading.Lock()
        self._session = requests.Session()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # -- lifecycle -------------------------------------------------------
    def start(self) -> None:
        """Start the background resolver thread (idempotent)."""
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._worker, name="geo-resolver", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the worker to stop; does not block."""
        self._stop.set()

    # -- public API ------------------------------------------------------
    def lookup(self, ip: str) -> str:
        """Return a display string for ``ip`` (may be a pending marker)."""
        if not ip:
            return GEO_RESERVED
        local = classify_ip(ip)
        if local is not None:
            return local
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
            if ip not in self._pending:
                self._pending.add(ip)
                self._queue.put(ip)
        return GEO_PENDING

    def resolve_now(self, ips: list[str]) -> None:
        """Synchronously resolve the given public IPs (used by --once)."""
        todo = []
        for ip in ips:
            if classify_ip(ip) is None:
                with self._lock:
                    if ip not in self._cache:
                        todo.append(ip)
        for start in range(0, len(todo), IPAPI_MAX_BATCH):
            self._resolve_batch(todo[start:start + IPAPI_MAX_BATCH])

    # -- internals -------------------------------------------------------
    def _worker(self) -> None:
        """Drain the queue in batches, throttled between network calls."""
        while not self._stop.is_set():
            batch = self._drain_batch()
            if not batch:
                # Nothing to do; wait briefly for new work.
                time.sleep(0.2)
                continue
            self._resolve_batch(batch)
            # Throttle so bursts of unique IPs stay under the rate limit.
            self._stop.wait(self._min_interval)

    def _drain_batch(self) -> list[str]:
        """Collect up to IPAPI_MAX_BATCH queued IPs without blocking long."""
        batch: list[str] = []
        try:
            batch.append(self._queue.get(timeout=0.3))
        except queue.Empty:
            return batch
        while len(batch) < IPAPI_MAX_BATCH:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return batch

    def _resolve_batch(self, ips: list[str]) -> None:
        """Query ip-api for a batch and update the cache."""
        if not ips:
            return
        payload = [{"query": ip, "fields": IPAPI_FIELDS} for ip in ips]
        results: dict[str, str] = {}
        try:
            resp = self._session.post(
                IPAPI_BATCH_URL, json=payload, timeout=self._timeout)
            if resp.status_code == 200:
                for item in resp.json():
                    ip = item.get("query", "")
                    if item.get("status") == "success":
                        code = item.get("countryCode", "")
                        name = item.get("country", "")
                        results[ip] = f"{code}, {name}" if code else name or GEO_UNKNOWN
                    else:
                        results[ip] = GEO_UNKNOWN
        except (requests.exceptions.RequestException, ValueError):
            # Network/JSON failure: mark this batch unknown (retry next launch).
            results = {ip: GEO_UNKNOWN for ip in ips}

        with self._lock:
            for ip in ips:
                self._cache[ip] = results.get(ip, GEO_UNKNOWN)
                self._pending.discard(ip)


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
    # System load averages (present when mod_status has getloadavg support).
    status.load1 = _to_float(fields["Load1"]) if "Load1" in fields else None
    status.load5 = _to_float(fields["Load5"]) if "Load5" in fields else None
    status.load15 = _to_float(fields["Load15"]) if "Load15" in fields else None
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
    # System load averages, when the server reports them.
    if auto.load1 is not None:
        loads = [auto.load1, auto.load5, auto.load15]
        server_load = "  ".join(
            f"{v:.2f}" if v is not None else "-" for v in loads)
        table.add_row("Server Load", f"{server_load}  (1/5/15m)")

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
                   max_rows: Optional[int],
                   geo: Optional["GeoResolver"] = None) -> Panel:
    """Bottom panel: sortable, filtered table of active worker connections.

    When ``cfg.show_country`` is set, a Country column is inserted after
    Client, resolved via ``geo`` (falling back to a pending marker).
    """
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
    if cfg.show_country:
        table.add_column("Country", no_wrap=True, overflow="ellipsis",
                         style="magenta")
    table.add_column("VHost", no_wrap=True)
    table.add_column("Request", no_wrap=True, overflow="ellipsis", ratio=1)

    for r in visible:
        style = MODE_STYLES.get(r.mode, "white")
        cells: list[object] = [
            r.srv, r.pid,
            Text(r.mode, style=style),
            f"{r.cpu:.2f}",
            str(r.ss),
            r.req or "-",
            f"{r.conn_kb:.1f}",
            r.client,
        ]
        if cfg.show_country:
            country = geo.lookup(r.client) if geo is not None else GEO_PENDING
            cells.append(country)
        cells.append(r.vhost)
        cells.append(r.request or "")
        table.add_row(*cells)

    title = f"Active Requests  ({active_count} active | sort: {cfg.sort_key})"
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
    footer.append("  |  ", style="dim")
    footer.append(f"sort {cfg.sort_key}", style="dim")
    footer.append("  |  ", style="dim")
    footer.append("--all for idle workers", style="dim")
    footer.append("  |  ", style="dim")
    # Show the F2 country toggle as an on/off shortcut hint.
    footer.append("F2", style="bold cyan")
    footer.append(" country on/off", style="dim")
    footer.append("  |  ", style="dim")
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
                   console: Console,
                   geo: Optional["GeoResolver"] = None) -> Layout:
    """Assemble all panels into the full-screen layout grid."""
    now = datetime.now()
    counts = decode_scoreboard(auto.scoreboard)
    extended = detect_extended_status(rows)

    # Reserve vertical space for header(4) + metrics(10) + footer(1) + borders.
    reserved = 4 + 10 + 1
    if cfg.rows is not None:
        max_rows = cfg.rows
    else:
        max_rows = max(1, console.size.height - reserved - 3)

    layout = Layout()
    layout.split_column(
        Layout(build_header(auto, cfg, now, extended), name="header", size=4),
        Layout(name="metrics", size=10),
        Layout(build_requests(rows, cfg, max_rows, geo), name="requests"),
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

# Actions produced by keypresses.
Action = Literal["toggle_country", "quit"]

# Escape sequences emitted by F2 across common terminals (xterm/VT vs others).
_F2_SEQUENCES: tuple[bytes, ...] = (b"\x1bOQ", b"\x1b[12~")


def parse_key(data: bytes) -> Optional[Action]:
    """Map raw terminal input bytes to a UI action.

    Recognises F2 (and 'c'/'C' as a fallback since terminals or multiplexers
    often intercept function keys) for the country toggle, plus 'q' to quit.
    Returns None for anything unrecognised.
    """
    if not data:
        return None
    if data in _F2_SEQUENCES:
        return "toggle_country"
    if data in (b"c", b"C"):
        return "toggle_country"
    if data in (b"q", b"Q"):
        return "quit"
    return None


class KeyReader:
    """Context manager for non-blocking single-key reads on a POSIX TTY.

    Puts stdin into cbreak mode on enter and restores it on exit. When stdin
    is not a TTY (or termios is unavailable) it degrades to a no-op so the
    tool still runs; interactive toggles simply won't be available.
    """

    def __init__(self) -> None:
        self._fd: Optional[int] = None
        self._saved: object = None
        self.enabled = False

    def __enter__(self) -> "KeyReader":
        if not _HAS_TERMIOS or not sys.stdin.isatty():
            return self
        try:
            self._fd = sys.stdin.fileno()
            self._saved = termios.tcgetattr(self._fd)
            tty.setcbreak(self._fd)
            self.enabled = True
        except (termios.error, ValueError, OSError):
            self._fd = None
            self.enabled = False
        return self

    def __exit__(self, *exc: object) -> None:
        if self._fd is not None and self._saved is not None:
            try:
                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._saved)
            except (termios.error, ValueError, OSError):
                pass

    def poll(self, timeout: float) -> Optional[Action]:
        """Wait up to ``timeout`` seconds for a key; return its action.

        If interactive input is unavailable this just sleeps for ``timeout``
        so the caller's refresh cadence is unchanged.
        """
        if not self.enabled or self._fd is None:
            time.sleep(max(0.0, timeout))
            return None
        ready, _, _ = select.select([self._fd], [], [], timeout)
        if not ready:
            return None
        # Read the full escape sequence (or single byte) that is available.
        data = os.read(self._fd, 8)
        return parse_key(data)


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
    geo = GeoResolver(timeout=cfg.timeout)

    # Cache of the most recent fetch so a keypress toggle can re-render
    # instantly without hitting the network again.
    last: dict[str, object] = {"auto": None, "rows": [], "live": LiveMetrics()}

    def fetch_and_render() -> object:
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
        last["auto"], last["rows"], last["live"] = auto, rows, live
        return compose_layout(auto, rows, live, cfg, console, geo)

    def render_cached() -> object:
        """Re-render from the last fetch (used after a toggle keypress)."""
        auto = last["auto"]
        if auto is None:
            return Align.center(Text("Loading\u2026", style="dim"))
        return compose_layout(auto, last["rows"], last["live"],  # type: ignore[arg-type]
                              cfg, console, geo)

    if cfg.once:
        if cfg.show_country:
            # Block briefly so the single snapshot shows resolved countries.
            try:
                rows = parse_html_workers(fetcher.fetch_html())
                geo.resolve_now([r.client for r in rows])
            except FetchError:
                pass
        console.print(fetch_and_render())
        return 0

    geo.start()
    try:
        with KeyReader() as keys, Live(console=console, screen=True,
                                       transient=False,
                                       auto_refresh=False) as live_view:
            for tick in _ticks(cfg):
                live_view.update(fetch_and_render(), refresh=True)
                is_last = (cfg.iterations is not None
                           and tick >= cfg.iterations - 1)
                if is_last:
                    break
                # Wait out the refresh interval while polling for keypresses so
                # toggles feel instant instead of waiting a full cycle.
                deadline = time.monotonic() + cfg.interval
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    action = keys.poll(min(remaining, 0.15))
                    if action == "quit":
                        return 0
                    if action == "toggle_country":
                        cfg.show_country = not cfg.show_country
                        live_view.update(render_cached(), refresh=True)
    finally:
        geo.stop()
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
