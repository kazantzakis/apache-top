# apache-top

A `top`-style live monitor for Apache's `mod_status`. It polls the
server-status endpoints and renders a continuously refreshing terminal
dashboard using [`rich`](https://github.com/Textualize/rich).

```
╭─ apache-top ───────────────────────────────────────────────────────────────╮
│  Apache/2.4.58 (Ubuntu)   MPM: event   http://web01/server-status           │
│  Uptime: 12d 04h 37m      ExtendedStatus: on            ⟳ 2s  14:22:07       │
╰─────────────────────────────────────────────────────────────────────────────╯
╭─ Summary ─────────────────╮╭─ Workers ────────────────────────────────╮
│ Total Requests 1,284,553  ││ Busy 18  Idle 32  Total 50               │
│ Requests/sec   3.4 (5.1)  ││ [██████████░░░░░░░░░░░░░░░░]  36%         │
│ ...                       ││ Send 11 Read 2 Keep 3 Close 1 ...        │
╰───────────────────────────╯╰──────────────────────────────────────────╯
╭─ Active Requests (18 active · sort: ss) ────────────────────────────────────╮
│ Srv PID M CPU SS Req Conn Client VHost Request                              │
╰─────────────────────────────────────────────────────────────────────────────╯
```

## Requirements

- Python 3.10+
- Python packages: `requests`, `rich`, `beautifulsoup4`, `lxml`

```bash
pip install -r requirements.txt
```

## Apache setup

`apache-top` reads two endpoints:

- `<host>/server-status?auto` — machine-readable summary metrics + scoreboard
- `<host>/server-status` — HTML page, parsed for the per-request table

Enable `mod_status` and expose the handler (Apache 2.4 example):

```apache
LoadModule status_module modules/mod_status.so

<Location "/server-status">
    SetHandler server-status
    Require ip 127.0.0.1 ::1      # restrict as appropriate
</Location>

# Per-request details (Client / CPU / Request columns).
# Default-on in 2.4 when mod_status is loaded; set explicitly if unsure:
ExtendedStatus On
```

Without `ExtendedStatus On`, the summary and workers panels still work, but the
Active Requests table will have empty CPU/Client/Request columns (the header
will show `ExtendedStatus: off`).

## Usage

```bash
./apache-top.py <server> [options]
```

`<server>` may be a bare host, `host:port`, or a full URL. Bare hosts are
expanded to `http://<host>/server-status`.

```bash
./apache-top.py web01.example.com
./apache-top.py localhost:8080 -i 1
./apache-top.py https://host/server-status --sort cpu
./apache-top.py web01 --once
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --interval` | Refresh interval (seconds) | `2` |
| `-t, --timeout` | HTTP timeout (seconds) | `5` |
| `-u, --user` | HTTP Basic auth username | — |
| `-p, --password` | HTTP Basic auth password | — |
| `-k, --insecure` | Skip TLS certificate verification | off |
| `--once` | Render a single snapshot and exit | off |
| `-n, --iterations` | Exit after N refreshes | run forever |
| `--all` | Include idle/open worker slots in the table | off |
| `--sort` | Sort requests by `cpu`,`ss`,`req`,`acc`,`client` | `ss` |
| `--rows` | Max request rows to show | auto-fit |

Press `Ctrl-C` to quit.

## Scoreboard legend

`_` Waiting · `S` Starting · `R` Reading · `W` Sending · `K` Keepalive ·
`D` DNS · `C` Closing · `L` Logging · `G` Graceful · `I` Idle · `.` Open slot
