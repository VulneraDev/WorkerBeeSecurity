import html
import json
from typing import Any, Dict, Iterable, List, Sequence

STYLES = """
:root {
  color-scheme: dark;
  --bg: #0b0f14;
  --surface: #121821;
  --surface-2: #18212c;
  --line: #273342;
  --text: #eef3f8;
  --muted: #8fa0b3;
  --amber: #f2b84b;
  --amber-soft: rgba(242, 184, 75, .14);
  --green: #67d391;
  --red: #ff7b72;
  --blue: #70b7ff;
  --radius: 16px;
  --shadow: 0 16px 44px rgba(0, 0, 0, .22);
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background:
    radial-gradient(circle at 12% -10%, rgba(242, 184, 75, .14), transparent 30rem),
    var(--bg);
  color: var(--text);
  font: 14px/1.55 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
a { color: inherit; }
code, .mono { font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; }
.shell { width: min(1440px, calc(100% - 40px)); margin: 0 auto; }
.hero { padding: 50px 0 26px; }
.hero-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; }
.eyebrow { color: var(--amber); font-size: 12px; font-weight: 800; letter-spacing: .15em; text-transform: uppercase; }
h1 { margin: 6px 0 8px; font-size: clamp(32px, 5vw, 58px); line-height: 1; letter-spacing: -.045em; }
.subtitle { max-width: 700px; margin: 0; color: var(--muted); font-size: 16px; }
.mark {
  display: grid;
  flex: 0 0 68px;
  width: 68px;
  height: 68px;
  place-items: center;
  border: 1px solid rgba(242, 184, 75, .35);
  border-radius: 20px;
  background: var(--amber-soft);
  font-size: 34px;
  box-shadow: var(--shadow);
}
.meta { display: flex; flex-wrap: wrap; gap: 8px 18px; margin-top: 22px; color: var(--muted); }
.meta span { display: inline-flex; gap: 7px; align-items: center; }
.meta strong { color: var(--text); font-weight: 650; }
.nav-wrap {
  position: sticky;
  top: 0;
  z-index: 20;
  border-block: 1px solid rgba(39, 51, 66, .85);
  background: rgba(11, 15, 20, .88);
  backdrop-filter: blur(16px);
}
.nav { display: flex; align-items: center; gap: 8px; min-height: 62px; }
.nav a { padding: 8px 10px; color: var(--muted); text-decoration: none; font-weight: 700; }
.nav a:hover { color: var(--text); }
.nav-tools { display: flex; gap: 10px; margin-left: auto; }
.search {
  width: min(280px, 34vw);
  border: 1px solid var(--line);
  border-radius: 10px;
  outline: none;
  background: var(--surface);
  color: var(--text);
  padding: 9px 12px;
}
.search:focus { border-color: var(--amber); box-shadow: 0 0 0 3px var(--amber-soft); }
.button {
  border: 1px solid rgba(242, 184, 75, .45);
  border-radius: 10px;
  background: var(--amber-soft);
  color: var(--amber);
  padding: 9px 13px;
  font: inherit;
  font-weight: 800;
  cursor: pointer;
}
main { padding: 30px 0 64px; }
.section { scroll-margin-top: 82px; margin-bottom: 38px; }
.section-head { display: flex; align-items: end; justify-content: space-between; gap: 16px; margin-bottom: 14px; }
h2 { margin: 0; font-size: 23px; letter-spacing: -.02em; }
.section-note { color: var(--muted); }
.metrics { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 12px; }
.metric {
  min-height: 116px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: linear-gradient(145deg, rgba(24, 33, 44, .92), rgba(18, 24, 33, .96));
  padding: 18px;
  box-shadow: var(--shadow);
}
.metric-label { color: var(--muted); font-size: 12px; font-weight: 750; letter-spacing: .04em; text-transform: uppercase; }
.metric-value { margin-top: 14px; font-size: 29px; font-weight: 850; letter-spacing: -.04em; }
.grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
.grid-2 > :only-child { grid-column: 1 / -1; }
.panel {
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: var(--shadow);
}
.panel + .panel, .grid-2 + .panel, .panel + .grid-2 { margin-top: 14px; }
.panel-head { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 16px 18px; border-bottom: 1px solid var(--line); }
.panel-head h3 { margin: 0; font-size: 15px; }
.panel-head span { color: var(--muted); font-size: 12px; }
.bars { display: grid; gap: 13px; padding: 18px; }
.bar-row { display: grid; grid-template-columns: minmax(90px, 1.2fr) 4fr auto; align-items: center; gap: 12px; }
.bar-label { min-width: 0; overflow: hidden; color: var(--text); text-overflow: ellipsis; white-space: nowrap; }
.bar-track { height: 9px; overflow: hidden; border-radius: 99px; background: var(--surface-2); }
.bar-fill { width: var(--value); height: 100%; border-radius: inherit; background: linear-gradient(90deg, #d79524, var(--amber)); }
.bar-value { min-width: 28px; text-align: right; font-weight: 800; }
.table-scroll { width: 100%; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th { padding: 11px 14px; color: var(--muted); font-size: 11px; letter-spacing: .06em; text-align: left; text-transform: uppercase; white-space: nowrap; }
td { padding: 12px 14px; border-top: 1px solid rgba(39, 51, 66, .68); vertical-align: top; }
tbody tr:hover { background: rgba(112, 183, 255, .035); }
td code { color: #f8d792; overflow-wrap: anywhere; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.badge {
  display: inline-flex;
  align-items: center;
  min-height: 24px;
  border: 1px solid var(--line);
  border-radius: 99px;
  padding: 2px 8px;
  background: var(--surface-2);
  font-size: 11px;
  font-weight: 800;
  letter-spacing: .02em;
  white-space: nowrap;
}
.badge.danger { border-color: rgba(255, 123, 114, .35); background: rgba(255, 123, 114, .1); color: var(--red); }
.badge.warn { border-color: rgba(242, 184, 75, .35); background: var(--amber-soft); color: var(--amber); }
.badge.good { border-color: rgba(103, 211, 145, .35); background: rgba(103, 211, 145, .1); color: var(--green); }
.badge.info { border-color: rgba(112, 183, 255, .35); background: rgba(112, 183, 255, .1); color: var(--blue); }
.empty { padding: 26px 18px; color: var(--muted); text-align: center; }
.callout { margin-bottom: 14px; border: 1px solid rgba(242, 184, 75, .32); border-radius: 12px; background: var(--amber-soft); padding: 13px 15px; color: #f6d898; }
.command-list { display: grid; gap: 10px; padding: 14px; }
details.command { border: 1px solid var(--line); border-radius: 11px; background: var(--surface-2); }
details.command summary { cursor: pointer; padding: 12px 14px; font-weight: 750; }
details.command pre { margin: 0; border-top: 1px solid var(--line); padding: 14px; color: #dbe5ef; white-space: pre-wrap; overflow-wrap: anywhere; }
.footer { padding: 24px 0 48px; border-top: 1px solid var(--line); color: var(--muted); }
.footer strong { color: var(--amber); }
[hidden] { display: none !important; }
@media (max-width: 1100px) {
  .metrics { grid-template-columns: repeat(3, 1fr); }
}
@media (max-width: 760px) {
  .shell { width: min(100% - 24px, 1440px); }
  .hero { padding-top: 34px; }
  .mark { display: none; }
  .nav { align-items: stretch; flex-wrap: wrap; padding: 10px 0; }
  .nav > a { display: none; }
  .nav-tools { width: 100%; margin-left: 0; }
  .search { flex: 1; width: auto; }
  .metrics, .grid-2 { grid-template-columns: 1fr; }
  .metric { min-height: 92px; }
  .bar-row { grid-template-columns: minmax(82px, 1.3fr) 2fr auto; }
  .table-scroll table { min-width: 720px; }
  .table-scroll td code { white-space: nowrap; }
}
@media print {
  :root { color-scheme: light; --bg: #fff; --surface: #fff; --surface-2: #f5f5f5; --line: #ddd; --text: #111; --muted: #555; }
  body { background: #fff; }
  .nav-wrap, .button, .search { display: none; }
  .panel, .metric { break-inside: avoid; box-shadow: none; }
  .section { break-before: auto; }
}
"""

SCRIPT = """
const search = document.querySelector('#report-search');
const rows = [...document.querySelectorAll('.searchable')];
search.addEventListener('input', () => {
  const query = search.value.trim().toLowerCase();
  rows.forEach((row) => {
    row.hidden = query.length > 0 && !row.textContent.toLowerCase().includes(query);
  });
});
document.querySelector('#print-report').addEventListener('click', () => window.print());
"""


def _text(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True)
    return html.escape(str(value), quote=True)


def _credential(value: Any) -> str:
    if value == "":
        return "&lt;empty&gt;"
    return _text(value)


def _code(value: Any, credential: bool = False) -> str:
    rendered = _credential(value) if credential else _text(value)
    return f"<code>{rendered}</code>"


def _badge(value: Any, tone: str = "") -> str:
    tone = tone if tone in {"danger", "warn", "good", "info"} else ""
    return f'<span class="badge {tone}">{_text(value)}</span>'


def _classification(value: str) -> str:
    tones = {
        "brute_force": "danger",
        "password_spray": "warn",
        "mixed": "info",
        "repeated": "info",
        "low_volume": "",
    }
    return _badge(value, tones.get(value, ""))


def _severity(value: str) -> str:
    return _badge(value, {"high": "danger", "medium": "warn", "low": "good"}.get(value, ""))


def _table(headers: Sequence[str], rows: Iterable[Sequence[str]], empty: str) -> str:
    body = "".join(
        '<tr class="searchable">' + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    if not body:
        body = f'<tr><td class="empty" colspan="{len(headers)}">{_text(empty)}</td></tr>'
    headings = "".join(f"<th>{_text(header)}</th>" for header in headers)
    return f'<div class="table-scroll"><table><thead><tr>{headings}</tr></thead><tbody>{body}</tbody></table></div>'


def _panel(title: str, content: str, note: str = "") -> str:
    return (
        '<section class="panel">'
        f'<div class="panel-head"><h3>{_text(title)}</h3><span>{_text(note)}</span></div>'
        f"{content}</section>"
    )


def _bars(title: str, items: List[Dict[str, Any]], label: str, value: str) -> str:
    maximum = max((item[value] for item in items), default=0)
    rows = []
    for item in items[:10]:
        width = round(item[value] * 100 / maximum, 1) if maximum else 0
        rows.append(
            '<div class="bar-row searchable">'
            f'<div class="bar-label mono">{_credential(item[label])}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="--value:{width}%"></div></div>'
            f'<div class="bar-value">{_text(item[value])}</div>'
            "</div>"
        )
    content = (
        '<div class="bars">' + "".join(rows) + "</div>"
        if rows
        else '<div class="empty">No data</div>'
    )
    return _panel(title, content, f"Top {min(len(items), 10)}")


def _metric(label: str, value: Any) -> str:
    return f'<div class="metric"><div class="metric-label">{_text(label)}</div><div class="metric-value">{_text(value)}</div></div>'


def dashboard(report: Dict[str, Any]) -> str:
    summary = report["summary"]
    credentials = report["credential_intelligence"]
    metrics = "".join(
        [
            _metric("Events", summary["events"]),
            _metric("Sessions", summary["sessions"]),
            _metric("Source IPs", summary["source_ips"]),
            _metric("Login attempts", credentials["attempts"]),
            _metric("Commands", summary["commands"]),
            _metric("Indicators", summary["indicators"]),
        ]
    )

    source_bars = _bars("Top sources", report["top_sources"], "ip", "events")
    username_bars = _bars("Top usernames", credentials["top_usernames"], "username", "attempts")

    password_panel = ""
    pair_panel = ""
    privacy_callout = ""
    if credentials["passwords_redacted"]:
        privacy_callout = '<div class="callout">Password and credential-pair rankings were redacted for this report.</div>'
    else:
        password_panel = _bars(
            "Top passwords", credentials["top_passwords"], "password", "attempts"
        )
        pair_rows = (
            (
                _code(item["username"], credential=True),
                _code(item["password"], credential=True),
                _text(item["attempts"]),
                _text(item["successes"]),
                _text(f"{item['success_rate_percent']}%"),
                _text(item["source_count"]),
            )
            for item in credentials["top_pairs"]
        )
        pair_panel = _panel(
            "Credential pairs",
            _table(
                ["Username", "Password", "Attempts", "Successes", "Success rate", "Sources"],
                pair_rows,
                "No credential pairs",
            ),
            "Ranked by attempts",
        )

    pattern_rows = (
        (
            _code(item["source_ip"]),
            _classification(item["classification"]),
            _text(item["attempts"]),
            _text(item["successes"]),
            _text(item["unique_usernames"]),
            _text(item["unique_passwords"]),
            _text(item["first_seen"]),
            _text(item["last_seen"]),
        )
        for item in credentials["source_patterns"]
    )
    pattern_panel = _panel(
        "Source patterns",
        _table(
            [
                "Source",
                "Classification",
                "Attempts",
                "Successes",
                "Users",
                "Passwords",
                "First seen",
                "Last seen",
            ],
            pattern_rows,
            "No login patterns",
        ),
        "Observed behavior",
    )

    session_rows = (
        (
            _code(session["id"]),
            _code(session["src_ip"]),
            _text(session["protocol"]),
            _severity(session["severity"]),
            _text(session["first_seen"]),
            _text(session["last_seen"]),
            _text(session["event_count"]),
            _text(session["login_failures"] + session["login_successes"]),
            _text(len(session["commands"])),
            _text(len(session["downloads"])),
        )
        for session in report["sessions"]
    )
    session_panel = _panel(
        "Session timeline",
        _table(
            [
                "Session",
                "Source",
                "Protocol",
                "Severity",
                "First seen",
                "Last seen",
                "Events",
                "Logins",
                "Commands",
                "Downloads",
            ],
            session_rows,
            "No sessions",
        ),
        "Oldest first",
    )

    attempts = []
    for session in report["sessions"]:
        for item in session["credentials"]:
            attempts.append(
                (
                    item["timestamp"] or "",
                    (
                        _text(item["timestamp"]),
                        _code(session["id"]),
                        _code(session["src_ip"]),
                        _code(item["username"], credential=True),
                        _code(item["password"], credential=True),
                        _badge("success", "good")
                        if item["successful"]
                        else _badge("failed", "danger"),
                    ),
                )
            )
    attempt_rows = (row for _, row in sorted(attempts, key=lambda item: item[0]))
    attempt_panel = _panel(
        "Authentication attempts",
        _table(
            ["Timestamp", "Session", "Source", "Username", "Password", "Result"],
            attempt_rows,
            "No authentication attempts",
        ),
        f"{credentials['attempts']} observed",
    )

    command_groups = []
    for session in report["sessions"]:
        if not session["commands"]:
            continue
        commands = "\n".join(item["command"] for item in session["commands"])
        command_groups.append(
            '<details class="command searchable">'
            f"<summary>{_code(session['id'])} · {_code(session['src_ip'])} · {len(session['commands'])} commands</summary>"
            f"<pre>{_text(commands)}</pre></details>"
        )
    command_content = (
        '<div class="command-list">' + "".join(command_groups) + "</div>"
        if command_groups
        else '<div class="empty">No commands</div>'
    )
    command_panel = _panel("Commands", command_content, f"{summary['commands']} observed")

    downloads = []
    for session in report["sessions"]:
        for item in session["downloads"]:
            downloads.append(
                (
                    _text(item["timestamp"]),
                    _code(session["id"]),
                    _code(session["src_ip"]),
                    _text(item["eventid"]),
                    _code(item["url"]),
                    _code(item["path"]),
                    _code(item["sha256"]),
                )
            )
    download_panel = _panel(
        "Transfers",
        _table(
            ["Timestamp", "Session", "Source", "Event", "URL", "Path", "SHA-256"],
            downloads,
            "No transfers",
        ),
        f"{summary['downloads']} observed",
    )

    indicator_rows = (
        (
            _badge(item["type"], "info"),
            _code(item["value"]),
            _text(item["count"]),
            _text(len(item["sessions"])),
            _text(item["first_seen"]),
            _text(item["last_seen"]),
            _text(item["enrichment"]),
        )
        for item in report["indicators"]
    )
    indicator_panel = _panel(
        "Indicators",
        _table(
            ["Type", "Value", "Count", "Sessions", "First seen", "Last seen", "Enrichment"],
            indicator_rows,
            "No indicators",
        ),
        f"{summary['indicators']} extracted",
    )

    warning_rows = ((_text(item["line"]), _text(item["message"])) for item in report["warnings"])
    warning_panel = _panel(
        "Parse warnings",
        _table(["Line", "Message"], warning_rows, "No parse warnings"),
        f"{summary['parse_warnings']} warnings",
    )

    privacy = "Passwords redacted" if credentials["passwords_redacted"] else "Credentials included"
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'\">"
        f"<title>WorkerBee Security report · {_text(report['generated_at'])}</title>"
        f"<style>{STYLES}</style></head><body>"
        '<header class="hero"><div class="shell"><div class="hero-row"><div>'
        '<div class="eyebrow">WorkerBee Security</div><h1>Attack intelligence report</h1>'
        '<p class="subtitle">Cowrie telemetry distilled into credential patterns, sessions, commands, transfers, and indicators.</p>'
        f'<div class="meta"><span>Source <strong class="mono">{_text(report["source"])}</strong></span>'
        f"<span>Generated <strong>{_text(report['generated_at'])}</strong></span>"
        f'<span>Privacy <strong>{_text(privacy)}</strong></span></div></div><div class="mark" aria-hidden="true">🐝</div></div></div></header>'
        '<div class="nav-wrap"><nav class="shell nav" aria-label="Report sections">'
        '<a href="#overview">Overview</a><a href="#credentials">Credentials</a><a href="#activity">Activity</a><a href="#indicators">Indicators</a>'
        '<div class="nav-tools"><input id="report-search" class="search" type="search" placeholder="Filter report…" aria-label="Filter report">'
        '<button id="print-report" class="button" type="button">Print</button></div></nav></div>'
        '<main class="shell">'
        '<section id="overview" class="section"><div class="section-head"><h2>Overview</h2><span class="section-note">At-a-glance telemetry</span></div>'
        f'<div class="metrics">{metrics}</div><div class="grid-2" style="margin-top:14px">{source_bars}{username_bars}</div></section>'
        '<section id="credentials" class="section"><div class="section-head"><h2>Credential intelligence</h2>'
        f'<span class="section-note">{_text(credentials["success_rate_percent"])}% successful</span></div>{privacy_callout}'
        f'<div class="grid-2">{password_panel}{pattern_panel}</div>{pair_panel}{attempt_panel}</section>'
        '<section id="activity" class="section"><div class="section-head"><h2>Attack activity</h2><span class="section-note">Session-level evidence</span></div>'
        f"{session_panel}{command_panel}{download_panel}</section>"
        '<section id="indicators" class="section"><div class="section-head"><h2>Threat intelligence</h2><span class="section-note">Extracted observables</span></div>'
        f"{indicator_panel}{warning_panel}</section></main>"
        '<footer class="footer"><div class="shell"><strong>WorkerBee Security</strong> · Offline-first Cowrie log analysis</div></footer>'
        f"<script>{SCRIPT}</script></body></html>\n"
    )
