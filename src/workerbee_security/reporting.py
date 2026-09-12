import csv
import html
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .dashboard import dashboard


def _cell(value: Any) -> str:
    if value is None:
        return ""
    text = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
    return (
        html.escape(text, quote=False).replace("`", "&#96;").replace("|", "\\|").replace("\n", " ")
    )


def _csv_safe(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    stripped = value.lstrip()
    if stripped.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def markdown(report: Dict[str, Any]) -> str:
    summary = report["summary"]
    credentials = report["credential_intelligence"]
    lines = [
        "# WorkerBee Security report",
        "",
        f"Source: `{_cell(report['source'])}`  ",
        f"Generated: `{_cell(report['generated_at'])}`",
        "",
        "## Summary",
        "",
        "| Events | Sessions | Source IPs | Indicators | Commands | Downloads | Warnings |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {summary['events']} | {summary['sessions']} | {summary['source_ips']} | "
            f"{summary['indicators']} | {summary['commands']} | {summary['downloads']} | "
            f"{summary['parse_warnings']} |"
        ),
        "",
        "## Top sources",
        "",
        "| IP | Events |",
        "| --- | ---: |",
    ]
    if report["top_sources"]:
        lines.extend(
            f"| `{_cell(source['ip'])}` | {source['events']} |" for source in report["top_sources"]
        )
    else:
        lines.append("| — | 0 |")

    lines.extend(
        [
            "",
            "## Credential intelligence",
            "",
            "| Attempts | Successes | Success rate | Unique usernames | Unique passwords |",
            "| ---: | ---: | ---: | ---: | ---: |",
            (
                f"| {credentials['attempts']} | {credentials['successes']} | "
                f"{credentials['success_rate_percent']}% | {credentials['unique_usernames']} | "
                f"{credentials['unique_passwords']} |"
            ),
            "",
            "### Top usernames",
            "",
            "| Username | Attempts | Successes | Success rate | Sources | First seen | Last seen |",
            "| --- | ---: | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for item in credentials["top_usernames"]:
        lines.append(
            f"| `{_cell(item['username'])}` | {item['attempts']} | {item['successes']} | "
            f"{item['success_rate_percent']}% | {item['source_count']} | "
            f"{_cell(item['first_seen'])} | {_cell(item['last_seen'])} |"
        )
    if not credentials["top_usernames"]:
        lines.append("| — | 0 | 0 | 0.0% | 0 | — | — |")

    if credentials["passwords_redacted"]:
        lines.extend(["", "Password and credential-pair rankings were redacted."])
    else:
        lines.extend(
            [
                "",
                "### Top passwords",
                "",
                "| Password | Attempts | Successes | Success rate | Sources |",
                "| --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for item in credentials["top_passwords"]:
            lines.append(
                f"| `{_cell(item['password'])}` | {item['attempts']} | {item['successes']} | "
                f"{item['success_rate_percent']}% | {item['source_count']} |"
            )
        if not credentials["top_passwords"]:
            lines.append("| — | 0 | 0 | 0.0% | 0 |")

        lines.extend(
            [
                "",
                "### Top credential pairs",
                "",
                "| Username | Password | Attempts | Successes | Success rate | Sources |",
                "| --- | --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for item in credentials["top_pairs"]:
            lines.append(
                f"| `{_cell(item['username'])}` | `{_cell(item['password'])}` | "
                f"{item['attempts']} | {item['successes']} | "
                f"{item['success_rate_percent']}% | {item['source_count']} |"
            )
        if not credentials["top_pairs"]:
            lines.append("| — | — | 0 | 0 | 0.0% | 0 |")

    lines.extend(
        [
            "",
            "### Source patterns",
            "",
            "| Source | Classification | Attempts | Successes | Usernames | Passwords |",
            "| --- | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for item in credentials["source_patterns"]:
        lines.append(
            f"| `{_cell(item['source_ip'])}` | {item['classification']} | "
            f"{item['attempts']} | {item['successes']} | {item['unique_usernames']} | "
            f"{item['unique_passwords']} |"
        )
    if not credentials["source_patterns"]:
        lines.append("| — | — | 0 | 0 | 0 | 0 |")

    lines.extend(
        [
            "",
            "## Sessions",
            "",
            "| Session | Source | Protocol | Severity | Events | Logins | Commands | Downloads | Duration |",
            "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for session in report["sessions"]:
        logins = session["login_failures"] + session["login_successes"]
        lines.append(
            f"| `{_cell(session['id'])}` | `{_cell(session['src_ip'])}` | "
            f"{_cell(session['protocol'])} | {session['severity']} | {session['event_count']} | "
            f"{logins} | {len(session['commands'])} | {len(session['downloads'])} | "
            f"{_cell(session['duration_seconds'])} |"
        )
    if not report["sessions"]:
        lines.append("| — | — | — | — | 0 | 0 | 0 | 0 | — |")

    lines.extend(
        [
            "",
            "## Indicators",
            "",
            "| Type | Value | Count | Sessions | Enrichment |",
            "| --- | --- | ---: | ---: | --- |",
        ]
    )
    for indicator in report["indicators"]:
        lines.append(
            f"| {indicator['type']} | `{_cell(indicator['value'])}` | {indicator['count']} | "
            f"{len(indicator['sessions'])} | {_cell(indicator['enrichment'])} |"
        )
    if not report["indicators"]:
        lines.append("| — | — | 0 | 0 | — |")

    command_sessions = [session for session in report["sessions"] if session["commands"]]
    if command_sessions:
        lines.extend(["", "## Commands", ""])
        for session in command_sessions:
            lines.extend([f"### `{_cell(session['id'])}`", "", "```text"])
            lines.extend(
                html.escape(command["command"], quote=False).replace("```", "` ` `")
                for command in session["commands"]
            )
            lines.extend(["```", ""])

    if report["warnings"]:
        lines.extend(["## Parse warnings", ""])
        lines.extend(
            f"- Line {warning['line']}: {_cell(warning['message'])}"
            for warning in report["warnings"]
        )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _write_indicator_csv(path: Path, report: Dict[str, Any]) -> None:
    fields = [
        "type",
        "value",
        "count",
        "first_seen",
        "last_seen",
        "sessions",
        "eventids",
        "enrichment",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for indicator in report["indicators"]:
            row = {field: indicator.get(field) for field in fields}
            row["sessions"] = ";".join(indicator["sessions"])
            row["eventids"] = ";".join(indicator["eventids"])
            row["enrichment"] = json.dumps(indicator["enrichment"], sort_keys=True)
            writer.writerow({key: _csv_safe(value) for key, value in row.items()})


def _write_session_csv(path: Path, report: Dict[str, Any]) -> None:
    fields = [
        "id",
        "src_ip",
        "protocol",
        "severity",
        "first_seen",
        "last_seen",
        "duration_seconds",
        "event_count",
        "login_failures",
        "login_successes",
        "usernames",
        "command_count",
        "download_count",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for session in report["sessions"]:
            row = {
                **{field: session.get(field) for field in fields},
                "usernames": ";".join(session["usernames"]),
                "command_count": len(session["commands"]),
                "download_count": len(session["downloads"]),
            }
            writer.writerow({key: _csv_safe(value) for key, value in row.items()})


def _write_credential_csv(path: Path, report: Dict[str, Any]) -> None:
    fields = [
        "kind",
        "username",
        "password",
        "attempts",
        "successes",
        "success_rate_percent",
        "source_count",
        "first_seen",
        "last_seen",
    ]
    credentials = report["credential_intelligence"]
    rankings = (
        [("username", item) for item in credentials["top_usernames"]]
        + [("password", item) for item in credentials["top_passwords"]]
        + [("pair", item) for item in credentials["top_pairs"]]
    )
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for kind, item in rankings:
            row = {field: item.get(field) for field in fields}
            row["kind"] = kind
            writer.writerow({key: _csv_safe(value) for key, value in row.items()})


def write_reports(report: Dict[str, Any], output: str, formats: Iterable[str]) -> List[Path]:
    output_path = Path(output).expanduser()
    output_path.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []

    for report_format in dict.fromkeys(formats):
        if report_format == "html":
            path = output_path / "workerbee-report.html"
            path.write_text(dashboard(report), encoding="utf-8")
            written.append(path)
        elif report_format == "json":
            path = output_path / "workerbee-report.json"
            path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            written.append(path)
        elif report_format == "markdown":
            path = output_path / "workerbee-report.md"
            path.write_text(markdown(report), encoding="utf-8")
            written.append(path)
        elif report_format == "csv":
            indicator_path = output_path / "workerbee-indicators.csv"
            session_path = output_path / "workerbee-sessions.csv"
            credential_path = output_path / "workerbee-credentials.csv"
            _write_indicator_csv(indicator_path, report)
            _write_session_csv(session_path, report)
            _write_credential_csv(credential_path, report)
            written.extend([indicator_path, session_path, credential_path])
        else:
            raise ValueError(f"unsupported report format: {report_format}")

    return written
