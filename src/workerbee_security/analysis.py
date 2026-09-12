from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from . import __version__
from .indicators import extract_indicators
from .models import CowrieEvent, ParseResult


def _timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _duration(first: Optional[str], last: Optional[str]) -> Optional[float]:
    start = _timestamp(first)
    end = _timestamp(last)
    if not start or not end:
        return None
    return max(0.0, round((end - start).total_seconds(), 3))


def _new_session(event: CowrieEvent) -> Dict[str, Any]:
    return {
        "id": event.session,
        "src_ip": event.src_ip,
        "protocol": event.protocol,
        "first_seen": event.timestamp,
        "last_seen": event.timestamp,
        "duration_seconds": None,
        "event_count": 0,
        "login_failures": 0,
        "login_successes": 0,
        "usernames": set(),
        "credentials": [],
        "commands": [],
        "downloads": [],
        "severity": "low",
    }


def _update_session(session: Dict[str, Any], event: CowrieEvent, show_credentials: bool) -> None:
    session["event_count"] += 1
    session["src_ip"] = session["src_ip"] or event.src_ip
    session["protocol"] = session["protocol"] or event.protocol
    if event.timestamp:
        if session["first_seen"] is None or event.timestamp < session["first_seen"]:
            session["first_seen"] = event.timestamp
        if session["last_seen"] is None or event.timestamp > session["last_seen"]:
            session["last_seen"] = event.timestamp

    if event.eventid in {"cowrie.login.failed", "cowrie.login.success"}:
        successful = event.eventid.endswith("success")
        session["login_successes" if successful else "login_failures"] += 1
        username = event.data.get("username")
        password = event.data.get("password")
        if isinstance(username, str) and username:
            session["usernames"].add(username)
        session["credentials"].append(
            {
                "timestamp": event.timestamp,
                "username": username if isinstance(username, str) else None,
                "password": (
                    password
                    if show_credentials and isinstance(password, str)
                    else "<redacted>"
                    if isinstance(password, str)
                    else None
                ),
                "successful": successful,
            }
        )

    if event.eventid in {"cowrie.command.input", "cowrie.command.failed"}:
        command = event.data.get("input")
        if isinstance(command, str) and command:
            session["commands"].append(
                {"timestamp": event.timestamp, "command": command, "eventid": event.eventid}
            )

    if event.eventid in {
        "cowrie.session.file_download",
        "cowrie.session.file_upload",
        "cowrie.session.file_download.failed",
    }:
        session["downloads"].append(
            {
                "timestamp": event.timestamp,
                "eventid": event.eventid,
                "url": event.data.get("url"),
                "path": event.data.get("outfile") or event.data.get("filename"),
                "sha256": event.data.get("shasum"),
            }
        )


def _finalize_session(session: Dict[str, Any]) -> Dict[str, Any]:
    session["usernames"] = sorted(session["usernames"])
    session["duration_seconds"] = _duration(session["first_seen"], session["last_seen"])
    if session["downloads"] or (session["login_successes"] and session["commands"]):
        session["severity"] = "high"
    elif session["login_successes"] or session["commands"]:
        session["severity"] = "medium"
    return session


def analyze(result: ParseResult, show_credentials: bool = False) -> Dict[str, Any]:
    session_map: Dict[str, Dict[str, Any]] = {}
    event_counts: Counter = Counter()

    for event in result.events:
        event_counts[event.eventid] += 1
        if not event.session:
            continue
        session = session_map.setdefault(event.session, _new_session(event))
        _update_session(session, event, show_credentials)

    sessions = [_finalize_session(session) for session in session_map.values()]
    sessions.sort(key=lambda item: (item["first_seen"] or "", item["id"] or ""))
    indicators = extract_indicators(result.events)
    sources = Counter(event.src_ip for event in result.events if event.src_ip)
    generated = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    return {
        "tool": {"name": "workerbee-security", "version": __version__},
        "generated_at": generated,
        "source": result.source,
        "summary": {
            "lines_read": result.lines_read,
            "events": len(result.events),
            "sessions": len(sessions),
            "source_ips": len(sources),
            "indicators": len(indicators),
            "parse_warnings": len(result.warnings),
            "commands": sum(len(session["commands"]) for session in sessions),
            "downloads": sum(len(session["downloads"]) for session in sessions),
        },
        "event_counts": dict(sorted(event_counts.items())),
        "top_sources": [{"ip": ip, "events": count} for ip, count in sources.most_common(20)],
        "sessions": sessions,
        "indicators": indicators,
        "warnings": [warning.as_dict() for warning in result.warnings],
    }
