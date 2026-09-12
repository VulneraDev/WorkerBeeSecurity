from typing import Any, Dict, Iterable, List, Optional, Tuple

from .models import CowrieEvent

LOGIN_EVENTS = {"cowrie.login.failed", "cowrie.login.success"}


def _new_stat() -> Dict[str, Any]:
    return {
        "attempts": 0,
        "successes": 0,
        "sources": set(),
        "first_seen": None,
        "last_seen": None,
    }


def _record(
    stats: Dict[Any, Dict[str, Any]],
    key: Any,
    source: Optional[str],
    timestamp: Optional[str],
    successful: bool,
) -> None:
    item = stats.setdefault(key, _new_stat())
    item["attempts"] += 1
    item["successes"] += int(successful)
    if source:
        item["sources"].add(source)
    if timestamp:
        if item["first_seen"] is None or timestamp < item["first_seen"]:
            item["first_seen"] = timestamp
        if item["last_seen"] is None or timestamp > item["last_seen"]:
            item["last_seen"] = timestamp


def _finish(item: Dict[str, Any]) -> Dict[str, Any]:
    attempts = item["attempts"]
    return {
        "attempts": attempts,
        "successes": item["successes"],
        "success_rate_percent": round(item["successes"] * 100 / attempts, 1),
        "source_count": len(item["sources"]),
        "first_seen": item["first_seen"],
        "last_seen": item["last_seen"],
    }


def _ranked(
    stats: Dict[Any, Dict[str, Any]],
    fields: Tuple[str, ...],
    limit: int,
) -> List[Dict[str, Any]]:
    ranked = sorted(stats.items(), key=lambda item: (-item[1]["attempts"], str(item[0])))
    output = []
    for key, item in ranked[:limit]:
        values = key if isinstance(key, tuple) else (key,)
        output.append({**dict(zip(fields, values)), **_finish(item)})
    return output


def _classification(attempts: int, usernames: int, passwords: int) -> str:
    if attempts < 3:
        return "low_volume"
    if usernames == 1 and passwords > 1:
        return "brute_force"
    if passwords == 1 and usernames > 1:
        return "password_spray"
    if usernames > 1 and passwords > 1:
        return "mixed"
    return "repeated"


def summarize_credentials(
    events: Iterable[CowrieEvent], show_passwords: bool = True, limit: int = 20
) -> Dict[str, Any]:
    usernames: Dict[str, Dict[str, Any]] = {}
    passwords: Dict[str, Dict[str, Any]] = {}
    pairs: Dict[Tuple[str, str], Dict[str, Any]] = {}
    sources: Dict[str, Dict[str, Any]] = {}
    attempts = 0
    successes = 0

    for event in events:
        if event.eventid not in LOGIN_EVENTS:
            continue
        successful = event.eventid == "cowrie.login.success"
        username = event.data.get("username")
        password = event.data.get("password")
        username = username if isinstance(username, str) else None
        password = password if isinstance(password, str) else None
        attempts += 1
        successes += int(successful)

        if username is not None:
            _record(usernames, username, event.src_ip, event.timestamp, successful)
        if password is not None:
            _record(passwords, password, event.src_ip, event.timestamp, successful)
        if username is not None and password is not None:
            _record(pairs, (username, password), event.src_ip, event.timestamp, successful)

        if event.src_ip:
            source = sources.setdefault(
                event.src_ip,
                {
                    "attempts": 0,
                    "successes": 0,
                    "usernames": set(),
                    "passwords": set(),
                    "first_seen": None,
                    "last_seen": None,
                },
            )
            source["attempts"] += 1
            source["successes"] += int(successful)
            if username is not None:
                source["usernames"].add(username)
            if password is not None:
                source["passwords"].add(password)
            if event.timestamp:
                if source["first_seen"] is None or event.timestamp < source["first_seen"]:
                    source["first_seen"] = event.timestamp
                if source["last_seen"] is None or event.timestamp > source["last_seen"]:
                    source["last_seen"] = event.timestamp

    source_patterns = []
    for source_ip, item in sources.items():
        username_count = len(item["usernames"])
        password_count = len(item["passwords"])
        source_patterns.append(
            {
                "source_ip": source_ip,
                "classification": _classification(item["attempts"], username_count, password_count),
                "attempts": item["attempts"],
                "successes": item["successes"],
                "success_rate_percent": round(item["successes"] * 100 / item["attempts"], 1),
                "unique_usernames": username_count,
                "unique_passwords": password_count,
                "first_seen": item["first_seen"],
                "last_seen": item["last_seen"],
            }
        )
    source_patterns.sort(key=lambda item: (-item["attempts"], item["source_ip"]))

    return {
        "attempts": attempts,
        "successes": successes,
        "success_rate_percent": round(successes * 100 / attempts, 1) if attempts else 0.0,
        "unique_usernames": len(usernames),
        "unique_passwords": len(passwords),
        "passwords_redacted": not show_passwords,
        "top_usernames": _ranked(usernames, ("username",), limit),
        "top_passwords": _ranked(passwords, ("password",), limit) if show_passwords else [],
        "top_pairs": _ranked(pairs, ("username", "password"), limit) if show_passwords else [],
        "source_patterns": source_patterns,
    }
