import ipaddress
import re
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlsplit, urlunsplit

from .models import CowrieEvent

URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`]+", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_RE = re.compile(r"(?<![0-9a-z])\[?[0-9a-f:.]{2,}\]?(?![0-9a-z])", re.I)
DOMAIN_RE = re.compile(
    r"(?<![@\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w-])",
    re.IGNORECASE,
)
HASH_PATTERNS = {
    "md5": re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", re.I),
    "sha1": re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", re.I),
    "sha256": re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", re.I),
}
FILELIKE_TLDS = {
    "bin",
    "cfg",
    "conf",
    "deb",
    "dll",
    "exe",
    "gz",
    "json",
    "log",
    "py",
    "rpm",
    "sh",
    "so",
    "tar",
    "txt",
    "xml",
    "zip",
}
SKIP_FIELDS = {
    "dst_ip",
    "dst_port",
    "eventid",
    "fingerprint",
    "key",
    "password",
    "protocol",
    "sensor",
    "session",
    "username",
}


def _valid_ip(value: str) -> Optional[str]:
    try:
        return ipaddress.ip_address(value.strip("[]")).compressed
    except ValueError:
        return None


def _normalize_url(value: str) -> Optional[str]:
    value = value.rstrip('.,;:!?)"]}')
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https", "ftp"} or not parts.hostname:
        return None

    host = parts.hostname.lower().rstrip(".")
    try:
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return None
    userinfo = ""
    if parts.username:
        userinfo = parts.username
        if parts.password:
            userinfo += ":<redacted>"
        userinfo += "@"
    netloc = f"{userinfo}{host}{port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "", parts.query, ""))


def _strings(value: Any, key: str = "") -> Iterator[str]:
    if key in SKIP_FIELDS:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child_key, child_value in value.items():
            yield from _strings(child_value, str(child_key))
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child, key)


def indicators_in_text(text: str) -> Set[Tuple[str, str]]:
    found: Set[Tuple[str, str]] = set()

    for match in URL_RE.finditer(text):
        url = _normalize_url(match.group(0))
        if not url:
            continue
        found.add(("url", url))
        host = urlsplit(url).hostname
        if not host:
            continue
        ip = _valid_ip(host)
        found.add(("ip", ip) if ip else ("domain", host.lower()))

    for match in IPV4_RE.finditer(text):
        ip = _valid_ip(match.group(0))
        if ip:
            found.add(("ip", ip))

    for match in IPV6_RE.finditer(text):
        candidate = match.group(0)
        if candidate.count(":") < 2:
            continue
        ip = _valid_ip(candidate)
        if ip:
            found.add(("ip", ip))

    for match in DOMAIN_RE.finditer(text):
        domain = match.group(0).lower().rstrip(".")
        if domain.rsplit(".", 1)[-1] not in FILELIKE_TLDS and not _valid_ip(domain):
            found.add(("domain", domain))

    for kind, pattern in HASH_PATTERNS.items():
        for match in pattern.finditer(text):
            found.add((kind, match.group(0).lower()))

    return found


def extract_indicators(events: Iterable[CowrieEvent]) -> List[Dict[str, Any]]:
    records: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for event in events:
        found: Set[Tuple[str, str]] = set()
        if event.src_ip:
            ip = _valid_ip(event.src_ip)
            if ip:
                found.add(("ip", ip))
        for text in _strings(event.data):
            found.update(indicators_in_text(text))

        for kind, value in found:
            key = (kind, value)
            record = records.setdefault(
                key,
                {
                    "type": kind,
                    "value": value,
                    "count": 0,
                    "first_seen": event.timestamp,
                    "last_seen": event.timestamp,
                    "sessions": set(),
                    "eventids": set(),
                    "enrichment": {},
                },
            )
            record["count"] += 1
            if event.timestamp:
                current_first = record["first_seen"]
                current_last = record["last_seen"]
                if current_first is None or event.timestamp < current_first:
                    record["first_seen"] = event.timestamp
                if current_last is None or event.timestamp > current_last:
                    record["last_seen"] = event.timestamp
            if event.session:
                record["sessions"].add(event.session)
            record["eventids"].add(event.eventid)

    output = []
    for record in records.values():
        record["sessions"] = sorted(record["sessions"])
        record["eventids"] = sorted(record["eventids"])
        output.append(record)
    return sorted(output, key=lambda item: (item["type"], item["value"]))
