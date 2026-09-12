import json
import sys
from pathlib import Path
from typing import Iterable, List, Optional, TextIO

from .models import CowrieEvent, ParseResult, ParseWarning


class CowrieParseError(ValueError):
    pass


def _event_from_object(data: object, line: int) -> CowrieEvent:
    if not isinstance(data, dict):
        raise CowrieParseError("event must be a JSON object")

    eventid = data.get("eventid")
    if not isinstance(eventid, str) or not eventid.strip():
        raise CowrieParseError("eventid is missing")

    def optional_string(name: str) -> Optional[str]:
        value = data.get(name)
        return value if isinstance(value, str) and value else None

    return CowrieEvent(
        line=line,
        eventid=eventid,
        timestamp=optional_string("timestamp"),
        session=optional_string("session"),
        src_ip=optional_string("src_ip"),
        protocol=optional_string("protocol"),
        data=data,
    )


def parse_lines(
    lines: Iterable[str],
    source: str,
    strict: bool = False,
    limit: Optional[int] = None,
    max_line_bytes: int = 2_000_000,
) -> ParseResult:
    events: List[CowrieEvent] = []
    warnings: List[ParseWarning] = []
    lines_read = 0

    for line_number, raw_line in enumerate(lines, start=1):
        lines_read = line_number
        if limit is not None and len(events) >= limit:
            break
        if not raw_line.strip():
            continue

        if len(raw_line.encode("utf-8", errors="replace")) > max_line_bytes:
            message = f"line exceeds {max_line_bytes} bytes"
            if strict:
                raise CowrieParseError(f"{source}:{line_number}: {message}")
            warnings.append(ParseWarning(line_number, message))
            continue

        try:
            event = _event_from_object(json.loads(raw_line), line_number)
        except (json.JSONDecodeError, CowrieParseError) as exc:
            message = str(exc)
            if strict:
                raise CowrieParseError(f"{source}:{line_number}: {message}") from exc
            warnings.append(ParseWarning(line_number, message))
            continue

        events.append(event)

    return ParseResult(source, events, warnings, lines_read)


def parse_file(
    path: str,
    strict: bool = False,
    limit: Optional[int] = None,
    max_line_bytes: int = 2_000_000,
    stdin: Optional[TextIO] = None,
) -> ParseResult:
    if path == "-":
        stream = stdin or sys.stdin
        return parse_lines(stream, "<stdin>", strict, limit, max_line_bytes)

    source_path = Path(path).expanduser()
    if not source_path.is_file():
        raise CowrieParseError(f"input file does not exist: {source_path}")

    try:
        with source_path.open("r", encoding="utf-8", errors="replace") as handle:
            return parse_lines(handle, str(source_path), strict, limit, max_line_bytes)
    except OSError as exc:
        raise CowrieParseError(f"could not read {source_path}: {exc}") from exc
