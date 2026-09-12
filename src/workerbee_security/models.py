from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ParseWarning:
    line: int
    message: str

    def as_dict(self) -> Dict[str, Any]:
        return {"line": self.line, "message": self.message}


@dataclass
class CowrieEvent:
    line: int
    eventid: str
    timestamp: Optional[str]
    session: Optional[str]
    src_ip: Optional[str]
    protocol: Optional[str]
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParseResult:
    source: str
    events: List[CowrieEvent]
    warnings: List[ParseWarning]
    lines_read: int
