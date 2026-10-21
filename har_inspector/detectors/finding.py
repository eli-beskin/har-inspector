"""Finding: what a detector reports. Kept apart from __init__ to avoid import cycles."""

from dataclasses import dataclass, field

from har_inspector.model import Entry

SEVERITIES = ("error", "warning", "info")


@dataclass(frozen=True)
class Evidence:
    index: int
    method: str
    url: str
    status: int
    note: str = ""

    @classmethod
    def of(cls, entry: Entry, note: str = "") -> "Evidence":
        return cls(entry.index, entry.method, entry.url, entry.status, note)


@dataclass(frozen=True)
class Finding:
    severity: str  # one of SEVERITIES
    title: str
    evidence: list[Evidence] = field(default_factory=list)
    next_step: str = ""
