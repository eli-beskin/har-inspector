"""Normalized HAR data. Nothing past the parser touches raw HAR dicts."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta

# Report phases, in display order. "connect" already includes "ssl".
PHASES = ("blocked", "dns", "connect", "send", "wait", "receive")


@dataclass(frozen=True)
class Timings:
    """Phase durations in ms; None means "not applicable" (negative in the HAR)."""

    blocked: float | None = None
    dns: float | None = None
    connect: float | None = None
    ssl: float | None = None
    send: float | None = None
    wait: float | None = None
    receive: float | None = None

    def phases(self) -> dict[str, float | None]:
        return {name: getattr(self, name) for name in PHASES}


@dataclass(frozen=True)
class Entry:
    index: int
    started: datetime
    time_ms: float
    method: str
    url: str
    status: int
    status_text: str
    server_ip: str
    transfer_size: int | None
    error: str | None
    resource_type: str | None
    response_headers: list[tuple[str, str]] = field(default_factory=list)
    timings: Timings = field(default_factory=Timings)
    request_headers: list[tuple[str, str]] = field(default_factory=list)
    request_headers_size: int | None = None  # None: unknown (Chrome often writes -1)
    redirect_url: str = ""
    initiator_type: str | None = None  # Chrome's _initiator.type, e.g. "preflight"

    @property
    def finished(self) -> datetime:
        return self.started + timedelta(milliseconds=self.time_ms)

    def header(self, name: str) -> str | None:
        """Response header value (case-insensitive name), or None."""
        return _find_header(self.response_headers, name)

    def request_header(self, name: str) -> str | None:
        return _find_header(self.request_headers, name)


def _find_header(headers: list[tuple[str, str]], name: str) -> str | None:
    # HTTP/2 exports use lowercase names, HTTP/1.1 ones canonical case.
    name = name.lower()
    for key, value in headers:
        if key.lower() == name:
            return value
    return None


@dataclass(frozen=True)
class HarFile:
    path: str
    creator: str
    page_count: int
    entries: list[Entry]
