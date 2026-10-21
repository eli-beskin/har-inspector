"""Compute report data from parsed entries. No formatting here."""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from har_inspector.classify import endpoint, is_chrome_internal, is_failure, status_class
from har_inspector.detectors import Finding, run_all
from har_inspector.model import Entry, HarFile

STATUS_CLASSES = ("1xx", "2xx", "3xx", "4xx", "5xx", "failed")

# Chrome reports this for every 4xx/5xx; it adds nothing to the status code.
_GENERIC_ERRORS = {"net::ERR_HTTP_RESPONSE_CODE_FAILURE"}

# Share of total time in a single phase above which an entry without a server
# IP is treated as "breakdown unavailable" (tolerance for float noise).
_SINGLE_PHASE_SHARE = 0.95


@dataclass
class Summary:
    requests: int
    internal: int
    transferred_bytes: int
    unknown_size: int
    start: datetime | None
    end: datetime | None
    by_class: dict[str, int]

    @property
    def span_seconds(self) -> float:
        if self.start is None or self.end is None:
            return 0.0
        return (self.end - self.start).total_seconds()


@dataclass
class FailedGroup:
    status: int
    status_text: str
    endpoint: str
    count: int
    errors: list[str] = field(default_factory=list)


@dataclass
class SlowEntry:
    entry: Entry
    phases: dict[str, float | None]
    dominant: str | None  # None when the breakdown is unreliable
    dominant_share: float


@dataclass
class Analysis:
    har: HarFile
    summary: Summary
    failed: list[FailedGroup]
    slowest: list[SlowEntry]
    internal: list[Entry]
    findings: list[Finding] = field(default_factory=list)


def analyze(har: HarFile, top: int = 10) -> Analysis:
    internal = [e for e in har.entries if is_chrome_internal(e)]
    real = [e for e in har.entries if not is_chrome_internal(e)]
    return Analysis(
        har=har,
        summary=summarize(real, len(internal)),
        failed=failed_groups(real),
        slowest=slowest(real, top),
        internal=internal,
        # Detectors see internal entries too (redirect chains need HSTS hops).
        findings=run_all(har.entries),
    )


def summarize(entries: list[Entry], internal_count: int) -> Summary:
    counts = Counter(status_class(e) for e in entries)
    sizes = [e.transfer_size for e in entries]
    return Summary(
        requests=len(entries),
        internal=internal_count,
        transferred_bytes=sum(s for s in sizes if s is not None),
        unknown_size=sum(1 for s in sizes if s is None),
        start=min((e.started for e in entries), default=None),
        end=max((e.finished for e in entries), default=None),
        by_class={c: counts.get(c, 0) for c in STATUS_CLASSES},
    )


def failed_groups(entries: list[Entry]) -> list[FailedGroup]:
    groups: dict[tuple[int, str], FailedGroup] = {}
    errors: dict[tuple[int, str], set[str]] = defaultdict(set)
    for e in entries:
        if not is_failure(e):
            continue
        key = (e.status, endpoint(e))
        group = groups.setdefault(key, FailedGroup(e.status, e.status_text, key[1], 0))
        group.count += 1
        if e.error and e.error not in _GENERIC_ERRORS:
            errors[key].add(e.error)
    for key, group in groups.items():
        group.errors = sorted(errors[key])
    # Most frequent first; then server errors before client errors before failed.
    return sorted(groups.values(), key=lambda g: (-g.count, -g.status, g.endpoint))


def slowest(entries: list[Entry], top: int) -> list[SlowEntry]:
    ranked = sorted(entries, key=lambda e: e.time_ms, reverse=True)[:top]
    return [_slow_entry(e) for e in ranked]


def _slow_entry(entry: Entry) -> SlowEntry:
    phases = entry.timings.phases()
    measured = {k: v for k, v in phases.items() if v is not None}
    total = sum(measured.values())
    if not measured or total <= 0:
        return SlowEntry(entry, phases, None, 0.0)
    dominant = max(measured, key=measured.get)
    share = measured[dominant] / total
    # No server IP + all time in one phase: Chrome never reached the network
    # (blocked, cache, service worker), so the split is not a real diagnosis.
    if not entry.server_ip and share >= _SINGLE_PHASE_SHARE:
        return SlowEntry(entry, phases, None, share)
    return SlowEntry(entry, phases, dominant, share)
