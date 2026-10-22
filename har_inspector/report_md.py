"""Render an Analysis as a Markdown report (GitHub-flavored, for tickets).

Same content as report.py; findings come first because whoever opens the
ticket needs the diagnosis before the statistics.
"""

import os
import re

from har_inspector.analysis import Analysis
from har_inspector.model import PHASES
from har_inspector.render_common import (
    MAX_EVIDENCE, ms, size, truncate, utc_time, visible_evidence,
)

# Characters that can start emphasis, links, HTML or break a table cell.
# Not ">": it only matters at the start of a line (blockquote), and escaping
# "<" is enough to stop HTML; this keeps "->" in the capture span readable.
_SPECIAL = re.compile(r"([\\`*_\[\]<|])")


def render(a: Analysis) -> str:
    sections = [
        _header(a),
        _findings(a),
        _summary(a),
        _failed(a),
        _slowest(a),
        _internal(a),
    ]
    return "\n\n".join(sections) + "\n"


def _header(a: Analysis) -> str:
    name = _text(os.path.basename(a.har.path))
    creator = _text(a.har.creator or "unknown")
    return f"# HAR Inspector: {name}\n\nCreator: {creator}, Pages: {a.har.page_count}"


def _findings(a: Analysis) -> str:
    if not a.findings:
        return "## Findings\n\n*none*"
    blocks = []
    for f in a.findings:
        rows = []
        hidden = len(f.evidence) - MAX_EVIDENCE
        for ev in visible_evidence(f.evidence):
            if ev is None:
                rows.append(["", "", "", f"*... and {hidden} more*", ""])
                continue
            rows.append([
                str(ev.index), _text(ev.method), str(ev.status),
                _code(truncate(ev.url)), _text(ev.note),
            ])
        parts = [f"**{f.severity.upper()}** {_text(f.title)}"]
        if rows:
            parts.append(_table(["#", "Method", "Status", "URL", "Note"], "rlrll", rows))
        if f.next_step:
            parts.append(f"**Next step:** {_text(f.next_step)}")
        blocks.append("\n\n".join(parts))
    return "## Findings\n\n" + "\n\n".join(blocks)


def _summary(a: Analysis) -> str:
    s = a.summary
    transferred = size(s.transferred_bytes)
    if s.unknown_size:
        noun = "entry" if s.unknown_size == 1 else "entries"
        transferred += f" ({s.unknown_size} {noun} with unknown size not counted)"
    if s.start is None:
        span = "n/a"
    else:
        span = f"{s.span_seconds:.2f} s ({utc_time(s.start)} -> {utc_time(s.end)} UTC)"
    classes = ", ".join(
        f"{'failed(0)' if c == 'failed' else c} {n}"
        for c, n in s.by_class.items()
        if c != "1xx" or n  # 1xx shouldn't occur; show it only if it does
    )
    rows = [
        ["Requests", f"{s.requests} (Chrome-internal excluded: {s.internal})"],
        ["Transferred", transferred],
        ["Capture span", _text(span)],
        ["By status", classes],
    ]
    return "## Summary\n\n" + _table(["Metric", "Value"], "ll", rows)


def _failed(a: Analysis) -> str:
    if not a.failed:
        return "## Failed requests\n\n*none*"
    rows = []
    for g in a.failed:
        detail = ", ".join(filter(None, [g.status_text, *g.errors]))
        rows.append([str(g.count), str(g.status), _code(truncate(g.endpoint)), _text(detail)])
    return "## Failed requests\n\n" + _table(
        ["Count", "Status", "Endpoint", "Details"], "rrll", rows
    )


def _slowest(a: Analysis) -> str:
    title = f"## Top {len(a.slowest)} slowest"
    if not a.slowest:
        return f"{title}\n\n*none*"
    rows = []
    for i, s in enumerate(a.slowest, 1):
        e = s.entry
        if s.dominant is None:
            dominant = "breakdown unavailable"
        else:
            dominant = f"{s.dominant} ({s.dominant_share:.0%})"
        rows.append([
            str(i), f"{e.time_ms:.0f}", str(e.status), dominant,
            *(ms(s.phases[p]) for p in PHASES),
            _code(truncate(f"{e.method} {e.url}")),
        ])
    head = ["#", "Time ms", "Status", "Dominant", *PHASES, "Request"]
    align = "rrrl" + "r" * len(PHASES) + "l"
    return (
        f"{title}\n\n*connect includes ssl; `-` = not applicable*\n\n"
        + _table(head, align, rows)
    )


def _internal(a: Analysis) -> str:
    title = "## Chrome-internal entries (excluded from stats)"
    if not a.internal:
        return f"{title}\n\n*none*"
    rows = [
        [
            str(e.status),
            _code(truncate(f"{e.method} {e.url}")),
            _text(e.header("Non-Authoritative-Reason") or ""),
        ]
        for e in a.internal
    ]
    return f"{title}\n\n" + _table(["Status", "Request", "Reason"], "rll", rows)


def _table(head: list[str], align: str, rows: list[list[str]]) -> str:
    rule = ["--:" if c == "r" else "---" for c in align]
    lines = [_row(head), _row(rule)] + [_row(r) for r in rows]
    return "\n".join(lines)


def _row(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def _text(value: str) -> str:
    """Free text, safe inline and in a table cell."""
    value = _one_line(value)
    value = _SPECIAL.sub(r"\\\1", value)
    # A leading "#" would turn a line (the severity line aside) into a heading.
    return "\\" + value if value.startswith("#") else value


def _code(value: str) -> str:
    """URL or endpoint as a code span: no emphasis from "_" or "*", no autolink."""
    value = _one_line(value)
    # Backslash escapes don't work inside code spans, so the fence has to be
    # longer than any backtick run in the value.
    runs = [len(r) for r in re.findall(r"`+", value)]
    fence = "`" * (max(runs, default=0) + 1)
    if value.startswith("`") or value.endswith("`"):
        value = f" {value} "
    # GFM splits table rows on "|" before it parses code spans; "\|" is the
    # one escape that works inside them (and only in tables, where we use it).
    return fence + value.replace("|", "\\|") + fence


def _one_line(value: str) -> str:
    # A newline would end the table row or the paragraph.
    return re.sub(r"[\r\n]+", " ", value)
