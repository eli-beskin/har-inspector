"""Render an Analysis as a plain-text report."""

import os
import textwrap

from har_inspector.analysis import Analysis
from har_inspector.model import PHASES
from har_inspector.render_common import MAX_EVIDENCE, visible_evidence
from har_inspector.render_common import endpoint as _endpoint
from har_inspector.render_common import ms as _ms
from har_inspector.render_common import request as _request
from har_inspector.render_common import size as _size
from har_inspector.render_common import text as _masked
from har_inspector.render_common import url as _url
from har_inspector.render_common import utc_time as _time

TEXT_WIDTH = 100


def render(a: Analysis) -> str:
    sections = [
        _header(a),
        _summary(a),
        _findings(a),
        _failed(a),
        _slowest(a),
        _internal(a),
    ]
    return "\n\n".join(sections) + "\n"


def _header(a: Analysis) -> str:
    lines = [f"HAR Inspector - {os.path.basename(a.har.path)}"]
    lines.append(f"Creator: {a.har.creator or 'unknown'}   Pages: {a.har.page_count}")
    return "\n".join(lines)


def _summary(a: Analysis) -> str:
    s = a.summary
    size = _size(s.transferred_bytes)
    if s.unknown_size:
        noun = "entry" if s.unknown_size == 1 else "entries"
        size += f"  ({s.unknown_size} {noun} with unknown size not counted)"
    if s.start is None:
        span = "n/a"
    else:
        span = f"{s.span_seconds:.2f} s  ({_time(s.start)} -> {_time(s.end)} UTC)"
    classes = " | ".join(
        f"{'failed(0)' if c == 'failed' else c} {n}"
        for c, n in s.by_class.items()
        if c != "1xx" or n  # 1xx shouldn't occur; show it only if it does
    )
    return "\n".join([
        "SUMMARY",
        f"  Requests:      {s.requests}   (Chrome-internal excluded: {s.internal})",
        f"  Transferred:   {size}",
        f"  Capture span:  {span}",
        f"  By status:     {classes}",
    ])


def _findings(a: Analysis) -> str:
    if not a.findings:
        return "FINDINGS\n  none"
    pad = " " * 11
    blocks = []
    for f in a.findings:
        lines = [_wrap(_masked(f.title), f"  {f.severity.upper():<8} ", pad)]
        hidden = len(f.evidence) - MAX_EVIDENCE
        for ev in visible_evidence(f.evidence):
            if ev is None:
                lines.append(f"{pad}... and {hidden} more")
                continue
            line = f"{pad}#{ev.index:<4} {ev.method:<7} {ev.status:<4} {_url(ev.url)}"
            lines.append(f"{line}  {_masked(ev.note)}" if ev.note else line)
        if f.next_step:
            lines.append(_wrap(_masked(f.next_step), f"{pad}Next step: ", pad + " " * 11))
        blocks.append("\n".join(lines))
    return "FINDINGS\n" + "\n\n".join(blocks)


def _failed(a: Analysis) -> str:
    if not a.failed:
        return "FAILED REQUESTS\n  none"
    lines = ["FAILED REQUESTS", f"  {'Count':>5}  {'Status':<6}  Endpoint"]
    for g in a.failed:
        status = str(g.status) if g.status else "0"
        detail = f"{g.status_text}" if g.status_text else ""
        if g.errors:
            detail = ", ".join(filter(None, [detail, *g.errors]))
        lines.append(f"  {g.count:>5}  {status:<6}  {_endpoint(g.endpoint)}")
        if detail:
            lines.append(f"  {'':>5}  {'':<6}    {detail}")
    return "\n".join(lines)


def _slowest(a: Analysis) -> str:
    title = f"TOP {len(a.slowest)} SLOWEST"
    if not a.slowest:
        return f"{title}\n  none"
    head = (
        f"  {'#':>3}  {'Time ms':>8}  {'Status':<6}  {'Dominant':<22}"
        + "".join(f"{p:>9}" for p in PHASES)
    )
    lines = [title, "  (connect includes ssl; '-' = not applicable)", head]
    for i, s in enumerate(a.slowest, 1):
        e = s.entry
        if s.dominant is None:
            dominant = "breakdown unavailable"
        else:
            dominant = f"{s.dominant} ({s.dominant_share:.0%})"
        phases = "".join(f"{_ms(s.phases[p]):>9}" for p in PHASES)
        lines.append(
            f"  {i:>3}  {e.time_ms:>8.0f}  {e.status:<6}  {dominant:<22}{phases}"
        )
        lines.append(f"       {_request(e.method, e.url)}")
    return "\n".join(lines)


def _internal(a: Analysis) -> str:
    title = "CHROME-INTERNAL ENTRIES (excluded from stats)"
    if not a.internal:
        return f"{title}\n  none"
    lines = [title]
    for e in a.internal:
        reason = e.header("Non-Authoritative-Reason") or ""
        lines.append(f"  {e.status}  {_request(e.method, e.url)}")
        lines.append(f"       reason: {reason}")
    return "\n".join(lines)


def _wrap(text: str, first: str, rest: str) -> str:
    # Never split URLs or header names like Access-Control-Allow-Origin.
    return textwrap.fill(
        text, TEXT_WIDTH, initial_indent=first, subsequent_indent=rest,
        break_long_words=False, break_on_hyphens=False,
    )
