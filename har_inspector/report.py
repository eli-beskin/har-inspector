"""Render an Analysis as a plain-text report."""

import os
import textwrap
from datetime import datetime

from har_inspector.analysis import Analysis
from har_inspector.classify import status_class
from har_inspector.model import PHASES

URL_WIDTH = 80
MAX_EVIDENCE = 5  # per finding; the rest is summarized as "... and N more"
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
        lines = [_wrap(f.title, f"  {f.severity.upper():<8} ", pad)]
        evidence = f.evidence
        hidden = len(evidence) - MAX_EVIDENCE
        # Keep the last item: for a redirect chain it is where the chain ends.
        # Hiding a single line behind a "... and 1 more" line saves nothing.
        if hidden > 1:
            evidence = evidence[: MAX_EVIDENCE - 1] + [None] + evidence[-1:]
        for ev in evidence:
            if ev is None:
                lines.append(f"{pad}... and {hidden} more")
                continue
            line = f"{pad}#{ev.index:<4} {ev.method:<7} {ev.status:<4} {_truncate(ev.url)}"
            lines.append(f"{line}  {ev.note}" if ev.note else line)
        if f.next_step:
            lines.append(_wrap(f.next_step, f"{pad}Next step: ", pad + " " * 11))
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
        lines.append(f"  {g.count:>5}  {status:<6}  {_truncate(g.endpoint)}")
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
        lines.append(f"       {_truncate(f'{e.method} {e.url}')}")
    return "\n".join(lines)


def _internal(a: Analysis) -> str:
    title = "CHROME-INTERNAL ENTRIES (excluded from stats)"
    if not a.internal:
        return f"{title}\n  none"
    lines = [title]
    for e in a.internal:
        reason = e.header("Non-Authoritative-Reason") or ""
        lines.append(f"  {e.status}  {_truncate(f'{e.method} {e.url}')}")
        lines.append(f"       reason: {reason}")
    return "\n".join(lines)


def _wrap(text: str, first: str, rest: str) -> str:
    # Never split URLs or header names like Access-Control-Allow-Origin.
    return textwrap.fill(
        text, TEXT_WIDTH, initial_indent=first, subsequent_indent=rest,
        break_long_words=False, break_on_hyphens=False,
    )


def _ms(value: float | None) -> str:
    return "-" if value is None else f"{value:.0f}"


def _size(n: int) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024 or unit == "MB":
            return f"{n} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def _time(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def _truncate(text: str, width: int = URL_WIDTH) -> str:
    # Cut the middle: host and the tail of the path are the useful parts.
    if len(text) <= width:
        return text
    keep = width - 3
    return text[: keep - keep // 3] + "..." + text[-(keep // 3):]
