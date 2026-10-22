"""Formatting helpers shared by the text and Markdown renderers."""

import re
from datetime import datetime

from har_inspector.detectors import Evidence
from har_inspector.urls import mask_url, mask_urls_in_text

URL_WIDTH = 80
MAX_EVIDENCE = 5  # per finding; the rest is summarized as "... and N more"

# Characters a crafted HAR could use to rewrite the terminal or disguise text:
# C0 controls (ESC starts CSI/OSC sequences, CR returns to the line start), DEL,
# C1 controls (0x9B is a one-byte CSI), bidi embeddings/overrides/isolates and
# the LRM/RLM/ALM marks (reorder what a URL looks like), and U+2028/U+2029
# (line breaks inside a "single-line" value in some viewers).
_BIDI = "\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069"
_UNSAFE = re.compile(f"[\x00-\x1f\x7f-\x9f{_BIDI}]")
_UNSAFE_KEEP_NL = re.compile(f"[\x00-\x09\x0b-\x1f\x7f-\x9f{_BIDI}]")
_SHORT = {"\r": "\\r", "\n": "\\n", "\t": "\\t"}


def safe(value: str, keep_newlines: bool = False) -> str:
    """Untrusted (HAR-derived) text made safe to print: control and bidi
    characters become visible escapes (\\x1b, \\r, \\u202e); other Unicode is kept.
    Backslashes are not escaped: a literal "\\x1b" in the HAR is harmless text.
    keep_newlines is for the final pass over a whole rendered report."""
    pattern = _UNSAFE_KEEP_NL if keep_newlines else _UNSAFE
    return pattern.sub(_escape, value)


def _escape(m: re.Match) -> str:
    ch = m[0]
    if ch in _SHORT:
        return _SHORT[ch]
    return f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}"


def visible_evidence(evidence: list[Evidence]) -> list[Evidence | None]:
    """Evidence to show; None marks where "... and N more" goes
    (N = len(evidence) - MAX_EVIDENCE)."""
    hidden = len(evidence) - MAX_EVIDENCE
    # Keep the last item: for a redirect chain it is where the chain ends.
    # Hiding a single line behind a "... and 1 more" line saves nothing.
    if hidden > 1:
        return evidence[: MAX_EVIDENCE - 1] + [None] + evidence[-1:]
    return list(evidence)


def ms(value: float | None) -> str:
    return "-" if value is None else f"{value:.0f}"


def size(n: int) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024 or unit == "MB":
            return f"{n} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def utc_time(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def url(value: str) -> str:
    """A URL for display. Reports go into tickets: URL passwords and secret-named
    params are masked, before truncation so a cut can't expose half a secret.
    Grouping in analysis still uses the raw URL."""
    # Mask, cut, then escape: masking must see the raw URL (an inserted "\" would
    # end the userinfo match early), and escaping last never leaves half an escape.
    return safe(truncate(mask_url(value)))


def request(method: str, value: str) -> str:
    return safe(truncate(f"{method} {mask_url(value)}"))


def endpoint(value: str) -> str:
    # "METHOD scheme://host/path" (classify.endpoint): userinfo is all that can be left.
    return safe(truncate(mask_urls_in_text(value)))


def text(value: str) -> str:
    """Free text that may embed URLs (finding titles, notes, next steps)."""
    return safe(mask_urls_in_text(value))


def truncate(text: str, width: int = URL_WIDTH) -> str:
    # Cut the middle: host and the tail of the path are the useful parts.
    if len(text) <= width:
        return text
    keep = width - 3
    return text[: keep - keep // 3] + "..." + text[-(keep // 3):]
