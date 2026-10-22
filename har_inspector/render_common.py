"""Formatting helpers shared by the text and Markdown renderers."""

from datetime import datetime

from har_inspector.detectors import Evidence
from har_inspector.urls import mask_url, mask_urls_in_text

URL_WIDTH = 80
MAX_EVIDENCE = 5  # per finding; the rest is summarized as "... and N more"


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
    return truncate(mask_url(value))


def request(method: str, value: str) -> str:
    return truncate(f"{method} {mask_url(value)}")


def endpoint(value: str) -> str:
    # "METHOD scheme://host/path" (classify.endpoint): userinfo is all that can be left.
    return truncate(mask_urls_in_text(value))


def text(value: str) -> str:
    """Free text that may embed URLs (finding titles, notes, next steps)."""
    return mask_urls_in_text(value)


def truncate(text: str, width: int = URL_WIDTH) -> str:
    # Cut the middle: host and the tail of the path are the useful parts.
    if len(text) <= width:
        return text
    keep = width - 3
    return text[: keep - keep // 3] + "..." + text[-(keep // 3):]
