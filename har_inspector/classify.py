"""Per-entry classification rules."""

from urllib.parse import urlsplit

from har_inspector.model import Entry


def is_chrome_internal(entry: Entry) -> bool:
    # Chrome synthesizes e.g. the HTTP->HTTPS (HSTS) upgrade as a 307 carrying
    # Non-Authoritative-Reason. Empty IP / zero _transferSize usually accompany
    # it but are not required: non-Chrome HARs lack _transferSize.
    return entry.status == 307 and entry.header("Non-Authoritative-Reason") is not None


def status_class(entry: Entry) -> str:
    """'failed' for status 0 (no response at all), otherwise '1xx'..'5xx'."""
    if entry.status <= 0:
        return "failed"
    return f"{min(entry.status // 100, 5)}xx"


def is_failure(entry: Entry) -> bool:
    return entry.status == 0 or entry.status >= 400


def endpoint(entry: Entry) -> str:
    """METHOD scheme://host/path, without query string or fragment."""
    parts = urlsplit(entry.url)
    return f"{entry.method} {parts.scheme}://{parts.netloc}{parts.path or '/'}"
