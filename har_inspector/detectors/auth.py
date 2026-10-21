"""Auth: 401/403 grouped by endpoint, auth scheme, and whether credentials were sent."""

from urllib.parse import urlsplit

from har_inspector.classify import endpoint
from har_inspector.detectors.finding import Evidence, Finding
from har_inspector.model import Entry

_SENT, _LIKELY, _UNKNOWN = "sent", "likely", "unknown"


def detect(entries: list[Entry]) -> list[Finding]:
    groups: dict[tuple[int, str], list[Entry]] = {}
    for e in entries:
        # A rejected preflight is a CORS problem, reported by the cors detector.
        if e.status in (401, 403) and e.method != "OPTIONS":
            groups.setdefault((e.status, endpoint(e)), []).append(e)

    findings = []
    for (status, ep), group in groups.items():
        creds = [_credentials(e, entries) for e in group]
        kinds = {kind for kind, _ in creds}
        schemes = sorted({s for s in (_scheme(e) for e in group) if s})
        scheme = "/".join(schemes) if schemes else "none given"
        n = len(group)
        head = f"{status} on {ep} ({n} request{'s' if n > 1 else ''}, scheme {scheme})"
        evidence = [
            Evidence.of(e, f"credentials: {note}") for e, (_, note) in zip(group, creds)
        ]
        if kinds & {_SENT, _LIKELY}:
            sent = "sent" if _SENT in kinds else "likely sent"
            outcome = "and rejected" if status == 401 else "but access denied"
            findings.append(Finding(
                "error", f"{head} — credentials {sent} {outcome}", evidence,
                _SENT_HINT[status],
            ))
        else:
            # Absence of Authorization proves nothing: Chrome strips it from
            # exports unless "with sensitive data" is chosen. Never say "not sent".
            findings.append(Finding(
                "warning",
                f"{head} — no evidence credentials were sent "
                "(export may strip Authorization)",
                evidence, _UNKNOWN_HINT[status],
            ))

    findings.extend(_basic_over_http(entries))
    return findings


_SENT_HINT = {
    401: "Credentials reached the server and were rejected: check the username/"
         "password or token (expired, revoked, wrong realm/audience).",
    403: "The server identified the user but refused access: check the account's "
         "roles/permissions for this resource.",
}
_UNKNOWN_HINT = {
    401: "Ask for a HAR exported \"with sensitive data\" to see the Authorization "
         "header; otherwise check that the client attaches credentials.",
    403: "Access refused: check the account's permissions; a HAR exported \"with "
         "sensitive data\" shows whether credentials/cookies were attached.",
}


def _credentials(e: Entry, entries: list[Entry]) -> tuple[str, str]:
    if e.request_header("Authorization") is not None:
        return _SENT, "sent (Authorization header)"
    # The export may strip Authorization but still count it in headersSize, so a
    # retry whose request headers grew is a hint the browser added credentials.
    prev = _previous_identical(e, entries)
    if prev is not None and e.request_headers_size > prev.request_headers_size:
        grew = e.request_headers_size - prev.request_headers_size
        return _LIKELY, f"likely sent (request headers +{grew} B vs #{prev.index})"
    return _UNKNOWN, "no evidence"


def _previous_identical(e: Entry, entries: list[Entry]) -> Entry | None:
    if e.request_headers_size is None:
        return None
    earlier = [
        p for p in entries
        if p.index < e.index and (p.method, p.url) == (e.method, e.url)
        and p.request_headers_size is not None
    ]
    return max(earlier, key=lambda p: p.index, default=None)


def _scheme(e: Entry) -> str | None:
    value = e.header("WWW-Authenticate")
    if not value or not value.strip():
        return None
    return value.split()[0].rstrip(",")


def _basic_over_http(entries: list[Entry]) -> list[Finding]:
    by_endpoint: dict[str, list[Entry]] = {}
    for e in entries:
        if urlsplit(e.url).scheme != "http":
            continue
        offered = (_scheme(e) or "").lower() == "basic"
        auth = (e.request_header("Authorization") or "").lower()
        if offered or auth.startswith("basic "):
            by_endpoint.setdefault(endpoint(e), []).append(e)
    return [
        Finding(
            "warning",
            f"Basic auth over plain HTTP: {ep} — password travels unencrypted",
            [Evidence.of(e) for e in group],
            "Serve this endpoint over HTTPS only (redirect HTTP, enable HSTS); "
            "treat credentials used here as exposed.",
        )
        for ep, group in by_endpoint.items()
    ]
