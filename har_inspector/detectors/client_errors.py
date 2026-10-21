"""Client-side failures: Chrome net::ERR_* codes mapped to a likely cause and a hint."""

from har_inspector.detectors import cors
from har_inspector.detectors.finding import Evidence, Finding
from har_inspector.model import Entry

# code -> (severity, likely cause, next step)
KNOWN = {
    "net::ERR_BLOCKED_BY_CLIENT": (
        "warning", "blocked by an ad blocker or browser extension",
        "Retry in an incognito window with extensions disabled, or allowlist the "
        "site in the ad blocker.",
    ),
    "net::ERR_BLOCKED_BY_ORB": (
        "warning", "browser blocked a cross-origin response (Opaque Response Blocking)",
        "Usually harmless for third-party trackers. If the resource matters, the "
        "server must return the right Content-Type (or the page must use CORS).",
    ),
    "net::ERR_NETWORK_ACCESS_DENIED": (
        "error", "network access denied by a firewall, antivirus or OS policy",
        "Check the user's firewall/antivirus/proxy and corporate policy; retry from "
        "another network or with security software paused.",
    ),
    "net::ERR_NAME_NOT_RESOLVED": (
        "error", "DNS lookup failed (host name not found)",
        "Check the host name for typos and that it resolves from the user's network "
        "(nslookup); check VPN/DNS settings.",
    ),
    "net::ERR_CONNECTION_REFUSED": (
        "error", "server refused the connection (nothing listening, or blocked)",
        "Check that the service is up on that host/port and not blocked by a "
        "firewall; retry from another network.",
    ),
    "net::ERR_CONNECTION_RESET": (
        "error", "connection reset (server, proxy or firewall dropped it)",
        "Check proxy/firewall/antivirus TLS inspection and server logs for that "
        "time; retry from another network.",
    ),
    "net::ERR_CONNECTION_TIMED_OUT": (
        "error", "connection timed out (no answer from the server)",
        "Check that the host is reachable from the user's network (ping/traceroute), "
        "firewall rules and VPN/proxy settings.",
    ),
}
_CERT_PREFIX = "net::ERR_CERT_"
_CERT = (
    "error", "TLS certificate rejected",
    "Open the URL in the browser to see the certificate error: check expiry, host "
    "name, chain, the user's system clock, and antivirus/proxy TLS interception.",
)
_UNKNOWN_HINT = "Look up the code in Chromium's net error list (chrome://network-errors)."

# Chrome adds this to every 4xx/5xx; it is not a client-side failure.
_GENERIC = "net::ERR_HTTP_RESPONSE_CODE_FAILURE"


def detect(entries: list[Entry]) -> list[Finding]:
    explained = cors.blocked_indices(entries)
    by_code: dict[str, list[Entry]] = {}
    for e in entries:
        code = e.error
        if not code or code == _GENERIC or e.index in explained:
            continue
        if _lookup(code) is None and e.status != 0:
            # Unmapped code but a response arrived, e.g. ERR_ABORTED on a beacon
            # whose page moved on (about 40 of those in a real news-site HAR).
            continue
        by_code.setdefault(code, []).append(e)

    findings = []
    for code, group in by_code.items():
        n = len(group)
        count = f"{n} request{'s' if n > 1 else ''}"
        known = _lookup(code)
        if known is None:
            findings.append(Finding(
                "warning", f"{code} ({count}): no known mapping",
                [Evidence.of(e, code) for e in group], _UNKNOWN_HINT,
            ))
            continue
        severity, cause, hint = known
        findings.append(Finding(
            severity, f"{code} ({count}): {cause}",
            [Evidence.of(e) for e in group], hint,
        ))
    return findings


def _lookup(code: str) -> tuple[str, str, str] | None:
    if code in KNOWN:
        return KNOWN[code]
    if code.startswith(_CERT_PREFIX):
        return _CERT
    return None
