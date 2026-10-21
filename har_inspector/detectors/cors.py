"""CORS: a failed preflight (OPTIONS) and the request it blocked."""

from har_inspector.classify import endpoint
from har_inspector.detectors.finding import Evidence, Finding
from har_inspector.model import Entry

# A blocked request starts within this many ms of its preflight. Not "the next
# entry": in real Chrome exports the blocked request is often logged *before*
# its preflight (normal.har: PUT at .921, OPTIONS at .922).
LINK_WINDOW_MS = 1000


def detect(entries: list[Entry]) -> list[Finding]:
    links = link_preflights(entries)
    findings = []
    for pre in entries:
        if not (_is_preflight(pre) and _failed(pre)):
            continue
        how = _how(pre)
        origin = pre.request_header("Origin")
        for_origin = f" for origin {origin}" if origin else ""
        blocked = links.get(pre.index)
        if blocked is not None:
            findings.append(Finding(
                "error",
                f"CORS preflight {how}: {endpoint(blocked)} blocked",
                [Evidence.of(pre, "preflight"), Evidence.of(blocked, blocked.error or "")],
                "The server must answer OPTIONS on this URL with 2xx and "
                f"Access-Control-Allow-Origin/-Methods/-Headers{for_origin}; "
                "check its CORS config, or a gateway/WAF that rejects OPTIONS.",
            ))
        else:
            wanted = pre.request_header("Access-Control-Request-Method")
            findings.append(Finding(
                "warning",
                f"CORS preflight {how}: {endpoint(pre)}"
                + (f" (for {wanted})" if wanted else "")
                + ", blocked request not found in the HAR",
                [Evidence.of(pre, "preflight")],
                "The actual request was probably never sent. The server must answer "
                f"OPTIONS with 2xx and Access-Control-Allow-* headers{for_origin}.",
            ))
    return findings


def link_preflights(entries: list[Entry]) -> dict[int, Entry]:
    """Failed preflight index -> the status-0 request it blocked."""
    pairs = []
    for pre in entries:
        if not (_is_preflight(pre) and _failed(pre)):
            continue
        wanted = pre.request_header("Access-Control-Request-Method")
        for req in entries:
            if req.status != 0 or req.url != pre.url or req is pre:
                continue
            if wanted and req.method.upper() != wanted.strip().upper():
                continue
            if not wanted and req.method == "OPTIONS":
                continue
            gap = abs((req.started - pre.started).total_seconds() * 1000)
            if gap <= LINK_WINDOW_MS:
                pairs.append((gap, pre.index, req))
    # Closest first; each preflight and each request is linked at most once.
    links, used = {}, set()
    for gap, pre_index, req in sorted(pairs, key=lambda p: (p[0], p[1], p[2].index)):
        if pre_index in links or req.index in used:
            continue
        links[pre_index] = req
        used.add(req.index)
    return links


def blocked_indices(entries: list[Entry]) -> set[int]:
    """Entries already explained by a CORS finding (other detectors skip them)."""
    return {req.index for req in link_preflights(entries).values()}


def _is_preflight(e: Entry) -> bool:
    # Non-Chrome exports lack _initiator; the request header is the portable signal.
    return e.method == "OPTIONS" and (
        e.request_header("Access-Control-Request-Method") is not None
        or e.initiator_type == "preflight"
    )


def _failed(e: Entry) -> bool:
    return not 200 <= e.status < 300


def _how(pre: Entry) -> str:
    return "failed (no response)" if pre.status == 0 else f"rejected ({pre.status})"
