"""Redirects: chains of 3+ hops, loops, and server-side HTTP->HTTPS hops."""

from urllib.parse import urldefrag, urljoin, urlsplit

from har_inspector.classify import endpoint, is_chrome_internal
from har_inspector.detectors.finding import Evidence, Finding
from har_inspector.model import Entry

LONG_CHAIN_HOPS = 3


def detect(entries: list[Entry]) -> list[Finding]:
    successor = _link(entries)
    claimed = {e.index for e in successor.values()}
    findings = []
    for e in entries:
        if e.index in successor and e.index not in claimed:
            findings.extend(_chain_findings(_follow(e, successor)))
    return findings


def target(e: Entry) -> str | None:
    """Absolute redirect target, or None if this entry is not a redirect."""
    if not 300 <= e.status < 400:
        return None
    # redirectURL and Location are often relative (errors.har: /relative-redirect/4).
    raw = e.redirect_url or e.header("Location")
    if not raw:
        return None
    # Request URLs in a HAR never carry a fragment, so drop it to match.
    return urldefrag(urljoin(e.url, raw)).url


def _link(entries: list[Entry]) -> dict[int, Entry]:
    """Redirect entry index -> the entry that requested its target."""
    successor: dict[int, Entry] = {}
    taken: set[int] = set()
    for e in entries:
        t = target(e)
        if t is None:
            continue
        nxt = next(
            (n for n in entries
             if n.index > e.index and n.started >= e.started
             and n.url == t and n.index not in taken),
            None,
        )
        if nxt is not None:
            successor[e.index] = nxt
            taken.add(nxt.index)
    return successor


def _follow(start: Entry, successor: dict[int, Entry]) -> list[Entry]:
    # Terminates: every successor has a higher index than its predecessor.
    chain = [start]
    while chain[-1].index in successor:
        chain.append(successor[chain[-1].index])
    return chain


def _chain_findings(chain: list[Entry]) -> list[Finding]:
    findings = []
    # Chrome-internal hops (HSTS 307) cost no round trip: labelled, not counted.
    hops = sum(1 for e in chain if 300 <= e.status < 400 and not is_chrome_internal(e))
    evidence = [Evidence.of(e, _note(e, i == len(chain) - 1)) for i, e in enumerate(chain)]
    start = endpoint(chain[0])

    seen: dict[str, int] = {}
    repeat_at = None
    for i, e in enumerate(chain):
        if e.url in seen:
            repeat_at = i
            break
        seen[e.url] = i
    if repeat_at is not None:
        findings.append(Finding(
            "error",
            f"Redirect loop: {chain[repeat_at].url} requested again after "
            f"{repeat_at - seen[chain[repeat_at].url]} hops (chain starts at {start})",
            evidence,
            "The server keeps redirecting back, often a session cookie that is not "
            "set/sent or conflicting HTTP/HTTPS or www rules: check the redirect rules "
            "and the Set-Cookie on these responses.",
        ))
    elif hops >= LONG_CHAIN_HOPS:
        findings.append(Finding(
            "warning",
            f"Redirect chain of {hops} hops starting at {start}",
            evidence,
            "Each hop is a full round trip: link to the final URL directly, or "
            "collapse the server rules that chain these redirects.",
        ))

    for e, nxt in zip(chain, chain[1:]):
        if _is_https_upgrade(e, nxt):
            findings.append(Finding(
                "info",
                f"Server redirects HTTP to HTTPS: {endpoint(e)}",
                [Evidence.of(e), Evidence.of(nxt)],
                "Use the https:// URL in links and bookmarks; HSTS (with preload) "
                "lets the browser skip this round trip.",
            ))
            break  # one per chain is enough
    return findings


def _is_https_upgrade(e: Entry, nxt: Entry) -> bool:
    a, b = urlsplit(e.url), urlsplit(nxt.url)
    return (
        not is_chrome_internal(e)
        and a.scheme == "http" and b.scheme == "https"
        and a.hostname == b.hostname
    )


def _note(e: Entry, last: bool) -> str:
    if is_chrome_internal(e):
        reason = e.header("Non-Authoritative-Reason") or ""
        return f"Chrome-internal {reason}".strip()
    if not last:
        return ""
    return "redirect target not in HAR" if target(e) else "final"
