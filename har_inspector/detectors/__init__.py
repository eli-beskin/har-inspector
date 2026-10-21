"""Detectors: each module turns entries into diagnostic findings."""

from har_inspector.detectors import auth, client_errors, cors, redirects
from har_inspector.detectors.finding import SEVERITIES, Evidence, Finding
from har_inspector.model import Entry

__all__ = ["Evidence", "Finding", "SEVERITIES", "run_all"]

# Fixed order; it is also the tie-break between findings of equal severity.
DETECTORS = (cors.detect, auth.detect, redirects.detect, client_errors.detect)


def run_all(entries: list[Entry]) -> list[Finding]:
    """Findings from all detectors, most severe first.

    Detectors get every entry, Chrome-internal ones included, and filter
    for themselves (redirect chains need the internal HSTS hops).
    """
    keyed = []
    for order, detect in enumerate(DETECTORS):
        for f in detect(entries):
            first = min((ev.index for ev in f.evidence), default=-1)
            keyed.append(((SEVERITIES.index(f.severity), order, first), f))
    # Python's sort is stable, so equal keys keep the detector's own order.
    return [f for _, f in sorted(keyed, key=lambda kf: kf[0])]
