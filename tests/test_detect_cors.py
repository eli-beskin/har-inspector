"""CORS detector on cors.har. Expected values are read off the fixture by hand."""

from har_inspector.detectors import cors


def _summary(findings):
    return [(f.severity, f.title, [ev.index for ev in f.evidence]) for f in findings]


def test_failed_preflights_are_linked_or_reported_alone(load_fixture):
    entries = load_fixture("cors.har").entries
    assert _summary(cors.detect(entries)) == [
        # #1 OPTIONS 403 (ACRM PUT, lowercase header) at .001; the blocked PUT #0
        # is logged 1 ms BEFORE it, as in real Chrome exports: gap 1 ms <= 1000.
        ("error", "CORS preflight rejected (403): PUT https://api.example.com/upload blocked",
         [1, 0]),
        # #2 OPTIONS status 0 at 1.000 -> POST #3 status 0 at 1.050: gap 50 ms.
        ("error",
         "CORS preflight failed (no response): POST https://api.example.com/items blocked",
         [2, 3]),
        # #6 OPTIONS 500 at 3.000; PATCH #7 status 0 is at 5.000: gap 2000 > 1000.
        ("warning",
         "CORS preflight rejected (500): OPTIONS https://api.example.com/orphan (for PATCH), "
         "blocked request not found in the HAR",
         [6]),
        # #9: no ACRM header, recognized by _initiator.type; POST #10 at +200 ms.
        ("error", "CORS preflight rejected (403): POST https://api.example.com/legacy blocked",
         [9, 10]),
    ]
    # Not reported: #4 preflight 204 (OK); #11 OPTIONS 405 without ACRM or
    # _initiator is not a preflight.


def test_link_respects_requested_method(load_fixture):
    entries = load_fixture("cors.har").entries
    links = cors.link_preflights(entries)
    # #8 GET /upload is status 0 and 9 ms from preflight #1, but #1 asked for PUT.
    assert links[1].index == 0
    assert cors.blocked_indices(entries) == {0, 3, 10}


def test_next_step_names_origin(load_fixture):
    first = cors.detect(load_fixture("cors.har").entries)[0]
    assert "for origin https://app.example.com" in first.next_step
    assert first.evidence[1].note == "net::ERR_FAILED"
