"""Client-side failures on client_errors.har. Expected values are read off the fixture by hand."""

from har_inspector.detectors import client_errors


def test_codes_mapped_grouped_and_filtered(load_fixture):
    findings = client_errors.detect(load_fixture("client_errors.har").entries)
    got = [(f.severity, f.title, [ev.index for ev in f.evidence]) for f in findings]
    assert got == [
        # Two entries, one finding.
        ("warning", "net::ERR_BLOCKED_BY_CLIENT (2 requests): blocked by an ad blocker "
                    "or browser extension", [0, 1]),
        # Mapped code with a non-zero status (204), as in real exports.
        ("warning", "net::ERR_BLOCKED_BY_ORB (1 request): browser blocked a cross-origin "
                    "response (Opaque Response Blocking)", [2]),
        ("error", "net::ERR_NETWORK_ACCESS_DENIED (1 request): network access denied by a "
                  "firewall, antivirus or OS policy", [3]),
        ("error", "net::ERR_NAME_NOT_RESOLVED (1 request): DNS lookup failed "
                  "(host name not found)", [4]),
        ("error", "net::ERR_CONNECTION_REFUSED (1 request): server refused the connection "
                  "(nothing listening, or blocked)", [5]),
        ("error", "net::ERR_CONNECTION_RESET (1 request): connection reset (server, proxy "
                  "or firewall dropped it)", [6]),
        ("error", "net::ERR_CONNECTION_TIMED_OUT (1 request): connection timed out "
                  "(no answer from the server)", [7]),
        # Any ERR_CERT_* matches by prefix.
        ("error", "net::ERR_CERT_DATE_INVALID (1 request): TLS certificate rejected", [8]),
        # Unknown code with status 0: raw code, no guessed cause.
        ("warning", "net::ERR_FOO_BAR (1 request): no known mapping", [10]),
        # ERR_ABORTED is unmapped: shown raw only when status is 0 (#15), not on
        # the 200 beacon (#9).
        ("warning", "net::ERR_ABORTED (1 request): no known mapping", [15]),
    ]
    # Also skipped: #11 (generic ERR_HTTP_RESPONSE_CODE_FAILURE on a 404),
    # #12 (ERR_FAILED explained by the CORS preflight #13), #14 (no _error).


def test_unknown_code_hint_does_not_guess(load_fixture):
    findings = client_errors.detect(load_fixture("client_errors.har").entries)
    foo = next(f for f in findings if "ERR_FOO_BAR" in f.title)
    assert foo.next_step == client_errors._UNKNOWN_HINT
    assert foo.evidence[0].note == "net::ERR_FOO_BAR"


def test_skips_every_entry_a_cors_finding_reports(load_fixture):
    # cors.har (read off by hand): net::ERR_FAILED on #0, #2, #3, #7, #8, #10.
    # CORS reports #0/#1, #2/#3, #9/#10 and the orphan preflight #6, so the failed
    # preflight #2 (status 0, its own ERR_FAILED) must not show up here again.
    # Left: #7 (PATCH 2000 ms after #6, outside the 1000 ms window) and
    # #8 (GET, but preflight #1 asked for PUT).
    findings = client_errors.detect(load_fixture("cors.har").entries)
    got = [(f.title, [ev.index for ev in f.evidence]) for f in findings]
    assert got == [("net::ERR_FAILED (2 requests): no known mapping", [7, 8])]
