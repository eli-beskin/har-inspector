"""Report text: targeted substring checks, not full snapshots."""

from dataclasses import replace

from har_inspector.analysis import analyze
from har_inspector.detectors import Evidence, Finding
from har_inspector.report import render


def _render(load_fixture, name, **kwargs):
    return render(analyze(load_fixture(name), **kwargs))


def test_breakdown_unavailable_and_na_phases(load_fixture):
    text = _render(load_fixture, "timings.har")
    # sw-cached.js and api/queued.
    assert text.count("breakdown unavailable") == 2
    assert "wait (100%)" in text
    # api/reused: blocked/dns/connect N/A, then send 1, wait 90, receive 9.
    assert "        -        -        -        1       90        9" in text


def test_chrome_internal_only_in_its_section(load_fixture):
    text = _render(load_fixture, "chrome_internal_307.har")
    stats, internal = text.split("CHROME-INTERNAL ENTRIES")
    assert "Chrome-internal excluded: 1" in stats
    assert "http://example.com/login" not in stats
    assert "307  GET http://example.com/login?next=%2F" in internal
    assert "reason: HSTS" in internal


def test_unknown_size_note(load_fixture):
    text = _render(load_fixture, "sizes.har")
    # 3048 B / 1024 = 2.98 -> "3.0 KB"
    assert "Transferred:   3.0 KB  (1 entry with unknown size not counted)" in text


def test_failed_status_zero_shows_errors(load_fixture):
    text = _render(load_fixture, "failures.har")
    assert "net::ERR_BLOCKED_BY_CLIENT, net::ERR_CONNECTION_RESET" in text
    assert "ERR_HTTP_RESPONSE_CODE_FAILURE" not in text
    assert "failed(0) 2" in text


# --- Findings ----------------------------------------------------------------

def test_findings_section_sits_after_summary(load_fixture):
    text = _render(load_fixture, "cors.har")
    assert text.index("SUMMARY") < text.index("FINDINGS") < text.index("FAILED REQUESTS")


def test_findings_none(load_fixture):
    # timings.har: all 200s, no _error, no redirects.
    assert "FINDINGS\n  none\n\nFAILED REQUESTS" in _render(load_fixture, "timings.har")


def test_finding_block_layout(load_fixture):
    text = _render(load_fixture, "cors.har")
    assert (
        "  ERROR    CORS preflight rejected (403): PUT https://api.example.com/upload blocked\n"
        "           #1    OPTIONS 403  https://api.example.com/upload  preflight\n"
        "           #0    PUT     0    https://api.example.com/upload  net::ERR_FAILED\n"
        "           Next step: "
    ) in text
    # Wrapping never splits a header name at its hyphens.
    assert "Access-Control-Allow-Origin/-Methods/-Headers" in text


def test_rendered_severity_order(load_fixture):
    text = _render(load_fixture, "client_errors.har")
    findings = text.split("FINDINGS\n")[1].split("FAILED REQUESTS")[0]
    # Title lines are indented by exactly two spaces; evidence lines by 11.
    labels = [
        line.split()[0] for line in findings.splitlines()
        if line.startswith("  ") and not line.startswith("   ")
    ]
    # 7 errors (CORS + 6 client codes), then 4 warnings; see test_analysis.
    assert labels == ["ERROR"] * 7 + ["WARNING"] * 4


def _with_evidence(load_fixture, n):
    a = analyze(load_fixture("timings.har"))
    evidence = [Evidence(i, "GET", f"https://x.example.com/{i}", 0) for i in range(n)]
    return render(replace(a, findings=[Finding("info", "T", evidence, "")]))


def test_evidence_cap_keeps_first_four_and_last(load_fixture):
    # 8 items, cap 5: #0..#3, "... and 3 more" (#4, #5, #6), then the last (#7).
    text = _with_evidence(load_fixture, 8)
    assert "x.example.com/3\n           ... and 3 more\n           #7 " in text
    assert "x.example.com/4" not in text and "x.example.com/6" not in text


def test_evidence_cap_never_hides_a_single_item(load_fixture):
    # 6 items = cap + 1: all shown, no "... and 1 more".
    text = _with_evidence(load_fixture, 6)
    assert "more" not in text
    assert all(f"x.example.com/{i}" in text for i in range(6))
