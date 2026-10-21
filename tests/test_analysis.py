"""Analysis rules. Expected values are computed by hand from the fixtures."""

from datetime import datetime, timezone

import pytest

from har_inspector.analysis import analyze


def _utc(*args):
    return datetime(*args, tzinfo=timezone.utc)


def _by_url(analysis):
    return {s.entry.url: s for s in analysis.slowest}


# --- Chrome-internal entries -------------------------------------------------

def test_chrome_internal_307_excluded_everywhere(load_fixture):
    a = analyze(load_fixture("chrome_internal_307.har"))
    s = a.summary
    assert s.requests == 1
    assert s.internal == 1
    assert s.by_class["3xx"] == 0
    assert s.by_class["2xx"] == 1
    assert s.transferred_bytes == 2048
    # The internal entry starts at .000; the span must start at the real one (.002)
    # and end at .002 + 210.5 ms = .2125.
    assert s.start == _utc(2026, 10, 20, 10, 0, 0, 2000)
    assert s.end == _utc(2026, 10, 20, 10, 0, 0, 212500)
    assert s.span_seconds == pytest.approx(0.2105)
    assert a.failed == []
    assert [x.entry.url for x in a.slowest] == ["https://example.com/login?next=%2F"]
    assert [e.index for e in a.internal] == [0]


def test_chrome_internal_header_match_is_case_insensitive(load_fixture):
    # Entry 0: 307 with lowercase non-authoritative-reason -> internal.
    # Entry 2: a real server 307 without that header -> counted as 3xx.
    a = analyze(load_fixture("chrome_internal_lowercase.har"))
    assert a.summary.internal == 1
    assert a.summary.requests == 2
    assert a.summary.by_class["3xx"] == 1
    assert [e.url for e in a.internal] == ["http://shop.example.com/"]


def test_real_redirect_is_not_internal(load_fixture):
    # failures.har has a real 302 (server IP, no Non-Authoritative-Reason).
    a = analyze(load_fixture("failures.har"))
    assert a.internal == []
    assert a.summary.by_class["3xx"] == 1


# --- Slowest / breakdown -----------------------------------------------------

@pytest.mark.parametrize(
    "url, dominant, share",
    [
        # No IP, all 500 ms blocked: never reached the network.
        ("https://app.example.com/sw-cached.js", None, 1.0),
        # No IP, 300 of 300.4 ms blocked (0.4 receive is float noise).
        ("https://app.example.com/api/queued", None, 300 / 300.4),
        # All time in wait but the IP is present: a real diagnosis.
        ("https://app.example.com/api/report", "wait", 1.0),
        # No IP but split: 140 / (50 + 140 + 10).
        ("https://app.example.com/api/split", "wait", 0.70),
        # N/A phases ignored: 90 / (1 + 90 + 9).
        ("https://app.example.com/api/reused", "wait", 0.90),
    ],
)
def test_breakdown_rule(load_fixture, url, dominant, share):
    s = _by_url(analyze(load_fixture("timings.har")))[url]
    assert s.dominant == dominant
    assert s.dominant_share == pytest.approx(share)


def test_breakdown_boundary_95_percent(load_fixture):
    slow = _by_url(analyze(load_fixture("breakdown_boundary.har")))
    # 95 / (95 + 5) = 0.95 exactly; the rule is ">= 0.95" -> unavailable.
    exact = slow["https://app.example.com/exactly-95"]
    assert exact.dominant is None
    assert exact.dominant_share == pytest.approx(0.95)
    # 94.9 / (94.9 + 5.1) = 0.949 < 0.95 -> shown; the largest phase is blocked.
    below = slow["https://app.example.com/below-95"]
    assert below.dominant == "blocked"
    assert below.dominant_share == pytest.approx(0.949)


def test_breakdown_without_underscore_fields(load_fixture):
    slow = _by_url(analyze(load_fixture("no_underscore_fields.har")))
    # 404 has no IP, but 75 / 80 = 0.9375 < 0.95 -> real diagnosis.
    s404 = slow["https://example.org/missing.js?v=3"]
    assert (s404.dominant, s404.dominant_share) == ("wait", pytest.approx(0.9375))
    # Status 0 with all phases 0 or N/A: nothing to attribute.
    s0 = slow["https://tracker.example.net/collect"]
    assert (s0.dominant, s0.dominant_share) == (None, 0.0)


def test_slowest_order_and_top(load_fixture):
    a = analyze(load_fixture("timings.har"), top=3)
    # times: 500, 300.4, 400, 200, 100 -> top 3 = 500, 400, 300.4
    assert [s.entry.url for s in a.slowest] == [
        "https://app.example.com/sw-cached.js",
        "https://app.example.com/api/report",
        "https://app.example.com/api/queued",
    ]


# --- Summary -----------------------------------------------------------------

def test_summary_without_underscore_fields(load_fixture):
    s = analyze(load_fixture("no_underscore_fields.har")).summary
    assert s.requests == 3
    assert s.transferred_bytes == 1150 + 350
    assert s.unknown_size == 1
    assert s.by_class == {"1xx": 0, "2xx": 1, "3xx": 0, "4xx": 1, "5xx": 0, "failed": 1}
    # Ends: .000+120, .200+80, .300+0 -> last finish .300.
    assert s.span_seconds == pytest.approx(0.300)


def test_summary_sizes(load_fixture):
    s = analyze(load_fixture("sizes.har")).summary
    assert s.transferred_bytes == 2048 + 1000 + 0
    assert s.unknown_size == 1


# --- Failed requests ---------------------------------------------------------

def test_failed_grouping(load_fixture):
    a = analyze(load_fixture("failures.har"))
    assert a.summary.requests == 10
    assert a.summary.by_class == {"1xx": 0, "2xx": 1, "3xx": 1, "4xx": 2, "5xx": 4, "failed": 2}
    groups = [(g.status, g.endpoint, g.count, g.errors, g.status_text) for g in a.failed]
    # Sort: count desc, then status desc, then endpoint asc. The status tie-break
    # (5xx before 4xx before status 0) was NOT in the original spec; it is pinned
    # here as current behavior and documented in CLAUDE.md.
    assert groups == [
        # Query string and fragment are dropped; the generic
        # ERR_HTTP_RESPONSE_CODE_FAILURE is filtered out.
        (500, "GET https://api.example.com/items", 3, [], "Internal Server Error"),
        # Status 0 grouped like any status; distinct errors, sorted.
        (0, "GET https://cdn.example.com/lib.js", 2,
         ["net::ERR_BLOCKED_BY_CLIENT", "net::ERR_CONNECTION_RESET"], ""),
        # count 1 each: 500 > 404 > 401. Method is part of the endpoint.
        (500, "POST https://api.example.com/items", 1, [], "Internal Server Error"),
        # Same URL as the status-0 group but a different status: separate group.
        (404, "GET https://cdn.example.com/lib.js", 1, [], "Not Found"),
        (401, "GET https://api.example.com/me", 1, [], ""),
    ]


# --- Findings ----------------------------------------------------------------

def test_findings_sorted_by_severity_then_detector_then_entry(load_fixture):
    a = analyze(load_fixture("client_errors.har"))
    assert [(f.severity, f.evidence[0].index) for f in a.findings] == [
        # Errors: CORS detector first (preflight #13 -> PUT #12, min index 12),
        # then client codes by first entry: 3, 4, 5, 6, 7, 8.
        ("error", 13),
        ("error", 3), ("error", 4), ("error", 5), ("error", 6), ("error", 7), ("error", 8),
        # Warnings: BLOCKED_BY_CLIENT #0, ORB #2, ERR_FOO_BAR #10, ERR_ABORTED #15.
        ("warning", 0), ("warning", 2), ("warning", 10), ("warning", 15),
    ]


def test_findings_do_not_change_other_sections(load_fixture):
    # The existing stats are computed exactly as before, findings or not.
    a = analyze(load_fixture("cors.har"))
    # 12 entries, none Chrome-internal. Status 0: #0 #2 #3 #7 #8 #10 = 6;
    # 2xx: #4 #5 = 2; 4xx: #1 #9 #11 = 3; 5xx: #6 = 1.
    assert a.summary.requests == 12
    assert a.summary.by_class == {"1xx": 0, "2xx": 2, "3xx": 0, "4xx": 3, "5xx": 1, "failed": 6}
