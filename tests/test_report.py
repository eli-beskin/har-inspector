"""Report text: targeted substring checks, not full snapshots."""

from har_inspector.analysis import analyze
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
