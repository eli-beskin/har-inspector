"""Markdown report: targeted substring and structure checks, not full snapshots."""

import re
from dataclasses import replace
from pathlib import Path

import pytest

from har_inspector.analysis import analyze
from har_inspector.detectors import Evidence, Finding
from har_inspector.render_common import visible_evidence
from har_inspector.report_md import render

FIXTURES = sorted(p.name for p in (Path(__file__).parent / "fixtures").glob("*.har"))

# A cell separator is a "|" not escaped by a backslash.
_SEPARATOR = re.compile(r"(?<!\\)\|")


def _render(load_fixture, name, **kwargs):
    return render(analyze(load_fixture(name), **kwargs))


def _section(text, heading):
    """Body of one "## " section, up to the next one."""
    return text.split(f"## {heading}", 1)[1].split("\n## ", 1)[0]


def test_section_order_findings_first(load_fixture):
    text = _render(load_fixture, "cors.har")
    order = [
        "# HAR Inspector: cors.har", "## Findings", "## Summary", "## Failed requests",
        "## Top ", "## Chrome-internal entries",
    ]
    positions = [text.index(h) for h in order]
    assert positions == sorted(positions)


def test_header(load_fixture):
    # cors.har: creator name "WebInspector" + version "537.36" (parser joins them),
    # no "pages" list.
    text = _render(load_fixture, "cors.har")
    assert text.startswith(
        "# HAR Inspector: cors.har\n\nCreator: WebInspector 537.36, Pages: 0\n"
    )


def test_cors_finding_block(load_fixture):
    # cors.har #0 PUT /upload (status 0, net::ERR_FAILED) at 12:00:00.000 and its
    # preflight #1 OPTIONS /upload 403 at .001: one ERROR, preflight listed first.
    text = _render(load_fixture, "cors.har")
    assert (
        "**ERROR** CORS preflight rejected (403): PUT https://api.example.com/upload blocked\n"
        "\n"
        "| # | Method | Status | URL | Note |\n"
        "| --: | --- | --: | --- | --- |\n"
        "| 1 | OPTIONS | 403 | `https://api.example.com/upload` | preflight |\n"
        "| 0 | PUT | 0 | `https://api.example.com/upload` | net::ERR\\_FAILED |\n"
        "\n"
        "**Next step:** "
    ) in text


def test_severity_order(load_fixture):
    findings = _section(_render(load_fixture, "client_errors.har"), "Findings")
    # Severity lines only: "**Next step:**" is not all caps.
    labels = re.findall(r"^\*\*([A-Z]+)\*\* ", findings, re.MULTILINE)
    # 7 errors (CORS + 6 client codes), then 4 warnings; see test_analysis.
    assert labels == ["ERROR"] * 7 + ["WARNING"] * 4


def test_findings_none(load_fixture):
    # timings.har: all 200s, no _error, no redirects.
    text = _render(load_fixture, "timings.har")
    assert "## Findings\n\n*none*\n\n## Summary" in text


def test_summary_unknown_size(load_fixture):
    # 3048 B / 1024 = 2.98 -> "3.0 KB"
    text = _render(load_fixture, "sizes.har")
    assert "| Transferred | 3.0 KB (1 entry with unknown size not counted) |" in text


def test_failed_requests_table(load_fixture):
    # failures.har failures: GET /items 500 x3 (#0-#2; query and #top stripped),
    # GET lib.js status 0 x2 (#4, #5), then one each of POST /items 500,
    # lib.js 404, /me 401. Sorted by count desc, then status desc.
    # The generic ERR_HTTP_RESPONSE_CODE_FAILURE is dropped from details.
    text = _render(load_fixture, "failures.har")
    failed = _section(text, "Failed requests")
    rows = [l for l in failed.splitlines() if l.startswith("| ")][2:]
    assert rows == [
        "| 3 | 500 | `GET https://api.example.com/items` | Internal Server Error |",
        "| 2 | 0 | `GET https://cdn.example.com/lib.js` | "
        "net::ERR\\_BLOCKED\\_BY\\_CLIENT, net::ERR\\_CONNECTION\\_RESET |",
        "| 1 | 500 | `POST https://api.example.com/items` | Internal Server Error |",
        "| 1 | 404 | `GET https://cdn.example.com/lib.js` | Not Found |",
        "| 1 | 401 | `GET https://api.example.com/me` |  |",
    ]
    assert "ERR\\_HTTP\\_RESPONSE\\_CODE\\_FAILURE" not in failed
    # #4, #5 are status 0; 1xx is 0 and therefore hidden.
    assert "failed(0) 2" in _section(text, "Summary")
    assert "1xx" not in text


def test_slowest_breakdown(load_fixture):
    text = _render(load_fixture, "timings.har")
    slowest = _section(text, "Top ")
    # sw-cached.js and api/queued.
    assert slowest.count("breakdown unavailable") == 2
    assert "| wait (100%) |" in slowest
    # api/reused: blocked/dns/connect N/A, then send 1, wait 90, receive 9.
    assert "| - | - | - | 1 | 90 | 9 |" in slowest


def test_chrome_internal_only_in_its_section(load_fixture):
    # #0 is the HSTS 307 (empty server IP); #1 is the real request to https.
    text = _render(load_fixture, "chrome_internal_307.har")
    stats, internal = text.split("## Chrome-internal entries")
    assert "Chrome-internal excluded: 1" in stats
    assert "http://example.com/login" not in stats
    assert "| 307 | `GET http://example.com/login?next=%2F` | HSTS |" in internal


def _with_finding(load_fixture, finding):
    a = analyze(load_fixture("timings.har"))
    return render(replace(a, findings=[finding]))


def _evidence(n):
    return [Evidence(i, "GET", f"https://x.example.com/{i}", 0) for i in range(n)]


def test_evidence_cap_keeps_first_four_and_last(load_fixture):
    # 8 items, cap 5: #0..#3, "... and 3 more" (#4, #5, #6), then the last (#7).
    text = _with_finding(load_fixture, Finding("info", "T", _evidence(8), ""))
    assert (
        "x.example.com/3` |  |\n"
        "|  |  |  | *... and 3 more* |  |\n"
        "| 7 | GET |"
    ) in text
    assert "x.example.com/4" not in text and "x.example.com/6" not in text


def test_evidence_cap_never_hides_a_single_item(load_fixture):
    # 6 items = cap + 1: all shown, no "... and 1 more".
    text = _with_finding(load_fixture, Finding("info", "T", _evidence(6), ""))
    assert "more*" not in text
    assert all(f"x.example.com/{i}`" in text for i in range(6))


@pytest.mark.parametrize("n, shown", [
    (5, [0, 1, 2, 3, 4]),
    (6, [0, 1, 2, 3, 4, 5]),          # hidden would be 1: show all
    (7, [0, 1, 2, 3, None, 6]),       # hidden 2 (#4, #5)
    (8, [0, 1, 2, 3, None, 7]),       # hidden 3 (#4..#6)
])
def test_visible_evidence(n, shown):
    got = visible_evidence(_evidence(n))
    assert [None if e is None else e.index for e in got] == shown


def test_escaping(load_fixture):
    finding = Finding(
        "warning",
        "Odd *title* with _under_ and [link](x)",
        [Evidence(0, "GET", "https://x.example.com/a|b`c", 0, "note\nwith | pipe")],
        "# not a heading",
    )
    text = _with_finding(load_fixture, finding)
    assert "**WARNING** Odd \\*title\\* with \\_under\\_ and \\[link\\](x)\n" in text
    # One backtick inside -> a two-backtick fence; "|" escaped even in the code span.
    # The newline in the note becomes a visible "\n" (render_common.safe), whose
    # backslash is then Markdown-escaped: source "note\\nwith", rendered "note\nwith".
    assert "| ``https://x.example.com/a\\|b`c`` | note\\\\nwith \\| pipe |" in text
    assert "**Next step:** \\# not a heading" in text


def _tables(text):
    """Each run of consecutive "|" lines, as a list of lines."""
    tables, current = [], []
    for line in text.splitlines():
        if line.startswith("|"):
            current.append(line)
        elif current:
            tables.append(current)
            current = []
    if current:
        tables.append(current)
    return tables


@pytest.mark.parametrize("name", FIXTURES)
def test_table_shape(load_fixture, name):
    # Every row has as many cells as its header: an unescaped "|" or a newline in
    # a value would break this.
    text = _render(load_fixture, name)
    for table in _tables(text):
        widths = {len(_SEPARATOR.findall(line)) for line in table}
        assert len(widths) == 1, table
        assert re.fullmatch(r"\|( (---|--:) \|)+", table[1]), table[1]


def test_secrets_in_urls_masked(load_fixture):
    text = _render(load_fixture, "redact_userinfo.har")
    for secret in ("LoopPass77", "S3cr", "p+q", "sid=s1"):
        assert secret not in text
    # Free text is escaped after masking: the marker's brackets too.
    assert ("**ERROR** Redirect loop: https://gina:\\[REDACTED\\]@loop.example.com/a?"
            "sid=\\[REDACTED\\] requested again") in text
    assert "| 1 | 500 | `GET https://erin:[REDACTED]@api.example.com/v1` |  |" in text
    assert "`GET https://alice:[REDACTED]@files.example.com/report.csv?page=1`" in text
