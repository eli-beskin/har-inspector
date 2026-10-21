"""Parser: raw HAR -> model. Expected values are read off the fixtures by hand."""

import pytest

from har_inspector.model import Timings
from har_inspector.parser import HarError, load


def test_negative_timings_become_not_applicable(load_fixture):
    # timings.har entry 4: blocked -0.8 (clock rounding), dns/connect/ssl -1.
    e = load_fixture("timings.har").entries[4]
    assert e.timings == Timings(
        blocked=None, dns=None, connect=None, ssl=None, send=1.0, wait=90.0, receive=9.0
    )
    # Only the non-negative phases make up the total: 1 + 90 + 9 = 100 = time.
    measured = [v for v in e.timings.phases().values() if v is not None]
    assert sum(measured) == pytest.approx(e.time_ms) == pytest.approx(100.0)


def test_ssl_is_inside_connect_and_not_a_report_phase(load_fixture):
    # chrome_internal_307.har entry 1: ssl 40 is part of connect 75.
    e = load_fixture("chrome_internal_307.har").entries[1]
    assert e.timings.ssl == 40.0
    assert e.timings.connect == 75.0
    assert "ssl" not in e.timings.phases()
    # 1.5 + 12 + 75 + 0.5 + 110 + 11.5 = 210.5 = time; adding ssl would give 250.5.
    assert sum(e.timings.phases().values()) == pytest.approx(210.5)
    assert e.time_ms == pytest.approx(210.5)


def test_transfer_size_prefers_chrome_field_then_falls_back(load_fixture):
    sizes = [e.transfer_size for e in load_fixture("sizes.har").entries]
    assert sizes == [
        2048,  # _transferSize wins over headersSize+bodySize (100+500)
        1000,  # no _transferSize: 120 + 880
        0,     # _transferSize 0 is a real value (cache), not "missing"
        None,  # no _transferSize and headersSize -1: unknown
    ]


def test_missing_underscore_fields(load_fixture):
    # Firefox export: no _transferSize, _error, _resourceType; 3rd entry has no IP.
    entries = load_fixture("no_underscore_fields.har").entries
    assert [e.resource_type for e in entries] == [None, None, None]
    assert [e.error for e in entries] == [None, None, None]
    assert [e.transfer_size for e in entries] == [250 + 900, 200 + 150, None]
    assert [e.server_ip for e in entries] == ["93.184.215.14", "", ""]


def test_chrome_underscore_fields_are_read(load_fixture):
    e = load_fixture("chrome_internal_307.har").entries[1]
    assert e.resource_type == "document"
    assert e.transfer_size == 2048


@pytest.mark.parametrize(
    "content, message",
    [
        ("{not json", "not valid JSON"),
        ('{"foo": 1}', "missing log.entries"),
        ('{"log": {"entries": "x"}}', "missing log.entries"),
        ('{"log": {"entries": [{}]}}', "entry #0 is malformed"),
    ],
)
def test_bad_input_raises_har_error(tmp_path, content, message):
    path = tmp_path / "bad.har"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(HarError, match=message):
        load(str(path))


def test_missing_file_raises_har_error(tmp_path):
    with pytest.raises(HarError, match="file not found"):
        load(str(tmp_path / "nope.har"))


def test_request_fields(load_fixture):
    cors_entries = load_fixture("cors.har").entries
    pre = cors_entries[1]
    # Lowercase HTTP/2 name, looked up with canonical case.
    assert pre.request_header("Access-Control-Request-Method") == "PUT"
    assert pre.request_header(":method") == "OPTIONS"
    assert pre.initiator_type == "preflight"
    assert pre.request_headers_size is None  # -1 in the HAR
    assert cors_entries[0].initiator_type is None  # no _initiator

    basic = load_fixture("auth_basic.har").entries
    assert [e.request_headers_size for e in basic] == [500, 527, 500, 540]

    redirects = load_fixture("redirects.har").entries
    assert redirects[0].redirect_url == "/step1"
    assert redirects[1].redirect_url == ""  # only the location header has it
    assert redirects[1].header("Location") == "step2"


def test_request_fields_default_when_missing(load_fixture):
    # failures.har predates these fields: no headersSize, redirectURL, _initiator.
    e = load_fixture("failures.har").entries[0]
    assert (e.request_headers_size, e.redirect_url, e.initiator_type) == (None, "", None)
