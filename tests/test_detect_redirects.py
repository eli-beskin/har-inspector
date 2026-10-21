"""Redirects detector on redirects.har. Expected values are read off the fixture by hand."""

from har_inspector.detectors import redirects


def _detect(load_fixture):
    return redirects.detect(load_fixture("redirects.har").entries)


def _chain(finding):
    return [(ev.index, ev.status, ev.note) for ev in finding.evidence]


def test_findings_overview(load_fixture):
    assert [(f.severity, f.title) for f in _detect(load_fixture)] == [
        ("warning", "Redirect chain of 4 hops starting at GET https://www.example.com/start"),
        ("error", "Redirect loop: https://shop.example.com/login requested again after 2 hops "
                  "(chain starts at GET https://shop.example.com/login)"),
        ("warning", "Redirect chain of 3 hops starting at GET http://news.example.com/"),
        ("info", "Server redirects HTTP to HTTPS: GET http://blog.example.com/post"),
        # cdn /a -> /b: 1 hop, nothing reported.
    ]


def test_relative_targets_and_location_fallback(load_fixture):
    # #0 "/step1"; #1 empty redirectURL, location "step2" (relative to /step1);
    # #2 absolute with #top fragment (dropped); #3 "/done". 301+302+302+307 = 4 hops.
    long_chain = _detect(load_fixture)[0]
    assert _chain(long_chain) == [
        (0, 301, ""), (1, 302, ""), (2, 302, ""), (3, 307, ""), (4, 200, "final"),
    ]


def test_loop_chain(load_fixture):
    # login(#5) -> account(#6) -> login(#7) -> account(#8) -> /login never fetched.
    loop = _detect(load_fixture)[1]
    assert _chain(loop) == [
        (5, 302, ""), (6, 302, ""), (7, 302, ""), (8, 302, "redirect target not in HAR"),
    ]


def test_internal_hsts_hop_is_labelled_not_counted(load_fixture):
    # #9 internal 307 (HSTS) + server 301/302/302 = 3 counted hops, not 4.
    # The http->https step is Chrome's, so no "server redirects HTTP" finding.
    news = _detect(load_fixture)[2]
    assert _chain(news) == [
        (9, 307, "Chrome-internal HSTS"),
        (10, 301, ""), (11, 302, ""), (12, 302, ""), (13, 200, "final"),
    ]


def test_server_https_upgrade(load_fixture):
    info = _detect(load_fixture)[3]
    assert [ev.index for ev in info.evidence] == [14, 15]


def test_target_resolution(load_fixture):
    entries = load_fixture("redirects.har").entries
    assert redirects.target(entries[1]) == "https://www.example.com/step2"
    assert redirects.target(entries[11]) == "https://news.example.com/en/home"
    assert redirects.target(entries[4]) is None  # 200
