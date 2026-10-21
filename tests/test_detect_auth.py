"""Auth detector. Expected values are read off the fixtures by hand."""

from har_inspector.detectors import auth


def _notes(finding):
    return [(ev.index, ev.note) for ev in finding.evidence]


def test_basic_inferred_from_headers_size(load_fixture):
    group, *_ = auth.detect(load_fixture("auth_basic.har").entries)
    # Lowercase www-authenticate "Basic realm=..." -> scheme Basic. Query dropped.
    assert group.severity == "error"
    assert group.title == (
        "401 on GET http://intranet.example.com/admin (3 requests, scheme Basic) "
        "— credentials likely sent and rejected"
    )
    assert _notes(group) == [
        # No earlier identical request -> nothing to compare with.
        (0, "credentials: no evidence"),
        # 527 - 500 = 27 B more than #0 (Authorization stripped from the export).
        (1, "credentials: likely sent (request headers +27 B vs #0)"),
        # Compared with the most recent identical request #1: 500 < 527.
        (2, "credentials: no evidence"),
    ]


def test_basic_over_plain_http(load_fixture):
    _, *basic = auth.detect(load_fixture("auth_basic.har").entries)
    assert [(f.severity, f.title, [ev.index for ev in f.evidence]) for f in basic] == [
        # Offered by the server (www-authenticate: Basic) on http://.
        ("warning", "Basic auth over plain HTTP: GET http://intranet.example.com/admin "
                    "— password travels unencrypted", [0, 1, 2]),
        # Sent by the client (lowercase authorization: Basic ...) even though 200.
        ("warning", "Basic auth over plain HTTP: GET http://intranet.example.com/report "
                    "— password travels unencrypted", [3]),
    ]


def test_bearer_and_no_evidence(load_fixture):
    findings = auth.detect(load_fixture("auth_bearer.har").entries)
    me, admin = findings  # https only, so no Basic-over-HTTP warning
    # #0 has an Authorization header; #4 has none and no earlier identical
    # request with a known headersSize (#0 is -1) -> no evidence.
    assert me.severity == "error"
    assert me.title == (
        "401 on GET https://api.example.com/me (2 requests, scheme Bearer) "
        "— credentials sent and rejected"
    )
    assert _notes(me) == [
        (0, "credentials: sent (Authorization header)"),
        (4, "credentials: no evidence"),
    ]
    # #1 and #3: no WWW-Authenticate, headersSize -1. The OPTIONS 403 (#2) is a
    # preflight, left to the CORS detector.
    assert admin.severity == "warning"
    assert admin.title == (
        "403 on GET https://api.example.com/admin (2 requests, scheme none given) "
        "— no evidence credentials were sent (export may strip Authorization)"
    )
    assert [ev.index for ev in admin.evidence] == [1, 3]


def test_never_claims_not_sent(load_fixture):
    for name in ("auth_basic.har", "auth_bearer.har"):
        for f in auth.detect(load_fixture(name).entries):
            assert "not sent" not in f.title
            assert all("not sent" not in ev.note for ev in f.evidence)
