"""Redaction of URL userinfo (redact_userinfo.har) and of body formats beyond
JSON/urlencoded: multipart, text/plain, untyped, WebSocket frames (redact_bodies.har)."""

import json
from collections import Counter
from datetime import datetime, timezone

import pytest

from har_inspector.analysis import analyze
from har_inspector.parser import load, read_har_json
from har_inspector.redact import summary
from har_inspector.redact.scrub import NotScanned, redact
from har_inspector.report import render

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
R = "[REDACTED]"
U = "%5BREDACTED%5D"  # userinfo marker: "[" in the authority would break urlsplit


def _redact(fixture_path, name):
    return redact(read_har_json(fixture_path(name)), NOW)


def _headers(message):
    return [h["value"] for h in message["headers"]]


# -- URL userinfo ------------------------------------------------------------


@pytest.fixture
def userinfo(fixture_path):
    return _redact(fixture_path, "redact_userinfo.har")


def test_userinfo_in_urls_and_headers(userinfo):
    out, _ = userinfo
    e = out["log"]["entries"]
    # Username, host and non-secret params are kept.
    assert e[0]["request"]["url"] == f"https://alice:{U}@files.example.com/report.csv?page=1"
    assert _headers(e[0]["request"]) == [f"https://bob:{U}@intranet.example.com/home?tab=2"]
    carol = f"https://carol:{U}@app.example.com/next#token={R}"
    assert _headers(e[0]["response"]) == [carol]
    assert e[0]["response"]["redirectURL"] == carol
    # "+" is literal in userinfo; short passwords are redacted too (found by position).
    assert e[1]["request"]["url"] == f"https://erin:{U}@api.example.com/v1?x=1"
    loop_a = f"https://gina:{U}@loop.example.com/a?sid={R}"
    assert e[2]["request"]["url"] == e[4]["request"]["url"] == loop_a
    assert e[3]["response"]["redirectURL"] == loop_a


def test_userinfo_in_initiator_and_page_title(userinfo):
    out, _ = userinfo
    init = out["log"]["entries"][0]["_initiator"]
    assert init["url"] == f"https://cdn.example.com/a.js?token={R}"
    assert init["stack"]["callFrames"][0]["url"] == (
        f"https://dave:{U}@cdn.example.com/b.js?sig={R}"
    )
    assert init["stack"]["parent"]["callFrames"][0]["url"] == (
        f"https://cdn.example.com/c.js?key={R}"
    )
    assert out["log"]["pages"][0]["title"] == f"https://frank:{U}@portal.example.com/?code={R}"


def test_userinfo_echo_and_non_matches_in_body(userinfo):
    out, _ = userinfo
    # The decoded password (%40 -> @) echoed in the body goes by the value scrub;
    # "mailto://x@" has no password and "https://u:@" an empty one: kept.
    assert out["log"]["entries"][0]["response"]["content"]["text"] == (
        f"Downloaded with {R}; see mailto://x@y.example and https://u:@h.example/"
    )
    text = json.dumps(out)
    for secret in ("S3cr", "LoopPass77", "pw1", "pw2", "pw4", "pw6", "p+q"):
        assert secret not in text


def test_userinfo_stats(userinfo):
    _, stats = userinfo
    # request.url #0..#4 = 5, redirectURL #0 #2 #3 = 3 -> url 8;
    # Referer #0 + Location #0 #2 #3 -> header 4; one callFrame; one page title.
    assert stats.userinfo == Counter({"url": 8, "header": 4, "initiator": 1, "page title": 1})
    # sid: url #2 #4, redirectURL #3, Location #3 = 4; token: #0 redirectURL and
    # Location fragments + _initiator.url = 3; sig, key (callFrames), code (title).
    assert stats.url_params == Counter({"sid": 4, "token": 3, "sig": 1, "key": 1, "code": 1})
    # Only the body echo of "S3cr@tPass99" is left for pass 2.
    assert stats.scrub == Counter({"body": 1})
    # S3cr%40tPass99, S3cr@tPass99, LoopPass77 (8+ chars) + pw1 pw2 pw4 pw6 p+q
    # abc abc123 s1 zz k9 xyz = 3 + 11 = 14
    assert (stats.secrets, stats.global_secrets) == (14, 3)


def test_redacted_userinfo_file_analyzes_and_reports(userinfo, tmp_path, fixture_path):
    out, _ = userinfo
    path = tmp_path / "out.har"
    path.write_text(json.dumps(out), encoding="utf-8")
    # urlsplit() runs on every URL in the detectors: this would raise with "[".
    report = render(analyze(load(str(path)), top=10))
    assert "https://alice:[REDACTED]@files.example.com/report.csv?page=1" in report
    # Same report as for the original file: both are masked the same way.
    assert report.replace("out.har", "redact_userinfo.har") == render(
        analyze(load(fixture_path("redact_userinfo.har")), top=10)
    )


# -- bodies ------------------------------------------------------------------


@pytest.fixture
def bodies(fixture_path):
    return _redact(fixture_path, "redact_bodies.har")


def test_multipart(bodies):
    out, _ = bodies
    post = out["log"]["entries"][0]["request"]["postData"]
    # Structure and CRLFs kept; the secret part and the JSON part's token redacted;
    # filename="password.txt" is not the part's name.
    assert post["text"] == "\r\n".join([
        "--XyZ", 'Content-Disposition: form-data; name="user"', "", "alice",
        "--XyZ", 'Content-Disposition: form-data; name="password"', "", R,
        "--XyZ", 'Content-Disposition: form-data; name="meta"',
        "Content-Type: application/json", "", f'{{"token":"{R}","n":1}}',
        "--XyZ", 'Content-Disposition: form-data; name="file"; filename="password.txt"',
        "Content-Type: text/plain", "", "hello",
        "--XyZ--", "",
    ])
    assert post["params"] == [
        {"name": "user", "value": "alice"},
        {"name": "password", "value": R},
        {"name": "file", "fileName": "password.txt", "contentType": "text/plain"},
    ]
    # MultiPass-123 is 13 chars: its echo in the response is scrubbed by value.
    assert out["log"]["entries"][0]["response"]["content"]["text"] == f"Uploaded by alice ({R})"


def test_multipart_lf_without_boundary_param(bodies):
    out, _ = bodies
    # Boundary taken from the first line; unquoted name; LF line ends kept.
    assert out["log"]["entries"][1]["request"]["postData"]["text"] == (
        f"--b1\nContent-Disposition: form-data; name=pin_otp\n\n{R}\n--b1--\n"
    )


def test_text_plain_and_untyped_bodies(bodies):
    out, _ = bodies
    e = out["log"]["entries"]
    assert e[3]["request"]["postData"]["text"] == f"event=click&session_id={R}&x="
    assert e[4]["request"]["postData"]["text"] == f'{{"jwt":"{R}","ok":true}}'
    # Not k=v&k=v (has spaces): left alone.
    assert e[4]["response"]["content"]["text"] == "hello world a=b"


def test_websocket_frames(bodies):
    out, _ = bodies
    frames = [m["data"] for m in out["log"]["entries"][5]["_webSocketMessages"]]
    assert frames == [
        f'{{"type":"auth","authToken":"{R}"}}',
        f'42["login",{{"password":"{R}"}}]',  # Socket.IO prefix kept
        "plain text frame",
        "AAEC",  # binary (opcode 2): reported as NOT SCANNED
    ]


def test_new_secret_names(bodies):
    out, _ = bodies
    e = out["log"]["entries"][6]
    assert e["request"]["headers"] == [{"name": "Cf-Access-Jwt-Assertion", "value": R}]
    # A CORS flag, not a credential.
    assert e["response"]["headers"] == [
        {"name": "Access-Control-Allow-Credentials", "value": "true"}
    ]
    # token_endpoint holds a URL: kept.
    assert e["request"]["postData"]["text"] == (
        f"client_assertion={R}&code_verifier={R}"
        "&token_endpoint=https%3A%2F%2Fidp.example.com%2Ftoken"
    )
    assert json.loads(e["response"]["content"]["text"]) == {
        "authorization_endpoint": "https://idp.example.com/auth", "SAMLResponse": R,
    }


def test_bodies_stats(bodies):
    _, stats = bodies
    assert stats.post_text == Counter({
        "password": 1, "token": 1,  # #0 multipart: part, JSON part
        "pin_otp": 1, "session_id": 1, "jwt": 1,  # #1, #3, #4
        "client_assertion": 1, "code_verifier": 1,  # #6
    })
    assert stats.post_params == Counter({"password": 1})
    assert stats.websocket == Counter({"authToken": 1, "password": 1})
    assert stats.response_bodies == Counter({"SAMLResponse": 1})
    assert stats.headers == Counter({"cf-access-jwt-assertion": 1})
    assert stats.scrub == Counter({"body": 1})  # the MultiPass-123 echo
    assert stats.not_scanned == [
        NotScanned(2, "multipart/form-data", "multipart body without boundary"),
        NotScanned(5, "websocket", "binary WebSocket frame"),
    ]
    # 8+ chars: MultiPass-123 SessText-777 JwtValue-0001 WsToken-31337 AsrtVal-55555
    # VerifierXYZ1 CfJwt-abcdefgh PHNhbWw+ = 8; shorter: tk1 4711 pw = 3
    assert (stats.secrets, stats.global_secrets) == (11, 8)


@pytest.mark.parametrize("name", ["redact_userinfo.har", "redact_bodies.har"])
def test_idempotent(fixture_path, name):
    out, _ = _redact(fixture_path, name)
    again, stats = redact(out, NOW)
    for doc in (out, again):
        doc["log"].pop("comment")
    assert again == out
    assert stats.secrets == 0 and stats.scrub.total() == 0 and not stats.userinfo


def test_summary_rows(userinfo, bodies):
    # Names and counts only; label padded to 17, count right-aligned in 5.
    text = summary.render(userinfo[1], "in.har", "out.har")
    assert "  URL passwords       14  header 4, initiator 1, page title 1, url 8\n" in text
    assert "  websocket frames     0\n" in text
    text = summary.render(bodies[1], "in.har", "out.har")
    assert "  websocket frames     2  authToken 1, password 1\n" in text
    assert "NOT SCANNED: 2 bodies (not redacted by name, may contain secrets)\n" in text
    assert "  #2 multipart/form-data: multipart body without boundary\n" in text
    assert "  #5 websocket: binary WebSocket frame\n" in text
    assert "WsToken" not in text and "LoopPass" not in text
