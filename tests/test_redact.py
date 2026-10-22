"""Redaction on redact_h1.har (HTTP/1.1 canonical-case headers) and redact_h2.har
(same data, lowercase names, plus :method/:path pseudo-headers)."""

import base64
import json
from collections import Counter
from datetime import datetime, timezone

import pytest

from har_inspector.analysis import analyze
from har_inspector.parser import load, read_har_json
from har_inspector.redact.scrub import NotScanned, redact
from har_inspector.report import render

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
R = "[REDACTED]"
FIXTURES = ["redact_h1.har", "redact_h2.har"]

# Every secret in the fixtures. "dark" and "pass" are shorter than 8 chars, so
# they are only redacted by name and survive elsewhere (checked separately).
LONG_SECRETS = [
    "AT-abcdef123456", "BEARER-xyz-7890123", "SESSIONVAL12345", "APIKEY-555666777",
    "REFSESSION-42abc", "CSRFVAL-98765432", "hunter2-secret-pw", "FRAG-TOKEN-777888",
    "CLIENTSECRET-0001", "ISSUED-TOKEN-ABCDEFG", "SESS-OBJ-9999", "B64-TOKEN-1234567",
    base64.b64encode(b"alice:hunter2-secret-pw").decode(),
]


@pytest.fixture(params=FIXTURES)
def run(request, fixture_path):
    har = read_har_json(fixture_path(request.param))
    out, stats = redact(har, NOW)
    return request.param, har, out, stats


def _headers(message):
    # Case-insensitive lookup so one assertion covers both fixtures.
    return {h["name"].lower(): h["value"] for h in message["headers"]}


def test_input_dict_untouched(run, fixture_path):
    name, har, _, _ = run
    assert har == read_har_json(fixture_path(name))


def test_entries_kept(run):
    _, har, out, stats = run
    assert len(out["log"]["entries"]) == len(har["log"]["entries"]) == stats.entries == 6


def test_no_long_secret_left_anywhere(run):
    _, _, out, _ = run
    text = json.dumps(out, ensure_ascii=False)
    for secret in LONG_SECRETS:
        assert secret not in text
    # The base64 body of #3 must not carry its token either.
    body = base64.b64decode(out["log"]["entries"][3]["response"]["content"]["text"])
    assert b"B64-TOKEN" not in body


def test_entry0_headers_cookies_query(run):
    _, _, out, _ = run
    e = out["log"]["entries"][0]
    req, resp = _headers(e["request"]), _headers(e["response"])
    assert req["authorization"] == f"Bearer {R}"  # scheme kept
    assert req["cookie"] == f"sid={R}; theme={R}"  # names kept
    assert req["x-api-key"] == R
    assert req["referer"] == f"https://app.example.com/home?session={R}&tab=1"
    assert req["accept"] == "application/json"
    assert resp["set-cookie"] == f"csrf={R}; Path=/; SameSite=Lax; Secure"
    assert resp["x-debug-echo"] == f"key={R}"  # by value: echo of the API key
    # Non-secret params stay byte-identical.
    url = f"https://api.example.com/v1/items?page=2&access_token={R}&country_code=US"
    assert e["request"]["url"] == url
    assert e["request"]["queryString"] == [
        {"name": "page", "value": "2"},
        {"name": "access_token", "value": R},
        {"name": "country_code", "value": "US"},
    ]
    assert [c["value"] for c in e["request"]["cookies"]] == [R, R]
    assert [c["value"] for c in e["response"]["cookies"]] == [R]
    if "h2" in run[0]:
        assert req[":path"] == f"/v1/items?page=2&access_token={R}&country_code=US"


def test_short_values_redacted_only_by_name(run):
    _, _, out, _ = run
    # "pass" (pwd) and "dark" (theme cookie) are < 8 chars: the body keeps them.
    body = out["log"]["entries"][0]["response"]["content"]["text"]
    assert body == f'{{"items":[1,2],"echo":"{R}","note":"pass is a word","theme":"dark"}}'
    post = out["log"]["entries"][1]["request"]["postData"]
    assert post["text"] == f"user=alice&pwd={R}"
    assert post["params"] == [{"name": "user", "value": "alice"}, {"name": "pwd", "value": R}]


def test_entry1_basic_auth_and_redirect_fragment(run):
    _, _, out, _ = run
    e = out["log"]["entries"][1]
    assert _headers(e["request"])["authorization"] == f"Basic {R}"
    location = f"https://app.example.com/cb#access_token={R}&state=xyz"
    assert _headers(e["response"])["location"] == location
    assert e["response"]["redirectURL"] == location
    # The decoded Basic password, echoed in clear text, is scrubbed by value.
    assert e["response"]["content"]["text"] == f"Welcome alice (debug: {R})"


def test_entry2_json_bodies_and_initiator(run):
    _, _, out, _ = run
    e = out["log"]["entries"][2]
    assert json.loads(e["request"]["postData"]["text"]) == {
        "client": {"client_secret": R, "name": "web"}, "grant": "x",
    }
    # Everything under a secret key is secret: session.id too.
    assert json.loads(e["response"]["content"]["text"]) == {
        "access_token": R, "expires_in": 3600, "session": {"id": R},
    }
    assert e["_initiator"]["url"] == f"https://app.example.com/app.js?access_token={R}"


def test_base64_bodies(run, fixture_path):
    name, _, out, stats = run
    entries = out["log"]["entries"]
    text = base64.b64decode(entries[3]["response"]["content"]["text"]).decode()
    assert json.loads(text) == {"token": R, "v": 1}
    assert entries[3]["response"]["content"]["encoding"] == "base64"
    # Binary and non-UTF-8 bodies are left byte-identical and reported.
    original = read_har_json(fixture_path(name))["log"]["entries"]
    for i in (4, 5):
        assert entries[i]["response"]["content"] == original[i]["response"]["content"]
    assert stats.not_scanned == [
        NotScanned(4, "image/png", "binary base64 body"),
        NotScanned(5, "text/plain", "base64 body is not UTF-8 text"),
    ]


def test_page_title(run):
    _, _, out, _ = run
    assert out["log"]["pages"][0]["title"] == f"Dashboard — {R}"


def test_stats(run):
    name, _, _, stats = run
    # Header objects changed by name: #0 Authorization, Cookie, X-Api-Key,
    # Set-Cookie; #1 Authorization. Referer/Location are counted per param.
    assert stats.headers == Counter(
        {"authorization": 2, "cookie": 1, "x-api-key": 1, "set-cookie": 1}
    )
    # request.cookies sid + theme, response.cookies csrf = 2 + 1
    assert stats.cookies == 3
    assert stats.query == Counter({"access_token": 1})
    # access_token: #0 url, #1 Location fragment, #1 redirectURL fragment = 3,
    # plus #0 :path in h2 = 4. session: #0 Referer.
    tokens = 4 if "h2" in name else 3
    assert stats.url_params == Counter({"access_token": tokens, "session": 1})
    assert stats.post_params == Counter({"pwd": 1})
    assert stats.post_text == Counter({"pwd": 1, "client_secret": 1})
    # #2 access_token + session.id (counted under "session"), #3 token
    assert stats.response_bodies == Counter({"access_token": 1, "session": 1, "token": 1})
    # Pass 2 echoes: #0 body (bearer), #1 body (password), #0 X-Debug-Echo
    # (api key), #2 _initiator (access token), page title (sid cookie).
    assert stats.scrub == Counter(
        {"body": 2, "header": 1, "initiator": 1, "page title": 1}
    )
    # 13 long secrets + "dark" + "pass" = 15 distinct
    assert (stats.secrets, stats.global_secrets) == (15, 13)


def test_idempotent(run):
    _, _, out, _ = run
    again, stats = redact(out, NOW)
    for doc in (out, again):
        doc["log"].pop("comment")
    assert again == out
    assert stats.secrets == 0 and stats.scrub.total() == 0


def test_comment_added():
    har = {"log": {"entries": []}}
    out, _ = redact(har, NOW)
    assert out["log"]["comment"] == "Redacted by har-inspector 0.1.0 on 2026-10-22 UTC"


def test_comment_appended_and_scrubbed():
    har = {"log": {"comment": "ticket 42, sid=SESSIONVAL12345", "entries": [
        {"request": {"headers": [{"name": "Cookie", "value": "sid=SESSIONVAL12345"}]},
         "response": {}},
    ]}}
    out, _ = redact(har, NOW)
    assert out["log"]["comment"] == (
        f"ticket 42, sid={R}\nRedacted by har-inspector 0.1.0 on 2026-10-22 UTC"
    )


def test_url_encoded_echo_is_scrubbed():
    # The secret is found decoded in queryString and echoed percent-encoded.
    har = {"log": {"entries": [{
        "request": {"url": "https://x.test/a", "headers": [],
                    "queryString": [{"name": "token", "value": "a b/c+d=e"}]},
        "response": {"content": {"mimeType": "text/html",
                                 "text": "next=a%20b%2Fc%2Bd%3De and a+b%2Fc%2Bd%3De"}},
    }]}}
    out, _ = redact(har, NOW)
    assert out["log"]["entries"][0]["response"]["content"]["text"] == f"next={R} and {R}"


def test_analyzer_report_unchanged_except_redacted_url(tmp_path, fixture_path):
    for name in FIXTURES:
        out, _ = redact(read_har_json(fixture_path(name)), NOW)
        path = tmp_path / name
        path.write_text(json.dumps(out), encoding="utf-8")
        before = render(analyze(load(fixture_path(name)), top=10)).splitlines()
        after = render(analyze(load(str(path)), top=10)).splitlines()
        assert len(before) == len(after)
        changed = [(b, a) for b, a in zip(before, after) if b != a]
        # Only the #0 URL line in the slowest list (it shows the query string).
        assert len(changed) == 1
        assert "access_t" in changed[0][0] and "def123456" not in changed[0][1]
