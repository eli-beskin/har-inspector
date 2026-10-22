"""Untrusted HAR text can't inject terminal control sequences or bidi tricks.

terminal_injection.har puts a payload in every field the reports print:
creator (OSC 0 window title), statusText (ESC[2J clear screen, raw \\r), URL path
(ESC[1A + ESC[2K cursor up and erase line, raw \\n, U+202E bidi override),
_error (OSC 8 hyperlink), method, Non-Authoritative-Reason, a secret header
name and a MIME type (redact summary). Entry #4 carries Hebrew that must stay.
"""

import json
import unicodedata

import pytest

from har_inspector.analysis import analyze
from har_inspector.cli import main
from har_inspector.render_common import safe
from har_inspector.report import render as render_text
from har_inspector.report_md import render as render_md

BIDI = {0x061C, 0x200E, 0x200F, 0x2028, 0x2029, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}
HEBREW_PATH = "https://example.com/\u05e9\u05dc\u05d5\u05dd"  # /shalom
HEBREW_STATUS = "\u05e9\u05d2\u05d9\u05d0\u05ea \u05e9\u05e8\u05ea"  # "server error"


def assert_clean(output: str) -> None:
    """Every character: no control char except the report's own "\\n", no bidi."""
    for i, ch in enumerate(output):
        if ch == "\n":
            continue
        assert unicodedata.category(ch) != "Cc", f"raw {ch!r} at {i}: {output[i-40:i+40]!r}"
        assert ord(ch) not in BIDI, f"bidi U+{ord(ch):04X} at {i}: {output[i-40:i+40]!r}"


@pytest.mark.parametrize("raw, shown", [
    ("\x1b[2J", "\\x1b[2J"),
    ("\x1b]0;t\x07", "\\x1b]0;t\\x07"),
    ("a\rb\nc\td", "a\\rb\\nc\\td"),
    ("\x00\x7f", "\\x00\\x7f"),
    ("\x9b", "\\x9b"),  # C1: one-byte CSI
    ("x\u202ey", "x\\u202ey"),
    ("\u2066\u2069\u200e\u200f\u061c", "\\u2066\\u2069\\u200e\\u200f\\u061c"),
    ("\u2028\u2029", "\\u2028\\u2029"),
    # Normal Unicode is untouched; a literal backslash stays as is.
    (HEBREW_STATUS, HEBREW_STATUS),
    ("\u041f\u0440\u0438\u0432\u0435\u0442 \U0001f642", "\u041f\u0440\u0438\u0432\u0435\u0442 \U0001f642"),
    ("C:\\path\\x1b", "C:\\path\\x1b"),
])
def test_safe(raw, shown):
    assert safe(raw) == shown
    assert safe(shown) == shown  # idempotent: escapes are plain ASCII


def test_safe_keep_newlines():
    assert safe("a\nb\r\x1b", keep_newlines=True) == "a\nb\\r\\x1b"


def test_text_report(load_fixture):
    text = render_text(analyze(load_fixture("terminal_injection.har")))
    assert_clean(text)
    assert "Creator: Evil\\x1b]0;pwned\\x07 1.0" in text
    assert "Server\\x1b[2JError" in text
    assert "Not\\rFound" in text
    assert "https://api.example.com/a\\x1b[1A\\x1b[2Kb" in text
    assert "net::ERR_FAILED\\x1b]8;;https://evil.example/\\x07click\\x1b]8;;\\x07" in text
    # The newline stays inside the URL's own line (TOP SLOWEST shows the full URL).
    assert "       GET https://api.example.com/line\\nbreak\n" in text
    assert "https://files.example.com/invoice\\u202egpj.exe" in text
    assert "GET\\x1b[0m https://api.example.com/m" in text
    assert "reason: HSTS\\x1b[2J" in text
    assert HEBREW_PATH in text and HEBREW_STATUS in text


def test_markdown_report(load_fixture):
    text = render_md(analyze(load_fixture("terminal_injection.har")))
    assert_clean(text)
    # Free text: safe() first, then Markdown escapes its backslash ("\\x1b" in source).
    assert "Creator: Evil\\\\x1b\\]0;pwned\\\\x07 1.0" in text
    assert "Server\\\\x1b\\[2JError" in text
    # Code spans take the escape as is.
    assert "`https://api.example.com/a\\x1b[1A\\x1b[2Kb`" in text
    assert "`GET https://api.example.com/line\\nbreak`" in text
    assert "`GET https://files.example.com/invoice\\u202egpj.exe`" in text
    assert "HSTS\\\\x1b\\[2J" in text
    assert HEBREW_PATH in text and HEBREW_STATUS in text


def test_redact_summary(fixture_path, tmp_path, capsys):
    assert main(["redact", fixture_path("terminal_injection.har"), "-o", str(tmp_path / "o.har")]) == 0
    out = capsys.readouterr().out
    assert_clean(out)
    # Header names are counted lowercased: "x-auth\x1b[2J-token" -> "...[2j...".
    assert "x-auth\\x1b[2j-token 1" in out
    assert "#7 image/png\\x1b]0;t\\x07: binary base64 body" in out


def test_error_message_echoing_har(tmp_path, capsys):
    path = tmp_path / "bad.har"
    entry = {"startedDateTime": "\u202e\x1b[2J", "request": {}, "response": {}}
    path.write_text(json.dumps({"log": {"entries": [entry]}}), encoding="utf-8")
    assert main([str(path)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("har-inspector: error: entry #0 is malformed")
    assert_clean(err)
