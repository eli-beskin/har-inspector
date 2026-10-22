# har-inspector

[![tests](https://github.com/eli-beskin/har-inspector/actions/workflows/tests.yml/badge.svg)](https://github.com/eli-beskin/har-inspector/actions/workflows/tests.yml)

A command-line tool that turns a browser HAR file into a diagnostic report for technical support.

Customers attach HAR files to support tickets, and reading them in DevTools by hand takes a
while: hundreds of requests, Chrome-internal noise, timings that are easy to misread.
har-inspector summarizes the capture, groups failed requests, shows where the slowest
requests spent their time, and calls out common root causes (CORS, auth, redirects,
client-side network errors) with a suggested next step. It can also write a redacted copy of
the HAR, so the file can be shared further without tokens, cookies or passwords.

## Features

- **Analyze** (`python -m har_inspector FILE.har`): a report with
  - **SUMMARY**: request count, bytes transferred, capture span, counts by status class;
  - **FINDINGS**: problems spotted by the detectors, each with evidence (HAR entry
    indices) and a next step;
  - **FAILED REQUESTS**: grouped by status and endpoint (method + URL without query);
  - **TOP N SLOWEST** (`--top N`, default 10): time per phase (blocked, dns, connect, send,
    wait, receive) and the dominant phase;
  - **CHROME-INTERNAL ENTRIES**: listed separately and excluded from the stats.
- **Detectors** (one module each in `har_inspector/detectors/`):
  - `cors`: a failed preflight (OPTIONS) and the request it blocked;
  - `auth`: 401/403 grouped by endpoint and auth scheme, with whether there is evidence
    that credentials were sent; Basic auth over plain HTTP;
  - `redirects`: chains of 3+ hops, loops, server-side HTTP->HTTPS hops;
  - `client_errors`: Chrome `net::ERR_*` codes mapped to a likely cause and a hint.
- **Redact** (`python -m har_inspector redact IN.har -o OUT.har [--force]`): writes a copy
  with secrets replaced by `[REDACTED]` (headers, cookies, query and fragment params,
  JSON/form bodies), then replaces every found secret value wherever else it appears in the
  file. The input file is never modified.
- **Markdown output** (`--format md`): the same report as GitHub-flavored Markdown, for
  tickets and issues. Findings come first.

## Quick start

Requires Python 3.11 or newer. No third-party dependencies, no install step.

Windows:

```powershell
git clone https://github.com/eli-beskin/har-inspector.git
cd har-inspector
py -m har_inspector path\to\capture.har
py -m har_inspector path\to\capture.har --format md > report.md
py -m har_inspector redact path\to\capture.har -o capture.redacted.har
```

Linux / macOS:

```sh
git clone https://github.com/eli-beskin/har-inspector.git
cd har-inspector
python3 -m har_inspector path/to/capture.har
python3 -m har_inspector path/to/capture.har --format md > report.md
python3 -m har_inspector redact path/to/capture.har -o capture.redacted.har
```

To export a HAR in Chrome: DevTools > Network > "Export HAR...".

## Example output

All examples are real output from the synthetic test fixtures in `tests/fixtures/`
(`...` marks lines cut from this README).

Text report, `python -m har_inspector tests/fixtures/cors.har`:

```text
HAR Inspector - cors.har
Creator: WebInspector 537.36   Pages: 0

SUMMARY
  Requests:      12   (Chrome-internal excluded: 0)
  Transferred:   150 B
  Capture span:  7.02 s  (2026-10-20 12:00:00.000 -> 2026-10-20 12:00:07.020 UTC)
  By status:     2xx 2 | 3xx 0 | 4xx 3 | 5xx 1 | failed(0) 6

FINDINGS
  ERROR    CORS preflight rejected (403): PUT https://api.example.com/upload blocked
           #1    OPTIONS 403  https://api.example.com/upload  preflight
           #0    PUT     0    https://api.example.com/upload  net::ERR_FAILED
           Next step: The server must answer OPTIONS on this URL with 2xx and
                      Access-Control-Allow-Origin/-Methods/-Headers for origin
                      https://app.example.com; check its CORS config, or a gateway/WAF that rejects
                      OPTIONS.
...
  WARNING  CORS preflight rejected (500): OPTIONS https://api.example.com/orphan (for PATCH),
           blocked request not found in the HAR
           #6    OPTIONS 500  https://api.example.com/orphan  preflight
           Next step: The actual request was probably never sent. The server must answer OPTIONS
                      with 2xx and Access-Control-Allow-* headers.
...
FAILED REQUESTS
  Count  Status  Endpoint
      1  500     OPTIONS https://api.example.com/orphan
                   Internal Server Error
      1  405     OPTIONS https://api.example.com/plain
                   Method Not Allowed
...
TOP 10 SLOWEST
  (connect includes ssl; '-' = not applicable)
    #   Time ms  Status  Dominant                blocked      dns  connect     send     wait  receive
    1       300  0       breakdown unavailable       300        -        -        0        0        0
       PUT https://api.example.com/upload
    2       200  403     wait (100%)                   -        -        -        0      200        0
       OPTIONS https://api.example.com/upload
...
```

Markdown report, `python -m har_inspector tests/fixtures/cors.har --format md` (source):

```markdown
# HAR Inspector: cors.har

Creator: WebInspector 537.36, Pages: 0

## Findings

**ERROR** CORS preflight rejected (403): PUT https://api.example.com/upload blocked

| # | Method | Status | URL | Note |
| --: | --- | --: | --- | --- |
| 1 | OPTIONS | 403 | `https://api.example.com/upload` | preflight |
| 0 | PUT | 0 | `https://api.example.com/upload` | net::ERR\_FAILED |

**Next step:** The server must answer OPTIONS on this URL with 2xx and Access-Control-Allow-Origin/-Methods/-Headers for origin https://app.example.com; check its CORS config, or a gateway/WAF that rejects OPTIONS.
...
## Summary

| Metric | Value |
| --- | --- |
| Requests | 12 (Chrome-internal excluded: 0) |
| Transferred | 150 B |
| Capture span | 7.02 s (2026-10-20 12:00:00.000 -> 2026-10-20 12:00:07.020 UTC) |
| By status | 2xx 2, 3xx 0, 4xx 3, 5xx 1, failed(0) 6 |
...
```

Underscores in free text are escaped (`\_`) so Markdown renderers don't turn them into italics.

Redaction summary, `python -m har_inspector redact tests/fixtures/redact_h1.har -o redacted.har`:

```text
REDACTED tests/fixtures/redact_h1.har -> redacted.har (6 entries, none removed)
  headers              5  authorization 2, cookie 1, set-cookie 1, x-api-key 1
  cookies              3
  query params         1  access_token 1
  params in URLs       4  access_token 3, session 1
  post data params     1  pwd 1
  post data text       2  client_secret 1, pwd 1
  response bodies      3  access_token 1, session 1, token 1
  value scrub          5  body 2, header 1, initiator 1, page title 1
    13 distinct values of 8+ chars replaced everywhere; 2 shorter redacted by name only
NOT SCANNED: 2 base64 bodies (left as is, may contain secrets)
  #4 image/png: binary base64 body
  #5 text/plain: base64 body is not UTF-8 text
```

## Design decisions

<details>
<summary>HAR format gotchas and the rules the report follows (click to expand)</summary>

Verified on real Chrome exports. The full spec is in [`CLAUDE.md`](CLAUDE.md).

**Timings**
- All timings are in milliseconds. `-1` (and Chrome's small negatives such as `-0.8`) means
  "not applicable", e.g. on a reused connection, and is never added to a total.
- `ssl` is already part of `connect`, so an entry's time is the sum of the non-negative
  phases without `ssl`.
- "Breakdown unavailable": when `serverIPAddress` is empty and one phase holds >= 95% of the
  measured time (exactly 95% included), the split can't be trusted, so the report says so
  instead of naming a dominant phase.

**Chrome quirks**
- Chrome-internal entries (e.g. the HTTP->HTTPS 307 with a `Non-Authoritative-Reason`
  header, empty IP, 0 bytes transferred) are not server responses: they are listed
  separately and excluded from stats.
- Status 0 means no response arrived (blocked, aborted, CORS, network error). But `_error`
  doesn't imply status 0: `net::ERR_BLOCKED_BY_ORB` comes with a real 200/204/404, and
  `net::ERR_ABORTED` often sits on a response that did arrive.
- Fields starting with `_` are Chrome-only and may be missing in HARs from other browsers;
  the report uses them when present and falls back gracefully when they're missing.

**Headers and credentials**
- Header names are compared case-insensitively (HTTP/2 lowercase vs HTTP/1.1 canonical case).
- Exports can strip `Authorization`, and HTTP/2 has no `headersSize`, so a missing header
  never proves credentials weren't sent: the report says "no evidence", never "not sent".

**Findings and grouping**
- CORS: a blocked request is linked to its preflight by time (±1000 ms), not by entry
  order. Chrome can log the request 1 ms *before* its preflight.
- A redirect chain is flagged at 3+ server hops; Chrome-internal HSTS hops are labelled but
  not counted.
- Findings are sorted by severity, then detector, then first evidence entry. More than 6
  evidence items: the first 4, "... and N more", then the last one (the end of a chain).
- Failed groups are sorted by count, then status (5xx before 4xx before 0), then endpoint.
  The status tie-break is explicit and pinned by a test.

**Redaction**
- Pass 1 redacts by name and keeps the structure (`Bearer [REDACTED]`, cookie names,
  Set-Cookie attributes), including query params inside URLs, `Referer`, `Location`, and the
  HTTP/2 `:path` pseudo-header.
- Pass 2 replaces every found value of 8+ characters (and its URL-encoded forms) anywhere in
  the file.
- Base64 text bodies are decoded, scrubbed and re-encoded; binary ones are reported as
  NOT SCANNED rather than silently passed.
- Never writes over the input, refuses to overwrite OUT without `--force`, writes via a temp
  file with a read-back check, and adds a note to `log.comment`.

**Code**
- Standard library only. Parsing, analysis and reporting live in separate modules; the
  text and Markdown renderers share truncation and evidence rules (`render_common.py`).

</details>

## Testing

Tests use pytest (dev-only dependency).

```powershell
# Windows
py -m venv .venv
.venv\Scripts\python -m pip install "pytest>=8"
.venv\Scripts\python -m pytest
```

```sh
# Linux / macOS
python3 -m venv .venv
.venv/bin/python -m pip install "pytest>=8"
.venv/bin/python -m pytest
```

Fixtures in `tests/fixtures/` are small, synthetic HAR files. Expected values are worked
out by hand from the fixture, with the arithmetic in a comment, and never copied from
the program's output. CI runs the suite on Ubuntu and Windows with Python 3.11 and the
latest Python release.

## Built with Claude Code

This project was built with [Claude Code](https://claude.com/claude-code).

**How I worked**
- `CLAUDE.md` as the project spec: HAR format gotchas, report rules, test rules.
- Every block: plan mode first, I reviewed the plan, then implementation.
- Independent verification by me after each block: compared reports with Chrome DevTools
  (including importing HAR files into DevTools), before/after baseline diffs of full reports,
  and a file hash check that redaction never touches the input.
- Tests with hand-computed expectations, never copied from program output.

**What Claude Code caught**
- Chrome writes small negative timings (e.g. `-0.8`), not only `-1`.
- ORB-blocked entries carry a real status (200/204/404) and an empty IP.
- An error in my own spec: blocked 94.9 + wait 5.1 means "blocked" dominates, not "wait".
- A CORS preflight can be logged *after* the request it blocks (by 1 ms), so linking uses
  time proximity, not entry order.
- In HTTP/2 the query string also lives in the `:path` pseudo-header (redaction).
- It asked scope questions instead of guessing (`ERR_ABORTED` noise, cookie structure,
  secret keys in response bodies).

**What I caught or decided in review**
- Boundary tests exactly at the 95% threshold; tests for case-insensitive header matching.
- An implicit sort tie-break, made explicit and documented.
- "No evidence" must never be reported as "credentials not sent": HTTP/2 has no
  `headersSize` and exports strip `Authorization`.
- Lowercase header names in fixtures, to mirror real HTTP/2 traffic.
- Baseline before/after diffs to prove existing output did not change.
- A redaction note in `log.comment`; findings first in Markdown; URL truncation kept for
  tickets.

**Real-world findings while testing on real HAR files**
- Chrome's internal HTTP->HTTPS 307 and lost timing breakdowns.
- Basic auth credentials detectable by a +27 B request `headersSize` even when the header was
  stripped from the export.
- A rejected CORS preflight (403) followed by a PUT with status 0 on an ad endpoint.
- A news site's video player requesting a missing localization file: 404 + ORB.

## Roadmap

- Server-side detector: 404/5xx on the main document, slow TTFB on single requests.
- Severity by resource type (document/xhr vs images, trackers, beacons).
- Connection reuse (`_connectionId`) and page load time (`pageTimings.onLoad`).
- Collapse parallel requests with identical timings; flag HTTP/2 contention; mark
  third-party domains.
- `ERR_ABORTED` on first-party documents and XHR.
- Display: don't round 94.9% up to 95%; no auto-linked URLs in Markdown text.
- HTML report.

## License

MIT, see [LICENSE](LICENSE).

Author: Ilya (Eli) Beskin — [LinkedIn](https://linkedin.com/in/eli-beskin-a5276140b)
