# har-inspector

CLI tool for technical support engineers: analyzes browser HAR files
and produces a diagnostic report.

## Stack
- Python 3.11+ (declared in pyproject.toml, checked at startup), standard library only (no third-party runtime dependencies)
- pytest for tests (dev-only, `dev` extra in pyproject.toml)
- Entry point: `python -m har_inspector <file.har>`

## HAR format gotchas (verified on real Chrome exports)
- All timings are in milliseconds.
- `-1` in `timings` means "not applicable" (e.g. reused connection), never a value to add.
- `ssl` is already included in `connect`. Entry `time` = sum of non-negative phases excluding `ssl`.
- Chrome adds internal entries (e.g. HTTP->HTTPS upgrade: 307 with header
  `Non-Authoritative-Reason`): empty `serverIPAddress`, `_transferSize` 0.
  They are not real server responses.
- If `serverIPAddress` is empty and the whole time sits in one phase, the timing
  breakdown is unreliable: report "breakdown unavailable", not a diagnosis.
- Status 0 means the request failed without a response (blocked, aborted, CORS, network error).
- Fields starting with `_` are Chrome-specific and may be missing in HARs from other browsers.
- A request blocked by CORS can be logged *before* its preflight OPTIONS (1 ms earlier in
  normal.har), so link them by time, never by "the next entry".
- `net::ERR_BLOCKED_BY_ORB` comes with a non-zero status (200/204/404); `net::ERR_ABORTED`
  often sits on a 200/204 that did arrive. Don't assume `_error` implies status 0.
- HTTP/2 header names are lowercase; HTTP/1.1 ones are canonical case. Always compare
  names case-insensitively. Exports may strip `Authorization` (and set request
  `headersSize` -1), so a missing header never proves credentials weren't sent.

## Report rules
- Failed groups are keyed by (status, METHOD + URL without query/fragment) and sorted by
  count desc, then status desc (5xx before 4xx before status 0), then endpoint asc.
  The status tie-break was not in the original spec; it is current behavior, pinned in
  `tests/test_analysis.py::test_failed_grouping`.
- "Breakdown unavailable" = empty `serverIPAddress` and one phase holds >= 95% of the
  measured time (exactly 95% counts as unavailable).
- FINDINGS (right after SUMMARY) come from `har_inspector/detectors/`, one module per
  detector. They are sorted by severity (error, warning, info), then detector order
  (cors, auth, redirects, client_errors), then first evidence entry. Evidence numbers are
  0-based HAR entry indices. More than 6 evidence items: show the first 4, then
  "... and N more", then the last one (the end of a redirect chain).
- Thresholds: CORS link window ±1000 ms; a redirect chain is flagged at >= 3 server hops
  (Chrome-internal HSTS hops are labelled but not counted).

## Redaction (`python -m har_inspector redact IN.har -o OUT.har [--force]`)
- Code in `har_inspector/redact/`: `names.py` (secret header/param name rules, pinned by
  `tests/test_redact_names.py`), `scrub.py` (works on the raw dict from
  `parser.read_har_json`, not the lossy model), `summary.py`.
- Pass 1 redacts by name and keeps structure: `Bearer [REDACTED]`, cookie names,
  Set-Cookie attributes. Query and fragment params are redacted inside `request.url`,
  `redirectURL`, `:path`, Referer, Location. JSON/form bodies are redacted by key, in
  requests and responses.
- Pass 2 replaces every value of 8+ chars found in pass 1 (also its URL-encoded forms) in
  every string of the file. Shorter values are only redacted where found by name.
- Base64 bodies: text-like ones are decoded, scrubbed and re-encoded. Binary/non-UTF-8
  ones are left as is and reported as NOT SCANNED. Sizes (`content.size`,
  `_transferSize`) are not adjusted.
- Never writes over IN (normcase + realpath + samefile), writes OUT only with `--force`
  if it exists, writes via a temp file + read-back check, and appends a note to `log.comment`.

## Tests
- Setup (once): `py -3.15 -m venv .venv`, then
  `.venv\Scripts\python -m pip install "pytest>=8"`.
- Run: `.venv\Scripts\python -m pytest` (from the repo root).
- Always run Python via `.venv\Scripts\python`; don't use activation scripts.
- Fixtures in `tests/fixtures/` are small and synthetic; never copy data from `samples/`.
- Expected values are worked out by hand from the fixture (show the arithmetic in a
  comment), never copied from the program's output. If they disagree, treat it as a
  possible bug and investigate before changing the test.

## Working rules
- `samples/` holds real HAR files: never commit them, never print them whole
  (they can be several MB). Inspect them with small Python snippets.
- Keep parsing, analysis and reporting in separate modules.
- Explain non-obvious decisions briefly in code comments.