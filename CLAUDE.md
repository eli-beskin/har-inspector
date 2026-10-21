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

## Report rules
- Failed groups are keyed by (status, METHOD + URL without query/fragment) and sorted by
  count desc, then status desc (5xx before 4xx before status 0), then endpoint asc.
  The status tie-break was not in the original spec; it is current behavior, pinned in
  `tests/test_analysis.py::test_failed_grouping`.
- "Breakdown unavailable" = empty `serverIPAddress` and one phase holds >= 95% of the
  measured time (exactly 95% counts as unavailable).

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