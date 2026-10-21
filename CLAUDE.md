# har-inspector

CLI tool for technical support engineers: analyzes browser HAR files
and produces a diagnostic report.

## Stack
- Python 3.11+ (declared in pyproject.toml, checked at startup), standard library only (no third-party runtime dependencies)
- pytest for tests (later)
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

## Working rules
- `samples/` holds real HAR files: never commit them, never print them whole
  (they can be several MB). Inspect them with small Python snippets.
- Keep parsing, analysis and reporting in separate modules.
- Explain non-obvious decisions briefly in code comments.