"""Command-line interface: load -> analyze -> report, or the redact subcommand."""

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone

from har_inspector import __version__
from har_inspector.analysis import analyze
from har_inspector.parser import HarError, load, read_har_json
from har_inspector.redact import summary
from har_inspector.redact.scrub import redact
from har_inspector import report, report_md

RENDERERS = {"text": report.render, "md": report_md.render}


def _positive_int(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    # Not argparse subparsers: they would turn `FILE.har` into a subcommand
    # choice and change the existing usage. A file named "redact" can still
    # be analyzed as ./redact.
    if argv[:1] == ["redact"]:
        return _redact_main(argv[1:])

    parser = argparse.ArgumentParser(
        prog="python -m har_inspector",
        description="Analyze a browser HAR file and print a diagnostic report.",
    )
    parser.add_argument("file", help="path to the .har file")
    parser.add_argument(
        "--top", type=_positive_int, default=10, metavar="N",
        help="number of slowest requests to show (default: 10)",
    )
    parser.add_argument(
        "--format", choices=RENDERERS, default="text",
        help="report format: text, or md (Markdown for tickets) (default: text)",
    )
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    try:
        har = load(args.file)
    except HarError as exc:
        print(f"har-inspector: error: {exc}", file=sys.stderr)
        return 2

    sys.stdout.write(RENDERERS[args.format](analyze(har, top=args.top)))
    return 0


def _redact_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m har_inspector redact",
        description="Write a copy of a HAR file with secrets replaced by [REDACTED].",
    )
    parser.add_argument("file", help="input .har file (never modified)")
    parser.add_argument("-o", "--output", required=True, metavar="OUT",
                        help="redacted .har file to write")
    parser.add_argument("--force", action="store_true",
                        help="overwrite OUT if it already exists")
    args = parser.parse_args(argv)

    try:
        _check_output(args.file, args.output, args.force)
        har = read_har_json(args.file)
        redacted, stats = redact(har, datetime.now(timezone.utc))
        _write(redacted, args.output, args.file)
    except HarError as exc:
        print(f"har-inspector: error: {exc}", file=sys.stderr)
        return 2

    sys.stdout.write(summary.render(stats, args.file, args.output))
    return 0


def _check_output(source: str, target: str, force: bool) -> None:
    # normcase: Windows paths are case-insensitive; realpath resolves ".." and
    # links. samefile also catches hard links and other aliases.
    def norm(p):
        return os.path.normcase(os.path.realpath(p))

    same = norm(source) == norm(target)
    if not same and os.path.exists(source) and os.path.exists(target):
        same = os.path.samefile(source, target)
    if same:
        raise HarError(f"output is the input file: {target}")
    if os.path.isdir(target):
        raise HarError(f"output is a directory: {target}")
    if os.path.exists(target) and not force:
        raise HarError(f"output already exists: {target} (use --force to overwrite)")


def _write(doc: dict, target: str, source: str) -> None:
    """Write via a temp file, check it reads back, then move it into place, so
    a failure never leaves a half-written or broken OUT."""
    try:
        text = json.dumps(doc, ensure_ascii=False, indent=2)
        text.encode("utf-8")
    except UnicodeEncodeError:
        # Lone surrogates (escaped in the input JSON) have no UTF-8 form.
        text = json.dumps(doc, indent=2)
    directory = os.path.dirname(os.path.abspath(target))
    try:
        fd, tmp = tempfile.mkstemp(prefix=".redact-", suffix=".har.tmp", dir=directory)
    except OSError as exc:
        raise HarError(f"cannot write {target}: {exc}") from None
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        if len(read_har_json(tmp)["log"]["entries"]) != len(doc["log"]["entries"]):
            raise HarError("self-check failed: entry count changed")
        if _analyzable(source) and not _analyzable(tmp):
            raise HarError("self-check failed: the analyzer cannot read the output")
        os.replace(tmp, target)
    except OSError as exc:
        raise HarError(f"cannot write {target}: {exc}") from None
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _analyzable(path: str) -> bool:
    try:
        load(path)
    except HarError:
        return False
    return True
