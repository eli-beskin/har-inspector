"""Command-line interface: load -> analyze -> report."""

import argparse
import sys

from har_inspector import __version__
from har_inspector.analysis import analyze
from har_inspector.parser import HarError, load
from har_inspector.report import render


def _positive_int(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m har_inspector",
        description="Analyze a browser HAR file and print a diagnostic report.",
    )
    parser.add_argument("file", help="path to the .har file")
    parser.add_argument(
        "--top", type=_positive_int, default=10, metavar="N",
        help="number of slowest requests to show (default: 10)",
    )
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    try:
        har = load(args.file)
    except HarError as exc:
        print(f"har-inspector: error: {exc}", file=sys.stderr)
        return 2

    sys.stdout.write(render(analyze(har, top=args.top)))
    return 0
