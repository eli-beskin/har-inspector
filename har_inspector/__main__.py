import sys

# Checked before importing the rest of the package, and written with old
# syntax only, so an older interpreter prints this instead of a SyntaxError.
# 3.11 is needed for datetime.fromisoformat() to accept the trailing "Z".
if sys.version_info < (3, 11):
    sys.stderr.write(
        "har-inspector requires Python 3.11+ (running %d.%d)\n" % sys.version_info[:2]
    )
    sys.exit(2)

from har_inspector.cli import main  # noqa: E402

sys.exit(main())
