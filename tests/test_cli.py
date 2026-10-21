"""CLI exit codes: 0 on success, 2 on unusable input or bad arguments."""

import subprocess
import sys
from pathlib import Path

import pytest

from har_inspector.cli import main

ROOT = Path(__file__).parent.parent


@pytest.mark.parametrize(
    "content",
    [
        None,  # file does not exist
        "{not json",
        '{"foo": 1}',
        '{"log": {"entries": [{}]}}',
    ],
)
def test_bad_input_exits_2(tmp_path, capsys, content):
    path = tmp_path / "bad.har"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    assert main([str(path)]) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("har-inspector: error: ")


def test_bad_top_exits_2(fixture_path):
    with pytest.raises(SystemExit) as exc:
        main([fixture_path("timings.har"), "--top", "0"])
    assert exc.value.code == 2


def test_good_input_exits_0(fixture_path, capsys):
    assert main([fixture_path("failures.har")]) == 0
    assert "FAILED REQUESTS" in capsys.readouterr().out


def test_module_entry_point_exits_2(tmp_path):
    # Covers __main__.py: sys.exit(main()) must propagate the code.
    result = subprocess.run(
        [sys.executable, "-m", "har_inspector", str(tmp_path / "nope.har")],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "file not found" in result.stderr
