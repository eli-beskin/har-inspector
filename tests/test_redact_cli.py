"""`python -m har_inspector redact IN -o OUT`: output safety and summary."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from har_inspector.cli import main
from har_inspector.parser import load

ROOT = Path(__file__).parent.parent


@pytest.fixture
def har_in(tmp_path, fixture_path):
    path = tmp_path / "in.har"
    shutil.copy(fixture_path("redact_h1.har"), path)
    return path


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _error(capsys):
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("har-inspector: error: ")
    return err


def test_redact_writes_output_and_summary(har_in, tmp_path, capsys):
    before = _sha(har_in)
    out = tmp_path / "out.har"
    assert main(["redact", str(har_in), "-o", str(out)]) == 0
    assert _sha(har_in) == before
    assert len(load(str(out)).entries) == 6
    assert "SESSIONVAL12345" not in out.read_text(encoding="utf-8")
    summary = capsys.readouterr().out
    # Counts worked out in test_redact.py::test_stats.
    assert f"REDACTED {har_in} -> {out} (6 entries, none removed)" in summary
    assert "headers              5  authorization 2, cookie 1, set-cookie 1, x-api-key 1" \
        in summary
    assert "cookies              3" in summary
    assert "value scrub          4  body 2, header 1, page title 1" in summary
    assert "13 distinct values of 8+ chars replaced everywhere; 2 shorter" in summary
    assert "NOT SCANNED: 2 bodies (not redacted by name, may contain secrets)" in summary
    assert "#4 image/png: binary base64 body" in summary
    # The summary never prints a secret value.
    assert "SESSIONVAL" not in summary and "BEARER-" not in summary


@pytest.mark.parametrize("variant", ["same", "dotdot", "case"])
def test_refuses_input_as_output(har_in, capsys, variant):
    before = _sha(har_in)
    if variant == "same":
        out = str(har_in)
    elif variant == "dotdot":
        out = str(har_in.parent / "sub" / ".." / har_in.name)
    else:
        out = str(har_in.parent / har_in.name.upper())
        if not os.path.exists(out):
            pytest.skip("file system is case-sensitive")
    assert main(["redact", str(har_in), "-o", out]) == 2
    assert "output is the input file" in _error(capsys)
    assert _sha(har_in) == before


def test_refuses_existing_output_without_force(har_in, tmp_path, capsys):
    out = tmp_path / "out.har"
    out.write_text("keep me", encoding="utf-8")
    assert main(["redact", str(har_in), "-o", str(out)]) == 2
    assert "--force" in _error(capsys)
    assert out.read_text(encoding="utf-8") == "keep me"

    assert main(["redact", str(har_in), "-o", str(out), "--force"]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["log"]["entries"]


def test_bad_input_writes_nothing(tmp_path, capsys):
    bad = tmp_path / "bad.har"
    bad.write_text('{"foo": 1}', encoding="utf-8")
    out = tmp_path / "out.har"
    assert main(["redact", str(bad), "-o", str(out)]) == 2
    assert "not a HAR file" in _error(capsys)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bad.har"]  # no temp left


def test_missing_output_dir(har_in, tmp_path, capsys):
    assert main(["redact", str(har_in), "-o", str(tmp_path / "nope" / "out.har")]) == 2
    assert "cannot write" in _error(capsys)


def test_output_required(har_in):
    with pytest.raises(SystemExit) as exc:
        main(["redact", str(har_in)])
    assert exc.value.code == 2


def test_module_entry_point(har_in, tmp_path):
    out = tmp_path / "out.har"
    result = subprocess.run(
        [sys.executable, "-m", "har_inspector", "redact", str(har_in), "-o", str(out)],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "REDACTED" in result.stdout
    assert out.exists()
