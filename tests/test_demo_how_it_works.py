"""Ensure the public demo script runs and detections hold."""
from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "demo_how_it_works.py"


@pytest.mark.skipif(not DEMO.is_file(), reason="demo script missing")
def test_demo_how_it_works_exits_zero(capsys):
    # runpy does not set sys.exit code the same way; call main()
    sys.path.insert(0, str(ROOT))
    ns = runpy.run_path(str(DEMO), run_name="not_main")
    code = ns["main"]()
    out = capsys.readouterr().out
    assert code == 0, out
    assert "zero-width" in out.lower() or "ZERO_WIDTH" in out or "zero_width" in out
    assert "PROMPT" in out or "injection" in out.lower()
    assert "How the tool works" in out
