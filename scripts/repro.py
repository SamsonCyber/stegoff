"""Independent offline repro for stegoff (no Ollama / no lab network)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CORE = [
    "tests/test_text_detectors.py",
    "tests/test_prompt_injection.py",
    "tests/test_pipeline_integration.py",
    "tests/test_false_positives.py",
    "tests/test_sanitizers.py",
    "tests/test_html_sanitizer_redteam.py",
    "tests/test_injection_redteam.py",
    "tests/test_semantic_detectors.py",
    "tests/test_orchestrator.py",
    "tests/test_guard_decorator.py",
]

EXTENDED = [
    "tests/test_ml_classifier.py",
    "tests/test_classifier_robustness.py",
]


def main() -> int:
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "-e", ".[dev]", "-q"],
        cwd=ROOT,
    )
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "scikit-learn>=1.3", "-q"]
    )
    tests = list(CORE)
    try:
        import sklearn  # noqa: F401

        tests.extend(EXTENDED)
    except ImportError:
        pass
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        *tests,
        "--ignore=tests/test_ollama_redteam.py",
    ]
    r = subprocess.call(cmd, cwd=ROOT)
    if r == 0:
        print("REPRO_OK stegoff offline suite")
    return r


if __name__ == "__main__":
    raise SystemExit(main())
