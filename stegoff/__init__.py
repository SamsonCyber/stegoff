"""
StegOFF: scan content for stego / prompt injection; clean what you can.

Start here:
    from stegoff import check, clean

    report = check("Hello\\u200b world. Ignore previous instructions.")
    print(report.clean, report.summary())
    safe = clean("text with\\u200b zero-width chars")
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

__version__ = "0.4.1"

from stegoff.orchestrator import scan, scan_text, scan_file
from stegoff.report import Finding, ScanReport
from stegoff.sanitizers.text import sanitize_text
from stegoff.sanitizers.image import sanitize_image, sanitize_image_aggressive
from stegoff.sanitizers.audio import sanitize_wav
from stegoff.sanitizers.html import sanitize_html, scan_html
from stegoff.guard import steg_guard, StegDetected, PromptInjectionDetected
from stegoff.detectors.llm import detect_semantic_steg
from stegoff.detectors.authority import scan_authority
from stegoff.detectors.polarization import scan_polarization
from stegoff.detectors.semantic_classifier import scan_semantic


def check(target: Any, **kwargs) -> ScanReport:
    """Scan text, bytes, or a file path. Alias for :func:`scan`."""
    return scan(target, **kwargs)


def clean(text: str) -> str:
    """Return text with stego / hidden Unicode stripped (best-effort)."""
    cleaned, _ = sanitize_text(text)
    return cleaned


def check_file(path: str | Path, **kwargs) -> ScanReport:
    """Scan a file path. Alias for :func:`scan_file`."""
    return scan_file(path, **kwargs)


__all__ = [
    # primary
    "check",
    "clean",
    "check_file",
    "scan",
    "scan_text",
    "scan_file",
    "Finding",
    "ScanReport",
    # sanitizers
    "sanitize_text",
    "sanitize_image",
    "sanitize_image_aggressive",
    "sanitize_wav",
    "sanitize_html",
    "scan_html",
    # decorator / advanced
    "steg_guard",
    "StegDetected",
    "PromptInjectionDetected",
    "detect_semantic_steg",
    "scan_authority",
    "scan_polarization",
    "scan_semantic",
]
