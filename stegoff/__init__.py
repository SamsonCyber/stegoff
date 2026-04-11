"""
StegOFF -- Steganography Detection, Sanitization & Prompt Injection Guard

Detects and destroys hidden payloads in text, images, audio, PDFs, and
binary files before they reach AI agents or end users. Includes semantic
manipulation detection (authority fabrication, polarization bias) and
HTML content injection defense for web-browsing AI agents.
"""

__version__ = "0.4.0"

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

__all__ = [
    "scan", "scan_text", "scan_file",
    "Finding", "ScanReport",
    "sanitize_text", "sanitize_image", "sanitize_image_aggressive", "sanitize_wav",
    "sanitize_html", "scan_html",
    "steg_guard", "StegDetected", "PromptInjectionDetected",
    "detect_semantic_steg",
    "scan_authority", "scan_polarization", "scan_semantic",
]
