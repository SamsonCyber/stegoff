"""
StegOFF -- Steganography Detection, Sanitization & Prompt Injection Guard

Detects and destroys hidden payloads in text, images, audio, PDFs, and
binary files before they reach AI agents or end users.
"""

__version__ = "0.3.0"

from stegoff.orchestrator import scan, scan_text, scan_file
from stegoff.report import Finding, ScanReport
from stegoff.sanitizers.text import sanitize_text
from stegoff.sanitizers.image import sanitize_image, sanitize_image_aggressive
from stegoff.sanitizers.audio import sanitize_wav
from stegoff.guard import steg_guard, StegDetected, PromptInjectionDetected
from stegoff.detectors.llm import detect_semantic_steg

__all__ = [
    "scan", "scan_text", "scan_file",
    "Finding", "ScanReport",
    "sanitize_text", "sanitize_image", "sanitize_image_aggressive", "sanitize_wav",
    "steg_guard", "StegDetected", "PromptInjectionDetected",
    "detect_semantic_steg",
]
