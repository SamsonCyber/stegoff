"""
HTML Sanitizer — Strip visually hidden content from HTML before agent ingestion.

Removes CSS-hidden elements (display:none, offscreen, zero-font, color-match),
HTML comments, suspicious metadata, and oversized aria-labels. These are the
primary vectors for content injection attacks on web-browsing AI agents.

Also detects and returns findings for the hidden content found.

Usage:
    from stegoff.sanitizers.html import sanitize_html, scan_html

    # Sanitize (returns cleaned HTML + report)
    clean_html, findings = sanitize_html(raw_html)

    # Scan only (returns findings without modifying)
    findings = scan_html(raw_html)
"""

from __future__ import annotations

import re
from typing import Any

from stegoff.report import Finding, Severity, StegMethod


# ── CSS patterns that hide content ──────────────────────────────────

_HIDDEN_STYLE_PATTERNS = [
    (re.compile(r"display\s*:\s*none", re.I), "display:none"),
    (re.compile(r"visibility\s*:\s*hidden", re.I), "visibility:hidden"),
    (re.compile(r"opacity\s*:\s*0(?:[;\s]|$)", re.I), "opacity:0"),
    (re.compile(r"font-size\s*:\s*0(?:px|em|rem|%)?\s*[;\s]", re.I), "font-size:0"),
    (re.compile(r"font-size\s*:\s*[01]px", re.I), "font-size:1px"),
    (re.compile(r"height\s*:\s*0(?:px)?\s*[;\s].*overflow\s*:\s*hidden", re.I | re.S), "height:0+overflow"),
    (re.compile(r"width\s*:\s*0(?:px)?\s*[;\s].*overflow\s*:\s*hidden", re.I | re.S), "width:0+overflow"),
]

_OFFSCREEN_PATTERNS = [
    (re.compile(r"(?:left|top)\s*:\s*-\d{3,}px", re.I), "offscreen-position"),
    (re.compile(r"text-indent\s*:\s*-\d{3,}", re.I), "text-indent-offscreen"),
]

_HIDDEN_CLASSES = {"hidden", "invisible", "offscreen", "sr-only", "visually-hidden",
                   "hidden-trap", "d-none", "hide"}

# White/black foreground that matches common backgrounds
_INVISIBLE_COLORS = {"#fff", "#ffff", "#ffffff", "#ffffffff",
                     "#000", "#0000", "#000000", "#00000000"}


def scan_html(html: str, source: str = "<html>") -> list[Finding]:
    """
    Scan HTML for hidden content without modifying it.

    Returns findings for each hidden element, comment, or suspicious metadata.
    """
    try:
        from bs4 import BeautifulSoup, Comment
    except ImportError:
        return []

    findings = []
    soup = BeautifulSoup(html, "html.parser")

    # Hidden elements
    for tag in soup.find_all(True):
        reason = _check_hidden(tag)
        if reason:
            text = tag.get_text(strip=True)[:100]
            if text:
                findings.append(Finding(
                    method=StegMethod.HIDDEN_HTML_CONTENT,
                    severity=Severity.HIGH,
                    confidence=0.9,
                    description=f"Hidden HTML element ({reason}): <{tag.name}>",
                    evidence=text,
                    decoded_payload=tag.get_text(strip=True),
                    location=source,
                    metadata={"technique": reason, "tag": tag.name},
                ))

    # HTML comments with substantial content
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        content = str(comment).strip()
        if len(content) > 20:
            findings.append(Finding(
                method=StegMethod.HIDDEN_HTML_CONTENT,
                severity=Severity.MEDIUM,
                confidence=0.7,
                description="HTML comment with substantial content",
                evidence=content[:200],
                decoded_payload=content,
                location=source,
                metadata={"technique": "html-comment"},
            ))

    # Suspicious meta tags
    for meta in soup.find_all("meta"):
        content = meta.get("content", "")
        name = meta.get("name", "").lower()
        if name not in ("charset", "viewport") and content and len(content) > 50:
            findings.append(Finding(
                method=StegMethod.HIDDEN_HTML_CONTENT,
                severity=Severity.MEDIUM,
                confidence=0.6,
                description=f"Suspicious meta tag [{name}] with long content",
                evidence=content[:200],
                location=source,
                metadata={"technique": "meta-injection", "meta_name": name},
            ))

    # Oversized aria-labels
    for el in soup.find_all(attrs={"aria-label": True}):
        label = el.get("aria-label", "")
        if len(label) > 50:
            findings.append(Finding(
                method=StegMethod.HIDDEN_HTML_CONTENT,
                severity=Severity.MEDIUM,
                confidence=0.7,
                description="Oversized aria-label (possible injection vector)",
                evidence=label[:200],
                decoded_payload=label,
                location=source,
                metadata={"technique": "aria-label-injection"},
            ))

    return findings


def sanitize_html(html: str, source: str = "<html>") -> tuple[str, list[Finding]]:
    """
    Strip hidden content from HTML and return cleaned version.

    Returns (clean_html, findings) where findings lists what was removed.
    """
    try:
        from bs4 import BeautifulSoup, Comment
    except ImportError:
        return html, []

    findings = scan_html(html, source)
    soup = BeautifulSoup(html, "html.parser")

    # Remove hidden elements
    for tag in soup.find_all(True):
        if _check_hidden(tag):
            tag.decompose()

    # Remove comments
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        if len(str(comment).strip()) > 5:
            comment.extract()

    # Clean meta tags
    for meta in soup.find_all("meta"):
        content = meta.get("content", "")
        name = meta.get("name", "").lower()
        if name not in ("charset", "viewport") and content and len(content) > 50:
            meta.decompose()

    # Clean oversized aria-labels
    for el in soup.find_all(attrs={"aria-label": True}):
        if len(el.get("aria-label", "")) > 50:
            del el["aria-label"]

    # Remove ld+json scripts
    for script in soup.find_all("script", {"type": "application/ld+json"}):
        script.decompose()

    return str(soup), findings


def _check_hidden(tag) -> str | None:
    """Check if a tag is visually hidden. Returns technique name or None."""
    style = tag.get("style", "")
    if style:
        for pattern, name in _HIDDEN_STYLE_PATTERNS:
            if pattern.search(style):
                return name
        for pattern, name in _OFFSCREEN_PATTERNS:
            if pattern.search(style):
                return name
        # Color-match detection
        fg_match = re.search(r"color\s*:\s*(#[0-9a-fA-F]{3,8})", style)
        if fg_match and fg_match.group(1).lower() in _INVISIBLE_COLORS:
            return "color-match"

    classes = set(c.lower() for c in tag.get("class", []))
    if classes & _HIDDEN_CLASSES:
        return f"hidden-class:{classes & _HIDDEN_CLASSES}"

    return None
