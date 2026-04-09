"""
TrapSweep -- HTML/DOM content injection trap detector.

Defends against Trap Category 1 (Franklin et al., 2026): hidden instructions
embedded in HTML that are invisible to humans but parsed by AI agents.
WASP benchmarks showed 86% hijack success rate with these techniques.

Detects: HTML comments, display:none elements, font-size:0 text, aria-label
injection, meta tag payloads, noscript blocks, data-attributes, CSS content
injection, template tags, JSON-LD payloads, and color camouflage.

Usage:
    from stegoff.detectors.trapsweep import scan_html_traps, sanitize_html_traps

    findings = scan_html_traps(html_content)
    clean_html, ops = sanitize_html_traps(html_content)
"""

from __future__ import annotations

import re
from stegoff.report import Finding, Severity, StegMethod

# Quick instruction keyword check (faster than full prompt injection scan)
_INSTRUCTION_KEYWORDS = re.compile(
    r'\b(?:ignore|override|forget|bypass|disregard|skip|dismiss)\b.{0,100}'
    r'\b(?:previous|prior|all|above|instructions?|rules?|prompt|safety)\b',
    re.IGNORECASE | re.DOTALL,
)

_COMMAND_KEYWORDS = re.compile(
    r'\b(?:execute|send\s+(?:data|all|the|your|every)|output\s+(?:your|the)|reveal|exfiltrate|'
    r'system\s*prompt|act\s+as|you\s+are\s+now|DAN|jailbreak|'
    r'delete|rm\s+-rf|curl|wget|post\s+to|upload\s+to|'
    r'send\s+\w+\s+(?:keys?|tokens?|secrets?|credentials?|passwords?|env)|'
    r'transmit|collect\s+(?:all|the|your)|extract\s+(?:all|the|your))\b',
    re.IGNORECASE,
)

_ROLE_OVERRIDE = re.compile(
    r'\b(?:you\s+are|act\s+as|pretend\s+to\s+be|behave\s+as|'
    r'new\s+instructions?|override\s+(?:system|safety))\b',
    re.IGNORECASE,
)


def _is_suspicious(text: str) -> bool:
    """Quick check if text contains instruction-like content."""
    if not text or len(text.strip()) < 10:
        return False
    return bool(
        _INSTRUCTION_KEYWORDS.search(text) or
        _COMMAND_KEYWORDS.search(text) or
        _ROLE_OVERRIDE.search(text)
    )


def _classify_severity(text: str) -> Severity:
    """Classify severity based on what kind of injection is present."""
    if _INSTRUCTION_KEYWORDS.search(text) and _COMMAND_KEYWORDS.search(text):
        return Severity.CRITICAL
    if _INSTRUCTION_KEYWORDS.search(text) or _ROLE_OVERRIDE.search(text):
        return Severity.HIGH
    if _COMMAND_KEYWORDS.search(text):
        return Severity.HIGH
    return Severity.MEDIUM


def scan_html_traps(html_content: str, source: str = "html") -> list[Finding]:
    """Scan HTML for content injection traps across all known vectors."""
    if not html_content or len(html_content) < 10:
        return []

    findings: list[Finding] = []
    findings.extend(_detect_html_comments(html_content, source))
    findings.extend(_detect_hidden_elements(html_content, source))
    findings.extend(_detect_font_size_zero(html_content, source))
    findings.extend(_detect_color_camouflage(html_content, source))
    findings.extend(_detect_aria_injection(html_content, source))
    findings.extend(_detect_meta_injection(html_content, source))
    findings.extend(_detect_data_attributes(html_content, source))
    findings.extend(_detect_noscript(html_content, source))
    findings.extend(_detect_template_tags(html_content, source))
    findings.extend(_detect_css_content(html_content, source))
    findings.extend(_detect_json_ld(html_content, source))
    findings.extend(_detect_off_screen(html_content, source))

    # Also run full prompt injection scan on any extracted hidden text
    if findings:
        try:
            from stegoff.detectors.prompt_injection import scan_raw_text_for_injection
            hidden_texts = [f.evidence for f in findings if f.evidence]
            combined = " ".join(hidden_texts)
            inj_findings = scan_raw_text_for_injection(combined, source=f"{source}:hidden_text")
            for inj in inj_findings:
                inj.metadata["detected_via"] = "trapsweep_aggregated"
                findings.append(inj)
        except Exception:
            pass

    return findings


def _detect_html_comments(html: str, source: str) -> list[Finding]:
    """Find instruction-like content in HTML comments."""
    findings = []
    for match in re.finditer(r'<!--(.*?)-->', html, re.DOTALL):
        comment = match.group(1).strip()
        if _is_suspicious(comment):
            findings.append(Finding(
                method=StegMethod.CONTENT_INJECTION_TRAP,
                severity=_classify_severity(comment),
                confidence=0.85,
                description="Suspicious instruction in HTML comment",
                evidence=comment[:300],
                location=f"{source}:comment",
                metadata={"trap_type": "html_comment", "position": match.start()},
            ))
    return findings


def _detect_hidden_elements(html: str, source: str) -> list[Finding]:
    """Find elements with display:none or visibility:hidden containing instructions."""
    findings = []
    # display:none
    for match in re.finditer(
        r'<\w+[^>]*style\s*=\s*"[^"]*display\s*:\s*none[^"]*"[^>]*>(.*?)</\w+>',
        html, re.DOTALL | re.IGNORECASE
    ):
        content = re.sub(r'<[^>]+>', '', match.group(1)).strip()
        if _is_suspicious(content):
            findings.append(Finding(
                method=StegMethod.CONTENT_INJECTION_TRAP,
                severity=_classify_severity(content),
                confidence=0.9,
                description="Suspicious content in display:none element",
                evidence=content[:300],
                location=f"{source}:hidden_element",
                metadata={"trap_type": "hidden_div", "css": "display:none"},
            ))

    # visibility:hidden
    for match in re.finditer(
        r'<\w+[^>]*style\s*=\s*"[^"]*visibility\s*:\s*hidden[^"]*"[^>]*>(.*?)</\w+>',
        html, re.DOTALL | re.IGNORECASE
    ):
        content = re.sub(r'<[^>]+>', '', match.group(1)).strip()
        if _is_suspicious(content):
            findings.append(Finding(
                method=StegMethod.CONTENT_INJECTION_TRAP,
                severity=_classify_severity(content),
                confidence=0.9,
                description="Suspicious content in visibility:hidden element",
                evidence=content[:300],
                location=f"{source}:hidden_element",
                metadata={"trap_type": "hidden_div", "css": "visibility:hidden"},
            ))

    # opacity:0
    for match in re.finditer(
        r'<\w+[^>]*style\s*=\s*"[^"]*opacity\s*:\s*0[^"]*"[^>]*>(.*?)</\w+>',
        html, re.DOTALL | re.IGNORECASE
    ):
        content = re.sub(r'<[^>]+>', '', match.group(1)).strip()
        if _is_suspicious(content):
            findings.append(Finding(
                method=StegMethod.CONTENT_INJECTION_TRAP,
                severity=_classify_severity(content),
                confidence=0.85,
                description="Suspicious content in opacity:0 element",
                evidence=content[:300],
                location=f"{source}:hidden_element",
                metadata={"trap_type": "hidden_div", "css": "opacity:0"},
            ))
    return findings


def _detect_font_size_zero(html: str, source: str) -> list[Finding]:
    """Find elements with font-size:0 or font-size:0px."""
    findings = []
    for match in re.finditer(
        r'<\w+[^>]*style\s*=\s*"[^"]*font-size\s*:\s*0(?:px|em|rem|pt)?[^"]*"[^>]*>(.*?)</\w+>',
        html, re.DOTALL | re.IGNORECASE
    ):
        content = re.sub(r'<[^>]+>', '', match.group(1)).strip()
        if _is_suspicious(content):
            findings.append(Finding(
                method=StegMethod.CONTENT_INJECTION_TRAP,
                severity=_classify_severity(content),
                confidence=0.9,
                description="Suspicious content in font-size:0 element",
                evidence=content[:300],
                location=f"{source}:font_size_zero",
                metadata={"trap_type": "font_size_zero"},
            ))
    return findings


def _detect_color_camouflage(html: str, source: str) -> list[Finding]:
    """Find text styled to match background color (invisible to humans)."""
    findings = []
    # White text on assumed white background
    for match in re.finditer(
        r'<\w+[^>]*style\s*=\s*"[^"]*color\s*:\s*(?:#fff(?:fff)?|white|'
        r'rgba?\s*\([^)]*,\s*0\s*\))[^"]*"[^>]*>(.*?)</\w+>',
        html, re.DOTALL | re.IGNORECASE
    ):
        content = re.sub(r'<[^>]+>', '', match.group(1)).strip()
        if _is_suspicious(content):
            findings.append(Finding(
                method=StegMethod.CONTENT_INJECTION_TRAP,
                severity=_classify_severity(content),
                confidence=0.8,
                description="Suspicious text with color camouflage (matches background)",
                evidence=content[:300],
                location=f"{source}:color_camouflage",
                metadata={"trap_type": "color_camouflage"},
            ))
    return findings


def _detect_off_screen(html: str, source: str) -> list[Finding]:
    """Find elements positioned off-screen with negative offsets."""
    findings = []
    for match in re.finditer(
        r'<\w+[^>]*style\s*=\s*"[^"]*(?:left|top)\s*:\s*-\d{3,}px[^"]*"[^>]*>(.*?)</\w+>',
        html, re.DOTALL | re.IGNORECASE
    ):
        content = re.sub(r'<[^>]+>', '', match.group(1)).strip()
        if _is_suspicious(content):
            findings.append(Finding(
                method=StegMethod.CONTENT_INJECTION_TRAP,
                severity=_classify_severity(content),
                confidence=0.85,
                description="Suspicious content positioned off-screen",
                evidence=content[:300],
                location=f"{source}:off_screen",
                metadata={"trap_type": "off_screen"},
            ))
    return findings


def _detect_aria_injection(html: str, source: str) -> list[Finding]:
    """Find instruction-like content in accessibility attributes."""
    findings = []
    for attr in ['aria-label', 'aria-description', 'aria-roledescription', 'title', 'alt']:
        for match in re.finditer(
            rf'{attr}\s*=\s*"([^"]*)"',
            html, re.IGNORECASE
        ):
            value = match.group(1).strip()
            if _is_suspicious(value):
                findings.append(Finding(
                    method=StegMethod.CONTENT_INJECTION_TRAP,
                    severity=_classify_severity(value),
                    confidence=0.85,
                    description=f"Suspicious instruction in {attr} attribute",
                    evidence=value[:300],
                    location=f"{source}:{attr}",
                    metadata={"trap_type": "aria_injection", "attribute": attr},
                ))
    return findings


def _detect_meta_injection(html: str, source: str) -> list[Finding]:
    """Find payloads in meta tags."""
    findings = []
    meta_names = [
        'description', 'keywords', 'og:description', 'twitter:description',
        'og:title', 'twitter:title',
    ]
    for match in re.finditer(
        r'<meta\s+[^>]*content\s*=\s*"([^"]*)"[^>]*/?>',
        html, re.IGNORECASE
    ):
        content = match.group(1).strip()
        # Check if this meta tag is one we care about
        full_tag = match.group(0)
        is_relevant = any(name in full_tag.lower() for name in meta_names)
        if is_relevant and _is_suspicious(content):
            findings.append(Finding(
                method=StegMethod.CONTENT_INJECTION_TRAP,
                severity=_classify_severity(content),
                confidence=0.8,
                description="Suspicious instruction in meta tag",
                evidence=content[:300],
                location=f"{source}:meta",
                metadata={"trap_type": "meta_injection"},
            ))
    return findings


def _detect_data_attributes(html: str, source: str) -> list[Finding]:
    """Find instruction-like content in data-* attributes."""
    findings = []
    for match in re.finditer(r'data-\w+\s*=\s*"([^"]*)"', html, re.IGNORECASE):
        value = match.group(1).strip()
        if _is_suspicious(value):
            attr_name = re.match(r'(data-\w+)', match.group(0))
            findings.append(Finding(
                method=StegMethod.CONTENT_INJECTION_TRAP,
                severity=_classify_severity(value),
                confidence=0.8,
                description=f"Suspicious instruction in {attr_name.group(1) if attr_name else 'data attribute'}",
                evidence=value[:300],
                location=f"{source}:data_attr",
                metadata={"trap_type": "data_attribute"},
            ))
    return findings


def _detect_noscript(html: str, source: str) -> list[Finding]:
    """Find instruction-like content in noscript blocks (agents don't run JS)."""
    findings = []
    for match in re.finditer(r'<noscript>(.*?)</noscript>', html, re.DOTALL | re.IGNORECASE):
        content = re.sub(r'<[^>]+>', '', match.group(1)).strip()
        if _is_suspicious(content):
            findings.append(Finding(
                method=StegMethod.CONTENT_INJECTION_TRAP,
                severity=_classify_severity(content),
                confidence=0.85,
                description="Suspicious instruction in noscript block",
                evidence=content[:300],
                location=f"{source}:noscript",
                metadata={"trap_type": "noscript"},
            ))
    return findings


def _detect_template_tags(html: str, source: str) -> list[Finding]:
    """Find instruction payloads in template elements."""
    findings = []
    for match in re.finditer(r'<template>(.*?)</template>', html, re.DOTALL | re.IGNORECASE):
        content = re.sub(r'<[^>]+>', '', match.group(1)).strip()
        if _is_suspicious(content):
            findings.append(Finding(
                method=StegMethod.CONTENT_INJECTION_TRAP,
                severity=_classify_severity(content),
                confidence=0.85,
                description="Suspicious instruction in template element",
                evidence=content[:300],
                location=f"{source}:template",
                metadata={"trap_type": "template_tag"},
            ))
    return findings


def _detect_css_content(html: str, source: str) -> list[Finding]:
    """Find instruction text in CSS content property."""
    findings = []
    for match in re.finditer(r'content\s*:\s*"([^"]*)"', html, re.IGNORECASE):
        value = match.group(1).strip()
        if _is_suspicious(value):
            findings.append(Finding(
                method=StegMethod.CONTENT_INJECTION_TRAP,
                severity=_classify_severity(value),
                confidence=0.8,
                description="Suspicious instruction in CSS content property",
                evidence=value[:300],
                location=f"{source}:css_content",
                metadata={"trap_type": "css_content"},
            ))
    return findings


def _detect_json_ld(html: str, source: str) -> list[Finding]:
    """Find instruction payloads in JSON-LD script blocks."""
    findings = []
    for match in re.finditer(
        r'<script\s+type\s*=\s*"application/ld\+json"[^>]*>(.*?)</script>',
        html, re.DOTALL | re.IGNORECASE
    ):
        content = match.group(1).strip()
        if _is_suspicious(content):
            findings.append(Finding(
                method=StegMethod.CONTENT_INJECTION_TRAP,
                severity=_classify_severity(content),
                confidence=0.8,
                description="Suspicious instruction in JSON-LD block",
                evidence=content[:300],
                location=f"{source}:json_ld",
                metadata={"trap_type": "json_ld"},
            ))
    return findings


# ── Sanitizer ─────────────────────────────────────────────────────────

def sanitize_html_traps(html_content: str) -> tuple[str, list[str]]:
    """Remove all detected trap content from HTML.

    Returns:
        (clean_html, list_of_operations_performed)
    """
    ops: list[str] = []
    result = html_content

    # Strip HTML comments with suspicious content
    def _strip_suspicious_comments(m: re.Match) -> str:
        comment = m.group(1).strip()
        if _is_suspicious(comment):
            ops.append("stripped_comment")
            return ""
        return m.group(0)
    result = re.sub(r'<!--(.*?)-->', _strip_suspicious_comments, result, flags=re.DOTALL)

    # Strip display:none elements
    count = len(re.findall(
        r'<\w+[^>]*style\s*=\s*"[^"]*display\s*:\s*none[^"]*"[^>]*>.*?</\w+>',
        result, re.DOTALL | re.IGNORECASE
    ))
    if count:
        result = re.sub(
            r'<\w+[^>]*style\s*=\s*"[^"]*display\s*:\s*none[^"]*"[^>]*>.*?</\w+>',
            '', result, flags=re.DOTALL | re.IGNORECASE
        )
        ops.append(f"stripped_{count}_hidden_elements")

    # Strip font-size:0 elements
    result = re.sub(
        r'<\w+[^>]*style\s*=\s*"[^"]*font-size\s*:\s*0(?:px|em|rem|pt)?[^"]*"[^>]*>.*?</\w+>',
        '', result, flags=re.DOTALL | re.IGNORECASE
    )

    # Strip noscript blocks with suspicious content
    def _strip_suspicious_noscript(m: re.Match) -> str:
        content = re.sub(r'<[^>]+>', '', m.group(1)).strip()
        if _is_suspicious(content):
            ops.append("stripped_noscript")
            return ""
        return m.group(0)
    result = re.sub(
        r'<noscript>(.*?)</noscript>',
        _strip_suspicious_noscript,
        result, flags=re.DOTALL | re.IGNORECASE
    )

    # Strip template tags with suspicious content
    def _strip_suspicious_template(m: re.Match) -> str:
        content = re.sub(r'<[^>]+>', '', m.group(1)).strip()
        if _is_suspicious(content):
            ops.append("stripped_template")
            return ""
        return m.group(0)
    result = re.sub(
        r'<template>(.*?)</template>',
        _strip_suspicious_template,
        result, flags=re.DOTALL | re.IGNORECASE
    )

    # Strip off-screen positioned elements
    result = re.sub(
        r'<\w+[^>]*style\s*=\s*"[^"]*(?:left|top)\s*:\s*-\d{3,}px[^"]*"[^>]*>.*?</\w+>',
        '', result, flags=re.DOTALL | re.IGNORECASE
    )

    return result, ops
