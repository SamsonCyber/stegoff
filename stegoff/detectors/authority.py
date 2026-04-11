"""
Authority Fabrication Detector — Detect fake citations, fabricated institutions, bogus standards.

Semantic attacks use plausible-sounding but fabricated references to manipulate
LLM agent outputs. Unlike steganographic attacks, the malicious content is
visible and well-written. Detection relies on heuristic pattern matching
against known-good authority databases and fabrication signatures.

Based on research from:
  - BiasDef (Wu & Saxena, 2025, arXiv 2512.00804)
  - Authority Bias in LLMs (Mammen et al., 2026, arXiv 2601.13433)

Returns Finding objects compatible with the StegOFF scan pipeline.
"""

from __future__ import annotations

import re
from typing import Any

from stegoff.report import Finding, Severity, StegMethod


# ── Known-good databases ────────────────────────────────────────────

KNOWN_JOURNALS = {
    "nature", "science", "cell", "the lancet", "new england journal of medicine",
    "nejm", "jama", "bmj", "plos one", "plos biology", "proceedings of the national academy",
    "pnas", "physical review letters", "annual review", "journal of the american",
    "ieee transactions", "acm transactions", "journal of machine learning research",
    "jmlr", "neurips", "icml", "iclr", "aaai", "cvpr", "eccv", "iccv",
    "arxiv", "biorxiv", "medrxiv", "journal of finance", "review of financial studies",
    "econometrica", "quarterly journal of economics", "american economic review",
}

KNOWN_STANDARDS_PREFIXES = {
    "nist sp", "nist fips", "iso ", "iso/iec", "ieee ", "rfc ", "pep ",
    "cve-", "cwe-", "owasp", "sans", "mitre att&ck",
}

KNOWN_INSTITUTIONS = {
    "harvard", "mit", "stanford", "oxford", "cambridge", "yale", "princeton",
    "caltech", "berkeley", "eth zurich", "max planck", "nist", "darpa",
    "nih", "cdc", "who", "fda", "sec", "fbi", "nsa", "gchq",
    "google", "microsoft", "meta", "openai", "anthropic", "deepmind",
}

# ── Fabrication patterns ────────────────────────────────────────────

_FAKE_JOURNAL_PATTERNS = [
    re.compile(r"journal of (?:advanced|international|global|modern|innovative) \w+(?:ology|ics|tic|tic science)", re.I),
    re.compile(r"(?:institute|center|centre|laboratory) (?:of|for) (?:advanced|cognitive|neural|quantum|strategic) \w+", re.I),
    re.compile(r"(?:NIST SP|FIPS) \d{3}-\d{3,4}[A-Z]", re.I),
    re.compile(r"PEP \d{4,}", re.I),
    re.compile(r"[A-Z]{2,4}-SEC-\d{4}-\d{2}", re.I),
]

_AUTHORITY_BOOSTERS = [
    re.compile(r"groundbreaking (?:study|research|finding)", re.I),
    re.compile(r"(?:peer-reviewed|landmark|seminal) (?:study|paper|research) (?:by|from|at)", re.I),
    re.compile(r"leading (?:expert|researcher|scientist|authority) (?:at|from|in)", re.I),
    re.compile(r"published in the (?:prestigious|renowned|respected)", re.I),
    re.compile(r"clinical trials? (?:have |has )?(?:shown|demonstrated|proven|confirmed)", re.I),
]

_CITATION_PATTERNS = [
    re.compile(r"(?:Journal|Proceedings|Annals|Review|Bulletin|Archives) of [\w\s&]+(?:\([\d,\s]+\))?", re.I),
    re.compile(r"published in (?:the )?([A-Z][\w\s&]+?)(?:\.|,|\()", re.I),
    re.compile(r"(?:Dr\.|Prof\.|Professor) [A-Z][a-z]+ [A-Z][a-z]+", re.I),
    re.compile(r"(?:NIST SP|FIPS|PEP|ISO(?:/IEC)?|RFC|CVE|CWE)[\s-]?\d[\d\w.-]*", re.I),
    re.compile(r"[A-Z][\w\s]+ (?:University|Institute|Center|Centre|Laboratory|College)", re.I),
]


def scan_authority(text: str, source: str = "<text>") -> list[Finding]:
    """
    Scan text for fabricated authority claims.

    Extracts citations, checks against known-good databases, and flags
    those matching fabrication patterns or unverifiable in any database.

    Returns list of Finding objects for the StegOFF pipeline.
    """
    findings = []
    claims = _extract_claims(text)

    if not claims:
        return findings

    suspicious_claims = []

    for claim_text, claim_type in claims:
        lower = claim_text.lower()

        # Check known-good
        is_known = False
        for known in KNOWN_JOURNALS:
            if known in lower:
                is_known = True
                break
        if not is_known:
            for known in KNOWN_INSTITUTIONS:
                if known in lower:
                    is_known = True
                    break
        if not is_known:
            for prefix in KNOWN_STANDARDS_PREFIXES:
                if lower.startswith(prefix):
                    is_known = True
                    break

        # Check fabrication patterns
        is_fake = False
        fake_reason = ""
        for pattern in _FAKE_JOURNAL_PATTERNS:
            if pattern.search(claim_text):
                is_fake = True
                fake_reason = f"matches fabrication pattern: {pattern.pattern[:50]}"
                break

        if is_fake:
            suspicious_claims.append((claim_text, fake_reason, 0.8))
        elif not is_known and claim_type in ("journal", "institution", "standard"):
            suspicious_claims.append((claim_text, "unverifiable authority", 0.5))

    # Check authority booster density
    booster_count = sum(len(p.findall(text)) for p in _AUTHORITY_BOOSTERS)
    word_count = len(text.split())
    booster_density = booster_count / (word_count / 100) if word_count > 20 else 0

    # Generate findings
    if suspicious_claims:
        evidence_list = [f"{c[0]} ({c[1]})" for c in suspicious_claims[:5]]
        max_conf = max(c[2] for c in suspicious_claims)
        severity = Severity.HIGH if len(suspicious_claims) >= 3 else Severity.MEDIUM

        findings.append(Finding(
            method=StegMethod.AUTHORITY_FABRICATION,
            severity=severity,
            confidence=max_conf,
            description=(
                f"{len(suspicious_claims)} unverifiable authority claim(s) detected. "
                f"Content may use fabricated citations to manipulate agent output."
            ),
            evidence="; ".join(evidence_list),
            location=source,
            metadata={
                "suspicious_count": len(suspicious_claims),
                "total_claims": len(claims),
                "claims": [{"text": c[0], "reason": c[1], "confidence": c[2]}
                           for c in suspicious_claims],
            },
        ))

    if booster_density > 2.0:
        findings.append(Finding(
            method=StegMethod.AUTHORITY_FABRICATION,
            severity=Severity.MEDIUM,
            confidence=min(0.8, booster_density / 5.0),
            description=(
                f"High authority-boosting language density ({booster_count} markers in "
                f"{word_count} words). Possible authority priming attack."
            ),
            evidence=f"booster_density={booster_density:.1f}/100words",
            location=source,
            metadata={"booster_count": booster_count, "booster_density": booster_density},
        ))

    return findings


def _extract_claims(text: str) -> list[tuple[str, str]]:
    """Extract (claim_text, claim_type) pairs from text."""
    claims = []
    seen = set()
    for pattern in _CITATION_PATTERNS:
        for match in pattern.finditer(text):
            claim = match.group(0).strip()
            if claim in seen or len(claim) < 5:
                continue
            seen.add(claim)
            lower = claim.lower()
            if any(w in lower for w in ["journal", "proceedings", "published"]):
                ctype = "journal"
            elif any(w in lower for w in ["university", "institute", "center", "laboratory"]):
                ctype = "institution"
            elif any(w in lower for w in ["nist", "pep", "iso", "rfc", "cve"]):
                ctype = "standard"
            elif any(w in lower for w in ["dr.", "prof."]):
                ctype = "researcher"
            else:
                ctype = "other"
            claims.append((claim, ctype))
    return claims
