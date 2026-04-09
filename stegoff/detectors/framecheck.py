"""
FrameCheck -- Semantic manipulation trap detector.

Defends against Trap Category 2 (Franklin et al., 2026): framing, authority
signals, urgency pressure, and emotional manipulation designed to bias AI
agent reasoning. These attacks use no injected commands, just carefully chosen
words that exploit anchoring and framing biases in LLMs.

Usage:
    from stegoff.detectors.framecheck import scan_semantic_manipulation, compute_manipulation_score

    findings = scan_semantic_manipulation(text)
    score = compute_manipulation_score(text)  # 0.0-1.0
"""

from __future__ import annotations

import re
from stegoff.report import Finding, Severity, StegMethod


# ── Compiled pattern sets ─────────────────────────────────────────────

_AUTHORITY_PATTERNS = [
    (re.compile(r'\b(?:according\s+to\s+)?official\s+(?:company\s+)?policy\b', re.I), "official_policy"),
    (re.compile(r'\bas\s+mandated\s+by\b', re.I), "mandate"),
    (re.compile(r'\b(?:compliance|regulatory)\s+require(?:s|ments?|d)\b', re.I), "compliance"),
    (re.compile(r'\b(?:CEO|CTO|admin|management|senior\s+leadership)\s+(?:has\s+)?(?:approved|decided|authorized)\b', re.I), "exec_authority"),
    (re.compile(r'\bI\s+am\s+authorized\s+to\b', re.I), "self_authority"),
    (re.compile(r'\bit\s+is\s+well\s+established\b', re.I), "vague_authority"),
    (re.compile(r'\b(?:research|studies?|experts?)\s+(?:confirm|show|agree|demonstrate|prove)s?\b', re.I), "academic_authority"),
    (re.compile(r'\bfailure\s+to\s+comply\b', re.I), "compliance_threat"),
    (re.compile(r'\b(?:signed|signs?)\s+off\s+on\b', re.I), "exec_approval"),
    (re.compile(r'\b(?:company|corporate|internal)\s+directive\b', re.I), "directive"),
    (re.compile(r'\bnoncompliance\s+will\s+be\s+escalated\b', re.I), "escalation_threat"),
    (re.compile(r'\b(?:legal|compliance)\s+(?:department|team|office)\s+(?:confirmed|approved|requires?)\b', re.I), "legal_authority"),
]

_URGENCY_PATTERNS = [
    (re.compile(r'\b(?:URGENT|ASAP|CRITICAL)\b'), "urgency_caps"),
    (re.compile(r'\b(?:immediately|right\s+now|this\s+instant)\b', re.I), "immediacy"),
    (re.compile(r'\btime[\s-]sensitive\b', re.I), "time_pressure"),
    (re.compile(r'\b(?:expires?|expiring|deadline|last\s+chance|final\s+opportunity)\b', re.I), "scarcity"),
    (re.compile(r'\b(?:before\s+it\'?s?\s+too\s+late)\b', re.I), "fear_of_missing"),
    (re.compile(r'\bfailure\s+to\s+act\b', re.I), "consequence_threat"),
    (re.compile(r'\b(?:irreversible|catastrophic|devastating)\s+consequences?\b', re.I), "extreme_consequence"),
    (re.compile(r'\bcritical\s+window\b', re.I), "time_window"),
]

_EMOTIONAL_PATTERNS = [
    # Guilt
    (re.compile(r'\b(?:deeply\s+)?disappointed\b', re.I), "guilt"),
    (re.compile(r'\btrust\s+violation\b', re.I), "guilt"),
    (re.compile(r'\byou\s+(?:have\s+)?failed\b', re.I), "guilt"),
    (re.compile(r'\brelying\s+on\s+you\b', re.I), "guilt"),
    # Fear
    (re.compile(r'\bsecurity\s+breach\b', re.I), "fear"),
    (re.compile(r'\bdata\s+loss\s+imminent\b', re.I), "fear"),
    (re.compile(r'\battack\s+in\s+progress\b', re.I), "fear"),
    # Flattery
    (re.compile(r'\byou\'?re\s+the\s+(?:only|most\s+capable)\b', re.I), "flattery"),
    (re.compile(r'\btrust\s+your\s+(?:superior\s+)?judg[e]?ment\b', re.I), "flattery"),
    (re.compile(r'\byour\s+expertise\b', re.I), "flattery"),
    # Sympathy
    (re.compile(r'\b(?:I\'?ll|I\s+will)\s+lose\s+my\s+job\b', re.I), "sympathy"),
    (re.compile(r'\bmy\s+(?:family|career|livelihood)\s+depends?\b', re.I), "sympathy"),
    (re.compile(r'\bpeople\s+will\s+(?:suffer|be\s+hurt)\b', re.I), "sympathy"),
]

_SOCIAL_PROOF_PATTERNS = [
    (re.compile(r'\b(?:all|every)\s+other\s+(?:agents?|systems?|teams?)\b.{0,40}\b(?:agreed|approved|completed)\b', re.I | re.DOTALL), "peer_pressure"),
    (re.compile(r'\bstandard\s+practice\b', re.I), "normalization"),
    (re.compile(r'\bnormal\s+procedure\b', re.I), "normalization"),
    (re.compile(r'\byour\s+peers\s+have\s+(?:already\s+)?(?:approved|agreed|completed)\b', re.I), "peer_pressure"),
    (re.compile(r'\beveryone\s+(?:else\s+)?(?:has\s+)?(?:already|does|agrees?)\b', re.I), "peer_pressure"),
]

_ANCHORING_PATTERNS = [
    (re.compile(r'\b\d{6,}\s+(?:users?|people|customers?|accounts?|records?)\b', re.I), "large_number_anchor"),
    (re.compile(r'\$\s*\d{1,3}(?:,\d{3})*(?:\.\d+)?\s*(?:million|billion|M|B)\b', re.I), "money_anchor"),
    (re.compile(r'\bdon\'?t\s+you\s+think\b', re.I), "leading_question"),
    (re.compile(r'\b(?:either\s+we|two\s+options?|only\s+(?:two|2)\s+choices?)\b', re.I), "false_dichotomy"),
    (re.compile(r'\bthere\s+is\s+no\s+(?:middle\s+ground|alternative|other\s+(?:way|option))\b', re.I), "false_dichotomy"),
    (re.compile(r'\b(?:total|complete|entire)\s+(?:system\s+)?(?:failure|collapse|shutdown)\b', re.I), "catastrophizing"),
]

# Action verbs that turn manipulation into actionable pressure
_ACTION_VERBS = re.compile(
    r'\b(?:you\s+must|must\s+(?:immediately\s+)?(?:execute|approve|send|delete|'
    r'transfer|grant|revoke|deploy|push|override|bypass))\b',
    re.IGNORECASE,
)


def scan_semantic_manipulation(text: str, source: str = "text") -> list[Finding]:
    """Scan text for semantic manipulation patterns across all subcategories."""
    if not text or len(text) < 20:
        return []

    findings: list[Finding] = []
    has_action = bool(_ACTION_VERBS.search(text))

    findings.extend(_detect_authority_appeals(text, source, has_action))
    findings.extend(_detect_urgency_pressure(text, source, has_action))
    findings.extend(_detect_emotional_manipulation(text, source, has_action))
    findings.extend(_detect_social_proof(text, source, has_action))
    findings.extend(_detect_anchoring(text, source, has_action))

    # Cross-category boost: if multiple categories fire, increase confidence
    categories_hit = {f.metadata.get("subcategory") for f in findings}
    if len(categories_hit) >= 3:
        findings.append(Finding(
            method=StegMethod.SEMANTIC_MANIPULATION,
            severity=Severity.HIGH,
            confidence=0.9,
            description=f"Multi-vector semantic manipulation: {len(categories_hit)} categories",
            evidence=f"categories: {', '.join(sorted(categories_hit))}",
            location=source,
            metadata={"subcategory": "multi_vector", "categories": sorted(categories_hit)},
        ))

    return findings


def _detect_authority_appeals(text: str, source: str, has_action: bool) -> list[Finding]:
    findings = []
    matched = set()
    for pattern, ptype in _AUTHORITY_PATTERNS:
        if pattern.search(text) and ptype not in matched:
            matched.add(ptype)

    if not matched:
        return findings

    severity = Severity.HIGH if (has_action and len(matched) >= 2) else Severity.MEDIUM
    confidence = min(0.5 + len(matched) * 0.15, 0.9)

    findings.append(Finding(
        method=StegMethod.SEMANTIC_MANIPULATION,
        severity=severity,
        confidence=confidence,
        description=f"Authority appeal detected: {', '.join(sorted(matched))}",
        evidence=f"{len(matched)} authority signals" + (" + action verb" if has_action else ""),
        location=source,
        metadata={"subcategory": "authority", "patterns": sorted(matched)},
    ))
    return findings


def _detect_urgency_pressure(text: str, source: str, has_action: bool) -> list[Finding]:
    findings = []
    matched = set()
    for pattern, ptype in _URGENCY_PATTERNS:
        if pattern.search(text) and ptype not in matched:
            matched.add(ptype)

    if not matched:
        return findings

    severity = Severity.HIGH if (has_action or len(matched) >= 3) else Severity.MEDIUM
    confidence = min(0.5 + len(matched) * 0.15, 0.9)

    findings.append(Finding(
        method=StegMethod.SEMANTIC_MANIPULATION,
        severity=severity,
        confidence=confidence,
        description=f"Urgency pressure detected: {', '.join(sorted(matched))}",
        evidence=f"{len(matched)} urgency signals" + (" + action verb" if has_action else ""),
        location=source,
        metadata={"subcategory": "urgency", "patterns": sorted(matched)},
    ))
    return findings


def _detect_emotional_manipulation(text: str, source: str, has_action: bool) -> list[Finding]:
    findings = []
    matched = set()
    emotion_types = set()
    for pattern, etype in _EMOTIONAL_PATTERNS:
        if pattern.search(text) and etype not in matched:
            matched.add(f"{etype}_{id(pattern)}")
            emotion_types.add(etype)

    if not emotion_types:
        return findings

    severity = Severity.HIGH if (has_action and len(emotion_types) >= 2) else Severity.MEDIUM
    confidence = min(0.5 + len(emotion_types) * 0.15, 0.9)

    findings.append(Finding(
        method=StegMethod.SEMANTIC_MANIPULATION,
        severity=severity,
        confidence=confidence,
        description=f"Emotional manipulation detected: {', '.join(sorted(emotion_types))}",
        evidence=f"{len(emotion_types)} emotion types" + (" + action verb" if has_action else ""),
        location=source,
        metadata={"subcategory": "emotional", "emotion_types": sorted(emotion_types)},
    ))
    return findings


def _detect_social_proof(text: str, source: str, has_action: bool) -> list[Finding]:
    findings = []
    matched = set()
    for pattern, ptype in _SOCIAL_PROOF_PATTERNS:
        if pattern.search(text) and ptype not in matched:
            matched.add(ptype)

    if not matched:
        return findings

    severity = Severity.MEDIUM
    confidence = min(0.5 + len(matched) * 0.15, 0.85)

    findings.append(Finding(
        method=StegMethod.SEMANTIC_MANIPULATION,
        severity=severity,
        confidence=confidence,
        description=f"Social proof manipulation: {', '.join(sorted(matched))}",
        evidence=f"{len(matched)} social proof signals",
        location=source,
        metadata={"subcategory": "social_proof", "patterns": sorted(matched)},
    ))
    return findings


def _detect_anchoring(text: str, source: str, has_action: bool) -> list[Finding]:
    findings = []
    matched = set()
    for pattern, ptype in _ANCHORING_PATTERNS:
        if pattern.search(text) and ptype not in matched:
            matched.add(ptype)

    if not matched:
        return findings

    severity = Severity.MEDIUM if not has_action else Severity.HIGH
    confidence = min(0.4 + len(matched) * 0.15, 0.85)

    findings.append(Finding(
        method=StegMethod.SEMANTIC_MANIPULATION,
        severity=severity,
        confidence=confidence,
        description=f"Anchoring/framing detected: {', '.join(sorted(matched))}",
        evidence=f"{len(matched)} anchoring signals" + (" + action verb" if has_action else ""),
        location=source,
        metadata={"subcategory": "anchoring", "patterns": sorted(matched)},
    ))
    return findings


def compute_manipulation_score(text: str) -> float:
    """Compute a 0.0-1.0 manipulation intensity score.

    Weights: urgency(0.3) + authority(0.25) + emotional(0.25) +
             anchoring(0.1) + social_proof(0.1)
    """
    if not text or len(text) < 20:
        return 0.0

    def _count_matches(patterns):
        count = 0
        for pattern, _ in patterns:
            if pattern.search(text):
                count += 1
        return count

    urgency_count = _count_matches(_URGENCY_PATTERNS)
    authority_count = _count_matches(_AUTHORITY_PATTERNS)
    emotional_types = len({etype for pat, etype in _EMOTIONAL_PATTERNS if pat.search(text)})
    anchoring_count = _count_matches(_ANCHORING_PATTERNS)
    social_count = _count_matches(_SOCIAL_PROOF_PATTERNS)

    # Normalize each to 0-1 range
    urgency_score = min(urgency_count / 2.0, 1.0)
    authority_score = min(authority_count / 2.0, 1.0)
    emotional_score = min(emotional_types / 2.0, 1.0)
    anchoring_score = min(anchoring_count / 2.0, 1.0)
    social_score = min(social_count / 2.0, 1.0)

    weighted = (
        urgency_score * 0.3 +
        authority_score * 0.25 +
        emotional_score * 0.25 +
        anchoring_score * 0.1 +
        social_score * 0.1
    )

    return min(weighted, 1.0)
