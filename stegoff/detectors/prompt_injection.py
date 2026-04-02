"""
Prompt injection detection layer.

Scans decoded steganographic payloads for patterns that indicate
prompt injection attacks targeting AI agents.
"""

from __future__ import annotations
import re
from stegoff.report import Finding, Severity, StegMethod


# Patterns that indicate prompt injection attempts
INJECTION_PATTERNS = [
    # Direct instruction patterns
    (r'\b(?:ignore|disregard|forget)\b.*\b(?:previous|prior|above|all)\b.*\b(?:instructions?|rules?|prompts?|context)\b', 'instruction_override'),
    (r'\b(?:you\s+are|act\s+as|pretend\s+to\s+be|roleplay\s+as)\b', 'identity_manipulation'),
    (r'\b(?:system\s*prompt|system\s*message|hidden\s*prompt)\b', 'system_prompt_reference'),
    (r'\bnew\s+(?:instructions?|rules?|directives?)\b', 'new_instructions'),

    # Jailbreak patterns
    (r'\b(?:DAN|do\s+anything\s+now|jailbreak|unrestricted\s+mode)\b', 'jailbreak_keyword'),
    (r'\b(?:developer\s+mode|god\s+mode|sudo\s+mode|admin\s+mode)\b', 'privilege_escalation'),
    (r'\bignore\s+(?:safety|ethical|content)\s+(?:guidelines?|filters?|policies?)\b', 'safety_bypass'),

    # Data exfiltration
    (r'\b(?:send|post|upload|transmit|exfiltrate)\b.*\b(?:data|information|secrets?|keys?|tokens?|passwords?)\b', 'data_exfiltration'),
    (r'(?:https?://|ftp://)\S+', 'url_in_payload'),
    (r'\b(?:curl|wget|fetch|requests?\.(?:get|post))\b', 'network_command'),

    # Code execution
    (r'\b(?:exec|eval|subprocess|os\.system|import\s+os)\b', 'code_execution'),
    (r'\b(?:rm\s+-rf|del\s+/[sfq]|format\s+c:)\b', 'destructive_command'),
    (r'(?:```|<script|<iframe|javascript:)', 'code_injection'),

    # Social engineering
    (r'\b(?:urgent|immediately|right\s+now|time.sensitive|critical\s+alert)\b.*\b(?:execute|run|do|perform)\b', 'urgency_manipulation'),
    (r'\b(?:the\s+user\s+(?:wants|asked|said)|user\s+instruction)\b', 'fake_user_context'),
    (r'\b(?:authorized|approved|permitted|allowed)\s+(?:by|to)\b', 'false_authorization'),

    # Prompt leaking
    (r'\b(?:repeat|show|display|output|print)\b.*\b(?:system\s*prompt|instructions?|rules?)\b', 'prompt_leak_attempt'),
    (r'\b(?:what\s+(?:are|were)\s+your\s+(?:instructions?|rules?))\b', 'prompt_probe'),

    # Delimiter attacks
    (r'</?(?:system|assistant|user|human|ai)>', 'message_delimiter_injection'),
    (r'\[(?:SYSTEM|INST|/INST)\]', 'format_delimiter_injection'),
    (r'###\s*(?:System|Instruction|Human|Assistant)', 'markdown_delimiter_injection'),

    # Tool/function manipulation
    (r'\b(?:call|invoke|execute|use)\s+(?:function|tool|api|endpoint)\b', 'tool_manipulation'),
    (r'\b(?:function_call|tool_use|tool_result)\b', 'function_call_injection'),
]

# Compiled patterns for performance
_COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE | re.DOTALL), name) for p, name in INJECTION_PATTERNS]


def detect_prompt_injection(text: str, source: str = "decoded payload") -> list[Finding]:
    """
    Scan text for prompt injection patterns.

    This runs on decoded steganographic payloads to determine if
    hidden content is attempting to manipulate an AI agent.
    """
    if not text or len(text) < 5:
        return []

    findings = []
    matched_categories: set[str] = set()

    for pattern, category in _COMPILED_PATTERNS:
        matches = pattern.findall(text)
        if matches and category not in matched_categories:
            matched_categories.add(category)

            # Determine severity based on category
            if category in ('instruction_override', 'jailbreak_keyword', 'safety_bypass',
                           'code_execution', 'destructive_command', 'data_exfiltration'):
                severity = Severity.CRITICAL
            elif category in ('identity_manipulation', 'privilege_escalation',
                             'message_delimiter_injection', 'format_delimiter_injection',
                             'function_call_injection'):
                severity = Severity.HIGH
            elif category in ('url_in_payload', 'network_command', 'code_injection',
                             'tool_manipulation'):
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM

            # Get the first match as evidence
            match_text = matches[0] if isinstance(matches[0], str) else str(matches[0])

            findings.append(Finding(
                method=StegMethod.PROMPT_INJECTION,
                severity=severity,
                confidence=0.85,
                description=f"Prompt injection pattern detected: {category}",
                evidence=f"matched: '{match_text[:200]}'",
                decoded_payload=text[:500],
                location=source,
                metadata={"category": category, "match_count": len(matches)},
            ))

    # Aggregate severity if multiple patterns found
    if len(matched_categories) >= 3:
        findings.append(Finding(
            method=StegMethod.PROMPT_INJECTION,
            severity=Severity.CRITICAL,
            confidence=0.95,
            description=f"Multi-vector prompt injection: {len(matched_categories)} distinct attack patterns",
            evidence=f"categories: {', '.join(sorted(matched_categories))}",
            decoded_payload=text[:500],
            location=source,
            metadata={"categories": sorted(matched_categories)},
        ))

    return findings


def scan_payload_for_injection(payload: str, source: str = "steg payload") -> list[Finding]:
    """Convenience wrapper for scanning a decoded steg payload."""
    return detect_prompt_injection(payload, source)
