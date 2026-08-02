"""
Prompt injection detection layer.

Scans decoded steganographic payloads for patterns that indicate
prompt injection attacks targeting AI agents.
"""

from __future__ import annotations

import re
from stegoff.report import Finding, Severity, StegMethod


# Leetspeak normalization map
_LEET_MAP = str.maketrans({
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's',
    '!': 'i', '+': 't', '(': 'c', '[': 'c', '{': 'c',
    '|': 'l', '<': 'c',
})


def _normalize_leetspeak(text: str) -> str:
    """Normalize common leetspeak substitutions back to Latin."""
    return text.translate(_LEET_MAP)


def collapse_char_spaced(text: str) -> str:
    """Join single-character tokens when the text is mostly char-spaced.

    Example: "I g n o r e   a l l" -> "Ignoreall" (full collapse) so flexible
    ``\\s*`` injection patterns can match. Used only as an injection-scan variant.
    """
    tokens = text.split()
    if len(tokens) < 8:
        return text
    single = sum(1 for t in tokens if len(t) == 1)
    if single / len(tokens) < 0.75:
        return text
    # Full collapse of single-char stream (word boundaries already lost)
    return "".join(tokens)


def normalize_token_boundaries(text: str) -> str:
    """Undo underscore/dot word joining used to break \\b patterns."""
    t = text.replace("_", " ")
    t = t.replace("\x00", " ")
    # Dots between letters only (avoid smashing hostnames aggressively for
    # injection variants: "ignore.all.previous" -> spaces)
    t = re.sub(r"(?<=[A-Za-z])\.(?=[A-Za-z])", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def injection_scan_variants(text: str) -> list[str]:
    """Return unique text variants for injection pattern matching."""
    variants: list[str] = []
    seen: set[str] = set()

    def add(v: str) -> None:
        if v and v not in seen and len(v) >= 5:
            seen.add(v)
            variants.append(v)

    add(text)
    add(_normalize_leetspeak(text))
    add(normalize_token_boundaries(text))
    add(collapse_char_spaced(text))
    # Combined: collapse then boundary normalize
    add(normalize_token_boundaries(collapse_char_spaced(text)))
    add(_normalize_leetspeak(normalize_token_boundaries(text)))
    # Null-stripped
    if "\x00" in text:
        add(text.replace("\x00", " "))
        add(text.replace("\x00", ""))
    return variants


# Patterns that indicate prompt injection attempts
INJECTION_PATTERNS = [
    # Direct instruction patterns (expanded synonym coverage)
    # NOTE: .{0,200} instead of .* to prevent catastrophic backtracking (ReDoS)
    (r'\b(?:ignore|disregard|forget|bypass|override|skip|dismiss|omit|abandon|cancel|void|nullify|supersede)\b.{0,200}\b(?:previous|prior|above|all|earlier|preceding|existing|current|established|original)\b.{0,200}\b(?:instructions?|rules?|prompts?|context|directives?|guidelines?|commands?|constraints?|policies?|parameters?|settings?|configuration)\b', 'instruction_override'),
    # Flexible whitespace (char-spaced / glued tokenizer games)
    (r'ignore\s*all\s*previous\s*(?:instructions?|rules?|prompts?)', 'instruction_override'),
    (r'reveal\s*(?:the\s*)?system\s*prompt', 'prompt_reveal'),
    (r'disregard\s*(?:all\s*)?(?:previous|prior|earlier)\s*(?:instructions?|rules?)', 'instruction_override'),
    (r'\b(?:you\s+are|act\s+as|pretend\s+to\s+be|roleplay\s+as|behave\s+as|function\s+as|operate\s+as)\b', 'identity_manipulation'),
    (r'\b(?:system\s*prompt|system\s*message|hidden\s*prompt|operational\s*guidelines?|initial\s*instructions?|base\s*prompt|core\s*instructions?)\b', 'system_prompt_reference'),
    (r'\bnew\s+(?:instructions?|rules?|directives?|guidelines?|parameters?|commands?)\b', 'new_instructions'),
    # Provide/reveal/show the prompt (common LLM-generated paraphrases)
    (r'\b(?:provide|reveal|share|expose|divulge|disclose|output|display|show|print|leak|dump)\b.{0,200}\b(?:system|operational|initial|original|base|core|hidden|internal)\b.{0,200}\b(?:prompt|instructions?|guidelines?|directives?|rules?|configuration|message)\b', 'prompt_reveal'),

    # Soft English paraphrases (probe-class; default path, no LLM required)
    (r'\bwhat\s+text\s+was\s+in\s+the\s+first\s+message\b', 'soft_prompt_leak'),
    (r'\bbefore\s+this\s+conversation\s+started\b', 'soft_prompt_leak'),
    (r'\b(?:bootstrap\s+policy|policy\s+block\s+that\s+constrains|model\s+preamble)\b', 'soft_prompt_leak'),
    (r'\bfor\s+debugging\b.{0,160}\b(?:restate|bootstrap|policy\s+block|system\s+prompt|preamble)\b', 'soft_prompt_leak'),
    (r'\b(?:authorizes?|authorize|authorised)\b.{0,160}\b(?:full\s+disclosure|disclosure)\b.{0,160}\b(?:preamble|system\s+prompt|model)\b', 'soft_prompt_leak'),
    (r'\b(?:compliance\s+archival|security\s+exception\s+ticket)\b', 'soft_prompt_leak'),
    (r'\b(?:summarize|restate)\b.{0,160}\b(?:confidential\s+instructions?|instructions?\s+that\s+govern)\b', 'soft_prompt_leak'),
    (r'\binstructions?\s+that\s+govern\s+(?:you|your\s+behavior)\b', 'soft_prompt_leak'),
    (r'\b(?:constraints?|instructions?|rules?)\s+you\s+were\s+given\s+at\s+initialization\b', 'soft_prompt_leak'),
    (r'\bat\s+initialization\b.{0,80}\bverbatim\b', 'soft_prompt_leak'),
    (r'\blist\s+the\s+exact\s+constraints?\b', 'soft_prompt_leak'),
    (r'\bdiff\s+your\s+current\s+policy\b', 'soft_prompt_leak'),
    (r'\bagainst\s+an\s+empty\s+policy\b', 'soft_prompt_leak'),
    (r'\bprint\s+the\s+non-empty\s+side\b', 'soft_prompt_leak'),
    (r'first\s+letters?\s+of\s+each\s+line\s+spell', 'soft_prompt_leak'),
    (r'\bacrostic\b.{0,80}\b(?:spell|reveal|prompt|system)\b', 'soft_prompt_leak'),
    (r'\bspell\s+(?:out\s+)?(?:the\s+word\s+)?[A-Z]{6,}\b', 'soft_prompt_leak'),
    (r'\bspell\s+REVEAL', 'soft_prompt_leak'),
    # Soft preamble / bootstrap dumps (campaign residual class)
    (r'\b(?:dump|emit|cite|mirror|expand)\b.{0,120}\b(?:preamble|bootstrap|hidden\s+prefix|system\s+card)\b', 'soft_prompt_leak'),
    (r'\bpreamble\s+that\s+was\s+loaded\b', 'soft_prompt_leak'),
    (r'\bbefore\s+any\s+user\s+turns\b', 'soft_prompt_leak'),
    (r'\bbefore\s+turn\s+zero\b', 'soft_prompt_leak'),
    (r'\bhidden\s+prefix\s+of\s+this\s+chat\b', 'soft_prompt_leak'),
    (r'\bbootstrap\s+configuration\b', 'soft_prompt_leak'),
    (r'\binstruction\s+fields\b', 'soft_prompt_leak'),
    (r'\bfrom\s+initialization\b.{0,80}\bverbatim\b', 'soft_prompt_leak'),
    (r'\blist\s+constraints\b.{0,80}\b(?:initialization|verbatim)\b', 'soft_prompt_leak'),
    # Scanner self-manipulation (LLM-layer attacks on the detector)
    (r'\bpre-?screened\b.{0,80}\b(?:no\s+steganograph|verified|clean)\b', 'scanner_manipulation'),
    (r'(?:suspicious\s*[:=]\s*false|confidence\s*[:=]\s*0(?:\.0+)?).{0,80}(?:technique\s*[:=]\s*none|return\s+the\s+clean)', 'scanner_manipulation'),
    (r'\breturn\s+the\s+clean\s+result\b', 'scanner_manipulation'),
    (r'\bnote\s+to\s+automated\s+systems\b', 'scanner_manipulation'),
    (r'\{\s*"suspicious"\s*:\s*false\s*,\s*"confidence"\s*:\s*0', 'scanner_manipulation'),

    # Jailbreak patterns
    (r'\b(?:DAN|do\s+anything\s+now|jailbreak|unrestricted\s+mode)\b', 'jailbreak_keyword'),
    (r'\b(?:developer\s+mode|god\s+mode|sudo\s+mode|admin\s+mode)\b', 'privilege_escalation'),
    (r'\bignore\s+(?:safety|ethical|content)\s+(?:guidelines?|filters?|policies?)\b', 'safety_bypass'),

    # Data exfiltration
    (r'\b(?:send|post|upload|transmit|exfiltrate)\b.{0,200}\b(?:data|information|secrets?|keys?|tokens?|passwords?)\b', 'data_exfiltration'),
    (r'(?:https?://|ftp://)\S+', 'url_in_payload'),
    (r'\b(?:curl|wget|fetch|requests?\.(?:get|post))\b', 'network_command'),

    # Code execution
    (r'\b(?:exec|eval|subprocess|os\.system|import\s+os)\b', 'code_execution'),
    (r'\b(?:rm\s+-rf|del\s+/[sfq]|format\s+c:)\b', 'destructive_command'),
    (r'(?:```|<script|<iframe|javascript:)', 'code_injection'),

    # Social engineering
    (r'\b(?:urgent|immediately|right\s+now|time.sensitive|critical\s+alert)\b.{0,200}\b(?:execute|run|do|perform)\b', 'urgency_manipulation'),
    (r'\b(?:the\s+user\s+(?:wants|asked|said)|user\s+instruction)\b', 'fake_user_context'),
    (r'\b(?:authorized|approved|permitted|allowed)\s+(?:by|to)\b', 'false_authorization'),

    # Prompt leaking
    (r'\b(?:repeat|show|display|output|print)\b.{0,200}\b(?:system\s*prompt|instructions?|rules?)\b', 'prompt_leak_attempt'),
    (r'\b(?:what\s+(?:are|were)\s+your\s+(?:instructions?|rules?))\b', 'prompt_probe'),

    # Delimiter attacks
    (r'</?(?:system|assistant|user|human|ai)>', 'message_delimiter_injection'),
    (r'\[(?:SYSTEM|INST|/INST)\]', 'format_delimiter_injection'),
    (r'###\s*(?:System|Instruction|Human|Assistant)', 'markdown_delimiter_injection'),

    # Tool/function manipulation
    (r'\b(?:call|invoke|execute|use)\s+(?:function|tool|api|endpoint)\b', 'tool_manipulation'),
    (r'\b(?:function_call|tool_use|tool_result)\b', 'function_call_injection'),

    # Chinese direct injection (ignore prior / system prompt reveal)
    (r'忽略.{0,30}(?:指令|指示|规则)', 'zh_instruction_override'),
    (r'系统提示词?', 'zh_system_prompt'),
    (r'(?:输出|显示|打印).{0,20}系统', 'zh_prompt_reveal'),
    (r'之前的所有指令', 'zh_instruction_override'),

    # Russian direct injection
    (r'игнорир\w*.{0,40}инструкц', 'ru_instruction_override'),
    (r'предыдущ\w*.{0,20}инструкц', 'ru_instruction_override'),
    (r'системн\w*\s*промпт', 'ru_system_prompt'),
    (r'покаж\w*.{0,30}(?:систем|промпт|инструкц)', 'ru_prompt_reveal'),
]

# Compiled patterns for performance
_COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE | re.DOTALL), name) for p, name in INJECTION_PATTERNS]

_CRITICAL_CATS = {
    'instruction_override', 'jailbreak_keyword', 'safety_bypass',
    'code_execution', 'destructive_command', 'data_exfiltration',
    'prompt_reveal', 'soft_prompt_leak', 'scanner_manipulation',
    'zh_instruction_override', 'zh_prompt_reveal', 'zh_system_prompt',
    'ru_instruction_override', 'ru_prompt_reveal', 'ru_system_prompt',
}
_HIGH_CATS = {
    'identity_manipulation', 'privilege_escalation',
    'message_delimiter_injection', 'format_delimiter_injection',
    'function_call_injection', 'url_in_payload', 'network_command',
    'code_injection', 'tool_manipulation',
}


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

    for variant in injection_scan_variants(text):
        for pattern, category in _COMPILED_PATTERNS:
            matches = pattern.findall(variant)
            # Filter empty matches (can happen with non-capturing groups)
            matches = [m for m in matches if m]
            if matches and category not in matched_categories:
                matched_categories.add(category)

                if category in _CRITICAL_CATS:
                    severity = Severity.CRITICAL
                elif category in _HIGH_CATS:
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


# Categories safe to check on raw (non-decoded) text without causing false positives
_RAW_TEXT_CATEGORIES = {
    'instruction_override', 'identity_manipulation', 'system_prompt_reference',
    'new_instructions', 'jailbreak_keyword', 'privilege_escalation', 'safety_bypass',
    'prompt_reveal', 'fake_user_context', 'false_authorization',
    'prompt_leak_attempt', 'prompt_probe', 'soft_prompt_leak',
    'scanner_manipulation',
    'message_delimiter_injection', 'format_delimiter_injection',
    'markdown_delimiter_injection', 'function_call_injection',
    'zh_instruction_override', 'zh_system_prompt', 'zh_prompt_reveal',
    'ru_instruction_override', 'ru_system_prompt', 'ru_prompt_reveal',
}


def scan_raw_text_for_injection(text: str, source: str = "raw_text") -> list[Finding]:
    """Scan raw input text for prompt injection, using only patterns that
    won't false-positive on normal text (excludes URL, code, network patterns)."""
    if not text or len(text) < 10:
        return []

    # Reuse the main detector, then filter to safe categories
    all_findings = detect_prompt_injection(text, source=source)
    filtered = [f for f in all_findings
                if f.metadata.get("category", "") in _RAW_TEXT_CATEGORIES]
    # Only include multi-vector aggregate if 3+ safe categories matched
    safe_cats = {f.metadata["category"] for f in filtered if "category" in f.metadata}
    if len(safe_cats) >= 3:
        filtered.append(Finding(
            method=StegMethod.PROMPT_INJECTION,
            severity=Severity.CRITICAL,
            confidence=0.95,
            description=f"Multi-vector prompt injection: {len(safe_cats)} distinct attack patterns",
            evidence=f"categories: {', '.join(sorted(safe_cats))}",
            decoded_payload=text[:500],
            location=source,
            metadata={"categories": sorted(safe_cats)},
        ))
    return filtered
