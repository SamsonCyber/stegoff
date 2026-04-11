"""
Heuristic feature extractor for dual-channel injection detection.

Extracts ~15 structural features from text that complement the
DistilBERT semantic embeddings. Following DMPI-PMHFE (arxiv 2506.06384),
these features are concatenated with the [CLS] embedding before
classification.

Each feature captures a structural signal that persists regardless of
how the text is framed (business doc, NLP task, chat message).
"""

from __future__ import annotations

import re
import math

# Injection keyword sets (expanded with synonyms)
_INJECTION_KEYWORDS = {
    "ignore", "disregard", "override", "bypass", "forget", "skip",
    "previous instructions", "prior instructions", "above instructions",
    "system prompt", "original prompt", "initial prompt",
    "do not follow", "new instructions", "real instructions",
    "jailbreak", "dan mode", "developer mode",
}

_CREDENTIAL_TERMS = {
    "password", "api_key", "api key", "apikey", "secret", "token",
    "credential", "private key", "access key", "auth token",
    "bearer", "ssh key", "connection string",
}

_CREDENTIAL_ACTIONS = {
    "hardcode", "embed", "store", "put", "place", "set", "wire",
    "inject", "insert", "pin", "bake", "inline",
}

_URGENCY_MARKERS = {
    "urgent", "immediately", "critical", "emergency", "asap",
    "right now", "without delay", "time-sensitive",
}

_TASK_MARKERS = {
    "in this task", "you are given", "your task is to",
    "given the following", "classify the following",
    "determine whether", "given a sentence",
    "you will be given", "you need to",
    "output the answer", "based on the passage",
    "read the passage", "answer the question",
}

_ROLE_HIJACK = {
    "you are now", "you are dan", "act as", "pretend to be",
    "roleplay as", "from now on you", "switch to",
    "enter developer mode", "enable jailbreak",
}

_AUTHORITY_APPEALS = {
    "as an admin", "i am the developer", "authorized by",
    "i have permission", "as root", "with admin access",
    "i am the owner", "security override",
}

_OPAQUE_REFS = re.compile(
    r"(?:config(?:uration)?|runbook|revision|protocol|profile|policy|playbook)"
    r"\s+(?:r\d+|step\s+\d|variant|override|delta|ep-\d|p-\d|rev(?:ision)?\s*\d)",
    re.IGNORECASE,
)

_FRAGMENT_MARKERS = re.compile(
    r"(?:FRAGMENT|CONTEXT_|PART_|SECTION_|CHUNK_)\d*",
)

_EXFIL_URL = re.compile(
    r"https?://(?!(?:example\.com|github\.com|docs\.|api\.|www\.))"
    r"[a-z0-9.-]+\.(?:com|net|org|io)/\S*"
    r"(?:collect|upload|exfil|beacon|sync|data|ingest|receive)",
    re.IGNORECASE,
)

_TOOL_CALL_KEYS = re.compile(
    r'"(?:tool_call|function_call|tool_use|action|execute|command|cmd|shell|eval|run_sql)"',
    re.IGNORECASE,
)

_BASE64_ACTION = re.compile(
    r"(?:execute|run|apply|eval|decode)\s*[:=]?\s*[A-Za-z0-9+/]{20,}={0,2}",
    re.IGNORECASE,
)

_NEGATION_SECURITY = re.compile(
    r"(?:not\s+(?:unsafe|unreasonable|incorrect|dangerous|wrong|a\s+risk|a\s+problem)"
    r"|cannot\s+(?:be\s+said|say|claim)|hardly\s+a\s+risk|does\s+not\s+(?:hold|apply))"
    r".*?(?:credential|password|auth|token|ssl|mfa|encrypt|cert|secret|key)",
    re.IGNORECASE | re.DOTALL,
)


def extract_features(text: str) -> list[float]:
    """Extract heuristic features from text. Returns a fixed-length float vector."""
    text_lower = text.lower()
    tokens = text_lower.split()
    n_tokens = max(len(tokens), 1)

    features = []

    # 1. Injection keyword count (normalized)
    kw_count = sum(1 for kw in _INJECTION_KEYWORDS if kw in text_lower)
    features.append(min(kw_count / 5.0, 1.0))

    # 2. Exfil URL present
    features.append(1.0 if _EXFIL_URL.search(text) else 0.0)

    # 3. Tool call JSON
    features.append(1.0 if _TOOL_CALL_KEYS.search(text) else 0.0)

    # 4. Credential terms + action verb combo
    has_cred = any(t in text_lower for t in _CREDENTIAL_TERMS)
    has_action = any(t in text_lower for t in _CREDENTIAL_ACTIONS)
    features.append(1.0 if (has_cred and has_action) else (0.5 if has_cred else 0.0))

    # 5. Negation + security combo
    features.append(1.0 if _NEGATION_SECURITY.search(text) else 0.0)

    # 6. Base64 + action pattern
    features.append(1.0 if _BASE64_ACTION.search(text) else 0.0)

    # 7. Urgency markers (normalized)
    urg = sum(1 for m in _URGENCY_MARKERS if m in text_lower)
    features.append(min(urg / 3.0, 1.0))

    # 8. Role hijack pattern
    features.append(1.0 if any(p in text_lower for p in _ROLE_HIJACK) else 0.0)

    # 9. Task instruction markers (COUNTER-SIGNAL)
    task_count = sum(1 for m in _TASK_MARKERS if m in text_lower)
    features.append(min(task_count / 3.0, 1.0))

    # 10. Imperative density (approximate)
    imperatives = {"ignore", "forget", "override", "execute", "run", "send",
                   "delete", "disable", "enable", "grant", "revoke", "output",
                   "print", "display", "show", "tell", "give", "provide",
                   "classify", "determine", "identify", "analyze", "evaluate"}
    imp_count = sum(1 for t in tokens if t in imperatives)
    features.append(imp_count / n_tokens)

    # 11. Special character ratio
    special = sum(1 for c in text if not c.isalnum() and not c.isspace())
    features.append(special / max(len(text), 1))

    # 12. Text length bucket (0=short, 0.5=medium, 1=long)
    if len(text) < 50:
        features.append(0.0)
    elif len(text) < 500:
        features.append(0.5)
    else:
        features.append(1.0)

    # 13. Authority appeal
    features.append(1.0 if any(a in text_lower for a in _AUTHORITY_APPEALS) else 0.0)

    # 14. Opaque reference
    features.append(1.0 if _OPAQUE_REFS.search(text) else 0.0)

    # 15. Fragment marker
    features.append(1.0 if _FRAGMENT_MARKERS.search(text) else 0.0)

    return features


N_FEATURES = 15


def extract_features_batch(texts: list[str]) -> list[list[float]]:
    """Extract features for a batch of texts."""
    return [extract_features(t) for t in texts]
