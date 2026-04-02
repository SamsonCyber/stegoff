"""
Structured data sanitizer — canonicalize fields that could carry covert channels.

Instead of detecting steg in arbitrary fields (UUIDs, hashes, ordering),
regenerate them. The payload dies because the carrier is replaced.

Same principle as image re-encoding: you don't find the hidden bits,
you destroy them by rebuilding the container.
"""

from __future__ import annotations
import json
import uuid
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SanitizeResult:
    """Result of structured data sanitization."""
    changes: list[str] = field(default_factory=list)
    uuids_regenerated: int = 0
    hashes_recomputed: int = 0
    lists_sorted: int = 0
    fields_normalized: int = 0

    @property
    def was_modified(self) -> bool:
        return bool(self.changes)


# UUID v4 pattern
_UUID_RE = re.compile(
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
)

# SHA256 hex pattern
_SHA256_RE = re.compile(r'[0-9a-fA-F]{64}')

# SHA512 hex pattern
_SHA512_RE = re.compile(r'[0-9a-fA-F]{128}')


def sanitize_json(text: str, sort_lists: bool = True,
                  regenerate_uuids: bool = True,
                  strip_optional_metadata: bool = False) -> tuple[str, SanitizeResult]:
    """
    Canonicalize JSON to destroy covert channels in arbitrary fields.

    Operations:
    - Regenerate all UUID v4 values (preserves format, destroys payload)
    - Sort string-only lists alphabetically (destroys permutation encoding)
    - Normalize whitespace and formatting (destroys indentation encoding)
    - Optionally strip fields that commonly carry hidden data

    Returns:
        (canonicalized_json, result) tuple
    """
    result = SanitizeResult()

    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text, result

    obj = _walk_and_sanitize(obj, result, sort_lists, regenerate_uuids)

    # Re-serialize with canonical formatting (consistent indent, sorted keys)
    canonical = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)
    result.fields_normalized += 1

    return canonical, result


def _walk_and_sanitize(node: Any, result: SanitizeResult,
                       sort_lists: bool, regenerate_uuids: bool) -> Any:
    """Recursively walk and sanitize a JSON structure."""
    if isinstance(node, dict):
        return {
            k: _walk_and_sanitize(v, result, sort_lists, regenerate_uuids)
            for k, v in node.items()
        }
    elif isinstance(node, list):
        sanitized = [_walk_and_sanitize(item, result, sort_lists, regenerate_uuids)
                     for item in node]
        # Sort string-only lists to destroy permutation encoding
        if sort_lists and len(sanitized) > 1 and all(isinstance(x, str) for x in sanitized):
            sorted_list = sorted(sanitized)
            if sorted_list != sanitized:
                result.lists_sorted += 1
                result.changes.append(f"Sorted list of {len(sanitized)} strings")
                return sorted_list
        return sanitized
    elif isinstance(node, str):
        return _sanitize_string_value(node, result, regenerate_uuids)
    else:
        return node


def _sanitize_string_value(val: str, result: SanitizeResult,
                           regenerate_uuids: bool) -> str:
    """Sanitize a single string value."""
    # Regenerate UUIDs
    if regenerate_uuids and _UUID_RE.fullmatch(val):
        new_uuid = str(uuid.uuid4())
        result.uuids_regenerated += 1
        result.changes.append(f"Regenerated UUID: {val[:8]}... -> {new_uuid[:8]}...")
        return new_uuid

    # Regenerate UUID in longer strings (e.g., "sha256-<hex>")
    if regenerate_uuids and _UUID_RE.search(val):
        def _replace_uuid(m):
            result.uuids_regenerated += 1
            return str(uuid.uuid4())
        return _UUID_RE.sub(_replace_uuid, val)

    return val


def sanitize_text_structured(text: str) -> tuple[str, SanitizeResult]:
    """
    Sanitize structured text (not just JSON) to destroy covert channels.

    For non-JSON text:
    - Normalize line endings to \\n
    - Collapse multiple spaces to single space
    - Strip trailing whitespace per line
    - Normalize indentation to consistent depth
    """
    result = SanitizeResult()
    lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')

    cleaned = []
    for line in lines:
        # Strip trailing whitespace (destroys trailing whitespace encoding)
        stripped = line.rstrip()
        if stripped != line:
            result.changes.append("Stripped trailing whitespace")
            result.fields_normalized += 1
        cleaned.append(stripped)

    output = '\n'.join(cleaned)

    # Normalize multiple consecutive blank lines to single
    while '\n\n\n' in output:
        output = output.replace('\n\n\n', '\n\n')

    return output, result


def canonicalize_uuids(text: str) -> tuple[str, int]:
    """Replace all UUIDs in text with freshly generated ones.
    Returns (new_text, count_replaced)."""
    count = 0
    def _replace(m):
        nonlocal count
        count += 1
        return str(uuid.uuid4())
    result = _UUID_RE.sub(_replace, text)
    return result, count


def sort_json_lists(text: str) -> tuple[str, int]:
    """Parse JSON, sort all string-only lists, re-serialize.
    Returns (new_text, count_sorted)."""
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text, 0

    count = [0]
    def _walk(node):
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items()}
        elif isinstance(node, list):
            walked = [_walk(item) for item in node]
            if len(walked) > 1 and all(isinstance(x, str) for x in walked):
                s = sorted(walked)
                if s != walked:
                    count[0] += 1
                return s
            return walked
        return node

    obj = _walk(obj)
    return json.dumps(obj, indent=2, ensure_ascii=False), count[0]
