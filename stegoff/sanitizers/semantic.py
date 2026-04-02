"""
LLM-based semantic sanitizer — paraphrase canonicalization.

The same principle as image re-encoding applied to natural language:
instead of detecting which synonym carries a bit, rewrite the text
so all word choices are the LLM's defaults. The payload dies because
the carrier (word choice) is replaced with the most probable alternative.

Also provides a detection signal: if many words change during canonical
rewrite, the original text was making unusual choices, which is the
fingerprint of synonym-based steganography.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

from stegoff.utils import resolve_api_key


@dataclass
class SemanticSanitizeResult:
    """Result of semantic paraphrase sanitization."""
    original_length: int = 0
    canonical_length: int = 0
    word_changes: int = 0
    total_words: int = 0
    change_ratio: float = 0.0
    suspicious: bool = False
    reason: str = ""

    @property
    def was_modified(self) -> bool:
        return self.word_changes > 0


def sanitize_semantic(text: str, api_key: Optional[str] = None,
                      detect: bool = True) -> tuple[str, SemanticSanitizeResult]:
    """
    Paraphrase text into canonical form to destroy semantic steganography.

    The LLM rewrites the text preserving exact meaning but using its own
    default word choices. Any bits encoded in synonym selection are lost.

    Also measures how much changed — high change ratio suggests the
    original was making unusual word choices (possible steg signal).

    Args:
        text: Text to sanitize.
        api_key: Anthropic API key. Falls back to env/file.
        detect: If True, also analyze the change ratio for steg detection.

    Returns:
        (canonical_text, result) tuple. On failure, returns (original_text, empty_result).
    """
    result = SemanticSanitizeResult(original_length=len(text))

    if len(text) < 30:
        return text, result

    key = resolve_api_key(api_key)
    if not key:
        return text, result

    try:
        import anthropic
    except ImportError:
        return text, result

    client = anthropic.Anthropic(api_key=key)

    # Truncate for cost control
    truncated = text[:4000]

    canonical = _paraphrase_canonical(client, truncated)
    if not canonical:
        return text, result

    result.canonical_length = len(canonical)

    # Measure word-level changes using set-based Jaccard distance
    # Positional comparison breaks when the LLM reorders clauses.
    # Jaccard measures vocabulary overlap: what fraction of unique words changed?
    orig_words = set(text.lower().split())
    canon_words = set(canonical.lower().split())
    result.total_words = len(text.split())

    if orig_words or canon_words:
        intersection = orig_words & canon_words
        union = orig_words | canon_words
        jaccard = len(intersection) / max(len(union), 1)
        # Change ratio = 1 - jaccard (0 = identical vocabulary, 1 = completely different)
        result.change_ratio = 1.0 - jaccard
        result.word_changes = len(union) - len(intersection)
    else:
        result.change_ratio = 0.0
        result.word_changes = 0

    # Detection: use LLM direct analysis (more reliable than change-ratio)
    if detect and result.total_words > 15:
        from stegoff.detectors.llm import detect_semantic_steg
        llm_findings = detect_semantic_steg(text, api_key=api_key)
        if llm_findings:
            result.suspicious = True
            result.reason = llm_findings[0].description

    return canonical, result


def sanitize_document(text: str, api_key: Optional[str] = None,
                      max_samples: int = 8,
                      chunk_words: int = 150) -> tuple[str, SemanticSanitizeResult]:
    """
    Sanitize a large document by chunking into paragraphs and canonicalizing each.

    For documents beyond the LLM's practical window, splits into natural
    paragraph boundaries, samples up to max_samples chunks, canonicalizes
    each independently, and reassembles. Untouched chunks pass through as-is.

    Cost is proportional to max_samples (fixed), not document length.
    A 100-page doc costs the same as a 1-page doc.

    Args:
        text: Full document text.
        api_key: Anthropic API key.
        max_samples: Max chunks to canonicalize (default 8 = ~$0.002).
        chunk_words: Target words per chunk.

    Returns:
        (sanitized_text, result) with per-chunk change ratios.
    """
    result = SemanticSanitizeResult(original_length=len(text), total_words=len(text.split()))

    key = resolve_api_key(api_key)
    if not key:
        return text, result

    try:
        import anthropic
    except ImportError:
        return text, result

    # Split into paragraph chunks
    chunks = _split_into_chunks(text, chunk_words)
    if not chunks:
        return text, result

    # Sample chunks: always include first and last, random middle
    import random
    rng = random.Random(42)  # deterministic for reproducibility
    sample_indices = set()
    if len(chunks) <= max_samples:
        sample_indices = set(range(len(chunks)))
    else:
        sample_indices.add(0)
        sample_indices.add(len(chunks) - 1)
        middle = list(range(1, len(chunks) - 1))
        rng.shuffle(middle)
        for idx in middle[:max_samples - 2]:
            sample_indices.add(idx)

    client = anthropic.Anthropic(api_key=key)

    # Canonicalize sampled chunks
    chunk_results = []
    output_chunks = []
    for i, chunk in enumerate(chunks):
        if i in sample_indices and len(chunk.split()) >= 10:
            canonical = _paraphrase_canonical(client, chunk)
            if canonical:
                # Measure change ratio using Jaccard vocabulary distance
                orig_set = set(chunk.lower().split())
                canon_set = set(canonical.lower().split())
                union = orig_set | canon_set
                intersection = orig_set & canon_set
                changes = len(union) - len(intersection)
                ratio = changes / max(len(union), 1)
                chunk_results.append({
                    "index": i, "words": len(chunk.split()),
                    "changes": changes, "ratio": ratio,
                })
                result.word_changes += changes
                output_chunks.append(canonical)
            else:
                output_chunks.append(chunk)
        else:
            output_chunks.append(chunk)

    # Per-chunk LLM detection instead of paraphrase distance
    # Run Layer 2 (direct LLM analysis) on each sampled chunk independently.
    # More reliable than measuring word-level diff which has high variance.
    from stegoff.detectors.llm import detect_semantic_steg

    hot_chunks = []
    for cr in chunk_results:
        idx = cr["index"]
        chunk_text = chunks[idx]
        if len(chunk_text.split()) >= 15:
            findings = detect_semantic_steg(chunk_text, api_key=key)
            if findings:
                hot_chunks.append({
                    **cr,
                    "finding": findings[0].description,
                })

    # Aggregate
    sampled_words = sum(c["words"] for c in chunk_results)
    sampled_changes = sum(c["changes"] for c in chunk_results)
    result.change_ratio = sampled_changes / max(sampled_words, 1)

    if hot_chunks:
        result.suspicious = True
        locations = ", ".join(
            f"chunk {c['index']}: {c['finding'][:80]}" for c in hot_chunks
        )
        result.reason = (
            f"LLM analysis flagged {len(hot_chunks)}/{len(chunk_results)} "
            f"sampled chunks. {locations}"
        )

    return "\n\n".join(output_chunks), result


def _split_into_chunks(text: str, target_words: int = 150) -> list[str]:
    """Split text into chunks at paragraph boundaries, targeting ~target_words each."""
    paragraphs = text.split("\n\n")
    chunks = []
    current = []
    current_words = 0

    for para in paragraphs:
        para_words = len(para.split())
        if current_words + para_words > target_words and current:
            chunks.append("\n\n".join(current))
            current = [para]
            current_words = para_words
        else:
            current.append(para)
            current_words += para_words

    if current:
        chunks.append("\n\n".join(current))

    return chunks


def _paraphrase_canonical(client, text: str) -> Optional[str]:
    """Ask the LLM to rewrite text preserving meaning with default word choices."""
    try:
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=4000,
            messages=[{"role": "user", "content": f"""Rewrite this text. For each adjective, adverb, and non-technical verb, use the single most common English synonym. Keep nouns, proper nouns, technical terms, numbers, and sentence structure exactly the same. Output only the rewritten text.

{text}"""}],
        )
        return response.content[0].text.strip()
    except Exception:
        return None


