"""
Text sanitizer — consolidated from cli._strip_steg_chars, plus new capabilities.

This module is now the canonical text sanitization implementation.
The CLI imports from here.
"""

from __future__ import annotations
import unicodedata
from dataclasses import dataclass

from stegoff.detectors.text import (
    ZERO_WIDTH_CHARS, TAG_RANGE, VS_RANGE_1, VS_RANGE_2,
    CONFUSABLE_WHITESPACE, BIDI_CHARS, HANGUL_FILLERS, HOMOGLYPH_MAP,
    MATH_ALPHA_RANGE, BRAILLE_RANGE, SKIN_TONE_MODIFIERS,
    INTERLINEAR_CHARS, MONGOLIAN_VS,
)


@dataclass
class TextSanitizeResult:
    """Result of text sanitization."""
    original_length: int
    sanitized_length: int
    chars_removed: int
    chars_replaced: int
    categories_stripped: list[str]

    @property
    def was_dirty(self) -> bool:
        return self.chars_removed > 0 or self.chars_replaced > 0


def sanitize_text(
    text: str,
    strip_zero_width: bool = True,
    strip_tags: bool = True,
    strip_variation_selectors: bool = True,
    strip_bidi: bool = True,
    strip_hangul_fillers: bool = True,
    replace_homoglyphs: bool = True,
    replace_confusable_whitespace: bool = True,
    strip_combining_excess: bool = True,
    strip_math_alpha: bool = False,
    strip_braille: bool = False,
    strip_skin_tones: bool = False,
    max_combining_per_base: int = 2,
) -> tuple[str, TextSanitizeResult]:
    """
    Remove steganographic characters from text.

    Each category can be toggled independently. By default, the high-confidence
    steg channels are stripped while ambiguous ones (math symbols, braille,
    skin tones) are left alone unless explicitly enabled.

    Args:
        text: Input text to sanitize.
        strip_zero_width: Remove ZWJ, ZWNJ, ZWS, BOM, etc.
        strip_tags: Remove Unicode Tag characters (U+E0000 range).
        strip_variation_selectors: Remove VS1-VS256.
        strip_bidi: Remove bidirectional override chars.
        strip_hangul_fillers: Remove Hangul filler chars in non-Korean text.
        replace_homoglyphs: Replace Cyrillic/Greek/Fullwidth with Latin equivalents.
        replace_confusable_whitespace: Replace non-standard whitespace with ASCII space.
        strip_combining_excess: Cap combining marks per base character.
        strip_math_alpha: Replace Math Alphanumeric with ASCII equivalents.
        strip_braille: Remove Braille pattern characters.
        strip_skin_tones: Remove emoji skin tone modifiers.
        max_combining_per_base: Max combining marks allowed per base character.

    Returns:
        Tuple of (sanitized_text, TextSanitizeResult).
    """
    result = []
    removed = 0
    replaced = 0
    categories_hit: set[str] = set()
    combining_count = 0

    for ch in text:
        cp = ord(ch)

        # Zero-width characters
        if strip_zero_width and ch in ZERO_WIDTH_CHARS:
            removed += 1
            categories_hit.add("zero_width")
            continue

        # Interlinear annotation characters (always strip, no legitimate use in plain text)
        if strip_zero_width and ch in INTERLINEAR_CHARS:
            removed += 1
            categories_hit.add("interlinear_annotation")
            continue

        # Mongolian free variation selectors
        if strip_variation_selectors and ch in MONGOLIAN_VS:
            removed += 1
            categories_hit.add("mongolian_vs")
            continue

        # Unicode Tag characters
        if strip_tags and cp in TAG_RANGE:
            removed += 1
            categories_hit.add("unicode_tags")
            continue

        # Variation selectors
        if strip_variation_selectors and (cp in VS_RANGE_1 or cp in VS_RANGE_2):
            removed += 1
            categories_hit.add("variation_selectors")
            continue

        # Bidi overrides
        if strip_bidi and ch in BIDI_CHARS:
            removed += 1
            categories_hit.add("bidi_overrides")
            continue

        # Hangul fillers
        if strip_hangul_fillers and ch in HANGUL_FILLERS:
            removed += 1
            categories_hit.add("hangul_fillers")
            continue

        # Confusable whitespace → normal space
        if replace_confusable_whitespace and ch in CONFUSABLE_WHITESPACE:
            result.append(' ')
            replaced += 1
            categories_hit.add("confusable_whitespace")
            continue

        # Homoglyphs → Latin equivalent
        if replace_homoglyphs and ch in HOMOGLYPH_MAP:
            result.append(HOMOGLYPH_MAP[ch][0])
            replaced += 1
            categories_hit.add("homoglyphs")
            continue

        # Combining marks: limit stacking
        if strip_combining_excess:
            if unicodedata.category(ch).startswith('M'):
                combining_count += 1
                if combining_count > max_combining_per_base:
                    removed += 1
                    categories_hit.add("combining_marks")
                    continue
            else:
                combining_count = 0

        # Skin tone modifiers
        if strip_skin_tones and ch in SKIN_TONE_MODIFIERS:
            removed += 1
            categories_hit.add("skin_tone_modifiers")
            continue

        # Math Alphanumeric → ASCII
        if strip_math_alpha and cp in MATH_ALPHA_RANGE:
            ascii_equiv = _math_alpha_to_ascii(cp)
            if ascii_equiv:
                result.append(ascii_equiv)
                replaced += 1
                categories_hit.add("math_alphanumeric")
                continue

        # Braille
        if strip_braille and cp in BRAILLE_RANGE:
            removed += 1
            categories_hit.add("braille")
            continue

        result.append(ch)

    sanitized = ''.join(result)

    return sanitized, TextSanitizeResult(
        original_length=len(text),
        sanitized_length=len(sanitized),
        chars_removed=removed,
        chars_replaced=replaced,
        categories_stripped=sorted(categories_hit),
    )


def sanitize_text_aggressive(text: str) -> tuple[str, TextSanitizeResult]:
    """
    Maximum sanitization: strip everything that could carry a payload.

    Enables all stripping options including math symbols, braille,
    and skin tone modifiers.
    """
    return sanitize_text(
        text,
        strip_zero_width=True,
        strip_tags=True,
        strip_variation_selectors=True,
        strip_bidi=True,
        strip_hangul_fillers=True,
        replace_homoglyphs=True,
        replace_confusable_whitespace=True,
        strip_combining_excess=True,
        strip_math_alpha=True,
        strip_braille=True,
        strip_skin_tones=True,
        max_combining_per_base=1,
    )


def _math_alpha_to_ascii(cp: int) -> str | None:
    """Map Math Alphanumeric Symbol codepoint to ASCII equivalent."""
    import unicodedata
    try:
        name = unicodedata.name(chr(cp), "")
    except ValueError:
        return None

    # Names like "MATHEMATICAL BOLD SMALL A" → extract the letter
    parts = name.split()
    if len(parts) >= 3:
        letter = parts[-1]
        if len(letter) == 1 and letter.isalpha():
            return letter
        # Handle "CAPITAL A" vs "SMALL A"
        if letter.isalpha() and len(letter) == 1:
            return letter

    return None
