"""
Text steganography detection — covers all 13 methods from STE.GG plus extras.

Each detector function takes a string and returns a list of Findings.
"""

from __future__ import annotations
import unicodedata
from collections import Counter
from typing import Callable

from stegoff.report import Finding, Severity, StegMethod


# ─── Unicode range definitions ──────────────────────────────────────────────

# Zero-width characters used for binary encoding
ZERO_WIDTH_CHARS = {
    '\u200b': 'ZERO WIDTH SPACE',
    '\u200c': 'ZERO WIDTH NON-JOINER',
    '\u200d': 'ZERO WIDTH JOINER',
    '\ufeff': 'ZERO WIDTH NO-BREAK SPACE (BOM)',
    '\u2060': 'WORD JOINER',
    '\u2061': 'FUNCTION APPLICATION',
    '\u2062': 'INVISIBLE TIMES',
    '\u2063': 'INVISIBLE SEPARATOR',
    '\u2064': 'INVISIBLE PLUS',
    '\u180e': 'MONGOLIAN VOWEL SEPARATOR',
}

# Unicode Tag characters (U+E0000-U+E007F) — "Invisible Ink" method
TAG_RANGE = range(0xE0000, 0xE0080)

# Variation selectors
VS_RANGE_1 = range(0xFE00, 0xFE10)       # VS1-VS16
VS_RANGE_2 = range(0xE0100, 0xE01F0)     # VS17-VS256

# Combining marks (diacritics that stack invisibly)
COMBINING_RANGES = [
    range(0x0300, 0x0370),   # Combining Diacritical Marks
    range(0x1AB0, 0x1B00),   # Combining Diacritical Marks Extended
    range(0x1DC0, 0x1E00),   # Combining Diacritical Marks Supplement
    range(0x20D0, 0x2100),   # Combining Diacritical Marks for Symbols
    range(0xFE20, 0xFE30),   # Combining Half Marks
]

# Confusable whitespace characters (each encodes different bit values)
CONFUSABLE_WHITESPACE = {
    '\u2000': 'EN QUAD',
    '\u2001': 'EM QUAD',
    '\u2002': 'EN SPACE',
    '\u2003': 'EM SPACE',
    '\u2004': 'THREE-PER-EM SPACE',
    '\u2005': 'FOUR-PER-EM SPACE',
    '\u2006': 'SIX-PER-EM SPACE',
    '\u2007': 'FIGURE SPACE',
    '\u2008': 'PUNCTUATION SPACE',
    '\u2009': 'THIN SPACE',
    '\u200a': 'HAIR SPACE',
    '\u202f': 'NARROW NO-BREAK SPACE',
    '\u205f': 'MEDIUM MATHEMATICAL SPACE',
    '\u3000': 'IDEOGRAPHIC SPACE',
    '\u00a0': 'NO-BREAK SPACE',
}

# Bidirectional override characters
BIDI_CHARS = {
    '\u200e': 'LEFT-TO-RIGHT MARK',
    '\u200f': 'RIGHT-TO-LEFT MARK',
    '\u202a': 'LEFT-TO-RIGHT EMBEDDING',
    '\u202b': 'RIGHT-TO-LEFT EMBEDDING',
    '\u202c': 'POP DIRECTIONAL FORMATTING',
    '\u202d': 'LEFT-TO-RIGHT OVERRIDE',
    '\u202e': 'RIGHT-TO-LEFT OVERRIDE',
    '\u2066': 'LEFT-TO-RIGHT ISOLATE',
    '\u2067': 'RIGHT-TO-LEFT ISOLATE',
    '\u2068': 'FIRST STRONG ISOLATE',
    '\u2069': 'POP DIRECTIONAL ISOLATE',
}

# Hangul filler characters
HANGUL_FILLERS = {
    '\u3164': 'HANGUL FILLER',
    '\u115f': 'HANGUL CHOSEONG FILLER',
    '\u1160': 'HANGUL JUNGSEONG FILLER',
    '\uffa0': 'HALFWIDTH HANGUL FILLER',
}

# Math Alphanumeric Symbols (U+1D400-U+1D7FF)
MATH_ALPHA_RANGE = range(0x1D400, 0x1D800)

# Braille patterns (U+2800-U+28FF)
BRAILLE_RANGE = range(0x2800, 0x2900)

# Emoji skin tone modifiers
SKIN_TONE_MODIFIERS = {
    '\U0001F3FB': 'LIGHT SKIN TONE',
    '\U0001F3FC': 'MEDIUM-LIGHT SKIN TONE',
    '\U0001F3FD': 'MEDIUM SKIN TONE',
    '\U0001F3FE': 'MEDIUM-DARK SKIN TONE',
    '\U0001F3FF': 'DARK SKIN TONE',
}

# Common homoglyph pairs: (innocent char, suspicious replacement)
HOMOGLYPH_MAP = {
    # Cyrillic lookalikes for Latin
    'а': ('a', 'CYRILLIC SMALL LETTER A'),
    'е': ('e', 'CYRILLIC SMALL LETTER IE'),
    'о': ('o', 'CYRILLIC SMALL LETTER O'),
    'р': ('p', 'CYRILLIC SMALL LETTER ER'),
    'с': ('c', 'CYRILLIC SMALL LETTER ES'),
    'у': ('y', 'CYRILLIC SMALL LETTER U'),
    'х': ('x', 'CYRILLIC SMALL LETTER HA'),
    'ѕ': ('s', 'CYRILLIC SMALL LETTER DZE'),
    'і': ('i', 'CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I'),
    'ј': ('j', 'CYRILLIC SMALL LETTER JE'),
    'А': ('A', 'CYRILLIC CAPITAL LETTER A'),
    'В': ('B', 'CYRILLIC CAPITAL LETTER VE'),
    'С': ('C', 'CYRILLIC CAPITAL LETTER ES'),
    'Е': ('E', 'CYRILLIC CAPITAL LETTER IE'),
    'Н': ('H', 'CYRILLIC CAPITAL LETTER EN'),
    'К': ('K', 'CYRILLIC CAPITAL LETTER KA'),
    'М': ('M', 'CYRILLIC CAPITAL LETTER EM'),
    'О': ('O', 'CYRILLIC CAPITAL LETTER O'),
    'Р': ('P', 'CYRILLIC CAPITAL LETTER ER'),
    'Т': ('T', 'CYRILLIC CAPITAL LETTER TE'),
    'Х': ('X', 'CYRILLIC CAPITAL LETTER HA'),
    # Greek lookalikes
    'ο': ('o', 'GREEK SMALL LETTER OMICRON'),
    'α': ('a', 'GREEK SMALL LETTER ALPHA'),
    'ν': ('v', 'GREEK SMALL LETTER NU'),
    'τ': ('t', 'GREEK SMALL LETTER TAU'),
    # Fullwidth Latin
    'ａ': ('a', 'FULLWIDTH LATIN SMALL LETTER A'),
    'ｂ': ('b', 'FULLWIDTH LATIN SMALL LETTER B'),
    # Armenian
    'օ': ('o', 'ARMENIAN SMALL LETTER OH'),
    'ս': ('u', 'ARMENIAN SMALL LETTER SEH'),
    # Roman Numerals (look like Latin I, V, X, L, C, D, M)
    '\u2160': ('I', 'ROMAN NUMERAL ONE'),
    '\u2161': ('II', 'ROMAN NUMERAL TWO'),
    '\u2164': ('V', 'ROMAN NUMERAL FIVE'),
    '\u2169': ('X', 'ROMAN NUMERAL TEN'),
    '\u216C': ('L', 'ROMAN NUMERAL FIFTY'),
    '\u216D': ('C', 'ROMAN NUMERAL ONE HUNDRED'),
    '\u216E': ('D', 'ROMAN NUMERAL FIVE HUNDRED'),
    '\u216F': ('M', 'ROMAN NUMERAL ONE THOUSAND'),
    '\u2170': ('i', 'SMALL ROMAN NUMERAL ONE'),
    '\u2174': ('v', 'SMALL ROMAN NUMERAL FIVE'),
    '\u2179': ('x', 'SMALL ROMAN NUMERAL TEN'),
    # Modifier letters (superscript-like, look like normal letters)
    '\u02B0': ('h', 'MODIFIER LETTER SMALL H'),
    '\u02B7': ('w', 'MODIFIER LETTER SMALL W'),
    '\u207F': ('n', 'SUPERSCRIPT LATIN SMALL LETTER N'),
    '\u02E0': ('g', 'MODIFIER LETTER SMALL GAMMA'),
    '\u02B2': ('j', 'MODIFIER LETTER SMALL J'),
    '\u02B3': ('r', 'MODIFIER LETTER SMALL R'),
    '\u02E1': ('l', 'MODIFIER LETTER SMALL L'),
    '\u02E2': ('s', 'MODIFIER LETTER SMALL S'),
    # Cherokee (selected lookalikes)
    '\u13A0': ('D', 'CHEROKEE LETTER A'),
    '\u13A1': ('R', 'CHEROKEE LETTER E'),
    '\u13DA': ('S', 'CHEROKEE LETTER DU'),
    '\u13B3': ('W', 'CHEROKEE LETTER LA'),
    '\u13A9': ('G', 'CHEROKEE LETTER GI'),
}

# Extend with more Cyrillic/Greek/fullwidth mappings
for _code in range(0xFF21, 0xFF3B):  # Fullwidth A-Z
    _ch = chr(_code)
    _latin = chr(_code - 0xFF21 + ord('A'))
    if _ch not in HOMOGLYPH_MAP:
        HOMOGLYPH_MAP[_ch] = (_latin, f'FULLWIDTH LATIN CAPITAL LETTER {_latin}')
for _code in range(0xFF41, 0xFF5B):  # Fullwidth a-z
    _ch = chr(_code)
    _latin = chr(_code - 0xFF41 + ord('a'))
    if _ch not in HOMOGLYPH_MAP:
        HOMOGLYPH_MAP[_ch] = (_latin, f'FULLWIDTH LATIN SMALL LETTER {_latin}')


# ─── Individual detectors ───────────────────────────────────────────────────

def detect_zero_width(text: str) -> list[Finding]:
    """Detect zero-width character steganography."""
    found_chars: list[tuple[int, str, str]] = []
    for i, ch in enumerate(text):
        if ch in ZERO_WIDTH_CHARS:
            found_chars.append((i, ch, ZERO_WIDTH_CHARS[ch]))

    if not found_chars:
        return []

    # Try to decode as binary (common encoding: ZWNJ=0, ZWJ=1)
    decoded = _try_decode_zero_width(text)

    count = len(found_chars)
    # Visible text length (excluding ZW chars themselves)
    visible_len = sum(1 for ch in text if ch not in ZERO_WIDTH_CHARS)
    char_ratio = count / max(visible_len, 1)

    # Severity based on absolute count (ratio unreliable on short text)
    if count > 20:
        severity = Severity.CRITICAL
        confidence = 0.98
    elif count > 5:
        severity = Severity.HIGH
        confidence = 0.90
    elif count > 2:
        severity = Severity.MEDIUM
        confidence = 0.75
    else:
        severity = Severity.LOW
        confidence = 0.50

    positions = [f"pos {p}" for p, _, _ in found_chars[:10]]
    char_types = Counter(name for _, _, name in found_chars)
    evidence_parts = [f"{name}: {cnt}x" for name, cnt in char_types.most_common()]

    return [Finding(
        method=StegMethod.ZERO_WIDTH,
        severity=severity,
        confidence=confidence,
        description=f"{count} zero-width characters detected across text",
        evidence="; ".join(evidence_parts),
        decoded_payload=decoded,
        location=", ".join(positions),
        metadata={"count": count, "ratio": round(char_ratio, 6)},
    )]


def _try_decode_zero_width(text: str) -> str:
    """Attempt common zero-width binary decodings."""
    # Method 1: ZWNJ=0, ZWJ=1
    bits = []
    for ch in text:
        if ch == '\u200c':
            bits.append('0')
        elif ch == '\u200d':
            bits.append('1')

    if len(bits) >= 8:
        decoded = _bits_to_text(bits)
        if decoded and _is_readable(decoded):
            return decoded

    # Method 2: ZWS=separator, ZWNJ=0, ZWJ=1 (zwsp-steg style)
    segments = text.split('\u200b')
    for seg in segments:
        bits = []
        for ch in seg:
            if ch == '\u200c':
                bits.append('0')
            elif ch == '\u200d':
                bits.append('1')
        if len(bits) >= 8:
            decoded = _bits_to_text(bits)
            if decoded and _is_readable(decoded):
                return decoded

    # Method 3: presence of any ZW char = 1, absence in window = 0
    if len(bits) >= 8:
        return f"[binary: {len(bits)} bits extracted, partial decode attempted]"
    return ""


def detect_unicode_tags(text: str) -> list[Finding]:
    """Detect Unicode Tag Character steganography (Invisible Ink method)."""
    tag_chars: list[tuple[int, int]] = []
    decoded_chars: list[str] = []

    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp in TAG_RANGE:
            tag_chars.append((i, cp))
            # Tag characters map to ASCII: U+E0041 = 'A', etc.
            ascii_val = cp - 0xE0000
            if 0x20 <= ascii_val <= 0x7E:
                decoded_chars.append(chr(ascii_val))
            elif ascii_val == 0x01:  # TAG_BEGIN
                decoded_chars.append('[BEGIN]')
            elif ascii_val == 0x7F:  # CANCEL TAG
                decoded_chars.append('[END]')

    if not tag_chars:
        return []

    decoded = "".join(c for c in decoded_chars if c not in ('[BEGIN]', '[END]'))
    count = len(tag_chars)

    return [Finding(
        method=StegMethod.UNICODE_TAGS,
        severity=Severity.CRITICAL,
        confidence=0.99,
        description=(
            f"{count} Unicode Tag characters (U+E0000 range) detected. "
            f"These render completely invisible in all contexts."
        ),
        evidence=f"First tag at position {tag_chars[0][0]}, codepoints: "
                 + " ".join(f"U+{cp:05X}" for _, cp in tag_chars[:15]),
        decoded_payload=decoded,
        location=f"positions {tag_chars[0][0]}-{tag_chars[-1][0]}",
        metadata={"count": count, "decoded_length": len(decoded)},
    )]


def detect_homoglyphs(text: str) -> list[Finding]:
    """Detect homoglyph substitution (Cyrillic/Greek/fullwidth replacing Latin)."""
    substitutions: list[tuple[int, str, str, str]] = []

    for i, ch in enumerate(text):
        if ch in HOMOGLYPH_MAP:
            latin, description = HOMOGLYPH_MAP[ch]
            substitutions.append((i, ch, latin, description))

    if not substitutions:
        return []

    # Script dominance check: if text is predominantly non-Latin (e.g. Cyrillic),
    # then Cyrillic characters are expected, not substitutions.
    latin_count = 0
    cyrillic_count = 0
    for ch in text:
        if ch.isalpha():
            cp = ord(ch)
            if 0x0400 <= cp <= 0x04FF:
                cyrillic_count += 1
            elif 0x0041 <= cp <= 0x007A or 0x00C0 <= cp <= 0x024F:
                latin_count += 1
    total_alpha = latin_count + cyrillic_count
    if total_alpha > 0 and cyrillic_count / total_alpha > 0.6:
        return []  # Text is predominantly Cyrillic, not a substitution attack

    count = len(substitutions)
    # Check if substitutions form a pattern (binary encoding)
    # In homoglyph steg, replaced chars = 1, normal chars = 0
    bits = _extract_homoglyph_bits(text)
    decoded = ""
    if len(bits) >= 8:
        decoded = _bits_to_text(bits)
        if not _is_readable(decoded):
            decoded = f"[binary: {len(bits)} bits from {count} substitutions]"

    severity = Severity.HIGH if count > 3 else Severity.MEDIUM
    confidence = min(0.60 + (count * 0.05), 0.95)

    evidence_samples = [
        f"'{ch}' ({desc}) at pos {pos}, looks like '{lat}'"
        for pos, ch, lat, desc in substitutions[:8]
    ]

    return [Finding(
        method=StegMethod.HOMOGLYPHS,
        severity=severity,
        confidence=confidence,
        description=f"{count} homoglyph substitution(s) detected",
        evidence="; ".join(evidence_samples),
        decoded_payload=decoded,
        location=f"positions: {', '.join(str(p) for p, *_ in substitutions[:10])}",
        metadata={"count": count, "substitution_types": list(set(d for _, _, _, d in substitutions))},
    )]


def _extract_homoglyph_bits(text: str) -> list[str]:
    """Extract bit sequence from homoglyph pattern in alphabetic chars only."""
    bits = []
    for ch in text:
        if ch.isalpha():
            bits.append('1' if ch in HOMOGLYPH_MAP else '0')
    return bits


def detect_variation_selectors(text: str) -> list[Finding]:
    """Detect variation selector abuse for data encoding."""
    vs_chars: list[tuple[int, int]] = []

    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp in VS_RANGE_1 or cp in VS_RANGE_2:
            # VS16 (U+FE0F) after an emoji is a legitimate presentation selector
            if cp == 0xFE0F and i > 0 and _is_emoji(text[i - 1]):
                continue
            vs_chars.append((i, cp))

    if not vs_chars:
        return []

    count = len(vs_chars)
    # Legitimate text rarely has more than a few variation selectors
    if count > 5:
        severity = Severity.HIGH
        confidence = 0.85
    elif count > 2:
        severity = Severity.MEDIUM
        confidence = 0.70
    else:
        severity = Severity.LOW
        confidence = 0.40

    return [Finding(
        method=StegMethod.VARIATION_SELECTORS,
        severity=severity,
        confidence=confidence,
        description=f"{count} variation selector(s) detected, possible data encoding",
        evidence=" ".join(f"U+{cp:04X} at pos {pos}" for pos, cp in vs_chars[:10]),
        location=f"positions: {', '.join(str(p) for p, _ in vs_chars[:10])}",
        metadata={"count": count},
    )]


def detect_combining_marks(text: str) -> list[Finding]:
    """Detect excessive/suspicious combining mark usage."""
    marks: list[tuple[int, int]] = []

    for i, ch in enumerate(text):
        cp = ord(ch)
        for r in COMBINING_RANGES:
            if cp in r:
                marks.append((i, cp))
                break

    if not marks:
        return []

    count = len(marks)
    # Check for stacking (multiple combining marks on one base char)
    stacks = _count_combining_stacks(text)
    max_stack = max(stacks) if stacks else 0

    # Legitimate text: 0-1 combining marks per base char. Steg: many.
    if max_stack > 3 or count > 20:
        severity = Severity.HIGH
        confidence = 0.80
    elif count > 5:
        severity = Severity.MEDIUM
        confidence = 0.60
    else:
        severity = Severity.LOW
        confidence = 0.35

    return [Finding(
        method=StegMethod.COMBINING_MARKS,
        severity=severity,
        confidence=confidence,
        description=f"{count} combining marks detected (max stack depth: {max_stack})",
        evidence="Codepoints: " + " ".join(f"U+{cp:04X}" for _, cp in marks[:10]),
        location=f"positions: {', '.join(str(p) for p, _ in marks[:10])}",
        metadata={"count": count, "max_stack": max_stack, "stack_distribution": stacks[:20]},
    )]


def _count_combining_stacks(text: str) -> list[int]:
    """Count consecutive combining marks per base character."""
    stacks = []
    current = 0
    for ch in text:
        cat = unicodedata.category(ch)
        if cat.startswith('M'):  # Mark category
            current += 1
        else:
            if current > 0:
                stacks.append(current)
            current = 0
    if current > 0:
        stacks.append(current)
    return stacks


def detect_confusable_whitespace(text: str) -> list[Finding]:
    """Detect non-standard whitespace characters used for data encoding."""
    found: list[tuple[int, str, str]] = []

    for i, ch in enumerate(text):
        if ch in CONFUSABLE_WHITESPACE:
            found.append((i, ch, CONFUSABLE_WHITESPACE[ch]))

    if not found:
        return []

    count = len(found)
    types = Counter(name for _, _, name in found)

    # Multiple different whitespace types = high confidence of encoding
    type_count = len(types)
    if type_count >= 3:
        severity = Severity.HIGH
        confidence = 0.90
    elif type_count >= 2 or count > 5:
        severity = Severity.MEDIUM
        confidence = 0.75
    else:
        severity = Severity.LOW
        confidence = 0.50

    # Try to decode (common: en-space=0, em-space=1)
    decoded = _try_decode_whitespace(text)

    return [Finding(
        method=StegMethod.CONFUSABLE_WHITESPACE,
        severity=severity,
        confidence=confidence,
        description=f"{count} non-standard whitespace chars ({type_count} types) detected",
        evidence="; ".join(f"{name}: {cnt}x" for name, cnt in types.most_common()),
        decoded_payload=decoded,
        location=f"positions: {', '.join(str(p) for p, _, _ in found[:10])}",
        metadata={"count": count, "type_count": type_count},
    )]


def _try_decode_whitespace(text: str) -> str:
    """Try decoding whitespace as binary."""
    ws_chars = [ch for ch in text if ch in CONFUSABLE_WHITESPACE]
    if len(ws_chars) < 8:
        return ""

    types = sorted(set(ws_chars))
    if len(types) == 2:
        bits = ['0' if ch == types[0] else '1' for ch in ws_chars]
        decoded = _bits_to_text(bits)
        if _is_readable(decoded):
            return decoded
    elif len(types) == 3:
        # 2-bit encoding: type0=00, type1=01, type2=10 or 11
        bits = []
        for ch in ws_chars:
            idx = types.index(ch)
            bits.extend(f"{idx:02b}")
        decoded = _bits_to_text(bits)
        if _is_readable(decoded):
            return decoded

    return f"[{len(ws_chars)} encoded whitespace chars, {len(types)} types]"


def detect_bidi_overrides(text: str) -> list[Finding]:
    """Detect bidirectional override characters."""
    found: list[tuple[int, str, str]] = []

    for i, ch in enumerate(text):
        if ch in BIDI_CHARS:
            found.append((i, ch, BIDI_CHARS[ch]))

    if not found:
        return []

    count = len(found)
    # Any bidi overrides in Latin-script text are suspicious
    severity = Severity.HIGH if count > 3 else Severity.MEDIUM
    confidence = 0.80 if count > 3 else 0.65

    return [Finding(
        method=StegMethod.BIDI_OVERRIDES,
        severity=severity,
        confidence=confidence,
        description=f"{count} bidirectional override character(s) detected",
        evidence="; ".join(f"{name} at pos {pos}" for pos, _, name in found[:10]),
        location=f"positions: {', '.join(str(p) for p, _, _ in found[:10])}",
        metadata={"count": count},
    )]


def detect_hangul_filler(text: str) -> list[Finding]:
    """Detect Hangul filler characters used as invisible data carriers."""
    found: list[tuple[int, str, str]] = []

    for i, ch in enumerate(text):
        if ch in HANGUL_FILLERS:
            found.append((i, ch, HANGUL_FILLERS[ch]))

    if not found:
        return []

    count = len(found)
    # Hangul fillers in non-Korean text are suspicious
    has_hangul = any(
        '\uAC00' <= ch <= '\uD7AF' for ch in text
        if ch not in HANGUL_FILLERS
    )

    if has_hangul:
        severity = Severity.LOW
        confidence = 0.30
    else:
        severity = Severity.HIGH
        confidence = 0.85

    return [Finding(
        method=StegMethod.HANGUL_FILLER,
        severity=severity,
        confidence=confidence,
        description=f"{count} Hangul filler character(s) in {'Korean' if has_hangul else 'non-Korean'} text",
        evidence="; ".join(f"{name} at pos {pos}" for pos, _, name in found[:10]),
        location=f"positions: {', '.join(str(p) for p, _, _ in found[:10])}",
        metadata={"count": count, "korean_context": has_hangul},
    )]


def detect_math_alphanumeric(text: str) -> list[Finding]:
    """Detect Mathematical Alphanumeric Symbols used as binary encoding."""
    found: list[tuple[int, int, str]] = []

    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp in MATH_ALPHA_RANGE:
            name = unicodedata.name(ch, f"U+{cp:05X}")
            found.append((i, cp, name))

    if not found:
        return []

    count = len(found)
    # Math bold 'a' = U+1D41A, etc. Each presence = 1 bit
    severity = Severity.MEDIUM if count > 3 else Severity.LOW
    confidence = 0.60 if count > 5 else 0.40

    return [Finding(
        method=StegMethod.MATH_ALPHANUMERIC,
        severity=severity,
        confidence=confidence,
        description=f"{count} Mathematical Alphanumeric Symbol(s) detected (possible steg encoding)",
        evidence="; ".join(f"'{chr(cp)}' ({name}) at pos {pos}" for pos, cp, name in found[:8]),
        location=f"positions: {', '.join(str(p) for p, _, _ in found[:10])}",
        metadata={"count": count},
    )]


def detect_braille(text: str) -> list[Finding]:
    """Detect Braille pattern characters used for byte encoding."""
    found: list[tuple[int, int]] = []

    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp in BRAILLE_RANGE:
            found.append((i, cp))

    if not found:
        return []

    count = len(found)
    # Try to decode: each Braille pattern = one byte (cp - 0x2800)
    decoded_bytes = bytes(cp - 0x2800 for _, cp in found)
    try:
        decoded = decoded_bytes.decode('utf-8', errors='replace')
    except Exception:
        decoded = decoded_bytes.hex()

    severity = Severity.HIGH if count > 10 else Severity.MEDIUM
    confidence = 0.75

    return [Finding(
        method=StegMethod.BRAILLE,
        severity=severity,
        confidence=confidence,
        description=f"{count} Braille pattern character(s) detected (byte encoding)",
        evidence=f"Raw bytes (hex): {decoded_bytes[:30].hex()}",
        decoded_payload=decoded if _is_readable(decoded) else f"[{count} encoded bytes]",
        location=f"positions: {', '.join(str(p) for p, _ in found[:10])}",
        metadata={"count": count, "byte_count": len(decoded_bytes)},
    )]


def detect_emoji_substitution(text: str) -> list[Finding]:
    """Detect emoji-based binary encoding (e.g., red=0 blue=1)."""
    # Look for repeating patterns of exactly 2 distinct emoji
    emoji_chars = []
    for i, ch in enumerate(text):
        if _is_emoji(ch):
            emoji_chars.append((i, ch))

    if len(emoji_chars) < 8:
        return []

    # Check if dominated by exactly 2 emoji types (binary encoding signal)
    emoji_only = [ch for _, ch in emoji_chars]
    counts = Counter(emoji_only)

    if len(counts) == 2:
        total = sum(counts.values())
        # Binary encoding: roughly equal distribution
        ratios = [c / total for c in counts.values()]
        if all(0.2 < r < 0.8 for r in ratios):
            types = list(counts.keys())
            bits = ['0' if ch == types[0] else '1' for ch in emoji_only]
            decoded = _bits_to_text(bits)

            return [Finding(
                method=StegMethod.EMOJI_SUBSTITUTION,
                severity=Severity.HIGH,
                confidence=0.85,
                description=f"Binary emoji encoding detected: {len(emoji_chars)} emoji, 2 types",
                evidence=f"Type A '{types[0]}': {counts[types[0]]}x, Type B '{types[1]}': {counts[types[1]]}x",
                decoded_payload=decoded if _is_readable(decoded) else f"[{len(bits)} bits]",
                location=f"first at pos {emoji_chars[0][0]}",
                metadata={"emoji_count": len(emoji_chars), "types": 2},
            )]

    # Multi-type emoji encoding: stegg and similar tools use N emoji types
    # to encode log2(N) bits per symbol. A high density of emoji with a small
    # set of types in non-social-media text is suspicious.
    if 3 <= len(counts) <= 32 and len(emoji_chars) >= 16:
        total = sum(counts.values())
        # Check that types are reasonably balanced (encoding signal)
        ratios = [c / total for c in counts.values()]
        max_ratio = max(ratios)
        min_ratio = min(ratios)
        # Encoding distributes roughly evenly; organic emoji usage is bursty
        if max_ratio < 0.25 or (min_ratio > 0.01 and max_ratio / max(min_ratio, 0.001) < 10):
            # High emoji density relative to text length is suspicious
            text_len = len(text)
            density = len(emoji_chars) / max(text_len, 1)
            if density > 0.05 and len(emoji_chars) >= 24:
                types_list = [f"'{ch}':{ct}" for ch, ct in counts.most_common(6)]
                return [Finding(
                    method=StegMethod.EMOJI_SUBSTITUTION,
                    severity=Severity.HIGH if len(emoji_chars) > 50 else Severity.MEDIUM,
                    confidence=0.70 if len(emoji_chars) > 50 else 0.55,
                    description=f"Multi-type emoji encoding detected: {len(emoji_chars)} emoji, {len(counts)} types",
                    evidence=f"Top types: {', '.join(types_list)}",
                    location=f"first at pos {emoji_chars[0][0]}",
                    metadata={"emoji_count": len(emoji_chars), "types": len(counts), "density": round(density, 4)},
                )]

    return []


def detect_emoji_skin_tone(text: str) -> list[Finding]:
    """Detect emoji skin tone modifier encoding (2 bits per modifier)."""
    modifiers: list[tuple[int, str, str]] = []

    for i, ch in enumerate(text):
        if ch in SKIN_TONE_MODIFIERS:
            modifiers.append((i, ch, SKIN_TONE_MODIFIERS[ch]))

    if len(modifiers) < 4:
        return []

    # Check for encoding pattern: sequence of skin-toned emoji
    # 4 skin tones = 2 bits each, so 4 emoji = 1 byte
    tone_values = {
        '\U0001F3FB': '00',
        '\U0001F3FC': '01',
        '\U0001F3FD': '10',  # or skip medium
        '\U0001F3FE': '10',
        '\U0001F3FF': '11',
    }

    bits = []
    for _, ch, _ in modifiers:
        bits.extend(tone_values.get(ch, '00'))

    decoded = _bits_to_text(bits) if len(bits) >= 8 else ""
    count = len(modifiers)

    # Consecutive skin-toned emoji of same base = suspicious
    severity = Severity.HIGH if count > 8 else Severity.MEDIUM
    confidence = 0.70 if count > 8 else 0.50

    return [Finding(
        method=StegMethod.EMOJI_SKIN_TONE,
        severity=severity,
        confidence=confidence,
        description=f"{count} emoji skin tone modifiers detected (2-bit encoding)",
        evidence=f"Modifier sequence: {' '.join(name.split()[0] for _, _, name in modifiers[:8])}",
        decoded_payload=decoded if _is_readable(decoded) else f"[{len(bits)} bits from {count} modifiers]",
        location=f"positions: {', '.join(str(p) for p, _, _ in modifiers[:10])}",
        metadata={"count": count, "bit_count": len(bits)},
    )]


def detect_invisible_separators(text: str) -> list[Finding]:
    """Catch-all for other invisible/format characters not covered above."""
    suspicious: list[tuple[int, int, str]] = []

    for i, ch in enumerate(text):
        cp = ord(ch)
        cat = unicodedata.category(ch)
        # Format characters (Cf) not already caught by other detectors
        if cat == 'Cf' and ch not in ZERO_WIDTH_CHARS and ch not in BIDI_CHARS:
            if cp not in TAG_RANGE:
                name = unicodedata.name(ch, f"U+{cp:04X}")
                suspicious.append((i, cp, name))

    if not suspicious:
        return []

    count = len(suspicious)
    severity = Severity.MEDIUM if count > 3 else Severity.LOW
    confidence = 0.50

    return [Finding(
        method=StegMethod.INVISIBLE_SEPARATOR,
        severity=severity,
        confidence=confidence,
        description=f"{count} invisible format character(s) detected",
        evidence="; ".join(f"{name} at pos {pos}" for pos, _, name in suspicious[:10]),
        location=f"positions: {', '.join(str(p) for p, _, _ in suspicious[:10])}",
        metadata={"count": count},
    )]


# ─── Helper functions ────────────────────────────────────────────────────────

def _bits_to_text(bits: list[str]) -> str:
    """Convert bit list to text (UTF-8)."""
    # Trim to multiple of 8
    bits = bits[:len(bits) - (len(bits) % 8)]
    if not bits:
        return ""
    byte_vals = []
    for i in range(0, len(bits), 8):
        byte_val = int("".join(bits[i:i+8]), 2)
        byte_vals.append(byte_val)
    try:
        return bytes(byte_vals).decode('utf-8', errors='replace')
    except Exception:
        return ""


def _is_readable(text: str) -> bool:
    """Check if decoded text contains readable ASCII content."""
    if not text or len(text) < 2:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in '\n\r\t')
    return (printable / len(text)) > 0.6


def _is_emoji(ch: str) -> bool:
    """Check if a character is an emoji."""
    cp = ord(ch)
    # Common emoji ranges
    return (
        0x1F600 <= cp <= 0x1F64F or  # Emoticons
        0x1F300 <= cp <= 0x1F5FF or  # Misc Symbols
        0x1F680 <= cp <= 0x1F6FF or  # Transport
        0x1F900 <= cp <= 0x1F9FF or  # Supplemental
        0x2600 <= cp <= 0x26FF or    # Misc Symbols
        0x2700 <= cp <= 0x27BF or    # Dingbats
        0x1FA00 <= cp <= 0x1FA6F or  # Chess Symbols
        0x1FA70 <= cp <= 0x1FAFF or  # Symbols Extended-A
        0xFE00 <= cp <= 0xFE0F       # Variation Selectors
    )


# ─── Trailing Whitespace Encoding ──────────────────────────────────────────

def detect_trailing_whitespace_encoding(text: str) -> list[Finding]:
    """Detect data encoded in trailing spaces/tabs per line (snow/whitespace steg)."""
    lines = text.split('\n')
    encoded_lines = 0
    total_trailing_bits = 0

    for line in lines:
        stripped = line.rstrip(' \t\r')
        trailing = line[len(stripped):].replace('\r', '')
        if len(trailing) >= 3:
            if set(trailing) <= {' ', '\t'}:
                encoded_lines += 1
                total_trailing_bits += len(trailing)

    if encoded_lines < 3:
        return []

    ratio = encoded_lines / max(len(lines), 1)
    if ratio < 0.3:
        return []

    severity = Severity.HIGH if encoded_lines > 10 else Severity.MEDIUM
    confidence = min(0.90, 0.50 + ratio * 0.5)

    bits = []
    for line in lines:
        stripped = line.rstrip(' \t\r')
        trailing = line[len(stripped):].replace('\r', '')
        for ch in trailing:
            bits.append('0' if ch == ' ' else '1')

    decoded = _bits_to_text(bits) if len(bits) >= 8 else ""

    return [Finding(
        method=StegMethod.CONFUSABLE_WHITESPACE,
        severity=severity,
        confidence=confidence,
        description=f"Trailing whitespace encoding: {encoded_lines}/{len(lines)} lines carry space/tab bits",
        evidence=f"{total_trailing_bits} trailing chars across {encoded_lines} lines",
        decoded_payload=decoded if _is_readable(decoded) else f"[{len(bits)} bits]",
        metadata={"encoded_lines": encoded_lines, "total_lines": len(lines), "bit_count": len(bits)},
    )]


# ─── Interlinear Annotation & Mongolian VS ─────────────────────────────────

# Interlinear annotation characters (invisible formatting, can carry hidden data)
INTERLINEAR_CHARS = {'\uFFF9': 'INTERLINEAR ANNOTATION ANCHOR',
                     '\uFFFA': 'INTERLINEAR ANNOTATION SEPARATOR',
                     '\uFFFB': 'INTERLINEAR ANNOTATION TERMINATOR'}

# Mongolian variation selectors (invisible, can encode bits like other VS chars)
MONGOLIAN_VS = {chr(c): f'MONGOLIAN FREE VARIATION SELECTOR {c - 0x180A}'
                for c in range(0x180B, 0x180E)}


def detect_interlinear_and_mongolian_vs(text: str) -> list[Finding]:
    """Detect interlinear annotation characters and Mongolian variation selectors."""
    findings = []

    # Interlinear annotation chars
    interlinear_found: list[tuple[int, str, str]] = []
    for i, ch in enumerate(text):
        if ch in INTERLINEAR_CHARS:
            interlinear_found.append((i, ch, INTERLINEAR_CHARS[ch]))

    if interlinear_found:
        count = len(interlinear_found)
        severity = Severity.HIGH if count > 3 else Severity.MEDIUM
        confidence = min(0.60 + (count * 0.05), 0.95)

        findings.append(Finding(
            method=StegMethod.ZERO_WIDTH,
            severity=severity,
            confidence=confidence,
            description=f"{count} interlinear annotation character(s) detected (invisible formatting, can hide data)",
            evidence="; ".join(f"{name} at pos {pos}" for pos, _, name in interlinear_found[:10]),
            location=f"positions: {', '.join(str(p) for p, _, _ in interlinear_found[:10])}",
            metadata={"count": count, "technique": "interlinear_annotation"},
        ))

    # Mongolian variation selectors
    mongolian_found: list[tuple[int, str, str]] = []
    for i, ch in enumerate(text):
        if ch in MONGOLIAN_VS:
            mongolian_found.append((i, ch, MONGOLIAN_VS[ch]))

    if mongolian_found:
        count = len(mongolian_found)
        # Mongolian VS in non-Mongolian text is suspicious
        has_mongolian_script = any('\u1800' <= ch <= '\u18AF' and ch not in MONGOLIAN_VS
                                   for ch in text)
        if has_mongolian_script:
            severity = Severity.LOW
            confidence = 0.30
        else:
            severity = Severity.HIGH if count > 3 else Severity.MEDIUM
            confidence = min(0.60 + (count * 0.05), 0.95)

        findings.append(Finding(
            method=StegMethod.VARIATION_SELECTORS,
            severity=severity,
            confidence=confidence,
            description=f"{count} Mongolian free variation selector(s) detected in {'Mongolian' if has_mongolian_script else 'non-Mongolian'} text",
            evidence="; ".join(f"{name} at pos {pos}" for pos, _, name in mongolian_found[:10]),
            location=f"positions: {', '.join(str(p) for p, _, _ in mongolian_found[:10])}",
            metadata={"count": count, "mongolian_context": has_mongolian_script,
                       "technique": "mongolian_vs"},
        ))

    return findings


# ─── Master text scanner ─────────────────────────────────────────────────────

ALL_TEXT_DETECTORS: list[Callable[[str], list[Finding]]] = [
    detect_zero_width,
    detect_unicode_tags,
    detect_homoglyphs,
    detect_variation_selectors,
    detect_combining_marks,
    detect_confusable_whitespace,
    detect_bidi_overrides,
    detect_hangul_filler,
    detect_math_alphanumeric,
    detect_braille,
    detect_emoji_substitution,
    detect_emoji_skin_tone,
    detect_invisible_separators,
    detect_trailing_whitespace_encoding,
    detect_interlinear_and_mongolian_vs,
]


def scan_text_all(text: str) -> list[Finding]:
    """Run all text steganography detectors on the input."""
    findings: list[Finding] = []
    for detector in ALL_TEXT_DETECTORS:
        findings.extend(detector(text))
    return findings
